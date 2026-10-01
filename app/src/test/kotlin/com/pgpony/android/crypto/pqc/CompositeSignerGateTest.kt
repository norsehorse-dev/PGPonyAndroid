// CompositeSignerGateTest.kt
// Composite ML-DSA + EdDSA signatures are graded like classical ones
// (ENGINE-4, SOP-1): a revoked or expired signer key, a signature older than
// its key, a non-document signature type, a missing or future creation time,
// an unknown critical subpacket or an expired signature never come out
// VERIFIED, on the detached, cleartext and inline forms.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.SignerStatus
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

class CompositeSignerGateTest {

    private val suite = CompositeSignSuite.MLDSA65_ED25519
    private val rnd = SecureRandom()
    private val day = 24L * 60 * 60 * 1000
    private val data = "release-1.2.3.tar.gz contents".toByteArray()

    private class Key(val raw: ByteArray, val secret: ByteArray, val fp: ByteArray, val pubBody: ByteArray) {
        val fpHex: String get() = fp.joinToString("") { "%02X".format(it) }
    }

    private fun newKey(created: Date = Date(System.currentTimeMillis() - day), expirySeconds: Long? = null): Key {
        val raw = CompositePrimaryKeyGen.assemble("Signer <signer@example.test>", suite, rnd, created, expirySeconds)
        val info = CompositeKeyFacade.parse(raw)
        val primary = CertificateBindings.packets(raw).first()
        val pubBody = CertificateBindings.publicPart(primary.tag, primary.body)!!
        return Key(raw, info.compositeSecret!!, info.fingerprint, pubBody)
    }

    private fun u32(v: Long) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun sub(type: Int, body: ByteArray): ByteArray = byteArrayOf((body.size + 1).toByte(), type.toByte()) + body

    private fun created(ms: Long) = sub(2 or 0x80, u32(ms / 1000))

    private fun issuer(k: Key) = sub(33, byteArrayOf(6) + k.fp)

    /** A v6 composite signature body over [signed] with the given hashed area. */
    private fun sigBody(k: Key, type: Int, signed: ByteArray, hashed: ByteArray): ByteArray {
        val salt = ByteArray(16).also { rnd.nextBytes(it) }
        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = 8, salt = salt, data = signed, signatureType = type,
            publicKeyAlgorithm = suite.algId, hashedSubpacketBody = hashed
        )
        val sig = CompositeSigner.sign(suite, k.secret, digest, rnd)
        return ByteArrayOutputStream().apply {
            write(6); write(type); write(suite.algId); write(8)
            write(u32(hashed.size.toLong())); write(hashed)
            write(u32(0))
            write(digest[0].toInt() and 0xFF); write(digest[1].toInt() and 0xFF)
            write(salt.size); write(salt)
            write(sig)
        }.toByteArray()
    }

    private fun detached(k: Key, hashed: ByteArray, type: Int = 0): ByteArray =
        CompositeSigPacket.packet(2, sigBody(k, type, data, hashed))

    private fun goodHashed(k: Key, at: Long = System.currentTimeMillis()) = created(at) + issuer(k)

    /** [k]'s certificate with a hard (key compromised) revocation made at [at]. */
    private fun revoked(k: Key, at: Long = System.currentTimeMillis()): ByteArray {
        val frame = byteArrayOf(0x9B.toByte()) + u32(k.pubBody.size.toLong()) + k.pubBody
        val hashed = created(at) + sub(29, byteArrayOf(2) + "compromised".toByteArray()) + issuer(k)
        val rev = CompositeSigPacket.packet(2, sigBody(k, 0x20, frame, hashed))
        val pkts = CertificateBindings.packets(k.raw)
        val out = ByteArrayOutputStream()
        out.write(CertificateBindings.frame(pkts[0].tag, pkts[0].body))
        out.write(rev)
        for (p in pkts.drop(1)) out.write(CertificateBindings.frame(p.tag, p.body))
        return out.toByteArray()
    }

    @Test
    fun `a good composite signature is VERIFIED and names the key that made it`() {
        val k = newKey()
        val sig = CompositeDocumentSigner.signDetached(suite, k.secret, k.fp, data, random = rnd)
        val g = CompositeSignerGate.verifyDetached(listOf(k.raw), sig, data)
        assertEquals(SignerStatus.VERIFIED, g.status)
        assertEquals(k.fpHex, g.signingKeyFingerprint)
        assertEquals(k.fpHex, g.signerPrimaryFingerprint)
        assertEquals(0, g.certIndex)
        // The public certificate alone grades the same.
        val pub = CompositeKeyFacade.publicRingOf(k.raw)
        assertEquals(SignerStatus.VERIFIED, CompositeSignerGate.verifyDetached(listOf(pub), sig, data).status)
    }

    @Test
    fun `ENGINE-4 a hard revoked composite primary is REVOKED_KEY even for an older signature`() {
        val k = newKey(created = Date(System.currentTimeMillis() - 10 * day))
        val sig = detached(k, goodHashed(k, System.currentTimeMillis() - 5 * day))
        val cert = revoked(k)
        assertTrue(CertificateBindings.analyze(cert)!!.primaryRevoked)
        assertEquals(SignerStatus.REVOKED_KEY, CompositeSignerGate.verifyDetached(listOf(cert), sig, data).status)
        // Before the revocation was known the same signature verified.
        assertEquals(SignerStatus.VERIFIED, CompositeSignerGate.verifyDetached(listOf(k.raw), sig, data).status)
    }

    @Test
    fun `ENGINE-4 an expired composite key is EXPIRED_KEY`() {
        val k = newKey(created = Date(System.currentTimeMillis() - 10 * day), expirySeconds = 24L * 60 * 60)
        val sig = detached(k, goodHashed(k))
        assertEquals(SignerStatus.EXPIRED_KEY, CompositeSignerGate.verifyDetached(listOf(k.raw), sig, data).status)
    }

    @Test
    fun `ENGINE-4 a signature older than its key is PREDATES_KEY`() {
        val k = newKey(created = Date(System.currentTimeMillis() - day))
        val sig = detached(k, goodHashed(k, System.currentTimeMillis() - 5 * day))
        assertEquals(SignerStatus.PREDATES_KEY, CompositeSignerGate.verifyDetached(listOf(k.raw), sig, data).status)
    }

    @Test
    fun `ENGINE-4 policy failures are never VERIFIED`() {
        val k = newKey()
        val now = System.currentTimeMillis()
        val cases = mapOf(
            "certification type" to (detached(k, goodHashed(k), type = 0x13) to SignerStatus.INVALID),
            "no creation time" to (detached(k, issuer(k)) to SignerStatus.WEAK_SIGNATURE),
            "future creation time" to (detached(k, goodHashed(k, now + 3 * day)) to SignerStatus.WEAK_SIGNATURE),
            "unknown critical subpacket" to
                (detached(k, goodHashed(k) + sub(99 or 0x80, byteArrayOf(1))) to SignerStatus.WEAK_SIGNATURE),
            "critical notation" to
                (detached(k, goodHashed(k) + sub(20 or 0x80, ByteArray(8))) to SignerStatus.WEAK_SIGNATURE),
            "ENGINE-7 expired signature" to
                (detached(k, created(now - 2 * 60 * 60 * 1000) + sub(3, u32(60)) + issuer(k)) to SignerStatus.EXPIRED_SIGNATURE)
        )
        for ((name, case) in cases) {
            val (sig, want) = case
            val g = CompositeSignerGate.verifyDetached(listOf(k.raw), sig, data)
            assertEquals(name, want, g.status)
            // The single-key verifier refuses the same signatures.
            val r = CompositeDocumentVerifier.verifyDetached(CompositeKeyFacade.parse(k.raw).compositePublic, sig, data)
            assertFalse(name, r.valid)
        }
        // A signature expiration that has not passed yet still verifies.
        val live = detached(k, created(now - 60_000) + sub(3, u32(3600)) + issuer(k))
        assertEquals(SignerStatus.VERIFIED, CompositeSignerGate.verifyDetached(listOf(k.raw), live, data).status)
    }

    @Test
    fun `wrong data is INVALID and a missing certificate is UNKNOWN_SIGNER`() {
        val k = newKey()
        val sig = CompositeDocumentSigner.signDetached(suite, k.secret, k.fp, data, random = rnd)
        assertEquals(SignerStatus.INVALID, CompositeSignerGate.verifyDetached(listOf(k.raw), sig, "other".toByteArray()).status)
        val other = newKey()
        val g = CompositeSignerGate.verifyDetached(listOf(other.raw), sig, data)
        assertEquals(SignerStatus.UNKNOWN_SIGNER, g.status)
        assertEquals(k.fpHex, g.claimedFingerprint)
    }

    @Test
    fun `the signer is the key that verifies, not the issuer subpacket`() {
        val k = newKey()
        val other = newKey()
        // Signed by k but claiming to be from other.
        val sig = detached(k, created(System.currentTimeMillis()) + issuer(other))
        val g = CompositeSignerGate.verifyDetached(listOf(other.raw, k.raw), sig, data)
        assertEquals(SignerStatus.VERIFIED, g.status)
        assertEquals(k.fpHex, g.signingKeyFingerprint)
        assertEquals(1, g.certIndex)
    }

    @Test
    fun `cleartext and inline forms are graded too`() {
        val k = newKey(created = Date(System.currentTimeMillis() - 10 * day))
        val text = "Hello,\n-----BEGIN PGP SIGNATURE-----\nsigned text\n"
        val clear = CompositeDocumentSigner.signCleartext(suite, k.secret, k.fp, text, random = rnd)
        val inline = CompositeDocumentSigner.signInline(suite, k.secret, k.fp, data, random = rnd)
        assertEquals(SignerStatus.VERIFIED, CompositeSignerGate.verifyCleartext(listOf(k.raw), clear).status)
        val gi = CompositeSignerGate.verifyInline(listOf(k.raw), inline)
        assertEquals(SignerStatus.VERIFIED, gi.status)
        assertArrayEquals(data, gi.content)
        val cert = revoked(k)
        assertEquals(SignerStatus.REVOKED_KEY, CompositeSignerGate.verifyCleartext(listOf(cert), clear).status)
        assertEquals(SignerStatus.REVOKED_KEY, CompositeSignerGate.verifyInline(listOf(cert), inline).status)
    }

    @Test
    fun `an inline signature must match its one-pass packet and the literal must be single`() {
        val k = newKey()
        val inline = CompositeDocumentSigner.signInline(suite, k.secret, k.fp, data, random = rnd)
        val pkts = CompositeDocumentVerifier.packetsOf(inline)
        assertEquals(4, pkts[0].first)
        // A one-pass packet naming another key.
        val ops = pkts[0].second.copyOf()
        val fpAt = 5 + (ops[4].toInt() and 0xFF)
        ops[fpAt] = (ops[fpAt].toInt() xor 1).toByte()
        val tampered = rebuild(listOf(4 to ops) + pkts.drop(1))
        assertEquals(SignerStatus.INVALID, CompositeSignerGate.verifyInline(listOf(k.raw), tampered).status)
        // A second literal.
        val twoLiterals = rebuild(listOf(pkts[0], pkts[1], pkts[1], pkts[2]))
        assertEquals(SignerStatus.INVALID, CompositeSignerGate.verifyInline(listOf(k.raw), twoLiterals).status)
    }

    private fun rebuild(pkts: List<Pair<Int, ByteArray>>): ByteArray =
        ByteArrayOutputStream().apply { pkts.forEach { write(CompositeSigPacket.packet(it.first, it.second)) } }.toByteArray()

    @Test
    fun `policyStatus reads only the hashed area`() {
        val k = newKey()
        val now = System.currentTimeMillis()
        val body = sigBody(k, 0, data, issuer(k))
        assertEquals(SignerStatus.WEAK_SIGNATURE, CompositeSignerGate.policyStatus(body, now))
        assertEquals(null, CompositeSignerGate.policyStatus(sigBody(k, 0, data, goodHashed(k, now)), now))
        assertNotNull(CertificateBindings.sigOrNull(body))
    }

    @Test
    fun `graded results map onto VerificationResult`() {
        val k = newKey(created = Date(System.currentTimeMillis() - 10 * day))
        val sig = CompositeDocumentSigner.signDetached(suite, k.secret, k.fp, data, random = rnd)
        val ok = CompositeSignerGate.toVerificationResult(
            CompositeSignerGate.verifyDetached(listOf(k.raw), sig, data), "Signer", "signer@example.test"
        ) as com.pgpony.android.crypto.VerificationResult.Verified
        assertEquals(k.fpHex.take(16), ok.signerKeyID)
        assertEquals(k.fpHex, ok.signingKeyFingerprint)
        assertEquals(k.fpHex, ok.signerFingerprint)
        val bad = CompositeSignerGate.toVerificationResult(
            CompositeSignerGate.verifyDetached(listOf(revoked(k)), sig, data), "Signer", null
        ) as com.pgpony.android.crypto.VerificationResult.Invalid
        assertEquals(SignerStatus.REVOKED_KEY, bad.signerStatus)
        assertEquals(k.fpHex, bad.signingKeyFingerprint)
        val unknown = CompositeSignerGate.toVerificationResult(CompositeSignerGate.verifyDetached(emptyList(), sig, data), null, null)
        assertTrue(unknown is com.pgpony.android.crypto.VerificationResult.UnknownSigner)
    }

    @Test
    fun `compositeSigners lists the primary even when revoked, so it is not a validity filter`() {
        val k = newKey(created = Date(System.currentTimeMillis() - 10 * day))
        val info = CompositeKeyFacade.parse(revoked(k))
        assertTrue(info.compositeSigners.any { it.fingerprintHex.equals(k.fpHex, ignoreCase = true) })
    }
}
