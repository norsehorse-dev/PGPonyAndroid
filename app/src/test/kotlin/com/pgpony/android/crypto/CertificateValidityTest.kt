// CertificateValidityTest.kt
// PGPony Android, 3.0.0 checkpoint 5d-1: certificate and signature validity
// judged the way the OpenPGP interoperability test suite expects.
//
// Every certificate here is built in the test from Bouncy Castle key pairs
// with chosen creation times, so each rule is pinned on its own:
//
//   * a signature older than its key is rejected;
//   * a self-signature must be alive at the signature's time (an expiring
//     User ID binding leaves a gap; a later one closes it);
//   * hard revocations (no reason, unspecified, compromised) apply at every
//     time, soft ones (superseded, retired) only from when they were made,
//     and an expiring soft revocation lapses;
//   * key flags: an empty key flags subpacket grants nothing;
//   * a critical subpacket or notation that is not understood invalidates a
//     binding or a data signature; a hashed creation time is required;
//   * a back-signature that has expired no longer binds a signing subkey;
//   * a signature whose issuer subpacket names the wrong key still verifies
//     under the key that made it;
//   * only keys marked for encryption decrypt;
//   * an unknown critical packet makes a certificate unreadable, and a third-
//     party certification Bouncy Castle cannot read is dropped instead;
//   * a public primary with secret subkeys imports as a key.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SignatureSubpacket
import org.bouncycastle.bcpg.sig.RevocationReasonTags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

class CertificateValidityTest {

    private val random = SecureRandom()
    private val uid = "Validity Test <validity@example.test>"
    private val day = 86_400L

    /** Key creation time used throughout, epoch seconds (2020-09-13). */
    private val t1 = 1_600_000_000L

    // ── Builders ─────────────────────────────────────────────────────────

    private fun signingPair(created: Long): PGPKeyPair {
        val g = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(random)) }
        return BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, g.generateKeyPair(), Date(created * 1000))
    }

    private fun encryptionPair(created: Long): PGPKeyPair {
        val g = X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(random)) }
        return BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, g.generateKeyPair(), Date(created * 1000))
    }

    /** A raw subpacket, [critical] setting the high bit of the type octet. */
    private class RawSubpacket(type: Int, critical: Boolean, data: ByteArray) :
        SignatureSubpacket(type, critical, false, data)

    private fun hashed(
        created: Long,
        signer: PGPKeyPair,
        flags: Int? = null,
        sigExpires: Long? = null,
        keyExpires: Long? = null,
        reason: Int? = null,
        extra: (PGPSignatureSubpacketGenerator) -> Unit = {}
    ): PGPSignatureSubpacketVector {
        val sp = PGPSignatureSubpacketGenerator()
        sp.setSignatureCreationTime(false, Date(created * 1000))
        sp.setIssuerFingerprint(false, signer.publicKey)
        flags?.let { sp.setKeyFlags(false, it) }
        sigExpires?.let { sp.setSignatureExpirationTime(false, it) }
        keyExpires?.let { sp.setKeyExpirationTime(false, it) }
        reason?.let { sp.setRevocationReason(false, it.toByte(), "") }
        extra(sp)
        return sp.generate()
    }

    private fun generator(signer: PGPKeyPair, type: Int, hashed: PGPSignatureSubpacketVector,
                          unhashed: PGPSignatureSubpacketVector? = null): PGPSignatureGenerator =
        PGPSignatureGenerator(BcPGPContentSignerBuilder(signer.publicKey.algorithm, HashAlgorithmTags.SHA256), signer.publicKey)
            .apply {
                init(type, signer.privateKey)
                setHashedSubpackets(hashed)
                unhashed?.let { setUnhashedSubpackets(it) }
            }

    private fun uidCert(primary: PGPKeyPair, created: Long, flags: Int? = 0x03, sigExpires: Long? = null): PGPSignature =
        generator(primary, PGPSignature.POSITIVE_CERTIFICATION, hashed(created, primary, flags, sigExpires))
            .generateCertification(uid, primary.publicKey)

    private fun uidRevocation(primary: PGPKeyPair, created: Long, reason: Int?, sigExpires: Long? = null): PGPSignature =
        generator(primary, PGPSignature.CERTIFICATION_REVOCATION, hashed(created, primary, sigExpires = sigExpires, reason = reason))
            .generateCertification(uid, primary.publicKey)

    private fun keyRevocation(primary: PGPKeyPair, created: Long, reason: Int?, sigExpires: Long? = null): PGPSignature =
        generator(primary, PGPSignature.KEY_REVOCATION, hashed(created, primary, sigExpires = sigExpires, reason = reason))
            .generateCertification(primary.publicKey)

    private fun backSig(primary: PGPKeyPair, sub: PGPKeyPair, created: Long, sigExpires: Long? = null): PGPSignature =
        generator(sub, PGPSignature.PRIMARYKEY_BINDING, hashed(created, sub, sigExpires = sigExpires))
            .generateCertification(primary.publicKey, sub.publicKey)

    private fun binding(
        primary: PGPKeyPair, sub: PGPKeyPair, created: Long, flags: Int?,
        back: PGPSignature? = null,
        extra: (PGPSignatureSubpacketGenerator) -> Unit = {}
    ): PGPSignature {
        val unhashed = back?.let { PGPSignatureSubpacketGenerator().apply { addEmbeddedSignature(false, it) }.generate() }
        return generator(primary, PGPSignature.SUBKEY_BINDING, hashed(created, primary, flags, extra = extra), unhashed)
            .generateCertification(primary.publicKey, sub.publicKey)
    }

    private fun body(encoded: ByteArray) = CertificateBindings.packets(encoded).first().body

    /** Primary, one User ID with [uidSigs], then each subkey with its signatures. */
    private fun cert(
        primary: PGPKeyPair,
        primarySigs: List<PGPSignature> = emptyList(),
        uidSigs: List<PGPSignature>,
        subkeys: List<Pair<PGPKeyPair, List<PGPSignature>>> = emptyList(),
        extraPackets: List<Pair<Int, ByteArray>> = emptyList()
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(CertificateBindings.frame(6, primary.publicKey.publicKeyPacket.encodedContents))
        primarySigs.forEach { out.write(CertificateBindings.frame(2, body(it.encoded))) }
        out.write(CertificateBindings.frame(13, uid.toByteArray()))
        uidSigs.forEach { out.write(CertificateBindings.frame(2, body(it.encoded))) }
        for ((k, sigs) in subkeys) {
            out.write(CertificateBindings.frame(14, k.publicKey.publicKeyPacket.encodedContents))
            sigs.forEach { out.write(CertificateBindings.frame(2, body(it.encoded))) }
        }
        extraPackets.forEach { (tag, b) -> out.write(CertificateBindings.frame(tag, b)) }
        return out.toByteArray()
    }

    private fun ring(raw: ByteArray) = PGPPublicKeyRing(CertificateBindings.sanitize(raw), BcKeyFingerprintCalculator())

    private fun status(key: PGPKeyPair, at: Long, raw: ByteArray): SignerStatus =
        SignerEvaluator.evaluate(key.keyID, Date(at * 1000), listOf(ring(raw)))

    private fun dataSig(signer: PGPKeyPair, created: Long, data: ByteArray,
                        hashedV: PGPSignatureSubpacketVector = hashed(created, signer),
                        unhashedV: PGPSignatureSubpacketVector? = null): ByteArray {
        val g = generator(signer, PGPSignature.BINARY_DOCUMENT, hashedV, unhashedV)
        g.update(data)
        return g.generate().encoded
    }

    private fun fp(k: PGPKeyPair) = SignerEvaluator.fpHex(k.publicKey)

    // ── Time ─────────────────────────────────────────────────────────────

    @Test
    fun `a signature older than its key is rejected`() {
        val p = signingPair(t1)
        val raw = cert(p, uidSigs = listOf(uidCert(p, t1)))
        assertEquals(SignerStatus.PREDATES_KEY, status(p, t1 - day, raw))
        assertEquals(SignerStatus.VERIFIED, status(p, t1 + day, raw))
    }

    @Test
    fun `an expired User ID binding leaves a gap that a later one closes`() {
        val p = signingPair(t1)
        val raw = cert(p, uidSigs = listOf(uidCert(p, t1, sigExpires = 28 * day), uidCert(p, t1 + 56 * day)))
        assertEquals(SignerStatus.VERIFIED, status(p, t1 + 10 * day, raw))
        assertEquals(SignerStatus.NOT_VALID_AT_TIME, status(p, t1 + 40 * day, raw))
        assertEquals(SignerStatus.VERIFIED, status(p, t1 + 60 * day, raw))
    }

    @Test
    fun `a certificate re-signed later still covers signatures made before the new self-signature`() {
        val p = signingPair(t1)
        // Only the newer self-signature survives (a minimal export, say).
        val raw = cert(p, uidSigs = listOf(uidCert(p, t1 + 100 * day)))
        assertEquals(SignerStatus.VERIFIED, status(p, t1 + day, raw))
    }

    @Test
    fun `a temporarily revoked User ID makes the certificate invalid only while the revocation lasts`() {
        val p = signingPair(t1)
        val raw = cert(
            p, uidSigs = listOf(uidCert(p, t1), uidRevocation(p, t1 + 28 * day, reason = 32, sigExpires = 28 * day))
        )
        assertEquals(SignerStatus.VERIFIED, status(p, t1 + 10 * day, raw))
        assertEquals(SignerStatus.NOT_VALID_AT_TIME, status(p, t1 + 40 * day, raw))
        assertEquals(SignerStatus.VERIFIED, status(p, t1 + 60 * day, raw))
    }

    // ── Revocations ──────────────────────────────────────────────────────

    @Test
    fun `hard revocations apply at every time`() {
        for (reason in listOf(null, RevocationReasonTags.NO_REASON.toInt(), RevocationReasonTags.KEY_COMPROMISED.toInt(), 100)) {
            val p = signingPair(t1)
            val raw = cert(p, primarySigs = listOf(keyRevocation(p, t1 + 30 * day, reason)), uidSigs = listOf(uidCert(p, t1)))
            assertEquals("reason $reason, before", SignerStatus.REVOKED_KEY, status(p, t1 + day, raw))
            assertEquals("reason $reason, after", SignerStatus.REVOKED_KEY, status(p, t1 + 40 * day, raw))
        }
    }

    @Test
    fun `soft revocations apply only from when they were made`() {
        for (reason in listOf(RevocationReasonTags.KEY_SUPERSEDED.toInt(), RevocationReasonTags.KEY_RETIRED.toInt(), 32)) {
            val p = signingPair(t1)
            val raw = cert(p, primarySigs = listOf(keyRevocation(p, t1 + 30 * day, reason)), uidSigs = listOf(uidCert(p, t1)))
            assertEquals("reason $reason, before", SignerStatus.VERIFIED, status(p, t1 + day, raw))
            assertEquals("reason $reason, after", SignerStatus.REVOKED_KEY, status(p, t1 + 40 * day, raw))
            assertTrue(CertificateBindings.analyze(CertificateBindings.sanitize(raw))!!.primaryRevoked)
        }
    }

    @Test
    fun `an expiring soft revocation lapses`() {
        val p = signingPair(t1)
        val raw = cert(
            p,
            primarySigs = listOf(keyRevocation(p, t1 + 28 * day, RevocationReasonTags.KEY_RETIRED.toInt(), sigExpires = 28 * day)),
            uidSigs = listOf(uidCert(p, t1))
        )
        assertEquals(SignerStatus.VERIFIED, status(p, t1 + 10 * day, raw))
        assertEquals(SignerStatus.REVOKED_KEY, status(p, t1 + 40 * day, raw))
        assertEquals(SignerStatus.VERIFIED, status(p, t1 + 60 * day, raw))
        assertFalse("not revoked now", CertificateBindings.analyze(CertificateBindings.sanitize(raw))!!.primaryRevoked)
    }

    @Test
    fun `a soft subkey revocation keeps older signatures and a hard one does not`() {
        val p = signingPair(t1)
        val s = signingPair(t1)
        fun revoked(reason: Int): ByteArray {
            val rev = generator(p, PGPSignature.SUBKEY_REVOCATION, hashed(t1 + 30 * day, p, reason = reason))
                .generateCertification(p.publicKey, s.publicKey)
            return cert(p, uidSigs = listOf(uidCert(p, t1, flags = 0x01)),
                subkeys = listOf(s to listOf(binding(p, s, t1, 0x02, backSig(p, s, t1)), rev)))
        }
        val soft = revoked(RevocationReasonTags.KEY_RETIRED.toInt())
        assertEquals(SignerStatus.VERIFIED, status(s, t1 + day, soft))
        assertEquals(SignerStatus.REVOKED_KEY, status(s, t1 + 40 * day, soft))
        val hard = revoked(RevocationReasonTags.KEY_COMPROMISED.toInt())
        assertEquals(SignerStatus.REVOKED_KEY, status(s, t1 + day, hard))
    }

    // ── Key flags and bindings ───────────────────────────────────────────

    @Test
    fun `an empty key flags subpacket grants neither signing nor encryption`() {
        val p = signingPair(t1)
        val s = signingPair(t1)
        val e = encryptionPair(t1)
        val raw = cert(
            p, uidSigs = listOf(uidCert(p, t1, flags = 0x01)),
            subkeys = listOf(
                s to listOf(binding(p, s, t1, 0, backSig(p, s, t1))),
                e to listOf(binding(p, e, t1, 0))
            )
        )
        assertEquals(SignerStatus.NOT_SIGNING_KEY, status(s, t1 + day, raw))
        val report = CertificateBindings.analyze(CertificateBindings.sanitize(raw))!!
        assertFalse(report.isUsableEncryptionKey(fp(e), System.currentTimeMillis()))
        assertFalse(report.mayDecryptWith(fp(e)))
    }

    @Test
    fun `only keys marked for encryption may decrypt`() {
        val p = signingPair(t1)
        val s = signingPair(t1)
        val e = encryptionPair(t1)
        val legacy = encryptionPair(t1)
        val raw = cert(
            p, uidSigs = listOf(uidCert(p, t1, flags = 0x03)),
            subkeys = listOf(
                s to listOf(binding(p, s, t1, 0x02, backSig(p, s, t1))),
                e to listOf(binding(p, e, t1, 0x0C)),
                legacy to listOf(binding(p, legacy, t1, null))
            )
        )
        val report = CertificateBindings.analyze(CertificateBindings.sanitize(raw))!!
        assertFalse("certify+sign primary", report.mayDecryptWith(fp(p)))
        assertFalse("signing subkey", report.mayDecryptWith(fp(s)))
        assertTrue("encryption subkey", report.mayDecryptWith(fp(e)))
        assertTrue("no key flags at all (older software)", report.mayDecryptWith(fp(legacy)))
    }

    @Test
    fun `a binding with a critical unknown subpacket or notation does not bind`() {
        val p = signingPair(t1)
        val cases = mapOf<String, (PGPSignatureSubpacketGenerator) -> Unit>(
            "critical unknown subpacket" to { it.addCustomSubpacket(RawSubpacket(99, true, byteArrayOf(1))) },
            "critical notation" to { it.addNotationData(true, true, "test@example.test", "x") }
        )
        for ((name, extra) in cases) {
            val e = encryptionPair(t1)
            val raw = cert(p, uidSigs = listOf(uidCert(p, t1)), subkeys = listOf(e to listOf(binding(p, e, t1, 0x0C, extra = extra))))
            val report = CertificateBindings.analyze(raw)!!
            assertFalse(name, report.subkeyByFingerprint(fp(e))!!.bound)
        }
        val ok = encryptionPair(t1)
        val raw = cert(p, uidSigs = listOf(uidCert(p, t1)), subkeys = listOf(ok to listOf(binding(p, ok, t1, 0x0C) {
            it.addCustomSubpacket(RawSubpacket(99, false, byteArrayOf(1)))
            it.addNotationData(false, true, "test@example.test", "x")
        })))
        assertTrue("non-critical unknowns are ignored", CertificateBindings.analyze(raw)!!.subkeyByFingerprint(fp(ok))!!.bound)
    }

    @Test
    fun `an expired back-signature no longer binds a signing subkey`() {
        val p = signingPair(t1)
        val s = signingPair(t1)
        val raw = cert(
            p, uidSigs = listOf(uidCert(p, t1, flags = 0x01)),
            subkeys = listOf(s to listOf(binding(p, s, t1, 0x02, backSig(p, s, t1, sigExpires = 10 * day))))
        )
        assertEquals(SignerStatus.VERIFIED, status(s, t1 + day, raw))
        assertEquals(SignerStatus.UNBOUND_SIGNER, status(s, t1 + 20 * day, raw))
    }

    // ── Data signatures ──────────────────────────────────────────────────

    @Test
    fun `a data signature needs a hashed creation time and no critical unknowns`() {
        val p = signingPair(t1)
        val data = "Hello World :)".toByteArray()
        val raw = cert(p, uidSigs = listOf(uidCert(p, t1)))
        val rings = listOf(ring(raw))
        val now = System.currentTimeMillis() / 1000
        fun verify(sig: ByteArray) = VerifyService.shared.verifyDetached(sig, data, rings)

        assertTrue(verify(dataSig(p, now, data)) is VerificationResult.Verified)
        val critical = hashed(now, p) { it.addCustomSubpacket(RawSubpacket(99, true, byteArrayOf(1))) }
        assertTrue(verify(dataSig(p, now, data, critical)) is VerificationResult.Invalid)
        val notation = hashed(now, p) { it.addNotationData(true, true, "test@example.test", "x") }
        assertTrue(verify(dataSig(p, now, data, notation)) is VerificationResult.Invalid)
        val unknown = hashed(now, p) { it.addCustomSubpacket(RawSubpacket(99, false, byteArrayOf(1))) }
        assertTrue(verify(dataSig(p, now, data, unknown)) is VerificationResult.Verified)
    }

    @Test
    fun `a signature naming the wrong issuer still verifies under the key that made it`() {
        val p = signingPair(t1)
        val data = "Hello World :)".toByteArray()
        val rings = listOf(ring(cert(p, uidSigs = listOf(uidCert(p, t1)))))
        val now = System.currentTimeMillis() / 1000
        val fake = PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date(now * 1000))
            setIssuerKeyID(false, 0x0123456789ABCDEFL)
        }.generate()
        val result = VerifyService.shared.verifyDetached(dataSig(p, now, data, fake), data, rings)
        assertTrue("$result", result is VerificationResult.Verified)
        assertEquals(fp(p), (result as VerificationResult.Verified).signingKeyFingerprint)
    }

    // ── Parsing ──────────────────────────────────────────────────────────

    @Test
    fun `an unknown critical packet makes the certificate unreadable`() {
        val p = signingPair(t1)
        val critical = cert(p, uidSigs = listOf(uidCert(p, t1)), extraPackets = listOf(39 to byteArrayOf(1, 2, 3)))
        assertEquals(0, CertificateBindings.sanitize(critical).size)
        assertTrue(PGPCryptoService.shared.explodeToArmoredKeys(critical).isEmpty())
        val harmless = cert(p, uidSigs = listOf(uidCert(p, t1)), extraPackets = listOf(40 to byteArrayOf(1, 2, 3)))
        assertEquals(1, PGPCryptoService.shared.explodeToArmoredKeys(harmless).size)
    }

    @Test
    fun `a third-party certification Bouncy Castle cannot read is dropped, not the certificate`() {
        val p = signingPair(t1)
        // v4 generic certification, public-key algorithm 99, issued by some other key.
        val hashedArea = byteArrayOf(5, 2) + beBytes(t1 + day) + byteArrayOf(9, 16) + ByteArray(8) { 0x42 }
        val sig = byteArrayOf(4, 0x10, 99, 8, 0, hashedArea.size.toByte()) + hashedArea +
            byteArrayOf(0, 0, 0x12, 0x34, 0, 8, 0x7F)
        val raw = cert(p, uidSigs = listOf(uidCert(p, t1)))
        val pkts = CertificateBindings.packets(raw)
        val out = ByteArrayOutputStream()
        pkts.forEach { out.write(CertificateBindings.frame(it.tag, it.body)) }
        out.write(CertificateBindings.frame(2, sig))
        val imported = PGPCryptoService.shared.importKeyData(out.toByteArray())
        assertEquals(fp(p), imported.fingerprint)
    }

    @Test
    fun `a public primary with secret subkeys imports as a key`() {
        val gen = PGPCryptoService.shared.generateKeyPair(
            name = "Stripped", email = "stripped@example.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = null
        )
        val secret = PGPCryptoService.shared.importKeyData(gen.privateKeyData).secretKeyRing!!.encoded
        val pkts = CertificateBindings.packets(secret)
        val out = ByteArrayOutputStream()
        out.write(CertificateBindings.frame(6, CertificateBindings.publicPart(5, pkts.first().body)!!))
        pkts.drop(1).forEach { out.write(CertificateBindings.frame(it.tag, it.body)) }
        val imported = PGPCryptoService.shared.importKeyData(out.toByteArray())
        assertTrue(imported.hasPrivateKey)
        val ring = imported.secretKeyRing!!
        assertTrue("primary is a stub", ring.secretKey.isPrivateKeyEmpty)
        assertTrue("subkeys keep their secrets", ring.secretKeys.asSequence().drop(1).all { !it.isPrivateKeyEmpty })
    }

    private fun beBytes(n: Long) = byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())
}
