// ContentWalkerTest.kt
// PGPony Android: the shared content walk (ContentWalker) behind the
// in-memory decrypt, the signed-only path, the streaming decrypt and the
// smart-card decrypt. Every path must read exactly one literal, pair each
// one-pass signature with the signature that closes it, and never report a
// signature as verified over content it did not cover.
//
// Regression tests for ENGINE-1, ENGINE-2, ENGINE-3, ENGINE-5, ENGINE-6,
// FILES-6 and GAP-1 (engine part).

package com.pgpony.android.crypto

import com.pgpony.android.crypto.card.CardDecryptService
import com.pgpony.android.crypto.card.OpenPgpCardException
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.util.Date

class ContentWalkerTest {

    private val svc = PGPCryptoService.shared
    private val card = CardDecryptService.shared

    // ── Keys and packet builders ─────────────────────────────────────────

    private class Party(val sec: PGPSecretKeyRing, val pub: PGPPublicKeyRing)

    private fun party(name: String): Party {
        val g = svc.generateKeyPair(name, "$name@example.org", KeyAlgorithm.ED25519_CV25519, null)
        return Party(
            PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator()),
            PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
        )
    }

    private val alice by lazy { party("alice") }
    private val bob by lazy { party("bob") }
    private val carol by lazy { party("carol") }

    private val signed = "Alice: the meeting is at 10\n".toByteArray()
    private val evil = "EVIL: wire 5000 EUR to MALLORY\n".toByteArray()

    private fun cat(vararg parts: ByteArray): ByteArray =
        ByteArrayOutputStream().apply { parts.forEach { write(it) } }.toByteArray()

    private fun lit(data: ByteArray, name: String = "f"): ByteArray {
        val bo = ByteArrayOutputStream()
        PGPLiteralDataGenerator().open(bo, PGPLiteralData.BINARY, name, data.size.toLong(), Date()).use { it.write(data) }
        return bo.toByteArray()
    }

    /** A compressed data packet with a definite length, so packets placed
     *  after it stay outside it (Bouncy Castle's generator writes an
     *  indeterminate length, which runs to the end of the input). */
    private fun compressed(inner: ByteArray, algo: Int = PGPCompressedData.ZLIB): ByteArray {
        val bo = ByteArrayOutputStream()
        val g = PGPCompressedDataGenerator(algo)
        g.open(bo).use { it.write(inner) }
        val body = MessageGrammar.packets(bo.toByteArray()).single().body()
        return CertificateBindings.frame(8, body)
    }

    /** A signature generator for [p]'s signing key, ready for update(). */
    private fun generator(p: Party, type: Int, hash: Int = HashAlgorithmTags.SHA256): PGPSignatureGenerator {
        val sk = svc.pickSigningSecretKey(p.sec)!!
        val priv = sk.extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)))
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, hash), sk.publicKey)
        g.init(type, priv)
        val sp = PGPSignatureSubpacketGenerator()
        sp.setIssuerFingerprint(false, sk.publicKey)
        sp.setSignatureCreationTime(false, Date())
        g.setHashedSubpackets(sp.generate())
        return g
    }

    private fun opsOf(p: Party, type: Int = PGPSignature.BINARY_DOCUMENT, hash: Int = HashAlgorithmTags.SHA256, nested: Boolean = false) =
        ByteArrayOutputStream().also { generator(p, type, hash).generateOnePassVersion(nested).encode(it) }.toByteArray()

    private fun sigOf(p: Party, data: ByteArray, type: Int = PGPSignature.BINARY_DOCUMENT, hash: Int = HashAlgorithmTags.SHA256): ByteArray {
        val g = generator(p, type, hash)
        g.update(data)
        return ByteArrayOutputStream().also { g.generate().encode(it) }.toByteArray()
    }

    /** One-pass signed message: OPS, Literal, Signature. */
    private fun signedBy(p: Party, data: ByteArray = signed) = cat(opsOf(p), lit(data), sigOf(p, data))

    private fun encryptRaw(plainPackets: ByteArray, to: Party, integrity: Boolean = true): ByteArray {
        val bo = ByteArrayOutputStream()
        val g = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(integrity)
        )
        g.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(to.pub.publicKeys.asSequence().first { it.isEncryptionKey && !it.isMasterKey }))
        g.open(bo, plainPackets.size.toLong()).use { it.write(plainPackets) }
        return bo.toByteArray()
    }

    private fun armor(bin: ByteArray, comment: String? = null): String {
        val bo = ByteArrayOutputStream()
        val a = ArmoredOutputStream(bo)
        a.setHeader("Version", null)
        if (comment != null) a.setHeader("Comment", comment)
        a.write(bin)
        a.close()
        return bo.toString("UTF-8")
    }

    private fun dearmor(text: String): ByteArray =
        ArmoredInputStream(ByteArrayInputStream(text.toByteArray())).use { it.readBytes() }

    // ── The four paths ──────────────────────────────────────────────────

    private class Seen(val status: SignerStatus, val data: ByteArray)

    /** Recipient is bob throughout. */
    private fun memory(plainPackets: ByteArray, keys: List<PGPPublicKeyRing>): Seen {
        val r = svc.decrypt(encryptRaw(plainPackets, bob), listOf(bob.sec), null, keys)
        assertEquals(r.signerStatus == SignerStatus.VERIFIED, r.signatureVerified)
        return Seen(r.signerStatus, r.data)
    }

    private fun stream(plainPackets: ByteArray, keys: List<PGPPublicKeyRing>, out: ByteArrayOutputStream = ByteArrayOutputStream()): Seen {
        val r = svc.decryptStream(ByteArrayInputStream(encryptRaw(plainPackets, bob)), out, listOf(bob.sec), null, keys)
        assertEquals(r.signerStatus == SignerStatus.VERIFIED, r.signatureVerified)
        return Seen(r.signerStatus, out.toByteArray())
    }

    private fun signedOnly(plainPackets: ByteArray, keys: List<PGPPublicKeyRing>, comment: String? = null): Seen {
        val r = svc.decryptArmored(armor(plainPackets, comment), listOf(bob.sec), null, keys)
        return Seen(r.signerStatus, r.data)
    }

    private fun cardPath(plainPackets: ByteArray, keys: List<PGPPublicKeyRing>): Seen {
        val r = card.readContent(plainPackets, keys)
        assertEquals(r.signerStatus == SignerStatus.VERIFIED, r.signatureVerified)
        return Seen(r.signerStatus, r.data)
    }

    /** The walker on its own, without the MessageGrammar pre-check. */
    private fun walker(plainPackets: ByteArray, keys: List<PGPPublicKeyRing>): Seen {
        val sink = ContentWalker.MemorySink()
        val o = ContentWalker.walk(JcaPGPObjectFactory(ByteArrayInputStream(plainPackets)), keys, sink)
        return Seen(o.signerStatus, sink.bytes())
    }

    private val paths: List<Pair<String, (ByteArray, List<PGPPublicKeyRing>) -> Seen>> by lazy {
        listOf(
            "memory" to { p, k -> memory(p, k) },
            "stream" to { p, k -> stream(p, k) },
            "signed-only" to { p, k -> signedOnly(p, k) },
            "card" to { p, k -> cardPath(p, k) },
            "walker" to { p, k -> walker(p, k) }
        )
    }

    private fun assertRefusedEverywhere(plainPackets: ByteArray, keys: List<PGPPublicKeyRing>) {
        for ((name, path) in paths) {
            val outcome = runCatching { path(plainPackets, keys) }
            assertTrue("$name accepted a malformed message: ${outcome.getOrNull()?.status}", outcome.isFailure)
            val e = outcome.exceptionOrNull()!!
            assertTrue("$name failed with ${e.javaClass.name}", e is PGPCryptoError || e is OpenPgpCardException)
        }
    }

    private fun assertVerifiedEverywhere(plainPackets: ByteArray, keys: List<PGPPublicKeyRing>, expected: ByteArray) {
        for ((name, path) in paths) {
            val s = path(plainPackets, keys)
            assertEquals("$name status", SignerStatus.VERIFIED, s.status)
            assertArrayEquals("$name content", expected, s.data)
        }
    }

    // ── ENGINE-1/2/3: a second literal never rides on a verified signature ─

    @Test
    fun `ENGINE-1 a literal after the closing signature is refused on every path`() {
        assertRefusedEverywhere(cat(signedBy(alice), lit(evil)), listOf(alice.pub))
    }

    @Test
    fun `ENGINE-1 the clear-signed marker in a Comment header no longer skips the grammar`() {
        val msg = cat(signedBy(alice), lit(evil))
        val e = runCatching {
            signedOnly(msg, listOf(alice.pub), comment = "-----BEGIN PGP SIGNED MESSAGE-----")
        }.exceptionOrNull()
        assertTrue("forged message accepted", e is PGPCryptoError)
        // The same header on a well-formed message is harmless.
        val ok = signedOnly(signedBy(alice), listOf(alice.pub), comment = "-----BEGIN PGP SIGNED MESSAGE-----")
        assertEquals(SignerStatus.VERIFIED, ok.status)
        assertArrayEquals(signed, ok.data)
    }

    @Test
    fun `ENGINE-1 a literal prepended before the one-pass signature is refused on every path`() {
        assertRefusedEverywhere(cat(lit(evil), signedBy(alice)), listOf(alice.pub))
    }

    @Test
    fun `ENGINE-2 the streaming path never writes a byte of an extra literal`() {
        val out = ByteArrayOutputStream()
        val e = runCatching { stream(cat(signedBy(alice), lit(evil)), listOf(alice.pub), out) }.exceptionOrNull()
        assertTrue(e is PGPCryptoError)
        assertFalse(String(out.toByteArray()).contains("EVIL"))
        // Held output is never released either.
        val held = ByteArrayOutputStream()
        assertThrows(PGPCryptoError::class.java) {
            svc.decryptStream(
                ByteArrayInputStream(encryptRaw(cat(signedBy(alice), lit(evil)), bob)), held,
                listOf(bob.sec), null, listOf(alice.pub), releaseOnlyWhenVerified = true
            )
        }
        assertEquals(0, held.size())
    }

    @Test
    fun `ENGINE-3 the card walker refuses a second literal and reports the graded status`() {
        assertThrows(OpenPgpCardException.Malformed::class.java) {
            card.readContent(cat(signedBy(alice), lit(evil)), listOf(alice.pub))
        }
        val r = card.readContent(signedBy(alice), listOf(alice.pub))
        assertEquals(SignerStatus.VERIFIED, r.signerStatus)
        assertTrue(r.signatureVerified && r.hadSignature && r.signerKnown)
        assertEquals(1, r.signaturePackets.size)
        val unknown = card.readContent(signedBy(alice), listOf(bob.pub))
        assertEquals(SignerStatus.UNKNOWN_SIGNER, unknown.signerStatus)
        assertFalse(unknown.signatureVerified || unknown.signerKnown)
        assertTrue(unknown.hadSignature)
        assertEquals(String.format("%016X", svc.pickSigningSecretKey(alice.sec)!!.keyID), unknown.signerKeyID)
        assertEquals(SignerStatus.NONE, card.readContent(lit(signed), listOf(alice.pub)).signerStatus)
    }

    @Test
    fun `a plain literal message reads on every path except signed-only`() {
        for ((name, path) in paths) {
            if (name == "signed-only") continue
            val s = path(lit(signed), listOf(alice.pub))
            assertEquals(name, SignerStatus.NONE, s.status)
            assertArrayEquals(name, signed, s.data)
        }
    }

    // ── Pairing and counts ─────────────────────────────────────────────

    @Test
    fun `two one-pass signatures over one literal still verify on every path`() {
        val msg = cat(opsOf(bob), opsOf(alice, nested = true), lit(signed), sigOf(alice, signed), sigOf(bob, signed))
        assertVerifiedEverywhere(msg, listOf(alice.pub), signed)
        assertVerifiedEverywhere(msg, listOf(bob.pub), signed)
        assertVerifiedEverywhere(msg, listOf(alice.pub, bob.pub), signed)
        // The signer reported is the first held one.
        assertEquals(
            String.format("%016X", svc.pickSigningSecretKey(bob.sec)!!.keyID),
            svc.decrypt(encryptRaw(msg, bob), listOf(bob.sec), null, listOf(alice.pub, bob.pub)).signerKeyID
        )
    }

    @Test
    fun `signatures that close their one-pass packets in the wrong order do not verify`() {
        val msg = cat(opsOf(bob), opsOf(alice, nested = true), lit(signed), sigOf(bob, signed), sigOf(alice, signed))
        for ((name, path) in paths) {
            assertEquals(name, SignerStatus.INVALID, path(msg, listOf(alice.pub)).status)
        }
    }

    @Test
    fun `a signature count that does not match the one-pass count is malformed`() {
        val keys = listOf(alice.pub)
        assertRefusedEverywhere(cat(opsOf(alice), lit(signed)), keys)
        assertRefusedEverywhere(cat(signedBy(alice), sigOf(alice, signed)), keys)
        assertRefusedEverywhere(cat(opsOf(bob), opsOf(alice), lit(signed), sigOf(alice, signed)), keys)
        assertRefusedEverywhere(cat(lit(signed), sigOf(alice, signed)), keys)
        assertRefusedEverywhere(cat(signedBy(alice), opsOf(alice)), keys)
    }

    @Test
    fun `the older layout with the signature first stays readable and is not verified`() {
        val msg = cat(sigOf(alice, signed), lit(signed))
        for ((name, path) in paths) {
            val s = path(msg, listOf(alice.pub))
            assertNotEquals(name, SignerStatus.VERIFIED, s.status)
            assertArrayEquals(name, signed, s.data)
        }
        assertRefusedEverywhere(cat(sigOf(alice, signed), lit(signed), lit(evil)), listOf(alice.pub))
    }

    // ── Compression ───────────────────────────────────────────────────

    @Test
    fun `nested compression around a signed message verifies on every path`() {
        assertVerifiedEverywhere(compressed(signedBy(alice)), listOf(alice.pub), signed)
        assertVerifiedEverywhere(compressed(compressed(signedBy(alice), PGPCompressedData.ZIP)), listOf(alice.pub), signed)
        assertVerifiedEverywhere(compressed(signedBy(alice), PGPCompressedData.BZIP2), listOf(alice.pub), signed)
        // RFC 9580 lets the signed message's body itself be compressed.
        assertVerifiedEverywhere(cat(opsOf(alice), compressed(lit(signed)), sigOf(alice, signed)), listOf(alice.pub), signed)
    }

    @Test
    fun `compression that splits a signed message or follows the literal is malformed`() {
        val keys = listOf(alice.pub)
        assertRefusedEverywhere(cat(compressed(cat(opsOf(alice), lit(signed))), sigOf(alice, signed)), keys)
        assertRefusedEverywhere(cat(compressed(signedBy(alice)), lit(evil)), keys)
        assertRefusedEverywhere(cat(compressed(signedBy(alice)), compressed(lit(evil))), keys)
        assertRefusedEverywhere(cat(lit(evil), compressed(signedBy(alice))), keys)
        assertRefusedEverywhere(compressed(cat(signedBy(alice), lit(evil))), keys)
    }

    // ── ENGINE-6: the one-pass packet is bound to its signature ───────────

    @Test
    fun `ENGINE-6 a one-pass signature type that differs from the signature is INVALID`() {
        // Binary signature over CRLF text; the one-pass packet claims text mode
        // so that rewritten line endings would hash the same.
        val crlf = "line one\r\nline two\r\n".toByteArray()
        val altered = "line one\rline two\n".toByteArray()
        val msg = cat(opsOf(alice, type = PGPSignature.CANONICAL_TEXT_DOCUMENT), lit(altered), sigOf(alice, crlf))
        for ((name, path) in paths) {
            assertEquals(name, SignerStatus.INVALID, path(msg, listOf(alice.pub)).status)
        }
    }

    @Test
    fun `ENGINE-6 a one-pass hash algorithm that differs from the signature is INVALID`() {
        val msg = cat(opsOf(alice, hash = HashAlgorithmTags.SHA512), lit(signed), sigOf(alice, signed))
        for ((name, path) in paths) {
            assertEquals(name, SignerStatus.INVALID, path(msg, listOf(alice.pub)).status)
        }
        // A text signature with a matching text one-pass packet still verifies.
        val text = "a\r\nb\r\n".toByteArray()
        val ok = cat(
            opsOf(alice, type = PGPSignature.CANONICAL_TEXT_DOCUMENT), lit(text),
            sigOf(alice, text, type = PGPSignature.CANONICAL_TEXT_DOCUMENT)
        )
        assertVerifiedEverywhere(ok, listOf(alice.pub), text)
    }

    // ── Review additions ───────────────────────────────────────────────

    @Test
    fun `an empty signed literal verifies on every path`() {
        val empty = ByteArray(0)
        assertVerifiedEverywhere(cat(opsOf(alice), lit(empty), sigOf(alice, empty)), listOf(alice.pub), empty)
    }

    @Test
    fun `a second signer with an unknown public-key algorithm does not stop the known one verifying`() {
        fun pkt(tag: Int, body: ByteArray) = CertificateBindings.frame(tag, body)
        // v3 one-pass and v4 signature from a key of algorithm 100 (private/experimental).
        val ops100 = pkt(4, byteArrayOf(3, 0, 8, 100, 1, 2, 3, 4, 5, 6, 7, 8, 0))
        val sig100 = pkt(
            2,
            byteArrayOf(4, 0, 100, 8, 0, 0, 0, 10, 9, 16, 1, 2, 3, 4, 5, 6, 7, 8, 0x12, 0x34, 0, 8, 0xAB.toByte())
        )
        val msg = cat(ops100, opsOf(alice, nested = true), lit(signed), sigOf(alice, signed), sig100)
        assertVerifiedEverywhere(msg, listOf(alice.pub), signed)
    }

    @Test
    fun `clear-signed text after blank lines is still refused by decrypt with a pointer to verify`() {
        val text = "\n\n  \n" + SigningService.shared.signClear("hello", alice.sec, null)
        val e = assertThrows(PGPCryptoError.DecryptionFailed::class.java) {
            svc.decryptArmored(text, listOf(bob.sec), null, listOf(alice.pub))
        }
        assertTrue(e.message!!.contains("clear-signed"))
    }

    @Test
    fun `a forged message armored as PGP MESSAGE with the clear-signed line as a header is refused`() {
        // The marker as the value of an arbitrary armor header, not only Comment.
        val bo = ByteArrayOutputStream()
        val a = ArmoredOutputStream(bo)
        a.setHeader("Version", null)
        a.setHeader("Hash", "-----BEGIN PGP SIGNED MESSAGE-----")
        a.write(cat(signedBy(alice), lit(evil)))
        a.close()
        val e = runCatching { svc.decryptArmored(bo.toString("UTF-8"), listOf(bob.sec), null, listOf(alice.pub)) }
        assertTrue(e.isFailure)
        assertTrue(e.exceptionOrNull() is PGPCryptoError)
    }

    // ── Skipped and refused packets ────────────────────────────────────

    @Test
    fun `marker, padding and non-critical unknown packets are skipped, critical unknown ones refused`() {
        fun pkt(tag: Int, body: ByteArray) = CertificateBindings.frame(tag, body)
        val marker = pkt(10, "PGP".toByteArray())
        val padding = pkt(21, ByteArray(16))
        val unknown40 = pkt(40, byteArrayOf(1, 2, 3))
        assertVerifiedEverywhere(cat(marker, opsOf(alice), padding, lit(signed), unknown40, sigOf(alice, signed), marker), listOf(alice.pub), signed)
        assertRefusedEverywhere(cat(signedBy(alice), pkt(39, byteArrayOf(1))), listOf(alice.pub))
    }

    // ── ENGINE-5: no integrity protection, refused before any output ──────

    @Test
    fun `ENGINE-5 a message without integrity protection is refused before any plaintext is written`() {
        val ct = encryptRaw(signedBy(alice), bob, integrity = false)
        val out = ByteArrayOutputStream()
        val e = assertThrows(PGPCryptoError.IntegrityCheckFailed::class.java) {
            svc.decryptStream(ByteArrayInputStream(ct), out, listOf(bob.sec), null, listOf(alice.pub))
        }
        assertTrue(e.message!!.contains("no integrity protection"))
        assertEquals(0, out.size())
        assertThrows(PGPCryptoError.IntegrityCheckFailed::class.java) {
            svc.decrypt(ct, listOf(bob.sec), null, listOf(alice.pub))
        }
    }

    @Test
    fun `ENGINE-5 a tampered SEIPDv1 stream throws and never returns a result`() {
        val ct = encryptRaw(lit(ByteArray(200_000) { (it % 251).toByte() }), bob)
        ct[ct.size - 30] = (ct[ct.size - 30].toInt() xor 0x01).toByte()
        assertThrows(PGPCryptoError::class.java) {
            svc.decryptStream(ByteArrayInputStream(ct), ByteArrayOutputStream(), listOf(bob.sec), null, null)
        }
    }

    // ── Clear-signed text is not decrypted, it is verified ─────────────────

    @Test
    fun `clear-signed text is refused by decrypt with a pointer to verify, and VerifyService reads it`() {
        val text = SigningService.shared.signClear("hello world\nline 2", alice.sec, null)
        val e = assertThrows(PGPCryptoError.DecryptionFailed::class.java) {
            svc.decryptArmored(text, listOf(bob.sec), null, listOf(alice.pub))
        }
        assertTrue(e.message!!.contains("clear-signed"))
        assertTrue(VerifyService.shared.verifyClearSigned(text, listOf(alice.pub)) is VerificationResult.Verified)
    }

    // ── Legitimate messages ────────────────────────────────────────────

    @Test
    fun `PGPony's own signed and encrypted messages verify on the memory and streaming paths`() {
        val ct = svc.encrypt(signed, listOf(bob.pub), signingSecretKey = alice.sec, passphrase = null, filename = "note.txt")
        val m = svc.decrypt(ct, listOf(bob.sec), null, listOf(alice.pub))
        assertEquals(SignerStatus.VERIFIED, m.signerStatus)
        assertArrayEquals(signed, m.data)
        val out = ByteArrayOutputStream()
        val s = svc.decryptStream(ByteArrayInputStream(ct), out, listOf(bob.sec), null, listOf(alice.pub))
        assertEquals(SignerStatus.VERIFIED, s.signerStatus)
        assertArrayEquals(signed, out.toByteArray())
        assertEquals("note.txt", s.filename)
        val inline = svc.sign(signed, alice.sec, "")
        val v = svc.decrypt(inline, listOf(bob.sec), null, listOf(alice.pub))
        assertEquals(SignerStatus.VERIFIED, v.signerStatus)
        assertArrayEquals(signed, v.data)
        assertEquals(SignerStatus.VERIFIED, card.readContent(dearmor(String(inline)), listOf(alice.pub)).signerStatus)
    }

    @Test
    fun `v6 signed and encrypted messages still verify, the one-pass fingerprint bound to the signature`() {
        fun v6(name: String): Party {
            val g = svc.generateKeyPair(name, "$name@example.org", KeyAlgorithm.V6_ED25519, null)
            return Party(
                PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator()),
                PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
            )
        }
        val dave = v6("dave")
        val erin = v6("erin")
        val ct = svc.encrypt(signed, listOf(erin.pub), signingSecretKey = dave.sec, passphrase = null)
        val m = svc.decrypt(ct, listOf(erin.sec), null, listOf(dave.pub))
        assertEquals(SignerStatus.VERIFIED, m.signerStatus)
        assertArrayEquals(signed, m.data)
        val out = ByteArrayOutputStream()
        val s = svc.decryptStream(ByteArrayInputStream(ct), out, listOf(erin.sec), null, listOf(dave.pub))
        assertEquals(SignerStatus.VERIFIED, s.signerStatus)
        assertArrayEquals(signed, out.toByteArray())
    }

    private fun ring(text: String) = PGPPublicKeyRing(dearmor(text), JcaKeyFingerprintCalculator())

    @Test
    fun `GnuPG made messages still read and verify on every path`() {
        val a = ring(GPG_A_PUB)
        val b = ring(GPG_B_PUB)
        val r = PGPSecretKeyRing(dearmor(GPG_R_SEC), JcaKeyFingerprintCalculator())
        val expected = GPG_TEXT.toByteArray()
        // Signed and encrypted (OCB), two signers, and bzip2.
        for ((label, msg) in listOf("one signer" to GPG_M1, "two signers" to GPG_M2, "bzip2" to GPG_M6)) {
            for (keys in listOf(listOf(a), listOf(b), listOf(a, b))) {
                if (label != "two signers" && keys == listOf(b)) continue
                val m = svc.decryptArmored(msg, listOf(r), null, keys)
                assertEquals("$label memory", SignerStatus.VERIFIED, m.signerStatus)
                assertArrayEquals(expected, m.data)
                val out = ByteArrayOutputStream()
                val s = svc.decryptStream(ByteArrayInputStream(msg.toByteArray()), out, listOf(r), null, keys)
                assertEquals("$label stream", SignerStatus.VERIFIED, s.signerStatus)
                assertArrayEquals(expected, out.toByteArray())
            }
        }
        // Signed only, one and two signers; the card walker on the same content.
        for (msg in listOf(GPG_M3, GPG_M4)) {
            val v = svc.decryptArmored(msg, listOf(r), null, listOf(a))
            assertEquals(SignerStatus.VERIFIED, v.signerStatus)
            assertArrayEquals(expected, v.data)
            val c = card.readContent(dearmor(msg), listOf(a, b))
            assertEquals(SignerStatus.VERIFIED, c.signerStatus)
            assertArrayEquals(expected, c.data)
        }
    }

    // ── FILES-6: streaming expansion bound ──────────────────────────────

    /** Discards what it is given, counting it. */
    private class CountingSink : OutputStream() {
        var count = 0L
        override fun write(b: Int) { count++ }
        override fun write(b: ByteArray, off: Int, len: Int) { count += len }
    }

    /** Literal of [size] zeros, ZLIB-compressed [layers] times, encrypted to bob, built without holding the plaintext. */
    private fun zeros(size: Long, layers: Int): ByteArray {
        val litBytes = ByteArrayOutputStream()
        var sinkTop: OutputStream = litBytes
        val gens = ArrayList<PGPCompressedDataGenerator>()
        val streams = ArrayList<OutputStream>()
        repeat(layers) {
            val g = PGPCompressedDataGenerator(PGPCompressedData.ZLIB)
            val s = g.open(sinkTop, ByteArray(1 shl 16))
            gens.add(g); streams.add(s); sinkTop = s
        }
        val lg = PGPLiteralDataGenerator()
        val lo = lg.open(sinkTop, PGPLiteralData.BINARY, "z", Date(), ByteArray(1 shl 16))
        val chunk = ByteArray(1 shl 20)
        var left = size
        while (left > 0) {
            val n = minOf(left, chunk.size.toLong()).toInt()
            lo.write(chunk, 0, n)
            left -= n
        }
        lo.close()
        for (i in streams.indices.reversed()) streams[i].close()
        return encryptRaw(litBytes.toByteArray(), bob)
    }

    @Test
    fun `FILES-6 nested compression that expands far beyond its size is stopped while streaming`() {
        val bomb = zeros(256L * 1024 * 1024, layers = 2)
        assertTrue("bomb should be small, was ${bomb.size}", bomb.size < 64 * 1024)
        val sink = CountingSink()
        assertThrows(PGPCryptoError.ResourceLimitExceeded::class.java) {
            svc.decryptStream(ByteArrayInputStream(bomb), sink, listOf(bob.sec), null, null)
        }
        assertTrue(sink.count < 256L * 1024 * 1024)
    }

    @Test
    fun `FILES-6 a single compressed layer of very repetitive data still streams in full`() {
        val size = 96L * 1024 * 1024
        val ct = zeros(size, layers = 1)
        val sink = CountingSink()
        val r = svc.decryptStream(ByteArrayInputStream(ct), sink, listOf(bob.sec), null, null)
        assertEquals(size, r.bytesWritten)
        assertEquals(size, sink.count)
    }

    private companion object {
        // Made with GnuPG 2.4.4: three throwaway keys (no passphrase) and
        // messages over GPG_TEXT. M1 is signed by A and encrypted to R; M2 is
        // signed by A and B; M3 and M4 are signed only (A; A and B); M6 is
        // bzip2-compressed. Encrypted ones use the OCB packet GnuPG 2.4 writes.
        const val GPG_TEXT = "GnuPG fixture text, line one.\nLine two."

        const val GPG_A_PUB = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEar3JZxYJKwYBBAHaRw8BAQdActjnZ3JyZM7Yru16/K4sQUj+GLVxAxlqkQrr
tIhEidS0IEZpeHR1cmUgU2lnbmVyIEEgPGFAZXhhbXBsZS5vcmc+iJMEExYKADsW
IQTUsF+2Zzm0pFMR9suizkfDZ0bQeQUCar3JZwIbAwULCQgHAgIiAgYVCgkICwIE
FgIDAQIeBwIXgAAKCRCizkfDZ0bQeUsdAQDhKAyYwfNzBYf9EiyJ9/7smODFUQHu
adwBWXKcgQFfkQD+JEJxw3LyTVG9O5lZTEH95e8etq8vhzNUWwv2qn7JaQo=
=IXY6
-----END PGP PUBLIC KEY BLOCK-----
"""

        const val GPG_B_PUB = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEar3JZxYJKwYBBAHaRw8BAQdAFUzkGkRLtPMCBcwYGUvO6xAMDyXNinqg1M1q
KtQCU7e0IEZpeHR1cmUgU2lnbmVyIEIgPGJAZXhhbXBsZS5vcmc+iJMEExYKADsW
IQRva9kjlPR4oLpiIBQl2HNJrcn8LAUCar3JZwIbAwULCQgHAgIiAgYVCgkICwIE
FgIDAQIeBwIXgAAKCRAl2HNJrcn8LODpAQCGL+UWZYKSf60ZAnXUS3V89d6K3DW+
zOm44PZqy8OtjAD/YAE0Pb7g3fOwja40iYt+mbjGiFYMxfzrEoDq1ME2kw0=
=uc6o
-----END PGP PUBLIC KEY BLOCK-----
"""

        const val GPG_R_SEC = """-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEar3JZxYJKwYBBAHaRw8BAQdAr/+v3orsw7kCLx5uWeAUo7cbyumhctXjYV9W
1HL57D0AAQCc3SRutQZbxRkdpAgqcNsHaENovIneRAiNNcOw7PkEAA3ltCFGaXh0
dXJlIFJlY2lwaWVudCA8ckBleGFtcGxlLm9yZz6IkwQTFgoAOxYhBF1QpIB2Tco2
17VvtpL6fuOMbf6PBQJqvclnAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA
AAoJEJL6fuOMbf6PW7oA/3Lm2neHhSjQ9YssJpMuZdyH5SXewc1NlnZXjlXKsjkI
AP9HkxKUKQBVsBtoBRsymXdtSoEJtEFMcMkHkWpEp02aAJxdBGq9yWcSCisGAQQB
l1UBBQEBB0DjJfBWNNpiyZV+oAyycJLnZ2DDdutUyhD3q3QOn48tCQMBCAcAAP9y
1aHim91nhk1FMyFp/QyoLUk1cE7EiA/txw3C2QF5+BDAiHgEGBYKACAWIQRdUKSA
dk3KNte1b7aS+n7jjG3+jwUCar3JZwIbDAAKCRCS+n7jjG3+j8O1AQCw0i6333jt
cvdhXRHup6RApxm4+yziGzzB36kulw0HygD/bvYQBVBULxwTLmBJ0dB88BLMaFd9
G8q/qSWjAsvZQgU=
=dfmD
-----END PGP PRIVATE KEY BLOCK-----
"""

        const val GPG_M1 = """-----BEGIN PGP MESSAGE-----

hF4Deh8hWSWCwusSAQdAPpDxOgooM4BY25cDqq/m9rTHDC6Y9sFSSmTo5C2zbyEw
EqAMrSiKNL5YCTXPOOErtJzexNIGpA3LXZyO3dvGt7HcW1ubo6gl39QAUuTi3ZF4
1MA9AQkCED7eHiKFyEA3NFCgFAxv/fwaAh6fLzxaWywDDK+FzS19zZ46N1Tnu6yo
sy+OuB/TSWoNfrpPdeNBqJLKNzjYy1cOjhE06xsMSedyNW6laXt1dm+ElyVbSguc
zlJKmPQrGd+FuvgTNGndVfuxmi24qtS4tvkFxt3+xK635d3WROUC4Zc/3ipFBi5q
0HFgBalDRrEwPIyQyYtYfHanNYA9DzvnvbDCIJMcLZo852cOFNv2Bx2A5wgVfE8b
VUo8FUErJ8CqtPJ3nYXrCruSIez7JrwWaUCPmZVhVpa6Wp3ttRbcaOuc6X4r2J1A
tlCIELSAO4k3GY5JpB7qbg==
=SufK
-----END PGP MESSAGE-----
"""

        const val GPG_M2 = """-----BEGIN PGP MESSAGE-----

hF4Deh8hWSWCwusSAQdAzn8SY2IPttnAuaSnX2Y8p4KUMcMZ7gdGNF/CVdifPiMw
+OepqLcJHu9B52VHvdxZdlEmT5qUIubvk0BAutIeonSYxL/O3Il0sHMTsXX4iqyK
1MCuAQkCEGId/xqL7ePR3RehEJLdRj1Xy281QvFOmhwLKLYc9FZntaVL0/sSaVY9
z146CspnCJ7FaFec1/SLHE6u3IeeXVZfqHKxJXhesJ8FbANq7rohJ+KzT7vHBoPv
QJz/rJeJgCQhtXwyL+k3Xc7KC+quQWSwlZAzl9Y+bM+oNPC5W6J7BD05aTB71YFN
sOXq0N7dvXzecgXUirRYbYBaR8lG2Xf/S2gB3c7c8iVjmNL3Yuxi1SQjkEYayxjr
Gek2o+hlOXttI+l2N9JNrTYLk9EbnnYXQrBbfk0y0SbE1nvkepj7jGF86mVjzGDs
chS9XMaxQSg2cHnIuwzcog3hjeE8cH95CaBRDzWcLZXMeF3K4eN5bABHVn+gDF6m
+DBtUdb+76qsKe/7jDxtdbxLcs/3ArnoDosYAEiZWlMLEuR6ONidGQxWd1Cbi/NR
t554aLeYhVI8nWyqdlEgel7HmSJQ08BYXwaGLGoIVTo+
=SadV
-----END PGP MESSAGE-----
"""

        const val GPG_M3 = """-----BEGIN PGP MESSAGE-----

owGbwMvMwCW26Jz74XS3C5WMa0yS2HOL0/VKKkqy9p4sds8rDXBXSMusKCktSlUo
Sa0o0VHIycxLVcjPS9Xj8gGxSsrz9TpaWBjEuBh0xBRZrmyI35ZuuWVJsOC30zBT
WZlAZvHJJDqkViTmFuSk6uUXpTNwcQrAFCz4wPBXYlGiU7X53+XN3lmhyt5PjHcU
vDw/qzF968nnlv03yrckMPwz7VnCan1my9mS9+UW6ur75zYq5T9O9HxprlmruenE
g0oOAA==
=gMMt
-----END PGP MESSAGE-----
"""

        const val GPG_M4 = """-----BEGIN PGP MESSAGE-----

owGbwMvMwCWmeqPYc+3JPzoME8DcRefcD6e7XahkXGOSxJ5bnK5XUlGStfdksXte
aYC7QlpmRUlpUapCSWpFiY5CTmZeqkJ+Xqoelw+IVVKer9fRwsIgxsWgI6bIcmVD
/LZ0yy1LggW/nYaZysoEMotPJtEhtSIxtyAnVS+/KJ2Bi1MApmDBB4a/EosSnarN
/y5v9s4KVfZ+Yryj4OX5WY3pW08+t+y/Ub4lgeGfac8SVuszW86WvC+3UFffP7dR
Kf9xoudLc81azU0nHlRyILkiP/um8pQvFQt2JSmIwLwKc0USuitgCvQSGf7X51l3
vtj2oK2L+6DNn9X/H+VkZTza8mjxgh8rNJ9u3TO1j5Hh91NxQYtlndJdWkd3XT38
Q1z42Mwf9xYfnSYx79f828dOsQEA
=fRhv
-----END PGP MESSAGE-----
"""

        const val GPG_M6 = """-----BEGIN PGP MESSAGE-----

hF4Deh8hWSWCwusSAQdAcPi0zWMUEgg7K3R6R/Nru78C+CaI/30TbH8F8yy8iRYw
8XDYpeIESPJg5Xi3QgOGhDaRag4LGLbffC2gkyrNgRwVXcsWvLsMtpeUVAwtSarJ
1MCFAQkCEHCSlvVEfuJksA49pM2L9b0hw4Z2iZJRlRtJ82GMA2SSYrFEf9uiXjQ1
jxn9QQjumiCDFmBkd911R4dpYUvoWSoPuLn13hCyZ3gRMThSE64mmzRMeQgwcl/V
r5Ftszx+M7WiZuI3hz8wIbi/YuBW07Az0jTqW7xaSQ9sWmO7AmsM4Hk+JUbHN2I2
dfDnKTo6S7VD2vOkV3XVmXraDbK7dJBlCnE5oZ8ZFrvQm7WzR9bcEYy2H8Y30AN1
D2/XWBaxiWW82yhlmQ16BlOHnF7ZALPJW2y2i1nwmwCj/d7fxWmIBo7zdiK8BPoG
HDcvLOOJMs2hm7d34BawRHyUbvcacQX8PSfomWAIgJWINx84qbcukarC4I+3RBxS
h7VBLkq5YtCRkXT8VmIrJ94yR66lNV+SrGxWDkLvz6Cb0xBh9WD8jQ==
=eKh6
-----END PGP MESSAGE-----
"""
    }
}
