// AlgorithmPolicyTest.kt
// PGPony Android, 3.0.0 checkpoint 5d-3: weak keys are read-only, forbidden
// secret-key protections are refused at import, and a message follows the
// cipher and hash its recipients list.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

class AlgorithmPolicyTest {

    private val svc = PGPCryptoService.shared
    private val random = SecureRandom()

    private fun rsaPair(bits: Int): PGPKeyPair {
        val g = RSAKeyPairGenerator().apply {
            init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), random, bits, 25))
        }
        return BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, g.generateKeyPair(), Date())
    }

    /** A one-key RSA certificate and key that may certify, sign and encrypt. */
    private fun rsaKey(bits: Int): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val kp = rsaPair(bits)
        val hashed = PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, 0x0F) }.generate()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, kp, "Weak <weak@example.test>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), hashed, null,
            BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256), null
        )
        return gen.generateSecretKeyRing() to gen.generatePublicKeyRing()
    }

    private fun <T> strict(block: () -> T): T {
        KeyPolicy.strict = true
        try { return block() } finally { KeyPolicy.strict = false }
    }

    // ── Weak keys ────────────────────────────────────────────────────────

    @Test
    fun `RSA under 2048 bits is weak and 2048 is not`() {
        assertTrue(KeyPolicy.isWeak(rsaPair(1024).publicKey))
        assertEquals("RSA 1024", KeyPolicy.weakLabel(rsaPair(1024).publicKey))
        assertFalse(KeyPolicy.isWeak(rsaPair(2048).publicKey))
    }

    @Test
    fun `nothing is encrypted to a weak key and a weak key never signs`() {
        val (sec, pub) = rsaKey(1024)
        assertTrue(svc.encryptionKeyOptions(pub).isEmpty())
        val e = assertThrows(PGPCryptoError.EncryptionFailed::class.java) { svc.encrypt("hi".toByteArray(), listOf(pub)) }
        assertTrue(e.message!!, e.message!!.contains("weak"))
        assertNull(svc.pickSigningSecretKey(sec))
    }

    @Test
    fun `a weak key's old signature still verifies with a warning, and strict callers refuse it`() {
        val (sec, pub) = rsaKey(1024)
        val data = "old signature".toByteArray()
        val key = sec.secretKey
        val priv = key.extractPrivateKey(null)
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(key.publicKey.algorithm, HashAlgorithmTags.SHA256), key.publicKey)
        g.init(PGPSignature.BINARY_DOCUMENT, priv)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date()); setIssuerFingerprint(false, key.publicKey)
        }.generate())
        g.update(data)
        val sig = g.generate().encoded
        val ok = VerifyService.shared.verifyDetached(sig, data, listOf(pub))
        assertTrue("$ok", ok is VerificationResult.Verified)
        assertEquals("RSA 1024", (ok as VerificationResult.Verified).signerWeakKey)
        val refused = strict { VerifyService.shared.verifyDetached(sig, data, listOf(pub)) }
        assertTrue("$refused", refused is VerificationResult.Invalid)
    }

    @Test
    fun `a weak key still decrypts old mail with a warning, and strict callers refuse it`() {
        val (sec, pub) = rsaKey(1024)
        val out = ByteArrayOutputStream()
        val gen = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true).setSecureRandom(random)
        )
        gen.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(pub.publicKey))
        gen.open(out, ByteArray(1 shl 12)).use { enc ->
            PGPLiteralDataGenerator().open(enc, PGPLiteralData.BINARY, "", Date(), ByteArray(1 shl 12)).use {
                it.write("old mail".toByteArray())
            }
        }
        val msg = out.toByteArray()
        val result = svc.decrypt(msg, listOf(sec), null)
        assertEquals("old mail", String(result.data))
        assertEquals("RSA 1024", result.decryptionWeakKey)
        assertThrows(PGPCryptoError::class.java) { strict { svc.decrypt(msg, listOf(sec), null) } }
    }

    // ── Secret-key protection ────────────────────────────────────────────

    private fun edPublicBody(version: Int): ByteArray {
        val g = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(random)) }
        val kp = BcPGPKeyPair(version, PublicKeyAlgorithmTags.Ed25519, g.generateKeyPair(), Date())
        return kp.publicKey.publicKeyPacket.encodedContents
    }

    /** A transferable secret key made of one secret key packet with [protection]
     *  appended to the public body, and junk where the encrypted material goes. */
    private fun secretKey(version: Int, protection: ByteArray): ByteArray =
        CertificateBindings.frame(5, edPublicBody(version) + protection + ByteArray(16) { 1 } + ByteArray(64) { 2 })

    private val argon2 = byteArrayOf(4) + ByteArray(16) { 3 } + byteArrayOf(1, 4, 16)

    @Test
    fun `Argon2 without AEAD is refused at import`() {
        // v4: usage 254, AES-256, Argon2 S2K.
        val v4 = secretKey(4, byteArrayOf(0xFE.toByte(), 9) + argon2)
        val e = assertThrows(PGPCryptoError.ImportFailed::class.java) { svc.importKeyData(v4) }
        assertTrue(e.message!!, e.message!!.contains("Argon2"))
    }

    @Test
    fun `legacy protection forms of a v6 key are refused at import`() {
        // v6: usage 254, count, AES-256, S2K length, Simple S2K with SHA-256.
        val simple = byteArrayOf(0, 8)
        val v6 = secretKey(6, byteArrayOf(0xFE.toByte(), (1 + 1 + simple.size + 16).toByte(), 9, simple.size.toByte()) + simple)
        assertThrows(PGPCryptoError.ImportFailed::class.java) { svc.importKeyData(v6) }
    }

    @Test
    fun `ordinary protected keys still import`() {
        val gen = svc.generateKeyPair("Protected", "protected@example.test", KeyAlgorithm.ED25519_CV25519, "a passphrase")
        assertTrue(svc.importKeyData(gen.privateKeyData).hasPrivateKey)
        val v6 = svc.generateKeyPair("Protected6", "protected6@example.test", KeyAlgorithm.V6_ED25519, "a passphrase")
        assertTrue(svc.importKeyData(v6.privateKeyData).hasPrivateKey)
    }

    // ── Recipient preferences ────────────────────────────────────────────

    private fun edCertWithPrefs(ciphers: IntArray?, hashes: IntArray?): PGPPublicKeyRing {
        val g = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(random)) }
        val kp = BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, g.generateKeyPair(), Date())
        val hashed = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, 0x03)
            ciphers?.let { setPreferredSymmetricAlgorithms(false, it) }
            hashes?.let { setPreferredHashAlgorithms(false, it) }
        }.generate()
        return PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, kp, "Prefs <prefs@example.test>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), hashed, null,
            BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.EDDSA_LEGACY, HashAlgorithmTags.SHA256), null
        ).generatePublicKeyRing()
    }

    @Test
    fun `the cipher is the strongest every recipient lists, AES-128 always allowed`() {
        val aes128 = edCertWithPrefs(intArrayOf(SymmetricKeyAlgorithmTags.AES_128), null)
        val aes256 = edCertWithPrefs(intArrayOf(SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_128), null)
        val both = edCertWithPrefs(intArrayOf(SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_256), null)
        val none = edCertWithPrefs(null, null)
        val camellia = edCertWithPrefs(intArrayOf(SymmetricKeyAlgorithmTags.CAMELLIA_256), null)
        assertEquals(SymmetricKeyAlgorithmTags.AES_128, RecipientPreferences.cipherFor(listOf(aes128)))
        assertEquals(SymmetricKeyAlgorithmTags.AES_256, RecipientPreferences.cipherFor(listOf(aes256)))
        assertEquals(SymmetricKeyAlgorithmTags.AES_256, RecipientPreferences.cipherFor(listOf(aes256, both)))
        assertEquals(SymmetricKeyAlgorithmTags.AES_128, RecipientPreferences.cipherFor(listOf(aes256, aes128)))
        assertEquals(SymmetricKeyAlgorithmTags.AES_256, RecipientPreferences.cipherFor(listOf(none)))
        assertEquals(SymmetricKeyAlgorithmTags.AES_128, RecipientPreferences.cipherFor(listOf(camellia)))
    }

    @Test
    fun `the signature hash is the strongest every recipient lists, SHA-256 always allowed`() {
        val sha384 = edCertWithPrefs(null, intArrayOf(HashAlgorithmTags.SHA384))
        val sha512 = edCertWithPrefs(null, intArrayOf(HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA256))
        val md5 = edCertWithPrefs(null, intArrayOf(HashAlgorithmTags.MD5))
        assertEquals(HashAlgorithmTags.SHA384, RecipientPreferences.hashFor(listOf(sha384)))
        assertEquals(HashAlgorithmTags.SHA512, RecipientPreferences.hashFor(listOf(sha512)))
        assertEquals(HashAlgorithmTags.SHA256, RecipientPreferences.hashFor(listOf(sha384, sha512)))
        assertEquals(HashAlgorithmTags.SHA256, RecipientPreferences.hashFor(listOf(md5)))
    }

    @Test
    fun `an encrypted message uses the recipient's cipher`() {
        val gen = svc.generateKeyPair("Recipient", "recipient@example.test", KeyAlgorithm.ED25519_CV25519, null)
        val pub = svc.importKeyData(gen.publicKeyData).publicKeyRing!!
        val sec = svc.importKeyData(gen.privateKeyData).secretKeyRing!!
        val msg = svc.encrypt("prefs".toByteArray(), listOf(pub))
        assertEquals("prefs", String(svc.decrypt(msg, listOf(sec), null).data))
    }
}
