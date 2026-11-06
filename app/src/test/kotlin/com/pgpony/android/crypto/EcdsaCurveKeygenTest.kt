// EcdsaCurveKeygenTest.kt
// PGPony Android, 4.8.0 (4l, #109): generating v4 ECDSA keys on
// brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 and secp256k1.
//
// For each curve, with and without a passphrase: the key is v4, the primary
// is ECDSA and the subkey ECDH on the same curve with gpg's KDF parameters,
// the self-signatures use the curve's hash, the label is the curve's, and
// encrypt / decrypt, encrypt-and-sign, cleartext and detached signatures all
// round-trip through the app's own services. gpg interop is checked by hand.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.ECPublicBCPGKey
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.security.Security

class EcdsaCurveKeygenTest {

    /** What a generated key on one curve must look like. */
    private class Expect(
        val algorithm: KeyAlgorithm,
        val oid: String,
        val hash: Int,
        val kek: Int,
        val label: String,
        val clearSignHeader: String
    )

    private data class Key(val sec: PGPSecretKeyRing, val pub: PGPPublicKeyRing, val importedAs: KeyAlgorithm)

    companion object {
        @BeforeClass
        @JvmStatic
        fun installBouncyCastle() {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        private const val PASS = "brainpool and secp256k1"
    }

    private val svc = PGPCryptoService.shared

    private val curves = listOf(
        Expect(
            KeyAlgorithm.ECDSA_BRAINPOOL_P256, "1.3.36.3.3.2.8.1.1.7",
            HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128,
            "ECDSA (brainpoolP256r1)", "Hash: SHA256"
        ),
        Expect(
            KeyAlgorithm.ECDSA_BRAINPOOL_P384, "1.3.36.3.3.2.8.1.1.11",
            HashAlgorithmTags.SHA384, SymmetricKeyAlgorithmTags.AES_192,
            "ECDSA (brainpoolP384r1)", "Hash: SHA384"
        ),
        Expect(
            KeyAlgorithm.ECDSA_BRAINPOOL_P512, "1.3.36.3.3.2.8.1.1.13",
            HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256,
            "ECDSA (brainpoolP512r1)", "Hash: SHA512"
        ),
        Expect(
            KeyAlgorithm.ECDSA_SECP256K1, "1.3.132.0.10",
            HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128,
            "ECDSA (secp256k1)", "Hash: SHA256"
        )
    )

    private fun generate(e: Expect, passphrase: String?): Key {
        val gen = svc.generateKeyPair("Curve Test", "curve@example.test", e.algorithm, passphrase)
        val secImport = svc.importKeyData(gen.privateKeyData)
        val pubImport = svc.importKeyData(gen.publicKeyData)
        val sec = secImport.secretKeyRing ?: error("generated key has no secret ring")
        val pub = pubImport.publicKeyRing ?: error("generated key has no public ring")
        assertEquals(gen.fingerprint, svc.fingerprintHex(pub.publicKey))
        return Key(sec, pub, pubImport.algorithm)
    }

    private fun subkeyOf(ring: PGPPublicKeyRing): PGPPublicKey =
        ring.publicKeys.asSequence().single { !it.isMasterKey }

    private fun curveOid(key: PGPPublicKey): String =
        (key.publicKeyPacket.key as ECPublicBCPGKey).curveOID.id

    private fun selfCertification(ring: PGPPublicKeyRing): PGPSignature =
        ring.publicKey.signatures.asSequence().filterIsInstance<PGPSignature>()
            .first { it.signatureType == PGPSignature.POSITIVE_CERTIFICATION }

    private fun subkeyBinding(subkey: PGPPublicKey): PGPSignature =
        subkey.signatures.asSequence().filterIsInstance<PGPSignature>()
            .first { it.signatureType == PGPSignature.SUBKEY_BINDING }

    private fun firstSignature(armoredOrBinary: ByteArray): PGPSignature {
        val input = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(armoredOrBinary.inputStream())
        val list = JcaPGPObjectFactory(input).nextObject() as PGPSignatureList
        return list[0]
    }

    // ── Shape ────────────────────────────────────────────────────────

    @Test
    fun `each curve generates a v4 ECDSA primary and a same-curve ECDH subkey, with and without a passphrase`() {
        for (e in curves) for (pass in listOf(null, PASS)) {
            val k = generate(e, pass)
            val what = "${e.algorithm} pass=${pass != null}"
            val primary = k.pub.publicKey
            val sub = subkeyOf(k.pub)

            assertEquals("$what primary version", 4, primary.version)
            assertEquals("$what subkey version", 4, sub.version)
            assertEquals("$what primary algorithm", PublicKeyAlgorithmTags.ECDSA, primary.algorithm)
            assertEquals("$what subkey algorithm", PublicKeyAlgorithmTags.ECDH, sub.algorithm)
            assertEquals("$what primary curve", e.oid, curveOid(primary))
            assertEquals("$what subkey curve", e.oid, curveOid(sub))

            val kdf = sub.publicKeyPacket.key as ECDHPublicBCPGKey
            assertEquals("$what KDF hash", e.hash, kdf.hashAlgorithm.toInt() and 0xFF)
            assertEquals("$what KDF key wrap", e.kek, kdf.symmetricKeyAlgorithm.toInt() and 0xFF)

            assertEquals("$what self-certification hash", e.hash, selfCertification(k.pub).hashAlgorithm)
            assertEquals("$what subkey binding hash", e.hash, subkeyBinding(sub).hashAlgorithm)

            val flags = selfCertification(k.pub).hashedSubPackets.keyFlags
            assertEquals("$what primary certifies and signs", 0x03, flags and 0x03)
            assertTrue("$what subkey encrypts", sub.isEncryptionKey)

            for (sk in k.sec.secretKeys) {
                if (pass == null) assertEquals("$what unprotected", 0, sk.s2KUsage.toInt())
                else assertNotEquals("$what protected", 0, sk.s2KUsage.toInt())
            }
        }
    }

    @Test
    fun `the label shown is the curve's ECDSA label`() {
        for (e in curves) {
            val k = generate(e, null)
            assertEquals(e.algorithm, k.importedAs)
            assertEquals(e.algorithm, svc.detectAlgorithm(k.pub.publicKey, k.pub))
            assertEquals(e.label, e.algorithm.displayName)
            assertFalse(e.algorithm.isV6)
            // The single-key choosers name the ECDH subkey by its curve.
            val curveName = e.label.removePrefix("ECDSA (").removeSuffix(")")
            assertEquals("ECDH $curveName", EcCurveOid.ecdhLabel(subkeyOf(k.pub)))
            assertNull(EcCurveOid.ecdhLabel(k.pub.publicKey))
        }
    }

    @Test
    fun `the four curves sit in the Advanced group only`() {
        val ecdsa = curves.map { it.algorithm }
        assertEquals(ecdsa, KeyAlgorithm.generatableEcdsa)
        assertTrue(KeyAlgorithm.generatableAdvanced.containsAll(ecdsa))
        for (a in ecdsa) {
            assertFalse(a in KeyAlgorithm.generatableClassical)
            assertFalse(a in KeyAlgorithm.generatablePostQuantum)
            assertFalse(a in KeyAlgorithm.generatableInterop)
        }
        val all = KeyAlgorithm.generatable
        assertEquals(all.size, all.toSet().size)
        // The NIST curves stay import-only.
        assertFalse(KeyAlgorithm.ECDSA_NIST_P256 in all)
        assertFalse(KeyAlgorithm.ECDSA_NIST_P384 in all)
        assertFalse(KeyAlgorithm.ECDSA_NIST_P521 in all)
    }

    // ── Encrypt and decrypt ──────────────────────────────────────────

    @Test
    fun `encrypt and decrypt round-trip on every curve`() {
        for (e in curves) for (pass in listOf(null, PASS)) {
            val k = generate(e, pass)
            val text = "to ${e.algorithm}"
            val ct = svc.encrypt(data = text.toByteArray(), recipientPublicKeys = listOf(k.pub), armor = true)
            val result = svc.decrypt(ct, listOf(k.sec), passphrase = pass)
            assertEquals("${e.algorithm} pass=${pass != null}", text, String(result.data))
            assertEquals(subkeyOf(k.pub).keyID, result.decryptingKeyIdRaw)
        }
    }

    @Test
    fun `encrypt-and-sign verifies on decrypt`() {
        for (e in curves) {
            val k = generate(e, PASS)
            val ct = svc.encrypt(
                data = "signed and sealed".toByteArray(),
                recipientPublicKeys = listOf(k.pub),
                signingSecretKey = k.sec,
                passphrase = PASS,
                armor = true
            )
            val result = svc.decrypt(ct, listOf(k.sec), passphrase = PASS, verificationKeys = listOf(k.pub))
            assertEquals("signed and sealed", String(result.data))
            assertTrue("${e.algorithm} signature verified", result.signatureVerified)
        }
    }

    // ── Sign and verify ──────────────────────────────────────────────

    @Test
    fun `cleartext signatures verify and name the curve's hash`() {
        for (e in curves) for (pass in listOf(null, PASS)) {
            val k = generate(e, pass)
            val message = "cleartext on ${e.algorithm}"
            val signed = SigningService.shared.signClear(message, k.sec, passphrase = pass)
            assertTrue("${e.algorithm} header", signed.contains(e.clearSignHeader))
            val result = VerifyService.shared.verifyClearSigned(signed, listOf(k.pub))
            assertTrue("${e.algorithm} pass=${pass != null}: $result", result is VerificationResult.Verified)
            assertEquals(message, (result as VerificationResult.Verified).signedContent)
        }
    }

    @Test
    fun `detached signatures verify and use the curve's hash`() {
        for (e in curves) for (pass in listOf(null, PASS)) {
            val k = generate(e, pass)
            val data = "detached on ${e.algorithm}".toByteArray()
            val sig = SigningService.shared.signDetached(data = data, secretKeyRing = k.sec, passphrase = pass, armor = false)
            assertEquals("${e.algorithm} hash", e.hash, firstSignature(sig).hashAlgorithm)
            val result = VerifyService.shared.verifyDetached(sig, data, listOf(k.pub))
            assertTrue("${e.algorithm} pass=${pass != null}: $result", result is VerificationResult.Verified)

            // The other detached path (PGPCryptoService.sign) uses the same hash.
            val viaService = svc.sign(data, k.sec, pass ?: "", detached = true, armor = true)
            assertEquals("${e.algorithm} service hash", e.hash, firstSignature(viaService).hashAlgorithm)
            val again = VerifyService.shared.verifyDetached(String(viaService), data, listOf(k.pub))
            assertTrue("${e.algorithm} service: $again", again is VerificationResult.Verified)
        }
    }

    // ── Export ───────────────────────────────────────────────────────

    @Test
    fun `armored export re-imports with the same fingerprint and curve`() {
        for (e in curves) {
            val k = generate(e, PASS)
            val pubBack = svc.importArmoredKey(svc.exportArmoredPublicKey(k.pub))
            val secBack = svc.importArmoredKey(svc.exportArmoredPrivateKey(k.sec))
            assertEquals(svc.fingerprintHex(k.pub.publicKey), pubBack.fingerprint)
            assertEquals(svc.fingerprintHex(k.pub.publicKey), secBack.fingerprint)
            assertEquals(e.algorithm, pubBack.algorithm)
            assertTrue(secBack.hasPrivateKey)
            val back = secBack.secretKeyRing
            assertNotNull(back)
            assertArrayEquals(k.sec.publicKey.fingerprint, back!!.publicKey.fingerprint)
            assertEquals(e.oid, curveOid(subkeyOf(pubBack.publicKeyRing!!)))
        }
    }

    // ── Hash choice ──────────────────────────────────────────────────

    @Test
    fun `an ECDSA signer never gets a hash shorter than its curve`() {
        val bp384 = generate(curves[1], null).pub.publicKey
        val bp512 = generate(curves[2], null).pub.publicKey
        val k1 = generate(curves[3], null).pub.publicKey
        assertEquals(HashAlgorithmTags.SHA384, EcCurveOid.signatureHash(bp384, HashAlgorithmTags.SHA256))
        assertEquals(HashAlgorithmTags.SHA512, EcCurveOid.signatureHash(bp384, HashAlgorithmTags.SHA512))
        assertEquals(HashAlgorithmTags.SHA512, EcCurveOid.signatureHash(bp512, HashAlgorithmTags.SHA256))
        assertEquals(HashAlgorithmTags.SHA256, EcCurveOid.signatureHash(k1, HashAlgorithmTags.SHA256))
        assertEquals(HashAlgorithmTags.SHA384, EcCurveOid.signatureHash(k1, HashAlgorithmTags.SHA384))
        // Other key types keep the requested hash.
        val ed = svc.importKeyData(
            svc.generateKeyPair("E", "e@example.test", KeyAlgorithm.ED25519_CV25519, null).publicKeyData
        ).publicKeyRing!!.publicKey
        assertEquals(HashAlgorithmTags.SHA256, EcCurveOid.signatureHash(ed, HashAlgorithmTags.SHA256))
    }

    @Test
    fun `a User ID added later is certified with the curve's hash`() {
        val e = curves[2]
        val k = generate(e, PASS)
        val updated = UserIdService.shared.addUserId(
            secretRing = k.sec,
            publicRing = k.pub,
            userId = "Second <second@example.test>",
            makePrimary = false,
            passphrase = PASS
        )
        val cert = updated.publicRing.publicKey.getSignaturesForID("Second <second@example.test>")
            .asSequence().filterIsInstance<PGPSignature>().first()
        assertEquals(e.hash, cert.hashAlgorithm)
    }
}
