// SelfSigHashChoiceTest.kt
// PGPony Android 4.8.0 (#86): Refresh self-signatures and the expiry change used SHA-256 for
// every signature they made. A user with an RSA key asked for SHA-512, so both now take the hash
// as a choice (SHA-256 or SHA-512), used for User ID self-certifications, subkey bindings and a
// signing subkey's back-signature. The default is SHA-512 for RSA of 3072 bits or more and for a
// key whose newest self-signature already uses SHA-512, SHA-256 otherwise.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

class SelfSigHashChoiceTest {

    private val day = 86_400L
    private val nowS = System.currentTimeMillis() / 1000L
    private val created = nowS - 400 * day
    private val uid = "Hash <hash@pgpony.test>"

    private fun ed(): PGPKeyPair = BcPGPKeyPair(
        PublicKeyAlgorithmTags.EDDSA_LEGACY,
        Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(),
        Date(created * 1000L)
    )

    private fun x(): PGPKeyPair = BcPGPKeyPair(
        PublicKeyAlgorithmTags.ECDH,
        X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(),
        Date(created * 1000L)
    )

    private fun rsa(bits: Int): PGPKeyPair = BcPGPKeyPair(
        PublicKeyAlgorithmTags.RSA_GENERAL,
        RSAKeyPairGenerator().apply {
            init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), SecureRandom(), bits, 80))
        }.generateKeyPair(),
        Date(created * 1000L)
    )

    private fun sub(flags: Int, expiry: Long?) = PGPSignatureSubpacketGenerator().apply {
        setKeyFlags(false, flags)
        setSignatureCreationTime(false, Date(created * 1000L))
        if (expiry != null) setKeyExpirationTime(false, expiry)
    }.generate()

    /** [primary] self-signed with [hash]: a User ID, an encryption subkey expiring in 600 days
     *  and a signing subkey (its back-signature with [hash] too). */
    private fun key(primary: PGPKeyPair, hash: Int): PGPKeyRingGenerator {
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, primary, uid,
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
                setSignatureCreationTime(false, Date(created * 1000L))
            }.generate(),
            null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, hash), null
        )
        gen.addSubKey(x(), sub(KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE, 1000 * day), null)
        val signing = ed()
        gen.addSubKey(
            signing, sub(KeyFlags.SIGN_DATA, null), null,
            BcPGPContentSignerBuilder(signing.publicKey.algorithm, hash)
        )
        return gen
    }

    private fun stored(ring: PGPPublicKeyRing) =
        PGPPublicKeyRing(CertificateBindings.sanitized(ring.encoded), BcKeyFingerprintCalculator())
    private fun subkeys(ring: PGPPublicKeyRing) = ring.publicKeys.asSequence().filter { !it.isMasterKey }.toList()
    private fun expiresAt(k: PGPPublicKey): Long? = k.validSeconds.takeIf { it > 0 }?.let { k.creationTime.time / 1000L + it }
    private fun newestBinding(k: PGPPublicKey) = k.signatures.asSequence()
        .filter { it.signatureType == PGPSignature.SUBKEY_BINDING }.maxByOrNull { it.creationTime }!!
    private fun selfCerts(ring: PGPPublicKeyRing): List<Pair<String, PGPSignature>> {
        val primary = ring.publicKey
        return primary.userIDs.asSequence().flatMap { id ->
            primary.getSignaturesForID(id).asSequence()
                .filter { it.keyID == primary.keyID && it.signatureType in PGPSignature.DEFAULT_CERTIFICATION..PGPSignature.POSITIVE_CERTIFICATION }
                .map { id to it }
        }.toList()
    }

    /** Every User ID self-certification, subkey binding and back-signature in [ring] uses
     *  [hash] and verifies. */
    private fun assertAllSignedWith(ring: PGPPublicKeyRing, hash: Int) {
        val primary = ring.publicKey
        val certs = selfCerts(ring)
        assertTrue("the key has User ID self-certifications", certs.isNotEmpty())
        for ((id, cert) in certs) {
            assertEquals("User ID self-certification hash", hash, cert.hashAlgorithm)
            cert.init(BcPGPContentVerifierBuilderProvider(), primary)
            assertTrue(cert.verifyCertification(id, primary))
        }
        var backSigs = 0
        for (s in subkeys(ring)) {
            val b = newestBinding(s)
            assertEquals("subkey binding hash", hash, b.hashAlgorithm)
            b.init(BcPGPContentVerifierBuilderProvider(), primary)
            assertTrue(b.verifyCertification(primary, s))
            if ((b.hashedSubPackets.keyFlags and KeyFlags.SIGN_DATA) != 0) {
                val back = b.hashedSubPackets.embeddedSignatures[0]
                assertEquals("back-signature hash", hash, back.hashAlgorithm)
                back.init(BcPGPContentVerifierBuilderProvider(), s)
                assertTrue(back.verifyCertification(primary, s))
                backSigs++
            }
        }
        assertTrue("a signing subkey's back-signature was checked", backSigs > 0)
    }

    @Test
    fun `refresh with SHA-512 re-signs User IDs, bindings and back-signatures with SHA-512`() {
        val gen = key(rsa(2048), HashAlgorithmTags.SHA256)
        val secret = gen.generateSecretKeyRing()
        val public = gen.generatePublicKeyRing()
        val out = KeyExpirationService.shared.refreshSelfSignatures(secret, public, null, HashAlgorithmTags.SHA512)
        val after = stored(out.rings.publicRing)
        assertEquals(2, subkeys(after).size)
        assertAllSignedWith(after, HashAlgorithmTags.SHA512)
        val original = subkeys(public).associateBy { it.keyID }
        subkeys(after).forEach { assertEquals("expiry kept", expiresAt(original.getValue(it.keyID)), expiresAt(it)) }
    }

    @Test
    fun `refresh with SHA-256 still signs with SHA-256`() {
        val gen = key(ed(), HashAlgorithmTags.SHA512)
        val out = KeyExpirationService.shared.refreshSelfSignatures(
            gen.generateSecretKeyRing(), gen.generatePublicKeyRing(), null, HashAlgorithmTags.SHA256
        )
        assertAllSignedWith(stored(out.rings.publicRing), HashAlgorithmTags.SHA256)
    }

    @Test
    fun `a SHA-512 refresh of a SHA-1 key leaves nothing flagged as a weak hash`() {
        val gen = key(ed(), HashAlgorithmTags.SHA1)
        val secret = gen.generateSecretKeyRing()
        val before = stored(gen.generatePublicKeyRing())
        assertEquals("the SHA-1 subkeys are left out when stored", 0, subkeys(before).size)
        val out = KeyExpirationService.shared.refreshSelfSignatures(secret, before, null, HashAlgorithmTags.SHA512)
        val after = stored(out.rings.publicRing)
        assertEquals(2, subkeys(after).size)
        assertTrue(SubkeyAdmission.leftOut(after.encoded).isEmpty())
        assertTrue((CertificateBindings.analyze(after.encoded)?.weakUserIds ?: emptySet<String>()).isEmpty())
        assertAllSignedWith(after, HashAlgorithmTags.SHA512)
    }

    @Test
    fun `a subkey's expiry change with SHA-512 signs its binding and back-signature with SHA-512`() {
        val gen = key(ed(), HashAlgorithmTags.SHA256)
        val secret = gen.generateSecretKeyRing()
        val public = gen.generatePublicKeyRing()
        val signing = subkeys(public).first { (newestBinding(it).hashedSubPackets.keyFlags and KeyFlags.SIGN_DATA) != 0 }
        val target = nowS + 365 * day
        val out = KeyExpirationService.shared.setExpirationSoftware(
            secret, public, target, null, KeyExpirationService.Target.Subkey(signing.keyID), HashAlgorithmTags.SHA512
        ).publicRing
        val edited = out.getPublicKey(signing.keyID)
        assertEquals(target, expiresAt(edited))
        val b = newestBinding(edited)
        assertEquals(HashAlgorithmTags.SHA512, b.hashAlgorithm)
        b.init(BcPGPContentVerifierBuilderProvider(), out.publicKey)
        assertTrue(b.verifyCertification(out.publicKey, edited))
        val back = b.hashedSubPackets.embeddedSignatures[0]
        assertEquals(HashAlgorithmTags.SHA512, back.hashAlgorithm)
        back.init(BcPGPContentVerifierBuilderProvider(), edited)
        assertTrue(back.verifyCertification(out.publicKey, edited))
        // The User ID was not part of this edit, so it keeps its SHA-256 certification.
        assertTrue(selfCerts(out).all { it.second.hashAlgorithm == HashAlgorithmTags.SHA256 })
    }

    @Test
    fun `the primary's expiry change with SHA-512 and current subkeys signs everything with SHA-512`() {
        val gen = key(ed(), HashAlgorithmTags.SHA256)
        val target = nowS + 365 * day
        val out = KeyExpirationService.shared.setExpirationSoftware(
            gen.generateSecretKeyRing(), gen.generatePublicKeyRing(), target, null,
            KeyExpirationService.Target.Primary(currentSubkeys = true), HashAlgorithmTags.SHA512
        ).publicRing
        assertEquals(target, expiresAt(out.publicKey))
        assertAllSignedWith(stored(out), HashAlgorithmTags.SHA512)
    }

    @Test
    fun `a v6 key refreshes with SHA-512`() {
        val svc = PGPCryptoService.shared
        val k = svc.generateKeyPair("V6 Hash", "v6hash@pgpony.test", KeyAlgorithm.V6_ED25519, null, null)
        val secret = svc.importKeyData(k.privateKeyData).secretKeyRing!!
        val public = PGPPublicKeyRing(k.publicKeyData, BcKeyFingerprintCalculator())
        val out = KeyExpirationService.shared.refreshSelfSignatures(secret, public, null, HashAlgorithmTags.SHA512)
        assertAllSignedWith(out.rings.publicRing, HashAlgorithmTags.SHA512)
    }

    @Test
    fun `a hash outside the choice is refused`() {
        val gen = key(ed(), HashAlgorithmTags.SHA256)
        try {
            KeyExpirationService.shared.refreshSelfSignatures(
                gen.generateSecretKeyRing(), gen.generatePublicKeyRing(), null, HashAlgorithmTags.SHA1
            )
            fail("SHA-1 must not be accepted")
        } catch (e: KeyExpirationService.ExpirationError.Failed) {
            // expected
        }
    }

    // ── Default choice ──────────────────────────────────────────────────

    @Test
    fun `RSA 3072 defaults to SHA-512`() {
        val ring = key(rsa(3072), HashAlgorithmTags.SHA256).generatePublicKeyRing()
        assertEquals(HashAlgorithmTags.SHA512, KeyExpirationService.defaultSelfSigHash(ring))
    }

    @Test
    fun `RSA 2048 signed with SHA-256 defaults to SHA-256`() {
        val ring = key(rsa(2048), HashAlgorithmTags.SHA256).generatePublicKeyRing()
        assertEquals(HashAlgorithmTags.SHA256, KeyExpirationService.defaultSelfSigHash(ring))
    }

    @Test
    fun `Ed25519 signed with SHA-256 defaults to SHA-256`() {
        val ring = key(ed(), HashAlgorithmTags.SHA256).generatePublicKeyRing()
        assertEquals(HashAlgorithmTags.SHA256, KeyExpirationService.defaultSelfSigHash(ring))
    }

    @Test
    fun `a key whose newest self-signature uses SHA-512 defaults to SHA-512`() {
        val ring = key(ed(), HashAlgorithmTags.SHA512).generatePublicKeyRing()
        assertEquals(HashAlgorithmTags.SHA512, KeyExpirationService.defaultSelfSigHash(ring))
    }

    @Test
    fun `the newest self-signature decides, so a key refreshed to SHA-256 defaults to SHA-256 again`() {
        val gen = key(ed(), HashAlgorithmTags.SHA512)
        val out = KeyExpirationService.shared.refreshSelfSignatures(
            gen.generateSecretKeyRing(), gen.generatePublicKeyRing(), null, HashAlgorithmTags.SHA256
        )
        assertEquals(HashAlgorithmTags.SHA256, KeyExpirationService.defaultSelfSigHash(out.rings.publicRing))
    }
}
