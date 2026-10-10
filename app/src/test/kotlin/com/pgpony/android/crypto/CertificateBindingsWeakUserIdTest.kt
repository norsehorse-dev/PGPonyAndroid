// CertificateBindingsWeakUserIdTest.kt
// PGPony Android 4.7.0 (item 27, #67): a User ID whose only self-certification
// uses SHA-1 after the key-signature cutoff is kept with a weak-hash mark, so
// an older key keeps its name through import and restore. When an accepted
// certification also exists, it is the one used.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class CertificateBindingsWeakUserIdTest {

    private val uid = "Old Key <old@pgpony.app>"
    private val keyCreated = Date(System.currentTimeMillis() - 3_600_000L)

    private fun ed25519Pair(): PGPKeyPair {
        val g = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
        g.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
        return BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, g.generateKeyPair(), keyCreated)
    }

    private fun certify(pair: PGPKeyPair, hash: Int, created: Date, expirySeconds: Long): PGPSignature {
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(pair.publicKey.algorithm, hash), pair.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, pair.privateKey)
        val h = PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, created)
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
            setIssuerFingerprint(false, pair.publicKey)
            setKeyExpirationTime(false, expirySeconds)
        }
        g.setHashedSubpackets(h.generate())
        return g.generateCertification(uid, pair.publicKey)
    }

    private fun certifyId(pair: PGPKeyPair, id: String, hash: Int, created: Date): PGPSignature {
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(pair.publicKey.algorithm, hash), pair.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, pair.privateKey)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, created)
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER)
            setIssuerFingerprint(false, pair.publicKey)
        }.generate())
        return g.generateCertification(id, pair.publicKey)
    }

    @Test
    fun `a weak-only User ID does not speak for the primary when an accepted one exists`() {
        val pair = ed25519Pair()
        val now = System.currentTimeMillis()
        val second = "Second <second@pgpony.app>"
        var key: PGPPublicKey = pair.publicKey
        key = PGPPublicKey.addCertification(key, uid, certify(pair, HashAlgorithmTags.SHA256, Date(now - 60_000L), 0))
        key = PGPPublicKey.addCertification(key, second, certifyId(pair, second, HashAlgorithmTags.SHA1, Date(now - 1_000L)))
        val r = CertificateBindings.analyze(PGPPublicKeyRing(listOf(key)).encoded)!!
        assertEquals(setOf(second), r.weakUserIds)
        val active = r.activePrimarySig(now)
        assertNotNull(active)
        assertFalse("the SHA-256 certification is the one in force", active!!.weakHash)
    }

    private fun ring(pair: PGPKeyPair, vararg sigs: PGPSignature): ByteArray {
        var key: PGPPublicKey = pair.publicKey
        for (s in sigs) key = PGPPublicKey.addCertification(key, uid, s)
        return PGPPublicKeyRing(listOf(key)).encoded
    }

    @Test
    fun `policy marks only SHA-1 past the cutoff as weak`() {
        val now = System.currentTimeMillis()
        assertTrue(SignaturePolicy.isWeakCertificationDigest(HashAlgorithmTags.SHA1, now))
        assertTrue(SignaturePolicy.isWeakCertificationDigest(HashAlgorithmTags.RIPEMD160, now))
        assertFalse(SignaturePolicy.isWeakCertificationDigest(HashAlgorithmTags.SHA1, 1_420_070_400_000L))
        assertFalse(SignaturePolicy.isWeakCertificationDigest(HashAlgorithmTags.SHA256, now))
        assertFalse(SignaturePolicy.isWeakCertificationDigest(HashAlgorithmTags.MD5, now))
    }

    @Test
    fun `a SHA-1 only User ID keeps its name with the weak mark, through sanitize`() {
        val pair = ed25519Pair()
        val raw = ring(pair, certify(pair, HashAlgorithmTags.SHA1, Date(), 0))
        val r = CertificateBindings.analyze(raw)
        assertNotNull(r)
        assertTrue("name kept", uid in r!!.certifiedUserIds)
        assertEquals(setOf(uid), r.weakUserIds)
        assertNotNull("the key is valid now", r.activePrimarySig(System.currentTimeMillis()))

        val clean = CertificateBindings.sanitize(raw)
        val r2 = CertificateBindings.analyze(clean)!!
        assertTrue("sanitize keeps the User ID", uid in r2.certifiedUserIds)
        assertEquals(setOf(uid), r2.weakUserIds)
        assertEquals("sanitize is idempotent", clean.toList(), CertificateBindings.sanitize(clean).toList())
    }

    @Test
    fun `an accepted certification wins over a newer SHA-1 one`() {
        val pair = ed25519Pair()
        val now = System.currentTimeMillis()
        val strong = certify(pair, HashAlgorithmTags.SHA256, Date(now - 60_000L), 365L * 86_400L)
        val weak = certify(pair, HashAlgorithmTags.SHA1, Date(now - 1_000L), 730L * 86_400L)
        val raw = ring(pair, strong, weak)
        val r = CertificateBindings.analyze(raw)!!
        assertTrue(uid in r.certifiedUserIds)
        assertTrue("not weak when an accepted binding exists", r.weakUserIds.isEmpty())
        assertEquals(
            "expiry comes from the SHA-256 certification",
            keyCreated.time / 1000L * 1000L + 365L * 86_400L * 1000L,
            r.primaryExpiresAtMs
        )
        val r2 = CertificateBindings.analyze(CertificateBindings.sanitize(raw))!!
        assertTrue(r2.weakUserIds.isEmpty())
        assertEquals(r.primaryExpiresAtMs, r2.primaryExpiresAtMs)
    }
}
