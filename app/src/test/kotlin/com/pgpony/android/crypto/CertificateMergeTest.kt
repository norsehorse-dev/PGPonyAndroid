// CertificateMergeTest.kt
// PGPony Android, 4.6.0 (items 17.1 and 12)
//
// The refresh / re-import merge is a verified union, not a replacement.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

class CertificateMergeTest {

    private val svc = PGPCryptoService.shared

    private fun gen(uid: String) = svc.generateKeyPair(uid.substringBefore(" <"), uid.substringAfter("<").trimEnd('>'),
        KeyAlgorithm.ED25519_CV25519, null, null)

    private fun secret(k: GeneratedKeyResult) = PGPSecretKeyRing(k.privateKeyData, BcKeyFingerprintCalculator())
    private fun pub(raw: ByteArray) = PGPPublicKeyRing(raw, BcKeyFingerprintCalculator())

    private fun uids(raw: ByteArray) = pub(raw).publicKey.userIDs.asSequence().toSet()

    /** [ring] with an extra User ID self-certified by its own primary. */
    private fun withUid(sec: PGPSecretKeyRing, uid: String): ByteArray {
        val sk = sec.secretKey
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, sk.extractPrivateKey(null))
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply { setSignatureCreationTime(false, Date()) }.generate())
        val cert = g.generateCertification(uid, sk.publicKey)
        val pubRing = PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
        val withCert = PGPPublicKey.addCertification(pubRing.publicKey, uid, cert)
        return PGPPublicKeyRing.insertPublicKey(pubRing, withCert).encoded
    }

    private fun revoked(sec: PGPSecretKeyRing): ByteArray {
        val sk = sec.secretKey
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey)
        g.init(PGPSignature.KEY_REVOCATION, sk.extractPrivateKey(null))
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply { setSignatureCreationTime(false, Date()) }.generate())
        val rev = g.generateCertification(sk.publicKey)
        val pubRing = PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
        return PGPPublicKeyRing.insertPublicKey(pubRing, PGPPublicKey.addCertification(pubRing.publicKey, rev)).encoded
    }

    @Test
    fun `a server copy missing a User ID does not remove it`() {
        val k = gen("Alice <alice@pgpony.app>")
        val local = withUid(secret(k), "Alice Work <alice@work.example>")
        val server = k.publicKeyData // only the first User ID
        val merged = CertificateMerge.merge(local, server, isKeyPair = false)
        assertEquals(uids(local), uids(merged))
    }

    @Test
    fun `a public-only key gains a new self-certified User ID but not a removed one`() {
        val k = gen("Bob <bob@pgpony.app>")
        val server = withUid(secret(k), "Bob New <bob@new.example>")
        val merged = CertificateMerge.merge(k.publicKeyData, server, isKeyPair = false)
        assertTrue("Bob New <bob@new.example>" in uids(merged))
        val tomb = CertificateMerge.merge(k.publicKeyData, server, isKeyPair = false,
            removedUserIds = setOf("Bob New <bob@new.example>"))
        assertFalse("Bob New <bob@new.example>" in uids(tomb))
    }

    @Test
    fun `a key pair takes only revocations from a fetched copy`() {
        val k = gen("Carol <carol@pgpony.app>")
        val sec = secret(k)
        val serverWithUid = withUid(sec, "Carol Extra <carol@extra.example>")
        val m1 = CertificateMerge.merge(k.publicKeyData, serverWithUid, isKeyPair = true)
        assertFalse("no new User ID on a key pair", "Carol Extra <carol@extra.example>" in uids(m1))
        val m2 = CertificateMerge.merge(k.publicKeyData, revoked(sec), isKeyPair = true)
        assertTrue("revocation arrives", CertificateBindings.analyze(m2)!!.primaryRevoked)
    }

    @Test
    fun `a User ID the primary never certified does not arrive`() {
        val k = gen("Dan <dan@pgpony.app>")
        val other = gen("Mallory <m@evil.example>")
        // Mallory certifies a "Dan" User ID with Mallory's key and appends it.
        val msk = secret(other).secretKey
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(msk.publicKey.algorithm, HashAlgorithmTags.SHA256), msk.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, msk.extractPrivateKey(null))
        val danPub = pub(k.publicKeyData)
        val fake = g.generateCertification("Dan <dan@bank.example>", danPub.publicKey)
        val server = PGPPublicKeyRing.insertPublicKey(
            danPub, PGPPublicKey.addCertification(danPub.publicKey, "Dan <dan@bank.example>", fake)
        ).encoded
        val merged = CertificateMerge.merge(k.publicKeyData, server, isKeyPair = false)
        assertFalse("Dan <dan@bank.example>" in uids(merged))
    }

    @Test
    fun `a different certificate is never merged in`() {
        val a = gen("A <a@pgpony.app>")
        val b = gen("B <b@pgpony.app>")
        val merged = CertificateMerge.merge(a.publicKeyData, b.publicKeyData, isKeyPair = false)
        assertTrue(merged.contentEquals(a.publicKeyData))
        assertNull(pub(merged).getPublicKey(pub(b.publicKeyData).publicKey.keyID))
    }
}
