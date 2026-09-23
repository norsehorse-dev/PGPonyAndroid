// PublicationStateTest.kt
// PGPony Android, 4.6.0 (items 9 and 11)
//
// The publish sheet reads confirmed addresses from a server's copy, refuses an
// ambiguous primary identity, and Key Detail knows when a published key has
// local changes the servers do not have.

package com.pgpony.android.keyserver

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.UserIdService
import com.pgpony.android.data.PGPKeyEntity
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
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

class PublicationStateTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `confirmed addresses are read from the served copy, not the armor text`() {
        val k = svc.generateKeyPair("Alice", "Alice@Example.org", KeyAlgorithm.ED25519_CV25519, null)
        val armored = svc.exportArmoredPublicKey(PGPPublicKeyRing(k.publicKeyData, BcKeyFingerprintCalculator()))
        assertFalse("the old check searched this text", armored.contains("alice@example.org", ignoreCase = true))
        assertEquals(setOf("alice@example.org"), ServerCopy.addressesIn(armored))
        assertEquals(emptySet<String>(), ServerCopy.addressesIn("<html>not a key</html>"))
    }

    /** [uid] added with a self-certification that sets the primary flag. */
    private fun withPrimaryUid(k: com.pgpony.android.crypto.GeneratedKeyResult, uid: String): PGPPublicKey {
        val sec = PGPSecretKeyRing(k.privateKeyData, BcKeyFingerprintCalculator())
        val sk = sec.secretKey
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, sk.extractPrivateKey(null))
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date())
            setPrimaryUserID(false, true)
        }.generate())
        val cert = g.generateCertification(uid, sk.publicKey)
        return PGPPublicKey.addCertification(sec.publicKey, uid, cert)
    }

    @Test
    fun `two User IDs both marked primary are reported`() {
        val k = svc.generateKeyPair("Bob", "bob@example.org", KeyAlgorithm.ED25519_CV25519, null)
        val primary = PGPPublicKeyRing(k.publicKeyData, BcKeyFingerprintCalculator()).publicKey
        val before = UserIdService.shared.primaryFlaggedLiveUserIds(primary)
        assertTrue(before.size <= 1)
        val two = withPrimaryUid(k, "Bob Work <bob@work.example>")
        val flagged = UserIdService.shared.primaryFlaggedLiveUserIds(two)
        assertTrue("Bob Work <bob@work.example>" in flagged)
        if (before.size == 1) assertEquals(2, flagged.size)
    }

    @Test
    fun `Make Primary clears every other primary flag`() {
        val k = svc.generateKeyPair("Carol", "carol@example.org", KeyAlgorithm.ED25519_CV25519, null)
        val sec = PGPSecretKeyRing(k.privateKeyData, BcKeyFingerprintCalculator())
        var pub = PGPPublicKeyRing(k.publicKeyData, BcKeyFingerprintCalculator())
        // Two extra User IDs, each self-certified with the primary flag.
        for (uid in listOf("Carol B <b@example.org>", "Carol C <c@example.org>")) {
            val sk = sec.secretKey
            val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey)
            g.init(PGPSignature.POSITIVE_CERTIFICATION, sk.extractPrivateKey(null))
            g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
                setSignatureCreationTime(false, Date()); setPrimaryUserID(false, true)
            }.generate())
            pub = PGPPublicKeyRing.insertPublicKey(pub,
                PGPPublicKey.addCertification(pub.publicKey, uid, g.generateCertification(uid, pub.publicKey)))
        }
        assertTrue(UserIdService.shared.primaryFlaggedLiveUserIds(pub.publicKey).size >= 2)
        val secRing = PGPSecretKeyRing.replacePublicKeys(sec, pub)
        Thread.sleep(1100) // new self-certifications must be newer than the old ones
        val fixed = UserIdService.shared.setPrimaryUserId(secRing, pub, "Carol B <b@example.org>", null)
        assertEquals(listOf("Carol B <b@example.org>"),
            UserIdService.shared.primaryFlaggedLiveUserIds(fixed.publicRing.publicKey))
    }

    private fun entity(uploaded: Boolean, uploadedAt: Long?, editedAt: Long?) = PGPKeyEntity(
        id = "x", fingerprint = "AA", userID = "A <a@b>", userName = "A", userEmail = "a@b",
        algorithm = KeyAlgorithm.ED25519_CV25519, isKeyPair = true, createdAt = 0L,
        keyServerUploaded = uploaded, lastUploadedAt = uploadedAt, lastLocalEditAt = editedAt
    )

    @Test
    fun `unpublished changes only for a published key edited after its upload`() {
        assertFalse(entity(uploaded = false, uploadedAt = null, editedAt = 5).hasUnpublishedChanges)
        assertFalse(entity(uploaded = true, uploadedAt = 10, editedAt = null).hasUnpublishedChanges)
        assertFalse(entity(uploaded = true, uploadedAt = 10, editedAt = 5).hasUnpublishedChanges)
        assertTrue(entity(uploaded = true, uploadedAt = 10, editedAt = 11).hasUnpublishedChanges)
        assertTrue("uploaded with no recorded date", entity(uploaded = true, uploadedAt = null, editedAt = 1).hasUnpublishedChanges)
    }
}
