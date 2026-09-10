// MixedRecipientPqTest.kt
// PGPony Android — 4.5.0 (item 2 / #36): mixed-recipient post-quantum warning.
//
// OpenPGP wraps one session key per recipient, so a message is post-quantum
// confidential only if EVERY recipient has a PQ encryption key. The classifier
// PGPCryptoService.isPostQuantumRecipient decides, per recipient, whether the
// key PGPony would encrypt to is a composite ML-KEM method; the UI warns when a
// set mixes PQ and classical recipients.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MixedRecipientPqTest {

    private val svc = PGPCryptoService.shared

    private fun pubRing(algorithm: KeyAlgorithm): PGPPublicKeyRing =
        svc.importKeyData(
            svc.generateKeyPair(
                name = "R", email = "r@example.test",
                algorithm = algorithm, passphrase = null
            ).publicKeyData
        ).publicKeyRing!!

    // The mixed-set rule the UI applies over the classifier.
    private fun isMixed(rings: List<PGPPublicKeyRing>): Boolean {
        val pq = rings.count { svc.isPostQuantumRecipient(it) }
        return pq in 1 until rings.size
    }

    @Test
    fun `a composite ML-KEM recipient is post-quantum`() {
        assertTrue(svc.isPostQuantumRecipient(pubRing(KeyAlgorithm.MLKEM768_X25519_V6)))
    }

    @Test
    fun `a classical Ed25519 CV25519 recipient is not post-quantum`() {
        assertFalse(svc.isPostQuantumRecipient(pubRing(KeyAlgorithm.ED25519_CV25519)))
    }

    @Test
    fun `a mixed set is flagged and a uniform set is not`() {
        val pq = pubRing(KeyAlgorithm.MLKEM768_X25519_V6)
        val classical = pubRing(KeyAlgorithm.ED25519_CV25519)

        assertTrue("PQ + classical is a mixed downgrade set", isMixed(listOf(pq, classical)))
        assertFalse("all-PQ set is clean", isMixed(listOf(pq, pubRing(KeyAlgorithm.MLKEM768_X25519_V6))))
        assertFalse("all-classical set is not a mix (no PQ to downgrade)", isMixed(listOf(classical)))
    }
}
