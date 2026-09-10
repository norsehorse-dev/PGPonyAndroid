// SubkeyRemoveTest.kt
// PGPony Android — 4.5.0 (item 16 / issue #54): local subkey remove (delete
// without revocation), classical and composite.
//
// Removing a subkey strips its packet from the stored key. Local only: it tells
// no correspondent. These tests confirm the subkey is gone and the primary and
// User IDs survive, for both a classical v4 key (BC removeSecretKey) and a
// composite ML-DSA primary (byte-splice).

package com.pgpony.android.crypto

import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositePrimaryKeyGen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SubkeyRemoveTest {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"

    @Test
    fun `classical remove strips the subkey and keeps the primary`() {
        val secRing = svc.importKeyData(
            svc.generateKeyPair(
                name = "Remover",
                email = "remove@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519,
                passphrase = pass
            ).privateKeyData
        ).secretKeyRing!!

        val primaryId = secRing.secretKey.keyID
        val subkeyId = secRing.publicKeys.asSequence().first { !it.isMasterKey }.keyID
        val before = secRing.publicKeys.asSequence().count()

        val updated = ClassicalSubkeyGen.removeSubkey(secRing, subkeyId)

        assertNull("the removed subkey must be gone", updated.getSecretKey(subkeyId))
        assertNotNull("the primary must survive", updated.getSecretKey(primaryId))
        assertEquals("exactly one key removed", before - 1, updated.publicKeys.asSequence().count())
    }

    @Test
    fun `classical remove refuses the primary`() {
        val secRing = svc.importKeyData(
            svc.generateKeyPair(
                name = "Remover",
                email = "remove@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519,
                passphrase = pass
            ).privateKeyData
        ).secretKeyRing!!
        assertThrows(ClassicalSubkeyGen.SubkeyAddError::class.java) {
            ClassicalSubkeyGen.removeSubkey(secRing, secRing.secretKey.keyID)
        }
    }

    @Test
    fun `composite remove strips the ML-KEM subkey and keeps the primary and User IDs`() {
        val ring = CompositePrimaryKeyGen.assemble("Composite Remover <cr@pgpony.app>")
        val before = CompositeKeyFacade.parse(ring)
        val subFp = before.encryptionSubkey!!.fingerprint

        val removed = CompositePrimaryKeyGen.removeSubkey(ring, subFp)
        val after = CompositeKeyFacade.parse(removed)

        assertNull("the encryption subkey must be gone", after.encryptionSubkey)
        assertEquals("User IDs must survive", before.userIds, after.userIds)
        assertNotNull("the primary secret must survive", after.compositeSecret)
    }

    @Test
    fun `composite remove refuses an unknown subkey`() {
        val ring = CompositePrimaryKeyGen.assemble("Composite Remover <cr@pgpony.app>")
        assertThrows(IllegalArgumentException::class.java) {
            CompositePrimaryKeyGen.removeSubkey(ring, ByteArray(32) { 0x11 })
        }
    }
}
