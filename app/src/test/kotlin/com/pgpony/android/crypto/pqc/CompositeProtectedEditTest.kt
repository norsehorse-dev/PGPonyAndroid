// CompositeProtectedEditTest.kt
// PGPony Android 4.6.3 (item 20): Add User ID and Revoke Subkey on a
// passphrase-protected composite ML-DSA key. Both edits copy the secret packet
// through still protected, so KeyRepository must re-protect with the user's
// passphrase as the OLD one too. With a null old passphrase reprotect threw
// ProtectedKeyException, so both edits always failed on a protected key.
// These run the same sequence KeyRepository.addUserIdEdit / revokeSubkeyEdit do.

package com.pgpony.android.crypto.pqc

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CompositeProtectedEditTest {

    private val pass = "edit-pass".toCharArray()

    private fun protectedKey(): ByteArray =
        CompositeKeyFacade.reprotect(
            CompositePrimaryKeyGen.assemble("Edit <edit@pgpony.app>", CompositeSignSuite.MLDSA65_ED25519),
            null, pass
        )

    private fun assertStillProtectedWithTheSamePassphrase(ring: ByteArray) {
        assertTrue(CompositeKeyFacade.isProtected(ring))
        assertNull(CompositeKeyFacade.parse(ring).encryptionSubkey?.secretMaterial)
        assertNotNull(CompositeKeyFacade.parse(ring, pass).encryptionSubkey?.secretMaterial)
    }

    @Test
    fun addUserId_onAProtectedKey_succeedsAndStaysProtected() {
        val updated = CompositePrimaryKeyGen.addUserId(protectedKey(), "Second <second@pgpony.app>", pass)
        val restored = CompositeKeyFacade.reprotect(updated, pass, pass)
        assertStillProtectedWithTheSamePassphrase(restored)
        assertTrue(CompositeKeyFacade.publicRingOf(restored).isNotEmpty())
    }

    @Test
    fun revokeSubkey_onAProtectedKey_succeedsAndStaysProtected() {
        val ring = protectedKey()
        val subFp = CompositeKeyFacade.parse(ring).encryptionSubkey!!.fingerprint
        val updated = CompositePrimaryKeyGen.revokeSubkey(ring, subFp, reasonCode = 3, reasonText = "retired", passphrase = pass)
        val restored = CompositeKeyFacade.reprotect(updated, pass, pass)
        assertStillProtectedWithTheSamePassphrase(restored)
    }

    @Test
    fun theOldNullOldPassphrase_isWhatFailed() {
        val updated = CompositePrimaryKeyGen.addUserId(protectedKey(), "Second <second@pgpony.app>", pass)
        try {
            CompositeKeyFacade.reprotect(updated, null, pass)
            fail("reprotect with a null old passphrase on a protected ring must throw")
        } catch (e: CompositeSecretProtection.ProtectedKeyException) {
            // the 4.6.1 / 4.6.2 failure
        }
    }

    @Test
    fun anUnprotectedKey_acceptsThePassphraseAsOldAndNew() {
        val raw = CompositePrimaryKeyGen.assemble("Edit <edit@pgpony.app>", CompositeSignSuite.MLDSA65_ED25519)
        val updated = CompositePrimaryKeyGen.addUserId(raw, "Second <second@pgpony.app>", null)
        assertNotNull(CompositeKeyFacade.parse(CompositeKeyFacade.reprotect(updated, pass, pass), pass)
            .encryptionSubkey?.secretMaterial)
    }
}
