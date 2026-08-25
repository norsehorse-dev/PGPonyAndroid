// CompositeKeyPassphraseTest.kt
// PGPony Android, 4.4.0 RC4 (#26 composite passphrase protection)
//
// Ties CompositeSecretProtection to the real composite key: a protected primary
// must parse locked without a passphrase, unlock and SIGN + VERIFY with one,
// reject a wrong one, and round-trip through set / change / remove.

package com.pgpony.android.crypto.pqc

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CompositeKeyPassphraseTest {

    private val suite = CompositeSignSuite.MLDSA65_ED25519

    private fun freshRaw(): ByteArray =
        CompositePrimaryKeyGen.assemble("Locked <locked@pgpony.app>", suite)

    private fun signsAndVerifies(info: CompositeKeyFacade.Info): Boolean {
        val data = "protected composite signature".toByteArray()
        val sig = CompositeDocumentSigner.signDetached(
            info.suite, info.compositeSecret!!, info.fingerprint, data
        )
        return CompositeDocumentVerifier.verifyDetached(info.compositePublic, sig, data).valid
    }

    @Test
    fun `a protected key is locked without a passphrase and signs with one`() {
        val protectedRaw = CompositeKeyFacade.reprotect(freshRaw(), null, "s3cret".toCharArray())

        assertTrue("must report protected", CompositeKeyFacade.isProtected(protectedRaw))
        assertNull(
            "no passphrase must leave the signing secret locked",
            CompositeKeyFacade.parse(protectedRaw).compositeSecret
        )

        val unlocked = CompositeKeyFacade.parse(protectedRaw, "s3cret".toCharArray())
        assertNotNull("the right passphrase must recover the signing secret", unlocked.compositeSecret)
        assertTrue("the unlocked key must sign and verify", signsAndVerifies(unlocked))
    }

    @Test
    fun `a wrong passphrase throws`() {
        val protectedRaw = CompositeKeyFacade.reprotect(freshRaw(), null, "right".toCharArray())
        try {
            CompositeKeyFacade.parse(protectedRaw, "wrong".toCharArray()).compositeSecret
            fail("a wrong passphrase must throw")
        } catch (expected: Exception) {
            // AEAD tag mismatch — pass.
        }
    }

    @Test
    fun `set change and remove round-trip`() {
        val raw = freshRaw()
        assertFalse("fresh key is unprotected", CompositeKeyFacade.isProtected(raw))

        val set = CompositeKeyFacade.reprotect(raw, null, "one".toCharArray())
        assertTrue(signsAndVerifies(CompositeKeyFacade.parse(set, "one".toCharArray())))

        val changed = CompositeKeyFacade.reprotect(set, "one".toCharArray(), "two".toCharArray())
        assertTrue(signsAndVerifies(CompositeKeyFacade.parse(changed, "two".toCharArray())))
        try {
            CompositeKeyFacade.parse(changed, "one".toCharArray()).compositeSecret
            fail("the old passphrase must no longer work")
        } catch (expected: Exception) {
        }

        val removed = CompositeKeyFacade.reprotect(changed, "two".toCharArray(), null)
        assertFalse("removal must clear protection", CompositeKeyFacade.isProtected(removed))
        assertTrue(signsAndVerifies(CompositeKeyFacade.parse(removed)))
    }
}
