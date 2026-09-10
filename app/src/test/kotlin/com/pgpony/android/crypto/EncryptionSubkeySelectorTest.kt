// EncryptionSubkeySelectorTest.kt
// PGPony Android — 4.5.0 (item 13 / #36): subkey selector for encrypt.
//
// A key with more than one encryption-capable subkey (e.g. a composite ML-KEM
// key that also carries a standalone X25519) can be addressed under a chosen
// subkey. encryptionKeyOptions enumerates the choices (first = automatic pick);
// encrypt(recipientSubkeyChoices=...) targets one. Confirmed by which secret
// subkey actually unwraps the session key on decrypt.

package com.pgpony.android.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptionSubkeySelectorTest {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"

    @Test
    fun `a classical key exposes a single non-PQ encryption option`() {
        val pub = svc.importKeyData(
            svc.generateKeyPair("C", "c@example.test", KeyAlgorithm.ED25519_CV25519, pass).publicKeyData
        ).publicKeyRing!!
        val options = svc.encryptionKeyOptions(pub)
        assertEquals("one encryption target", 1, options.size)
        assertFalse("classical, not post-quantum", options[0].isPostQuantum)
    }

    @Test
    fun `a composite key lists the PQ subkey first and the classical one too`() {
        val pub = svc.importKeyData(
            svc.generateKeyPair("P", "p@example.test", KeyAlgorithm.MLKEM768_X25519_V6, pass).publicKeyData
        ).publicKeyRing!!
        val options = svc.encryptionKeyOptions(pub)
        assertTrue("composite key has 2+ encryption targets", options.size >= 2)
        assertTrue("the automatic pick is the post-quantum subkey", options.first().isPostQuantum)
        assertTrue("a classical target is also present", options.any { !it.isPostQuantum })
    }

    @Test
    fun `choosing a subkey changes which one wraps the session key`() {
        val gen = svc.generateKeyPair("P", "p@example.test", KeyAlgorithm.MLKEM768_X25519_V6, pass)
        val pub = svc.importKeyData(gen.publicKeyData).publicKeyRing!!
        val sec = listOf(svc.importKeyData(gen.privateKeyData).secretKeyRing!!)
        val fpHex = svc.fingerprintHex(pub.publicKey)

        val options = svc.encryptionKeyOptions(pub)
        val classical = options.first { !it.isPostQuantum }

        // Default: the composite (PQ) subkey wraps it. The composite decrypt path
        // does not report a recipient key id, so decryptingKeyIdRaw is null.
        val ctDefault = svc.encrypt("hi".toByteArray(), listOf(pub), armor = false)
        assertNull(
            "the automatic pick is the composite subkey (no reported recipient id)",
            svc.decrypt(ctDefault, sec, pass).decryptingKeyIdRaw
        )

        // Forced classical choice: the standalone X25519 subkey wraps it, and the
        // classical decrypt path reports that subkey's id.
        val ctChosen = svc.encrypt(
            "hi".toByteArray(), listOf(pub), armor = false,
            recipientSubkeyChoices = mapOf(fpHex to classical.keyId)
        )
        assertEquals(
            "the chosen classical subkey unwrapped the message",
            classical.keyId,
            svc.decrypt(ctChosen, sec, pass).decryptingKeyIdRaw
        )
    }
}
