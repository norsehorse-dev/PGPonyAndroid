// TextSignatureLiteralTest.kt
// PGPony Android, 4.8.0 (item 4e): an inline text signature stores its literal
// data in canonical CR LF form.
//
// GnuPG hashes the literal data of an inline text signature as stored, so text
// written with LF line ends and hashed as CR LF was a BAD signature in gpg 2.4
// and 2.5. PGPony read its own messages because Bouncy Castle converts on the
// reading side as well.

package com.pgpony.android.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TextSignatureLiteralTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `the literal data of an inline text signature is CR LF and verifies`() {
        val key = svc.generateKeyPair("Text", "text@example.test", KeyAlgorithm.ED25519_CV25519, passphrase = null)
        val ring = svc.importKeyData(key.privateKeyData).secretKeyRing!!
        val pub = svc.importKeyData(key.publicKeyData).publicKeyRing!!

        val message = svc.sign("one\ntwo\r\nthree\rfour\n".toByteArray(), ring, "", detached = false, armor = true, textMode = true)
        val result = svc.decrypt(message, emptyList(), null, listOf(pub))

        assertArrayEquals(
            "stored in canonical form",
            "one\r\ntwo\r\nthree\r\nfour\r\n".toByteArray(),
            result.data
        )
        assertTrue("verifies", result.signatureVerified)
    }

    @Test
    fun `a binary inline signature keeps its data as given`() {
        val key = svc.generateKeyPair("Bin", "bin@example.test", KeyAlgorithm.ED25519_CV25519, passphrase = null)
        val ring = svc.importKeyData(key.privateKeyData).secretKeyRing!!
        val pub = svc.importKeyData(key.publicKeyData).publicKeyRing!!

        val data = "one\ntwo\n".toByteArray()
        val result = svc.decrypt(svc.sign(data, ring, "", detached = false, armor = true), emptyList(), null, listOf(pub))
        assertArrayEquals(data, result.data)
        assertTrue(result.signatureVerified)
    }

    @Test
    fun `canonical form maps lone CR and LF and keeps CR LF`() {
        assertArrayEquals("a\r\nb\r\nc\r\n\r\n".toByteArray(), TextCanonical.crlf("a\nb\r\nc\r\n\r".toByteArray()))
        assertArrayEquals(ByteArray(0), TextCanonical.crlf(ByteArray(0)))
    }
}
