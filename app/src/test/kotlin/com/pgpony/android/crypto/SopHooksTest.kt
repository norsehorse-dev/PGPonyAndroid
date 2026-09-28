// SopHooksTest.kt
// PGPony Android, 4.7.0 (#64): the engine hooks the Stateless OpenPGP wrapper needs. A canonical
// text signature (type 0x01) from SigningService and from the inline signer, and every signature
// packet of a signed message handed back on the decrypt result, so a caller can report each one.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SopHooksTest {

    private val svc = PGPCryptoService.shared

    private fun gen(email: String) = svc.generateKeyPair("Sop", email, KeyAlgorithm.ED25519_CV25519, null)

    private fun parse(sig: ByteArray): PGPSignature {
        val input = if (String(sig.copyOf(minOf(sig.size, 40)), Charsets.US_ASCII).contains("-----BEGIN"))
            ArmoredInputStream(sig.inputStream()) else sig.inputStream()
        return (JcaPGPObjectFactory(input).nextObject() as PGPSignatureList)[0]
    }

    @Test
    fun `a text signature is type 1 and covers either line ending`() {
        val key = gen("text@example.test")
        val ring = svc.importKeyData(key.privateKeyData).secretKeyRing!!
        val pub = svc.importKeyData(key.publicKeyData).publicKeyRing!!
        val sig = SigningService.shared.signDetached("one\ntwo\n".toByteArray(), ring, textMode = true)
        assertEquals(PGPSignature.CANONICAL_TEXT_DOCUMENT, parse(sig).signatureType)
        for (variant in listOf("one\ntwo\n", "one\r\ntwo\r\n")) {
            val r = VerifyService.shared.verifyDetached(sig, variant.toByteArray(), listOf(pub))
            assertTrue("$variant: $r", r is VerificationResult.Verified)
        }
        val binary = SigningService.shared.signDetached("x".toByteArray(), ring)
        assertEquals(PGPSignature.BINARY_DOCUMENT, parse(binary).signatureType)
    }

    @Test
    fun `a signed message returns each signature packet`() {
        val key = gen("inline@example.test")
        val ring = svc.importKeyData(key.privateKeyData).secretKeyRing!!
        val pub = svc.importKeyData(key.publicKeyData).publicKeyRing!!
        val message = svc.sign("hello\n".toByteArray(), ring, "", detached = false, armor = true, textMode = true)
        val result = svc.decrypt(message, emptyList(), null, listOf(pub))
        assertEquals(1, result.signaturePackets.size)
        val packet = result.signaturePackets.single()
        assertEquals(PGPSignature.CANONICAL_TEXT_DOCUMENT, parse(packet).signatureType)
        val r = VerifyService.shared.verifyDetached(packet, result.data, listOf(pub))
        assertTrue("$r", r is VerificationResult.Verified)
    }

    @Test
    fun `an encrypted and signed message returns its signature packet`() {
        val alice = gen("alice@example.test")
        val bob = gen("bob@example.test")
        val aliceSecret = svc.importKeyData(alice.privateKeyData).secretKeyRing!!
        val alicePub = svc.importKeyData(alice.publicKeyData).publicKeyRing!!
        val bobSecret = svc.importKeyData(bob.privateKeyData).secretKeyRing!!
        val bobPub = svc.importKeyData(bob.publicKeyData).publicKeyRing!!
        val ct = svc.encrypt("to bob".toByteArray(), listOf(bobPub), aliceSecret, null)
        val result = svc.decrypt(ct, listOf(bobSecret), null, listOf(alicePub))
        assertEquals("to bob", String(result.data))
        assertEquals(1, result.signaturePackets.size)
        val r = VerifyService.shared.verifyDetached(result.signaturePackets.single(), result.data, listOf(alicePub))
        assertTrue("$r", r is VerificationResult.Verified)
    }
}
