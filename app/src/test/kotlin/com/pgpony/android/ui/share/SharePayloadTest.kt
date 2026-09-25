// SharePayloadTest.kt
// PGPony Android, 4.6.0 (item 6)
//
// The Quick Action splits shared text into what it holds, so each part gets
// the action that fits: import a key, decrypt, verify, or encrypt the rest.

package com.pgpony.android.ui.share

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SigningService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SharePayloadTest {

    private val svc = PGPCryptoService.shared
    private val k by lazy { svc.generateKeyPair("Share", "share@example.org", KeyAlgorithm.ED25519_CV25519, null) }
    private val pub by lazy { PGPPublicKeyRing(k.publicKeyData, BcKeyFingerprintCalculator()) }
    private val sec by lazy { PGPSecretKeyRing(k.privateKeyData, BcKeyFingerprintCalculator()) }

    @Test
    fun `plain text has no PGP part`() {
        val p = SharePayload.of("Lunch at noon?")
        assertFalse(p.hasPgp)
        assertEquals("Lunch at noon?", p.otherText)
    }

    @Test
    fun `a key inside an email body is found, with the body as other text`() {
        val armored = svc.exportArmoredPublicKey(pub)
        val p = SharePayload.of("Hi, here is my key:\n\n$armored\n\nThanks")
        assertTrue(p.publicKey!!.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        assertTrue(p.otherText!!.contains("Hi, here is my key:"))
        assertTrue(p.otherText!!.contains("Thanks"))
        assertNull(p.encrypted); assertNull(p.signed)
    }

    @Test
    fun `an encrypted message goes to decrypt, and alone has no other text`() {
        val ct = String(svc.encrypt("secret".toByteArray(), listOf(pub)))
        val p = SharePayload.of(ct)
        assertNotNull(p.encrypted)
        assertNull(p.signed)
        assertNull(p.otherText)
    }

    @Test
    fun `a cleartext-signed and an inline-signed message go to verify`() {
        val clear = SigningService.shared.signClear("hello", sec, null)
        assertNotNull(SharePayload.of(clear).signed)
        assertNull(SharePayload.of(clear).encrypted)
        val text = String(svc.sign("hello".toByteArray(), sec, ""))
        assertTrue(text.contains("BEGIN PGP MESSAGE"))
        val p = SharePayload.of(text)
        assertNotNull("inline-signed, not encrypted", p.signed)
        assertNull(p.encrypted)
    }

    @Test
    fun `a private key block is offered for import, not as text to encrypt`() {
        val p = SharePayload.of(k.armoredPrivateKey)
        assertNotNull(p.privateKey)
        assertTrue(p.privateKey!!.contains("BEGIN PGP PRIVATE KEY BLOCK"))
        assertNull(p.publicKey)
        assertTrue(p.hasPgp)
        assertNull(p.otherText)
    }
}
