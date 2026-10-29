// GnuPgX448InteropTest.kt
// PGPony Android, 4.7.3
//
// Vectors in /gnupg448 were made with GnuPG (2.5.21 and 2.4.4) from a
// throwaway LibrePGP v5 key, "X448 test <x448@example.invalid>": an Ed448
// primary and an X448 ECDH encryption subkey, no passphrase. gpg made the
// encrypted, signed and encrypted+signed messages and the detached and
// cleartext signatures over plain.txt. The other direction is checked with
// gpg by hand: the tests at the end write PGPony's output for this key to
// app/build/gnupg448-out for `gpg --decrypt` and `gpg --verify`.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.Security

class GnuPgX448InteropTest {

    private fun bytes(name: String): ByteArray =
        javaClass.getResourceAsStream("/gnupg448/$name")!!.readBytes()

    private fun text(name: String) = String(bytes(name), Charsets.UTF_8)

    private fun dearmor(name: String) = ArmoredInputStream(bytes(name).inputStream()).readBytes()

    private val pub by lazy { PGPPublicKeyRing(dearmor("x448-public.asc"), BcKeyFingerprintCalculator()) }
    private val sec by lazy { PGPSecretKeyRing(dearmor("x448-secret.asc"), BcKeyFingerprintCalculator()) }
    private val plain by lazy { bytes("plain.txt") }

    @Before
    fun setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Test
    fun theVectorsAreV5WithGnuPgsX448() {
        assertEquals(5, pub.publicKey.version)
        val enc = pub.publicKeys.asSequence().first { it.isEncryptionKey }
        assertEquals(5, enc.version)
        assertTrue(GnuPgX448.isGnuPgEncoded(enc.publicKeyPacket))
    }

    @Test
    fun decryptsAGnuPgMessage() {
        val r = PGPCryptoService.shared.decryptArmored(text("gpg-encrypted.asc"), listOf(sec), null)
        assertArrayEquals(plain, r.data)
    }

    @Test
    fun decryptsAndVerifiesAGnuPgSignedMessage() {
        val r = PGPCryptoService.shared.decryptArmored(text("gpg-signed-encrypted.asc"), listOf(sec), null, listOf(pub))
        assertArrayEquals(plain, r.data)
        assertEquals(SignerStatus.VERIFIED, r.signerStatus)
    }

    @Test
    fun verifiesAGnuPgDetachedSignature() {
        val r = VerifyService.shared.verifyDetached(text("plain.txt.asc"), plain, listOf(pub))
        assertTrue("$r", r is VerificationResult.Verified)
    }

    @Test
    fun rejectsATamperedDetachedSignature() {
        val r = VerifyService.shared.verifyDetached(text("plain.txt.asc"), plain + 0x21, listOf(pub))
        assertTrue("$r", r !is VerificationResult.Verified)
    }

    @Test
    fun verifiesAGnuPgDetachedSignatureStreamed() {
        val sigBytes = dearmor("plain.txt.asc")
        val r = VerifyService.shared.verifyDetachedStream(sigBytes, plain.inputStream(), listOf(pub))
        assertTrue("$r", r is VerificationResult.Verified)
    }

    @Test
    fun verifiesAGnuPgCleartextSignature() {
        val r = VerifyService.shared.verifyClearSigned(text("clearsigned.asc"), listOf(pub))
        assertTrue("$r", r is VerificationResult.Verified)
    }

    @Test
    fun theSecretKeyProvesItsPublicKey() {
        val match = SecretKeyCheck.checkSecretForPublic(bytes("x448-secret.asc"), bytes("x448-public.asc"))
        assertEquals(SecretKeyCheck.SecretMatch.OK, match)
    }

    // PGPony's side: v5 signatures and X448 encryption that GnuPG must accept.

    private fun out(name: String, data: ByteArray) {
        val dir = File("build/gnupg448-out").apply { mkdirs() }
        File(dir, name).writeBytes(data)
    }

    @Test
    fun signsDetachedWithAV5Key() {
        val sig = SigningService.shared.signDetached(plain, sec)
        out("pgpony-detached.asc", sig)
        val r = VerifyService.shared.verifyDetached(String(sig, Charsets.UTF_8), plain, listOf(pub))
        assertTrue("$r", r is VerificationResult.Verified)
    }

    @Test
    fun signsCleartextWithAV5Key() {
        val signed = SigningService.shared.signClear("gpg to pgpony\n", sec)
        out("pgpony-clearsigned.asc", signed.toByteArray())
        val r = VerifyService.shared.verifyClearSigned(signed, listOf(pub))
        assertTrue("$r", r is VerificationResult.Verified)
    }

    @Test
    fun encryptsAndSignsWithAV5Key() {
        val msg = PGPCryptoService.shared.encrypt(
            data = plain, recipientPublicKeys = listOf(pub), signingSecretKey = sec, passphrase = "", armor = true
        )
        out("pgpony-signed-encrypted.asc", msg)
        val r = PGPCryptoService.shared.decryptArmored(String(msg, Charsets.UTF_8), listOf(sec), null, listOf(pub))
        assertArrayEquals(plain, r.data)
        assertEquals(SignerStatus.VERIFIED, r.signerStatus)
    }

    @Test
    fun signsInlineWithAV5Key() {
        val msg = PGPCryptoService.shared.sign(plain, sec, "", detached = false, armor = true)
        out("pgpony-inline-signed.asc", msg)
    }
}
