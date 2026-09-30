// SymmetricEncryptionTest.kt
// PGPony Android — Phase A1 (symmetric / passphrase-only encryption, `gpg -c`)
//
// Verifies the new PGPCryptoService.encryptSymmetric / decrypt PBE branch
// against real BouncyCastle 1.84. Like V6EncryptionTest these assert
// behavior (round-trip, error typing, detection) rather than poking at raw
// SKESK/SEIPD packet bytes:
//
//   - Argon2id S2K + SEIPDv1 round-trips for text and file (the defaults).
//   - SEIPDv2 (AEAD/OCB) round-trips when useAead = true, and with Argon2
//     writes a v6 SKESK (3.0.0 5d-4).
//   - Iterated-salted S2K round-trips when useArgon2 = false (GnuPG 2.2.x
//     interop posture).
//   - Wrong passphrase surfaces as the typed InvalidPassphrase.
//   - A symmetric message decrypted with no passphrase surfaces as
//     PassphraseRequired (the UI's signal to show the password prompt).
//   - inspectEncryptedMessage distinguishes a `gpg -c` message
//     (isSymmetricOnly) from a public-key-addressed message.
//
// The companion init of PGPCryptoService installs the BouncyCastle provider,
// so no per-test Security.addProvider is needed.
//
// NOTE: real `gpg -c` <-> PGPony interop is an on-machine check (see
// PHASE_A1_NOTES.md §Test); these JVM tests prove the BC round-trip and the
// error/detection contracts the UI relies on.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream

class SymmetricEncryptionTest {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"

    private fun pub(data: ByteArray) =
        PGPPublicKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun sec(data: ByteArray) =
        PGPSecretKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    // ── Round-trips ────────────────────────────────────────────────────

    @Test
    fun `argon2 seipdv1 text round-trips`() {
        val plaintext = "the eagle has landed"
        val ct = svc.encryptSymmetric(plaintext.toByteArray(), passphrase = pass)
        val result = svc.decrypt(ct, secretKeyRings = emptyList(), passphrase = pass)
        assertEquals(plaintext, String(result.data))
    }

    @Test
    fun `armored message wrapper round-trips`() {
        val plaintext = "armored convenience wrapper"
        val armored = svc.encryptSymmetricMessage(plaintext, passphrase = pass)
        assertTrue(armored.startsWith("-----BEGIN PGP MESSAGE-----"))
        val result = svc.decryptArmored(armored, secretKeyRings = emptyList(), passphrase = pass)
        assertEquals(plaintext, String(result.data))
    }

    @Test
    fun `binary file payload round-trips byte-for-byte`() {
        // Non-UTF-8 bytes prove the file path doesn't stringify the payload.
        val bytes = ByteArray(2048) { (it * 31 + 7).toByte() }
        val ct = svc.encryptSymmetric(bytes, passphrase = pass, filename = "secret.bin")
        val result = svc.decrypt(ct, secretKeyRings = emptyList(), passphrase = pass)
        assertTrue(bytes.contentEquals(result.data))
        assertEquals("secret.bin", result.filename)
    }

    @Test
    fun `seipdv2 aead round-trips`() {
        // 3.0.0 (5d-4): this path used to fail with a null SecureRandom inside
        // the PBE method generator (a v6 SKESK draws its AEAD IV from it) and
        // the test skipped itself. The generator now gets its own random.
        val plaintext = "aead ocb container"
        val ct = svc.encryptSymmetric(plaintext.toByteArray(), passphrase = pass, useAead = true)
        val result = svc.decrypt(ct, secretKeyRings = emptyList(), passphrase = pass)
        assertEquals(plaintext, String(result.data))
    }

    @Test
    fun `argon2 with aead writes a v6 skesk and round-trips`() {
        // The SOP rfc9580 password profile: SKESKv6 (Argon2 S2K) + SEIPDv2.
        val plaintext = "rfc9580 password profile"
        val ct = svc.encryptSymmetric(plaintext.toByteArray(), passphrase = pass, armor = false, useAead = true, useArgon2 = true)
        // New-format packet tag 3 (SKESK), one-octet length, then version 6.
        assertEquals(0xC3, ct[0].toInt() and 0xFF)
        assertEquals(6, ct[2].toInt())
        // S2K type 4 (Argon2) after version, count, cipher, AEAD mode, S2K length.
        assertEquals(4, ct[7].toInt())
        val result = svc.decrypt(ct, secretKeyRings = emptyList(), passphrase = pass)
        assertEquals(plaintext, String(result.data))
    }

    @Test
    fun `iterated-salted s2k round-trips`() {
        val plaintext = "classic s2k for old gpg"
        val ct = svc.encryptSymmetric(plaintext.toByteArray(), passphrase = pass, useArgon2 = false)
        val result = svc.decrypt(ct, secretKeyRings = emptyList(), passphrase = pass)
        assertEquals(plaintext, String(result.data))
    }

    @Test
    fun `binary (non-armored) output round-trips`() {
        val plaintext = "no armor"
        val ct = svc.encryptSymmetric(plaintext.toByteArray(), passphrase = pass, armor = false)
        val result = svc.decrypt(ct, secretKeyRings = emptyList(), passphrase = pass)
        assertEquals(plaintext, String(result.data))
    }

    // ── Error contracts ────────────────────────────────────────────────

    @Test
    fun `wrong passphrase throws InvalidPassphrase`() {
        val ct = svc.encryptSymmetric("secret".toByteArray(), passphrase = pass)
        try {
            svc.decrypt(ct, secretKeyRings = emptyList(), passphrase = "wrong passphrase")
            fail("expected InvalidPassphrase")
        } catch (e: PGPCryptoError.InvalidPassphrase) {
            // expected
        }
    }

    @Test
    fun `missing passphrase on symmetric message throws PassphraseRequired`() {
        val ct = svc.encryptSymmetric("secret".toByteArray(), passphrase = pass)
        try {
            svc.decrypt(ct, secretKeyRings = emptyList(), passphrase = null)
            fail("expected PassphraseRequired")
        } catch (e: PGPCryptoError.PassphraseRequired) {
            // expected — this is the UI's cue to prompt for the password
        }
    }

    @Test
    fun `empty passphrase on encrypt is rejected`() {
        try {
            svc.encryptSymmetric("x".toByteArray(), passphrase = "")
            fail("expected EncryptionFailed")
        } catch (e: PGPCryptoError.EncryptionFailed) {
            // expected
        }
    }

    // ── Detection (inspectEncryptedMessage) ────────────────────────────

    @Test
    fun `inspect reports symmetric-only for gpg -c style message`() {
        val ct = svc.encryptSymmetric("secret".toByteArray(), passphrase = pass)
        val info = svc.inspectEncryptedMessage(ct)
        assertTrue(info.isPasswordEncrypted)
        assertTrue(info.publicKeyIDs.isEmpty())
        assertTrue(info.isSymmetricOnly)
    }

    @Test
    fun `inspect reports public-key recipients for an addressed message`() {
        val k = svc.generateKeyPair(
            "Recipient", "r@pgpony.app", KeyAlgorithm.ED25519_CV25519, null, null
        )
        val ct = svc.encrypt(
            data = "addressed".toByteArray(),
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = true
        )
        val info = svc.inspectEncryptedMessage(ct)
        assertFalse(info.isPasswordEncrypted)
        assertFalse(info.isSymmetricOnly)
        assertTrue(info.publicKeyIDs.isNotEmpty())
    }
}
