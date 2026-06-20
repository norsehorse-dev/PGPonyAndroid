// IntegrityVerificationTest.kt — PGPonyCore
//
// Regression guard for the SEIPD integrity gate in PGPCryptoService.decrypt.
//
// THE BUG (fixed): decrypt() read the plaintext out of BouncyCastle's data
// stream but never called PGPEncryptedData.verify(), and never checked
// isIntegrityProtected(). BouncyCastle validates a SEIPDv1 message's trailing
// SHA-1 MDC ONLY on an explicit verify() after the stream is drained — so a
// tampered (CFB-malleable) ciphertext decrypted silently, and a legacy
// unprotected packet would have been accepted. This test proves the gate now
// fires: a clean message round-trips, and a message whose encrypted MDC was
// altered is rejected as IntegrityCheckFailed rather than returned as plaintext.
//
// Uses the passphrase (SKESK) path with armor = false, so the only integrity
// layer is the SEIPD MDC (no ASCII armor footer to absorb the tamper). The gate
// is shared by the public-key and card paths, which route the same verify().

package com.pgpony.android.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class IntegrityVerificationTest {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"

    @Test
    fun `clean SEIPDv1 message still round-trips`() {
        val plaintext = "attack at dawn"
        val ct = svc.encryptSymmetric(plaintext.toByteArray(), passphrase = pass, armor = false)
        val out = svc.decrypt(ct, secretKeyRings = emptyList(), passphrase = pass)
        assertEquals(plaintext, String(out.data))
    }

    @Test
    fun `tampered ciphertext is rejected, not returned as plaintext`() {
        val plaintext = "attack at dawn"
        // Binary SEIPDv1: the last ~22 bytes are the encrypted MDC packet
        // (0xD3 0x14 || 20-byte SHA-1). Flipping a byte 10 from the end lands
        // inside that hash, well clear of the SKESK/S2K header and the literal
        // packet framing — so the literal still parses, but verify() sees the
        // altered MDC and rejects.
        val ct = svc.encryptSymmetric(plaintext.toByteArray(), passphrase = pass, armor = false)
        val tampered = ct.copyOf()
        val pos = tampered.size - 10
        tampered[pos] = (tampered[pos].toInt() xor 0x01).toByte()

        try {
            val out = svc.decrypt(tampered, secretKeyRings = emptyList(), passphrase = pass)
            fail("tampered ciphertext must not decrypt silently; got ${out.data.size} bytes")
        } catch (e: PGPCryptoError.IntegrityCheckFailed) {
            // Expected: the integrity gate caught the altered MDC.
        }
    }
}
