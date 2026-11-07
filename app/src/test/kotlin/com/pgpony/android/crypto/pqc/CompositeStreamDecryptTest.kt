// CompositeStreamDecryptTest.kt
// PGPony Android, 4.1.2 (issue #33)
//
// Regression net for the bug where the composite (PQC) trial existed only
// in the buffered decrypt: a file encrypted to an ML-KEM key failed in
// decryptStream because BouncyCastle's PKESK parser throws on the unknown
// algorithm before any PGPony code runs. These tests drive the public
// decryptStream entry point end to end for both composite families and
// both armor states, plus the interchange a user actually crosses
// (encrypt buffered, decrypt streamed, and both streamed).
//
// Same strong-proof property as CompositeDecryptTest: the containers are
// AEAD or MDC checked, so a wrong session key fails the read rather than
// yielding wrong bytes quietly.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CompositeStreamDecryptTest {

    private val svc = PGPCryptoService.shared

    private fun pub(data: ByteArray) =
        PGPPublicKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun sec(data: ByteArray) =
        PGPSecretKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun newKey(algo: KeyAlgorithm, passphrase: String? = null) =
        svc.generateKeyPair("Streamer PQC", "pqc@pgpony.app", algo, passphrase, null)

    private fun decryptStreamed(
        ciphertext: ByteArray,
        rings: List<PGPSecretKeyRing>,
        passphrase: String? = null,
    ): Pair<ByteArray, com.pgpony.android.crypto.DecryptStreamResult> {
        val out = ByteArrayOutputStream()
        val result = svc.decryptStream(
            input = ByteArrayInputStream(ciphertext),
            output = out,
            secretKeyRings = rings,
            passphrase = passphrase,
        )
        return out.toByteArray() to result
    }

    private fun roundTrip(algo: KeyAlgorithm, armor: Boolean) {
        val k = newKey(algo)
        // Non-repeating and larger than one 64 KiB chunk, so truncation
        // or chunk duplication cannot hide behind compression.
        val plaintext = ByteArray(200_000) { (it * 31 + (it shr 8)).toByte() }
        val ct = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = armor
        )
        val (recovered, _) = decryptStreamed(ct, listOf(sec(k.privateKeyData)))
        assertArrayEquals(plaintext, recovered)
    }

    @Test
    fun `v6 composite file decrypts through the stream, binary`() =
        roundTrip(KeyAlgorithm.MLKEM768_X25519_V6, armor = false)

    @Test
    fun `v6 composite file decrypts through the stream, armored`() =
        roundTrip(KeyAlgorithm.MLKEM768_X25519_V6, armor = true)

    @Test
    fun `v5 LibrePGP composite file decrypts through the stream, binary`() =
        roundTrip(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, armor = false)

    @Test
    fun `v5 LibrePGP composite file decrypts through the stream, armored`() =
        roundTrip(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, armor = true)

    @Test
    fun `streamed composite encrypt decrypts through the stream`() {
        val k = newKey(KeyAlgorithm.MLKEM768_X25519_V6)
        val plaintext = "file both ways".toByteArray()
        val out = ByteArrayOutputStream()
        svc.encryptStream(
            input = ByteArrayInputStream(plaintext),
            output = out,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            filename = "notes.txt",
            armor = false,
            messagePassword = null,
        )
        val (recovered, result) = decryptStreamed(out.toByteArray(), listOf(sec(k.privateKeyData)))
        assertArrayEquals(plaintext, recovered)
        assertEquals("notes.txt", result.filename)
    }

    @Test
    fun `v6 composite large message decrypts through the buffer too`() {
        // The first run of this file exposed a second bug: split() parsed
        // the SEIPD's length before deciding it was the body, so the
        // partial-length framing BC emits past its 4 KiB buffer read as
        // "no composite PKESK" and the buffered text path failed on any
        // large composite message. This holds the line on that.
        val k = newKey(KeyAlgorithm.MLKEM768_X25519_V6)
        val plaintext = ByteArray(200_000) { (it * 31 + (it shr 8)).toByte() }
        val ct = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        val result = svc.decrypt(ct, secretKeyRings = listOf(sec(k.privateKeyData)), passphrase = null)
        assertArrayEquals(plaintext, result.data)
    }

    @Test
    fun `v5 LibrePGP large message decrypts through the buffer too`() {
        val k = newKey(KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
        val plaintext = ByteArray(200_000) { (it * 31 + (it shr 8)).toByte() }
        val ct = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        val result = svc.decrypt(ct, secretKeyRings = listOf(sec(k.privateKeyData)), passphrase = null)
        assertArrayEquals(plaintext, result.data)
    }

    @Test
    fun `classical key still streams untouched by the sniff`() {
        val k = newKey(KeyAlgorithm.ED25519_CV25519)
        val plaintext = ByteArray(150_000) { (it * 17).toByte() }
        val ct = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        val (recovered, _) = decryptStreamed(ct, listOf(sec(k.privateKeyData)))
        assertArrayEquals(plaintext, recovered)
    }

    // ── 4.2.0 workstream A: session-key handoff ──────────────────────
    //
    // The streaming path recovers the session key from the leading ESK
    // packets alone and never buffers the body. These prove the recovery
    // half in isolation: strip a real ciphertext to its ESK prefix and
    // recover from that region only. The end-to-end proof stays with the
    // round-trip tests above (which now exercise the handoff path) and the
    // on-device large-file check, which JVM heap cannot honestly assert.

    private fun eskRegionOf(ciphertext: ByteArray): ByteArray {
        var i = 0
        val out = ByteArrayOutputStream()
        while (i < ciphertext.size) {
            val first = ciphertext[i].toInt() and 0xFF
            if (first and 0x80 == 0) break
            val tag = if (first and 0x40 != 0) first and 0x3F else (first shr 2) and 0x0F
            if (tag != 1 && tag != 3) break
            var j = i + 1
            val bodyLen: Int
            if (first and 0x40 != 0) {
                val l0 = ciphertext[j++].toInt() and 0xFF
                bodyLen = when {
                    l0 < 192 -> l0
                    l0 < 224 -> ((l0 - 192) shl 8) + (ciphertext[j++].toInt() and 0xFF) + 192
                    else -> {
                        var v = 0
                        repeat(4) { v = (v shl 8) or (ciphertext[j++].toInt() and 0xFF) }
                        v
                    }
                }
            } else {
                bodyLen = when (first and 0x03) {
                    0 -> ciphertext[j++].toInt() and 0xFF
                    1 -> (((ciphertext[j].toInt() and 0xFF) shl 8) or
                        (ciphertext[j + 1].toInt() and 0xFF)).also { j += 2 }
                    else -> {
                        var v = 0
                        repeat(4) { v = (v shl 8) or (ciphertext[j++].toInt() and 0xFF) }
                        v
                    }
                }
            }
            out.write(ciphertext, i, (j - i) + bodyLen)
            i = j + bodyLen
        }
        return out.toByteArray()
    }

    @Test
    fun `session key recovers from the ESK region alone, v6 composite`() {
        val k = newKey(KeyAlgorithm.MLKEM768_X25519_V6)
        val ct = svc.encrypt(
            data = "handoff".toByteArray(),
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        val esk = eskRegionOf(ct)
        assertTrue("ESK region must be a proper prefix", esk.isNotEmpty() && esk.size < ct.size)
        val session = CompositeDecryptor.recoverSessionKey(esk, listOf(sec(k.privateKeyData)))
        assertNotNull("v6 session key must recover without the body", session)
    }

    @Test
    fun `session key recovers from the ESK region alone, v5 LibrePGP`() {
        val k = newKey(KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
        val ct = svc.encrypt(
            data = "handoff".toByteArray(),
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        val esk = eskRegionOf(ct)
        assertTrue("ESK region must be a proper prefix", esk.isNotEmpty() && esk.size < ct.size)
        val session = CompositeLibrePGPDecryptor.recoverSessionKey(esk, listOf(sec(k.privateKeyData)))
        assertNotNull("v5 session key must recover without the body", session)
    }

    @Test
    fun `classical ESK region recovers nothing from either composite path`() {
        val k = newKey(KeyAlgorithm.ED25519_CV25519)
        val ct = svc.encrypt(
            data = "classical".toByteArray(),
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        val esk = eskRegionOf(ct)
        assertTrue(esk.isNotEmpty())
        assertNull(CompositeDecryptor.recoverSessionKey(esk, listOf(sec(k.privateKeyData))))
        assertNull(CompositeLibrePGPDecryptor.recoverSessionKey(esk, listOf(sec(k.privateKeyData))))
    }

    // 4.8.0 RC5: the OpenPGP provider decrypts through the stream. A locked
    // composite key has to come out as PassphraseRequired there, as it does in
    // the buffered decrypt, or Thunderbird shows "Decryption failed: composite
    // secret key is passphrase-protected" and never offers the prompt.
    private fun lockedKeyAsks(algo: KeyAlgorithm) {
        val pass = "correct horse battery staple"
        val k = newKey(algo, pass)
        val plaintext = "locked composite".toByteArray()
        val ct = svc.encrypt(data = plaintext, recipientPublicKeys = listOf(pub(k.publicKeyData)), armor = true)
        val rings = listOf(sec(k.privateKeyData))
        try {
            decryptStreamed(ct, rings, passphrase = null)
            org.junit.Assert.fail("$algo: a locked key decrypted without a passphrase")
        } catch (e: com.pgpony.android.crypto.PGPCryptoError.PassphraseRequired) {
            // expected
        }
        val (recovered, _) = decryptStreamed(ct, rings, passphrase = pass)
        assertArrayEquals(plaintext, recovered)
    }

    @Test
    fun `a locked v6 composite key asks for the passphrase through the stream`() =
        lockedKeyAsks(KeyAlgorithm.MLKEM768_X25519_V6)

    @Test
    fun `a locked LibrePGP composite key asks for the passphrase through the stream`() =
        lockedKeyAsks(KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
}
