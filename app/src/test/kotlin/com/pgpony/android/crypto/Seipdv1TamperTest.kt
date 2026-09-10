// Seipdv1TamperTest.kt
// PGPony Android — 4.5.0 (item 11 / Finding D): indistinguishable SEIPDv1
// decrypt errors.
//
// A SEIPDv1 (AES-CFB + MDC) message where the session-key quick-check fails
// must not surface a different error type than one where the trailing MDC
// fails; a distinguishable pair is a (weak) CFB decryption oracle. After the
// fix, any tamper in an addressed recipient's ciphertext collapses to one
// IntegrityCheckFailed, and a clean message still round-trips.

package com.pgpony.android.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class Seipdv1TamperTest {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"

    private fun freshPair(): Pair<List<org.bouncycastle.openpgp.PGPSecretKeyRing>, List<org.bouncycastle.openpgp.PGPPublicKeyRing>> {
        val gen = svc.generateKeyPair(
            name = "Tamper", email = "tamper@example.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = pass
        )
        val sec = svc.importKeyData(gen.privateKeyData).secretKeyRing!!
        val pub = svc.importKeyData(gen.publicKeyData).publicKeyRing!!
        return listOf(sec) to listOf(pub)
    }

    @Test
    fun `clean SEIPDv1 message round-trips`() {
        val (sec, pub) = freshPair()
        val plain = "hello world".toByteArray()
        val ct = svc.encrypt(plain, pub, armor = false) // v4 recipient -> SEIPDv1
        assertArrayEquals(plain, svc.decrypt(ct, sec, pass).data)
    }

    @Test
    fun `a tail tamper is an integrity failure, never NoMatchingKey`() {
        val (sec, pub) = freshPair()
        val ct = svc.encrypt("hello world".toByteArray(), pub, armor = false)
        // The trailing bytes are the MDC; corrupting them fails the integrity
        // check rather than the packet parse.
        val bad = ct.copyOf()
        bad[bad.size - 3] = (bad[bad.size - 3].toInt() xor 0xFF).toByte()
        assertThrows(
            PGPCryptoError.IntegrityCheckFailed::class.java
        ) { svc.decrypt(bad, sec, pass) }
    }

    @Test
    fun `a session-key quick-check tamper collapses to IntegrityCheckFailed, not NoMatchingKey`() {
        val (sec, pub) = freshPair()
        val ct = svc.encrypt("hello world".toByteArray(), pub, armor = false)

        // Corrupt a ciphertext byte inside the SEIPD body's first block, the
        // SEIPDv1 session-key quick-check region. Before the fix this returned
        // null -> NoMatchingKey on the correctly-addressed packet, telling an
        // attacker "quick-check failed" apart from the MDC path's
        // IntegrityCheckFailed. After it, both stages fail the same way.
        val bodyStart = seipdBodyStart(ct)
        val bad = ct.copyOf()
        // +1 past the SEIPD version octet, then a few bytes into the ciphertext.
        val i = bodyStart + 1 + 4
        bad[i] = (bad[i].toInt() xor 0xFF).toByte()
        assertThrows(
            PGPCryptoError.IntegrityCheckFailed::class.java
        ) { svc.decrypt(bad, sec, pass) }
    }

    /** Offset of the SEIPD (tag 18) packet body in a raw, unarmored message:
     *  walk new-format packets past the PKESK to the encrypted-data packet.
     *  Handles 1/2/5-octet definite and partial length encodings. */
    private fun seipdBodyStart(raw: ByteArray): Int {
        var i = 0
        while (i < raw.size) {
            val c = raw[i++].toInt() and 0xFF
            check(c and 0xC0 == 0xC0) { "expected new-format packet at ${i - 1}" }
            val tag = c and 0x3F
            val l0 = raw[i++].toInt() and 0xFF
            val headerExtra: Int
            val definiteLen: Int?
            when {
                l0 < 192 -> { headerExtra = 0; definiteLen = l0 }
                l0 < 224 -> { headerExtra = 1; definiteLen = ((l0 - 192) shl 8) + (raw[i].toInt() and 0xFF) + 192 }
                l0 == 255 -> {
                    headerExtra = 4
                    definiteLen = ((raw[i].toInt() and 0xFF) shl 24) or ((raw[i + 1].toInt() and 0xFF) shl 16) or
                        ((raw[i + 2].toInt() and 0xFF) shl 8) or (raw[i + 3].toInt() and 0xFF)
                }
                else -> { headerExtra = 0; definiteLen = null } // partial length
            }
            val bodyStart = i + headerExtra
            if (tag == 18) return bodyStart // SEIPD body: version octet first
            i = bodyStart + (definiteLen ?: throw IllegalStateException("unexpected partial length before SEIPD"))
        }
        throw IllegalStateException("no SEIPD (tag 18) packet found")
    }
}
