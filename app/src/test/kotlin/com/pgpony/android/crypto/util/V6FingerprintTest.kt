// V6FingerprintTest.kt
// PGPony Android
//
// Locks the RFC 9580 v6 fingerprint framing and the leading-byte key-ID
// rule. These tests validate the algorithm, not OpenPGP key semantics —
// real-key validation is the sq interop acceptance test (import an
// sq-generated v6 key and confirm the displayed fingerprint matches).

package com.pgpony.android.crypto.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class V6FingerprintTest {

    // A small deterministic stand-in for a tag-6 packet body. Not a real
    // key — just fixed bytes so the framing assertion is reproducible.
    private val body = byteArrayOf(
        0x06, 0x01, 0x02, 0x03, 0x04, 0x1B, 0x55, 0x7F, 0xAA.toByte(), 0x00
    )

    @Test
    fun `fingerprint is 32 bytes`() {
        assertEquals(32, V6Fingerprint.compute(body).size)
    }

    @Test
    fun `framing is 0x9B plus 4-byte big-endian length plus body`() {
        val len = body.size
        val framed = byteArrayOf(
            0x9B.toByte(),
            ((len ushr 24) and 0xFF).toByte(),
            ((len ushr 16) and 0xFF).toByte(),
            ((len ushr 8) and 0xFF).toByte(),
            (len and 0xFF).toByte()
        ) + body
        val expected = MessageDigest.getInstance("SHA-256").digest(framed)
        assertArrayEquals(expected, V6Fingerprint.compute(body))
    }

    @Test
    fun `key id is the leading 8 bytes`() {
        val fp = ByteArray(32) { it.toByte() }   // 00 01 02 ... 1F
        assertArrayEquals(
            byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7),
            V6Fingerprint.longKeyIdFromFingerprint(fp)
        )
    }

    @Test
    fun `key id is the opposite end from the v4 convention`() {
        // Guards against anyone reusing the v4 trailing-bytes rule for v6.
        val fp = ByteArray(32) { it.toByte() }
        val v6KeyId = V6Fingerprint.longKeyIdFromFingerprint(fp)
        val v4StyleTrailing = fp.copyOfRange(24, 32)
        assertTrue(!v6KeyId.contentEquals(v4StyleTrailing))
    }

    @Test
    fun `longKeyIdFromFingerprint rejects non-32-byte input`() {
        assertThrows(IllegalArgumentException::class.java) {
            V6Fingerprint.longKeyIdFromFingerprint(ByteArray(20))
        }
    }

    @Test
    fun `computeHex matches compute and is 64 chars`() {
        val hex = V6Fingerprint.computeHex(body)
        val fromBytes = V6Fingerprint.compute(body).joinToString("") { "%02X".format(it) }
        assertEquals(fromBytes, hex)
        assertEquals(64, hex.length)
    }

    @Test
    fun `formatFingerprint groups in fours and rejects wrong size`() {
        val fp = ByteArray(32) { 0xAB.toByte() }
        assertEquals(16, V6Fingerprint.formatFingerprint(fp).split(" ").size)
        assertThrows(IllegalArgumentException::class.java) {
            V6Fingerprint.formatFingerprint(ByteArray(31))
        }
    }
}
