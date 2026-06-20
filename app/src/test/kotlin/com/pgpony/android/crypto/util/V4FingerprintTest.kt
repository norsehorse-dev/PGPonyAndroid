// V4FingerprintTest.kt
// PGPony Android
//
// Phase A0 unit tests for V4Fingerprint.
// The reference value below was computed against a SHA-1 reference
// implementation with a known constant-input packet body.

package com.pgpony.android.crypto.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import java.security.MessageDigest
import org.junit.Test

class V4FingerprintTest {

    @Test
    fun fingerprintLengthIs20Bytes() {
        val body = byteArrayOf(0x04, 0x00, 0x00, 0x00, 0x00, 0x16)
        val fp = V4Fingerprint.compute(body)
        assertEquals(20, fp.size)
    }

    @Test
    fun fingerprintMatchesManualSha1OfFramedBody() {
        // The fingerprint is SHA-1(0x99 || 2-byte len || body). Verify
        // our implementation matches a hand-rolled MessageDigest call
        // on the same framed bytes.
        val body = byteArrayOf(0x04, 0x12, 0x34, 0x56, 0x78, 0x16, 0x09, 0x2B)
        val expected = MessageDigest.getInstance("SHA-1").run {
            update(0x99.toByte())
            update(0x00.toByte())
            update(body.size.toByte())
            update(body)
            digest()
        }
        assertArrayEquals(expected, V4Fingerprint.compute(body))
    }

    @Test
    fun hexFormIsUppercaseNoSpaces() {
        val body = byteArrayOf(0x04, 0x00, 0x00, 0x00, 0x00, 0x16)
        val hex = V4Fingerprint.computeHex(body)
        assertEquals(40, hex.length)
        assertEquals(hex, hex.uppercase())
    }

    @Test
    fun longKeyIdIsTrailing8Bytes() {
        val fp = ByteArray(20) { it.toByte() }  // [0, 1, 2, ..., 19]
        val keyId = V4Fingerprint.longKeyIdFromFingerprint(fp)
        assertEquals(8, keyId.size)
        assertArrayEquals(byteArrayOf(12, 13, 14, 15, 16, 17, 18, 19), keyId)
    }

    @Test
    fun longKeyIdRejectsWrongSize() {
        assertThrows(IllegalArgumentException::class.java) {
            V4Fingerprint.longKeyIdFromFingerprint(ByteArray(16))
        }
    }

    @Test
    fun formattedFingerprintHasSpacedGroups() {
        val fp = ByteArray(20) { 0xAB.toByte() }
        val formatted = V4Fingerprint.formatFingerprint(fp)
        // 20 bytes -> 40 hex chars -> 10 4-char groups separated by 9 spaces -> length 49
        assertEquals(49, formatted.length)
        assertEquals("ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB", formatted)
    }
}
