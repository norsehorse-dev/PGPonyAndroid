// SubpacketLengthTest.kt
// PGPony Android
//
// Phase A0 unit tests for SubpacketLength.
// Boundary cases derived from RFC 4880 §5.2.3.1.

package com.pgpony.android.crypto.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SubpacketLengthTest {

    // ── Encode ────────────────────────────────────────────────────────

    @Test
    fun encodeShortLengthsUseOneByte() {
        assertArrayEquals(byteArrayOf(0), SubpacketLength.encode(0))
        assertArrayEquals(byteArrayOf(1), SubpacketLength.encode(1))
        assertArrayEquals(byteArrayOf(100), SubpacketLength.encode(100))
        assertArrayEquals(byteArrayOf(191.toByte()), SubpacketLength.encode(191))
    }

    @Test
    fun encodeMediumLengthsUseTwoBytes() {
        // length 192 is the smallest 2-byte length
        //   adjusted = 0 -> b1 = 192, b2 = 0
        assertArrayEquals(byteArrayOf(192.toByte(), 0), SubpacketLength.encode(192))

        // length 8383 is the largest 2-byte length
        //   adjusted = 8191 = 0x1FFF
        //   b1 = 0x1F + 192 = 223 = 0xDF, b2 = 0xFF
        assertArrayEquals(byteArrayOf(0xDF.toByte(), 0xFF.toByte()), SubpacketLength.encode(8383))
    }

    @Test
    fun encodeLargeLengthsUseFiveBytes() {
        // length 8384 is the smallest 5-byte length
        //   prefix 0xFF + 0x000020C0
        assertArrayEquals(
            byteArrayOf(0xFF.toByte(), 0x00, 0x00, 0x20, 0xC0.toByte()),
            SubpacketLength.encode(8384)
        )

        // arbitrary large value
        assertArrayEquals(
            byteArrayOf(0xFF.toByte(), 0x00, 0x01, 0x00, 0x00),
            SubpacketLength.encode(0x10000)
        )
    }

    // ── Decode ────────────────────────────────────────────────────────

    @Test
    fun decodeShortLength() {
        val d = SubpacketLength.decode(byteArrayOf(100))
        assertEquals(100, d.length)
        assertEquals(1, d.bytesRead)
    }

    @Test
    fun decodeMediumLength() {
        // 192 -> bytes [192, 0]
        var d = SubpacketLength.decode(byteArrayOf(192.toByte(), 0))
        assertEquals(192, d.length)
        assertEquals(2, d.bytesRead)

        // 8383 -> bytes [0xDF, 0xFF]
        d = SubpacketLength.decode(byteArrayOf(0xDF.toByte(), 0xFF.toByte()))
        assertEquals(8383, d.length)
        assertEquals(2, d.bytesRead)
    }

    @Test
    fun decodeLargeLength() {
        val d = SubpacketLength.decode(byteArrayOf(0xFF.toByte(), 0x00, 0x00, 0x20, 0xC0.toByte()))
        assertEquals(8384, d.length)
        assertEquals(5, d.bytesRead)
    }

    @Test
    fun roundTrip() {
        // Test that encode -> decode produces the original value for
        // several values that hit each branch.
        for (len in listOf(0, 1, 100, 191, 192, 193, 1000, 8383, 8384, 65535, 1_000_000)) {
            val encoded = SubpacketLength.encode(len)
            val decoded = SubpacketLength.decode(encoded)
            assertEquals("len=$len", len, decoded.length)
            assertEquals("len=$len", encoded.size, decoded.bytesRead)
        }
    }

    // ── Edge cases ────────────────────────────────────────────────────

    @Test
    fun decodeRejectsPartialBodyLength() {
        // b1 in 224..254 is the partial-body length range. Subpacket
        // length parsing should refuse — that range is only valid for
        // packet headers, not subpacket lengths.
        assertThrows(IllegalArgumentException::class.java) {
            SubpacketLength.decode(byteArrayOf(0xE0.toByte()))
        }
    }

    @Test
    fun encodeRejectsNegativeLength() {
        assertThrows(IllegalArgumentException::class.java) {
            SubpacketLength.encode(-1)
        }
    }

    @Test
    fun decodeAtOffsetWorks() {
        // Verify the offset parameter — useful when parsing a sig packet
        // that has multiple subpackets in sequence.
        val buf = byteArrayOf(0x00, 0x00, 100, 192.toByte(), 0)
        val d1 = SubpacketLength.decode(buf, offset = 2)
        assertEquals(100, d1.length)
        assertEquals(1, d1.bytesRead)
        val d2 = SubpacketLength.decode(buf, offset = 3)
        assertEquals(192, d2.length)
        assertEquals(2, d2.bytesRead)
    }
}
