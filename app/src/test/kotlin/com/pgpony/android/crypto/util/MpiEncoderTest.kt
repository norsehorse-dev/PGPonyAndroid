// MpiEncoderTest.kt
// PGPony Android
//
// Phase A0 unit tests for MpiEncoder.
// Examples drawn from RFC 4880 §3.2.

package com.pgpony.android.crypto.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class MpiEncoderTest {

    // ── Encode ────────────────────────────────────────────────────────

    @Test
    fun encodeEmptyArrayIsZeroMpi() {
        assertArrayEquals(byteArrayOf(0, 0), MpiEncoder.encode(ByteArray(0)))
    }

    @Test
    fun encodeAllZerosIsZeroMpi() {
        assertArrayEquals(byteArrayOf(0, 0), MpiEncoder.encode(byteArrayOf(0, 0, 0)))
    }

    @Test
    fun encodeSingleByte0x0FHas4BitLength() {
        // RFC 4880 §3.2 example: [0x0F] has bit length 4
        // -> MPI = [0x00, 0x04, 0x0F]
        assertArrayEquals(byteArrayOf(0x00, 0x04, 0x0F), MpiEncoder.encode(byteArrayOf(0x0F)))
    }

    @Test
    fun encodeTwoByte0x01FFHas9BitLength() {
        // RFC 4880 §3.2 example: [0x01, 0xFF] has bit length 9
        // -> MPI = [0x00, 0x09, 0x01, 0xFF]
        assertArrayEquals(
            byteArrayOf(0x00, 0x09, 0x01, 0xFF.toByte()),
            MpiEncoder.encode(byteArrayOf(0x01, 0xFF.toByte()))
        )
    }

    @Test
    fun encodeStripsLeadingZeroBytes() {
        // [0x00, 0x00, 0x01, 0xFF] should strip the leading zeros and
        // encode the same as [0x01, 0xFF].
        val withLeading = byteArrayOf(0x00, 0x00, 0x01, 0xFF.toByte())
        val withoutLeading = byteArrayOf(0x01, 0xFF.toByte())
        assertArrayEquals(MpiEncoder.encode(withoutLeading), MpiEncoder.encode(withLeading))
    }

    @Test
    fun encode32ByteWithHighBitSetHas256BitLength() {
        // A 32-byte Ed25519 R value with the top byte 0x80 has the
        // top bit set, so bit length is exactly 32 * 8 = 256.
        // MPI = [0x01, 0x00, <32 bytes>]
        val value = ByteArray(32).apply {
            this[0] = 0x80.toByte()
            for (i in 1 until 32) this[i] = i.toByte()
        }
        val encoded = MpiEncoder.encode(value)
        assertEquals(34, encoded.size)
        assertEquals(0x01, encoded[0].toInt())
        assertEquals(0x00, encoded[1].toInt())
        assertEquals(0x80, encoded[2].toInt() and 0xFF)
    }

    @Test
    fun encode32ByteWithLowTopByte() {
        // A 32-byte value with top byte 0x01 has bit length 31 * 8 + 1 = 249.
        val value = ByteArray(32).apply {
            this[0] = 0x01
            for (i in 1 until 32) this[i] = 0xFF.toByte()
        }
        val encoded = MpiEncoder.encode(value)
        assertEquals(34, encoded.size)
        // 249 = 0x00F9
        assertEquals(0x00, encoded[0].toInt())
        assertEquals(0xF9.toByte(), encoded[1])
    }

    // ── Decode ────────────────────────────────────────────────────────

    @Test
    fun decodeRoundTrip0x0F() {
        val encoded = MpiEncoder.encode(byteArrayOf(0x0F))
        val (value, consumed) = MpiEncoder.decode(encoded)
        assertArrayEquals(byteArrayOf(0x0F), value)
        assertEquals(3, consumed)
    }

    @Test
    fun decodeRoundTrip32ByteValue() {
        val original = ByteArray(32).apply {
            this[0] = 0x80.toByte()
            for (i in 1 until 32) this[i] = i.toByte()
        }
        val encoded = MpiEncoder.encode(original)
        val (decoded, consumed) = MpiEncoder.decode(encoded, expectedByteLength = 32)
        assertArrayEquals(original, decoded)
        assertEquals(34, consumed)
    }

    @Test
    fun decodeLeftPadsToExpectedLength() {
        // A 32-byte Ed25519 S value that happens to be small (top byte
        // 0x01) will MPI-encode to fewer than 32 stored bytes. Decoding
        // with expectedByteLength = 32 should restore the leading zeros
        // so the caller gets a fixed-size 32-byte buffer.
        val original = ByteArray(32).also { it[31] = 0x01 }  // value = 1
        val encoded = MpiEncoder.encode(original)
        val (decoded, _) = MpiEncoder.decode(encoded, expectedByteLength = 32)
        assertEquals(32, decoded.size)
        assertArrayEquals(original, decoded)
    }
}
