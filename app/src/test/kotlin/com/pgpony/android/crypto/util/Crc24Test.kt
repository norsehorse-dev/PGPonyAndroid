// Crc24Test.kt
// PGPony Android
//
// Phase A0 unit tests for Crc24.
// Reference values were generated against an independent Python
// implementation of RFC 4880 §6.1 and verified by hand.

package com.pgpony.android.crypto.util

import org.junit.Assert.assertEquals
import org.junit.Test

class Crc24Test {

    @Test
    fun emptyInputReturnsInitValue() {
        // With no input bytes, the loop body never runs and the
        // result is the masked init value (0xB704CE masked to 24 bits
        // is itself).
        assertEquals(0xB704CE, Crc24.compute(ByteArray(0)))
    }

    @Test
    fun helloAscii() {
        // Reference from Python implementation:
        //   crc24(b"hello") == 0x47F58A
        assertEquals(0x47F58A, Crc24.compute("hello".toByteArray()))
    }

    @Test
    fun referenceString123456789() {
        // Reference from Python implementation:
        //   crc24(b"123456789") == 0x21CF02
        assertEquals(0x21CF02, Crc24.compute("123456789".toByteArray()))
    }

    @Test
    fun bytesAreReturnedBigEndian() {
        val bytes = Crc24.computeBytes("hello".toByteArray())
        assertEquals(3, bytes.size)
        assertEquals(0x47, bytes[0].toInt() and 0xFF)
        assertEquals(0xF5, bytes[1].toInt() and 0xFF)
        assertEquals(0x8A, bytes[2].toInt() and 0xFF)
    }

    @Test
    fun base64IsFourCharsForThreeBytes() {
        // 3 bytes always base64-encode to 4 chars with no padding required.
        val encoded = Crc24.computeBase64("hello".toByteArray())
        assertEquals(4, encoded.length)
    }
}
