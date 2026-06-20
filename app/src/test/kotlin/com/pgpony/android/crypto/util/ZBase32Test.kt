// ZBase32Test.kt
// PGPony Android
//
// Phase A0 unit tests for ZBase32.
//
// The single most important test here is the WKD spec test vector:
//   zbase32(SHA1("joe.doe")) == "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
//
// If that ever fails, Phase A5 WKD discovery will not work — the
// hashed-localpart segment of the WKD URL will be wrong and every
// recipient lookup will 404.

package com.pgpony.android.crypto.util

import org.junit.Assert.assertEquals
import java.security.MessageDigest
import org.junit.Test

class ZBase32Test {

    @Test
    fun wkdSpecTestVector() {
        val sha1OfJoeDoe = MessageDigest.getInstance("SHA-1").digest("joe.doe".toByteArray())
        assertEquals("iy9q119eutrkn8s1mk4r39qejnbu3n5q", ZBase32.encode(sha1OfJoeDoe))
    }

    @Test
    fun emptyInputProducesEmptyString() {
        assertEquals("", ZBase32.encode(ByteArray(0)))
    }

    @Test
    fun singleByteUsesPgpAlphabet() {
        // 0x00 -> first 5 bits are 0 -> alphabet[0] = 'y'
        //         next 3 bits remaining in buffer -> pad with zeros
        //         -> 5-bit group = 0 -> alphabet[0] = 'y'
        assertEquals("yy", ZBase32.encode(byteArrayOf(0x00)))

        // 0xFF -> first 5 bits = 0b11111 = 31 -> alphabet[31] = '9'
        //         next 3 bits = 0b111, padded -> 0b11100 = 28 -> alphabet[28] = 'h'
        assertEquals("9h", ZBase32.encode(byteArrayOf(0xFF.toByte())))
    }

    @Test
    fun outputLengthIsCeilingOfBitsOverFive() {
        // 20 bytes (SHA-1 length) = 160 bits = exactly 32 5-bit groups,
        // so output is exactly 32 chars with no padding char needed.
        val sha1OfJoeDoe = MessageDigest.getInstance("SHA-1").digest("joe.doe".toByteArray())
        assertEquals(32, ZBase32.encode(sha1OfJoeDoe).length)
    }

    @Test
    fun outputContainsOnlyAlphabetCharacters() {
        val sha1OfJoeDoe = MessageDigest.getInstance("SHA-1").digest("joe.doe".toByteArray())
        val allowed = "ybndrfg8ejkmcpqxot1uwisza345h769".toSet()
        for (c in ZBase32.encode(sha1OfJoeDoe)) {
            assert(c in allowed) { "Char '$c' is not in z-base32 alphabet" }
        }
    }
}
