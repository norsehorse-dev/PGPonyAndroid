// CardSigningFormatTest.kt
// PGPony Android — HW Phase 2b tests

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CardSigningFormatTest {

    private val digest = ByteArray(32) { it.toByte() }

    @Test
    fun rsaPrependsSha256DigestInfoPrefix() {
        val out = CardSigningFormat.prepareInput(1, digest)
        assertEquals(CardSigningFormat.SHA256_DIGESTINFO_PREFIX.size + 32, out.size)
        assertArrayEquals(
            CardSigningFormat.SHA256_DIGESTINFO_PREFIX,
            out.copyOfRange(0, CardSigningFormat.SHA256_DIGESTINFO_PREFIX.size)
        )
        assertArrayEquals(digest, out.copyOfRange(CardSigningFormat.SHA256_DIGESTINFO_PREFIX.size, out.size))
    }

    @Test
    fun rsaSignVariantAlsoPrepends() {
        // algo 3 = RSA_SIGN
        assertEquals(CardSigningFormat.SHA256_DIGESTINFO_PREFIX.size + 32, CardSigningFormat.prepareInput(3, digest).size)
    }

    @Test
    fun eddsaPassesDigestThrough() {
        // algo 22 = EdDSA-legacy
        assertArrayEquals(digest, CardSigningFormat.prepareInput(22, digest))
    }

    @Test
    fun prefixIsCanonicalSha256DigestInfo() {
        // 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        val expected = byteArrayOf(
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48,
            0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
        )
        assertArrayEquals(expected, CardSigningFormat.SHA256_DIGESTINFO_PREFIX)
    }

    @Test
    fun isRsaClassification() {
        assertTrue(CardSigningFormat.isRsa(1))
        assertTrue(CardSigningFormat.isRsa(2))
        assertTrue(CardSigningFormat.isRsa(3))
        assertFalse(CardSigningFormat.isRsa(22))
        assertFalse(CardSigningFormat.isRsa(19))
    }
}
