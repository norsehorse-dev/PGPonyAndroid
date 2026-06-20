// ApplicationRelatedDataTest.kt
// PGPony Android — HW Phase 0 tests
//
// Crafts a realistic Application Related Data payload (the content of
// GET DATA 0x6E) for a card with an Ed25519 signature key, a Cv25519
// decryption key, and an empty (all-zero) authentication slot, then
// asserts the parser pulls out identity, algorithms, fingerprints, PIN
// retry counters, and generation times correctly.

package com.pgpony.android.crypto.card

import com.pgpony.android.crypto.KeyAlgorithm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ApplicationRelatedDataTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    /** Encode tag (1- or 2-byte) + definite length + value. */
    private fun tlv(tag: Int, value: ByteArray): ByteArray {
        val tagBytes = if (tag <= 0xFF) {
            byteArrayOf(tag.toByte())
        } else {
            byteArrayOf((tag shr 8).toByte(), tag.toByte())
        }
        val lenBytes = when {
            value.size < 0x80 -> byteArrayOf(value.size.toByte())
            value.size < 0x100 -> byteArrayOf(0x81.toByte(), value.size.toByte())
            else -> byteArrayOf(0x82.toByte(), (value.size shr 8).toByte(), value.size.toByte())
        }
        return tagBytes + lenBytes + value
    }

    private fun craftArd(): ByteArray {
        val aid = bytes(
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, // prefix
            0x03, 0x04,                         // version
            0x00, 0x06,                         // manufacturer = Yubico
            0x12, 0x34, 0x56, 0x78,             // serial
            0x00, 0x00                          // rfu
        )
        val c1 = bytes(0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01) // EdDSA Ed25519
        val c2 = bytes(0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01) // ECDH Cv25519
        val c3 = bytes(0x01, 0x08, 0x00, 0x00, 0x11, 0x00) // RSA modBits=0x0800, expBits=0x0011, fmt=00
        val c4 = bytes(0x01, 0x20, 0x00, 0x20, 0x03, 0x00, 0x03) // PW1 tries=3 (idx4), PW3 tries=3 (idx6)
        val c5 = ByteArray(20) { 0xAA.toByte() } +
            ByteArray(20) { 0xBB.toByte() } +
            ByteArray(20) { 0x00 }            // auth slot empty
        val cd = bytes(
            0x60, 0x00, 0x00, 0x00,           // sig gen time = 0x60000000
            0x60, 0x00, 0x00, 0x00,           // dec gen time = 0x60000000
            0x00, 0x00, 0x00, 0x00            // auth gen time = none
        )
        val disc = tlv(0xC1, c1) + tlv(0xC2, c2) + tlv(0xC3, c3) +
            tlv(0xC4, c4) + tlv(0xC5, c5) + tlv(0xCD, cd)
        return tlv(OpenPgpCard.DO_AID, aid) + tlv(OpenPgpCard.DO_DISCRETIONARY, disc)
    }

    @Test
    fun parsesIdentity() {
        val ard = ApplicationRelatedData.parse(craftArd())
        assertEquals(0x0006, ard.manufacturerId)
        assertEquals("Yubico", ard.manufacturerName)
        assertEquals("12345678", ard.serialHex)
        assertEquals("D2760001240103040006123456780000", ard.aidHex)
    }

    @Test
    fun parsesAlgorithms() {
        val ard = ApplicationRelatedData.parse(craftArd())
        assertEquals("Ed25519", ard.sigAlgorithm?.displayName)
        assertEquals(KeyAlgorithm.ED25519_CV25519, ard.sigAlgorithm?.mappedAlgorithm)
        assertEquals("Cv25519", ard.decAlgorithm?.displayName)
        assertEquals("RSA-2048", ard.authAlgorithm?.displayName)
        assertEquals(2048, ard.authAlgorithm?.modulusBits)
        assertEquals(KeyAlgorithm.RSA_2048, ard.authAlgorithm?.mappedAlgorithm)
    }

    @Test
    fun parsesFingerprintsWithEmptySlotAsNull() {
        val ard = ApplicationRelatedData.parse(craftArd())
        assertEquals("AA".repeat(20), ard.sigFingerprint)
        assertEquals("BB".repeat(20), ard.decFingerprint)
        assertNull(ard.authFingerprint) // all-zero slot
    }

    @Test
    fun parsesPinRetryCounters() {
        val ard = ApplicationRelatedData.parse(craftArd())
        assertEquals(3, ard.pw1TriesRemaining)
        assertEquals(3, ard.pw3TriesRemaining)
    }

    @Test
    fun parsesGenerationTimes() {
        val ard = ApplicationRelatedData.parse(craftArd())
        assertEquals(0x60000000L * 1000L, ard.sigGenTimeMs)
        assertEquals(0x60000000L * 1000L, ard.decGenTimeMs)
        assertNull(ard.authGenTimeMs)
    }
}
