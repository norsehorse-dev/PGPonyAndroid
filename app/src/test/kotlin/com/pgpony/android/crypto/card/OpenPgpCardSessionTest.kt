// OpenPgpCardSessionTest.kt
// PGPony Android — HW Phase 0 tests
//
// Drives OpenPgpCardSession against an in-memory fake transport — no
// device needed. Verifies the SELECT → GET DATA → CardInfo assembly and
// the 0x61xx GET RESPONSE chaining path.

package com.pgpony.android.crypto.card

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OpenPgpCardSessionTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    private fun tlv(tag: Int, value: ByteArray): ByteArray {
        val tagBytes = if (tag <= 0xFF) byteArrayOf(tag.toByte())
        else byteArrayOf((tag shr 8).toByte(), tag.toByte())
        val lenBytes = when {
            value.size < 0x80 -> byteArrayOf(value.size.toByte())
            value.size < 0x100 -> byteArrayOf(0x81.toByte(), value.size.toByte())
            else -> byteArrayOf(0x82.toByte(), (value.size shr 8).toByte(), value.size.toByte())
        }
        return tagBytes + lenBytes + value
    }

    private fun ardContent(): ByteArray {
        val aid = bytes(
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
            0x03, 0x04, 0x00, 0x06, 0xAB, 0xCD, 0xEF, 0x01, 0x00, 0x00
        )
        val c1 = bytes(0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01)
        val c4 = bytes(0x01, 0x20, 0x00, 0x20, 0x02, 0x00, 0x03)
        val c5 = ByteArray(20) { 0xAA.toByte() } +
            ByteArray(20) { 0x00 } +
            ByteArray(20) { 0x00 }
        val disc = tlv(0xC1, c1) + tlv(0xC4, c4) + tlv(0xC5, c5)
        return tlv(OpenPgpCard.DO_AID, aid) + tlv(OpenPgpCard.DO_DISCRETIONARY, disc)
    }

    private val SW9000 = bytes(0x90, 0x00)

    /** Returns the whole ARD in a single GET DATA response. */
    private class SimpleTransport(private val ard: ByteArray, private val sw: ByteArray) : CardTransport {
        override fun transceive(commandApdu: ByteArray): ByteArray {
            return when (commandApdu[1].toInt() and 0xFF) {
                OpenPgpCard.INS_SELECT -> byteArrayOf(0x90.toByte(), 0x00)
                OpenPgpCard.INS_GET_DATA -> ard + sw
                else -> byteArrayOf(0x6D.toByte(), 0x00)
            }
        }
    }

    /** Splits the ARD across a 0x61xx continuation + GET RESPONSE. */
    private class ChainingTransport(private val ard: ByteArray) : CardTransport {
        override fun transceive(commandApdu: ByteArray): ByteArray {
            return when (commandApdu[1].toInt() and 0xFF) {
                OpenPgpCard.INS_SELECT -> byteArrayOf(0x90.toByte(), 0x00)
                OpenPgpCard.INS_GET_DATA -> {
                    val first = ard.copyOfRange(0, 64)
                    first + byteArrayOf(0x61.toByte(), (ard.size - 64).toByte())
                }
                OpenPgpCard.INS_GET_RESPONSE -> {
                    val rest = ard.copyOfRange(64, ard.size)
                    rest + byteArrayOf(0x90.toByte(), 0x00)
                }
                else -> byteArrayOf(0x6D.toByte(), 0x00)
            }
        }
    }

    @Test
    fun readsCardInfoFromSingleResponse() {
        val session = OpenPgpCardSession(SimpleTransport(ardContent(), SW9000))
        val info = session.readCardInfo()
        assertEquals("Yubico", info.manufacturerName)
        assertEquals("ABCDEF01", info.serialHex)
        assertEquals("AA".repeat(20), info.primaryFingerprint)
        assertEquals(2, info.pw1TriesRemaining)
        assertEquals(3, info.pw3TriesRemaining)
        assertTrue(info.hasAnyKey)
        // Decryption + auth slots empty.
        assertNull(info.fingerprintFor(CardSlot.DECRYPTION))
        assertNull(info.fingerprintFor(CardSlot.AUTHENTICATION))
    }

    @Test
    fun reassemblesChainedResponse() {
        val session = OpenPgpCardSession(ChainingTransport(ardContent()))
        val info = session.readCardInfo()
        // If chaining reassembled correctly, identity + fingerprint parse fine.
        assertEquals("ABCDEF01", info.serialHex)
        assertEquals("AA".repeat(20), info.primaryFingerprint)
    }

    @Test(expected = OpenPgpCardException.NotAnOpenPgpCard::class)
    fun selectFailureThrows() {
        val failing = object : CardTransport {
            override fun transceive(commandApdu: ByteArray): ByteArray =
                byteArrayOf(0x6A.toByte(), 0x82.toByte()) // file not found
        }
        OpenPgpCardSession(failing).readCardInfo()
    }
}
