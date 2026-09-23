// CardAndArchiveBoundsTest.kt
// PGPony Android, 4.6.0 (item 17.10)
//
// A hostile card, NFC relay or HCE emulator cannot hang the card layer or
// make it re-send a PIN without limit, a wrapped TLV length is a typed error,
// and a crafted backup archive entry size cannot hang a restore.

package com.pgpony.android.crypto.card

import com.pgpony.android.backup.UstarArchive
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CardAndArchiveBoundsTest {

    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    /** A card (or NFC relay / HCE phone) that answers every GET RESPONSE with 61 00. */
    private class EndlessMoreData : CardTransport {
        var getResponses = 0
        override fun transceive(commandApdu: ByteArray): ByteArray {
            val ins = commandApdu[1].toInt() and 0xFF
            if (ins == OpenPgpCard.INS_GET_RESPONSE) getResponses++
            return ByteArray(256) + byteArrayOf(0x61, 0x00)
        }
    }

    /** A card that answers VERIFY with 6C 10 every time: transmit() re-sends the PIN forever. */
    private class EndlessWrongLe : CardTransport {
        var verifies = 0
        override fun transceive(commandApdu: ByteArray): ByteArray {
            return when (commandApdu[1].toInt() and 0xFF) {
                OpenPgpCard.INS_SELECT -> byteArrayOf(0x90.toByte(), 0x00)
                OpenPgpCard.INS_GET_DATA -> byteArrayOf(0x6A, 0x88.toByte()) // no KDF-DO
                OpenPgpCard.INS_VERIFY -> { verifies++; byteArrayOf(0x6C, 0x10) }
                else -> byteArrayOf(0x6D, 0x00)
            }
        }
    }

    @Test(timeout = 5_000)
    fun getResponseChainIsBounded() {
        val t = EndlessMoreData()
        try {
            OpenPgpCardSession(t).select()
        } catch (e: OpenPgpCardException) {
            // expected after the fix: a bounded loop gives up with a card error
        }
        assertTrue("GET RESPONSE loop should be capped, ran ${t.getResponses}", t.getResponses <= 64)
    }

    @Test(timeout = 5_000)
    fun wrongLeDoesNotResendPinForever() {
        val t = EndlessWrongLe()
        val s = OpenPgpCardSession(t)
        s.select()
        try {
            s.verify(OpenPgpCard.PW1_OTHER, "123456".toByteArray())
        } catch (e: OpenPgpCardException) {
            // expected after the fix
        }
        assertTrue("VERIFY (carrying the PIN) re-sent ${t.verifies} times", t.verifies <= 2)
    }

    /** BER long form 0x84 with length 0xFFFFFFFF: Int goes negative, copyOfRange throws IAE, not TlvException. */
    @Test
    fun tlvFourByteLengthRejectedAsTlvException() {
        val raw = b(0xC1, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00)
        try {
            Tlv.parse(raw); fail("parsed")
        } catch (e: TlvException) {
            // correct
        } catch (e: Exception) {
            fail("expected TlvException, got ${e::class.java.name}")
        }
    }

    /** Directory entry with size 037777776000 (Int wraps to -1024): UstarArchive.read never advances. */
    @Test(timeout = 5_000)
    fun ustarNegativeSizeTerminates() {
        val h = ByteArray(512)
        "keys/".toByteArray().copyInto(h, 0)
        "37777776000".toByteArray().copyInto(h, 124)
        h[156] = '5'.code.toByte()
        val tar = h + ByteArray(1024)
        try { UstarArchive.read(tar) } catch (e: Exception) { /* a clean rejection is fine */ }
    }
}
