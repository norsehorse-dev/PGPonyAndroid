// CardDecryptPrimitivesTest.kt
// PGPony Android — HW Phase 3a tests

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class CardDecryptPrimitivesTest {

    private fun sw(hi: Int, lo: Int) = byteArrayOf(hi.toByte(), lo.toByte())

    private class ScriptedTransport(private val responses: Map<Int, ByteArray>) : CardTransport {
        val sent = mutableListOf<ByteArray>()
        override fun transceive(commandApdu: ByteArray): ByteArray {
            sent.add(commandApdu)
            val ins = commandApdu[1].toInt() and 0xFF
            return responses[ins] ?: byteArrayOf(0x6D.toByte(), 0x00)
        }
    }

    @Test
    fun decipherSendsPsoDecipherApdu() {
        val shared = ByteArray(32) { 0xCC.toByte() }
        val t = ScriptedTransport(
            mapOf(OpenPgpCard.INS_PERFORM_SECURITY_OPERATION to (shared + sw(0x90, 0x00)))
        )
        val cipher = ByteArray(40) { it.toByte() }
        val out = OpenPgpCardSession(t).decipher(cipher)
        assertArrayEquals(shared, out)
        val cmd = t.sent[0]
        // 00 2A 80 86 <Lc> <cipher...> 00
        assertEquals(0x2A, cmd[1].toInt() and 0xFF)
        assertEquals(0x80, cmd[2].toInt() and 0xFF)
        assertEquals(0x86, cmd[3].toInt() and 0xFF)
        assertEquals(40, cmd[4].toInt() and 0xFF)
    }

    @Test
    fun cipherDoWrapsPointInA6_7F49_86() {
        val point = ByteArray(33) { 0x40.toByte() } // 0x40 prefix + 32 (values irrelevant)
        val doBytes = EcdhCipherData.cipherDoForPoint(point)
        // A6 26 7F 49 23 86 21 <33 bytes>
        assertEquals(0xA6, doBytes[0].toInt() and 0xFF)
        assertEquals(0x26, doBytes[1].toInt() and 0xFF) // 38
        assertEquals(0x7F, doBytes[2].toInt() and 0xFF)
        assertEquals(0x49, doBytes[3].toInt() and 0xFF)
        assertEquals(0x23, doBytes[4].toInt() and 0xFF) // 35
        assertEquals(0x86, doBytes[5].toInt() and 0xFF)
        assertEquals(0x21, doBytes[6].toInt() and 0xFF) // 33
        assertArrayEquals(point, doBytes.copyOfRange(7, 7 + 33))
        assertEquals(40, doBytes.size)
    }

    @Test
    fun cipherDoUsesLongFormLengthsForP521Point() {
        // NIST P-521 uncompressed point 0x04 || X(66) || Y(66) = 133 bytes,
        // which exceeds the 127-byte short-form TLV limit at every level. This
        // is the case the reported card decrypt failed on (issue #62).
        val point = ByteArray(133) { if (it == 0) 0x04 else it.toByte() }
        val doBytes = EcdhCipherData.cipherDoForPoint(point)
        // A6 81 8C  7F 49 81 88  86 81 85  <133 bytes>
        val expectedHead = byteArrayOf(
            0xA6.toByte(), 0x81.toByte(), 0x8C.toByte(),
            0x7F, 0x49, 0x81.toByte(), 0x88.toByte(),
            0x86.toByte(), 0x81.toByte(), 0x85.toByte()
        )
        assertArrayEquals(expectedHead, doBytes.copyOfRange(0, expectedHead.size))
        assertArrayEquals(point, doBytes.copyOfRange(expectedHead.size, expectedHead.size + 133))
        assertEquals(expectedHead.size + 133, doBytes.size) // 143
    }

    @Test
    fun cipherDoKeepsPointLengthShortFormAt127() {
        // A 127-byte point value still fits a short-form length octet in its 86
        // DO (128 would flip it to long form). The outer 7F49/A6 lengths do go
        // long here because the 86 DO is then 129 bytes, so check the point's
        // own length octet off the tail rather than at a fixed index.
        val point = ByteArray(127) { it.toByte() }
        val doBytes = EcdhCipherData.cipherDoForPoint(point)
        val pointStart = doBytes.size - 127
        assertEquals(0x86, doBytes[pointStart - 2].toInt() and 0xFF) // 86 DO tag
        assertEquals(127, doBytes[pointStart - 1].toInt() and 0xFF)  // short-form len
        assertArrayEquals(point, doBytes.copyOfRange(pointStart, doBytes.size))
    }
}
