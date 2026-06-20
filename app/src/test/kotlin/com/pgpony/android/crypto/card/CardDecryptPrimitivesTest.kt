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
}
