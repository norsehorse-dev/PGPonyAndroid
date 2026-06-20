// CommandApduTest.kt
// PGPony Android — HW Phase 0 tests

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Test

class CommandApduTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun case1_noDataNoLe() {
        val apdu = CommandApdu(ins = 0xA4, p1 = 0x04, p2 = 0x00)
        assertArrayEquals(bytes(0x00, 0xA4, 0x04, 0x00), apdu.toBytes())
    }

    @Test
    fun case2_leOnly_256EncodesAsZero() {
        // GET DATA 0x6E with Le = 256
        val apdu = CommandApdu(ins = 0xCA, p1 = 0x00, p2 = 0x6E, le = 256)
        assertArrayEquals(bytes(0x00, 0xCA, 0x00, 0x6E, 0x00), apdu.toBytes())
    }

    @Test
    fun case3_dataNoLe() {
        val apdu = CommandApdu(ins = 0x20, p1 = 0x00, p2 = 0x82, data = bytes(0x31, 0x32, 0x33, 0x34))
        assertArrayEquals(bytes(0x00, 0x20, 0x00, 0x82, 0x04, 0x31, 0x32, 0x33, 0x34), apdu.toBytes())
    }

    @Test
    fun case4_dataAndLe_selectAid() {
        val apdu = CommandApdu(
            ins = OpenPgpCard.INS_SELECT,
            p1 = OpenPgpCard.P1_SELECT_BY_NAME,
            p2 = OpenPgpCard.P2_SELECT_FIRST_OR_ONLY,
            data = OpenPgpCard.AID_PREFIX,
            le = 256
        )
        assertArrayEquals(
            bytes(0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00),
            apdu.toBytes()
        )
    }

    @Test
    fun le255EncodesLiterally() {
        val apdu = CommandApdu(ins = 0xC0, p1 = 0x00, p2 = 0x00, le = 0xFF)
        assertArrayEquals(bytes(0x00, 0xC0, 0x00, 0x00, 0xFF), apdu.toBytes())
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsOversizeDataInShortForm() {
        CommandApdu(ins = 0x2A, p1 = 0x80, p2 = 0x86, data = ByteArray(256)).toBytes()
    }
}
