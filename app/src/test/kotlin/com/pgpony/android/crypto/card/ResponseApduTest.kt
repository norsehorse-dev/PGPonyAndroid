// ResponseApduTest.kt
// PGPony Android — HW Phase 0 tests

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResponseApduTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun parsesSuccessWithNoData() {
        val r = ResponseApdu.parse(bytes(0x90, 0x00))
        assertEquals(0, r.data.size)
        assertEquals(0x9000, r.sw)
        assertTrue(r.isSuccess)
    }

    @Test
    fun splitsDataFromStatusWord() {
        val r = ResponseApdu.parse(bytes(0xAA, 0xBB, 0xCC, 0x90, 0x00))
        assertArrayEquals(bytes(0xAA, 0xBB, 0xCC), r.data)
        assertTrue(r.isSuccess)
    }

    @Test
    fun detectsMoreDataAvailable() {
        val r = ResponseApdu.parse(bytes(0x01, 0x02, 0x61, 0x10))
        assertTrue(r.hasMoreData)
        assertFalse(r.isSuccess)
        assertEquals(0x10, r.sw2)
    }

    @Test
    fun detectsWrongLe() {
        val r = ResponseApdu.parse(bytes(0x6C, 0x05))
        assertTrue(r.wrongLe)
        assertEquals(0x05, r.sw2)
    }

    @Test(expected = OpenPgpCardException.Communication::class)
    fun rejectsTooShortResponse() {
        ResponseApdu.parse(bytes(0x90))
    }
}
