// TlvTest.kt
// PGPony Android — HW Phase 0 tests

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class TlvTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun parsesFlatSequence() {
        // C1 02 AA BB  |  C4 01 03
        val tlvs = Tlv.parse(bytes(0xC1, 0x02, 0xAA, 0xBB, 0xC4, 0x01, 0x03))
        assertEquals(2, tlvs.size)
        assertEquals(0xC1, tlvs[0].tag)
        assertArrayEquals(bytes(0xAA, 0xBB), tlvs[0].value)
        assertEquals(0xC4, tlvs[1].tag)
        assertArrayEquals(bytes(0x03), tlvs[1].value)
    }

    @Test
    fun parsesNestedConstructed() {
        // 73 04 [ C1 02 AA BB ]
        val parsed = Tlv.parse(bytes(0x73, 0x04, 0xC1, 0x02, 0xAA, 0xBB))
        assertEquals(1, parsed.size)
        assertEquals(0x73, parsed[0].tag)
        val children = parsed[0].children()
        assertEquals(1, children.size)
        assertEquals(0xC1, children[0].tag)
        assertArrayEquals(bytes(0xAA, 0xBB), children[0].value)
    }

    @Test
    fun parsesTwoByteTag() {
        // 5F52 02 AA BB
        val parsed = Tlv.parse(bytes(0x5F, 0x52, 0x02, 0xAA, 0xBB))
        assertEquals(1, parsed.size)
        assertEquals(0x5F52, parsed[0].tag)
        assertArrayEquals(bytes(0xAA, 0xBB), parsed[0].value)
    }

    @Test
    fun parsesPublicKeyTemplateTag() {
        // 7F49 03 81 01 01
        val parsed = Tlv.parse(bytes(0x7F, 0x49, 0x03, 0x81, 0x01, 0x01))
        assertEquals(0x7F49, parsed[0].tag)
        assertEquals(3, parsed[0].value.size)
    }

    @Test
    fun parsesLongFormLength() {
        // 53 81 82 <130 bytes>  (0x81 → 1 length byte = 0x82 = 130)
        val value = ByteArray(130) { 0x11 }
        val raw = bytes(0x53, 0x81, 0x82) + value
        val parsed = Tlv.parse(raw)
        assertEquals(1, parsed.size)
        assertEquals(0x53, parsed[0].tag)
        assertEquals(130, parsed[0].value.size)
    }

    @Test
    fun findRecursiveDescendsThroughConstructed() {
        // 6E 06 [ 73 04 [ C5 02 AA BB ] ]
        val raw = bytes(0x6E, 0x06, 0x73, 0x04, 0xC5, 0x02, 0xAA, 0xBB)
        val found = Tlv.findRecursive(raw, 0xC5)
        assertNotNull(found)
        assertArrayEquals(bytes(0xAA, 0xBB), found!!.value)
    }

    @Test
    fun findRecursiveReturnsNullWhenAbsent() {
        val raw = bytes(0x73, 0x04, 0xC1, 0x02, 0xAA, 0xBB)
        assertNull(Tlv.findRecursive(raw, 0xC5))
    }

    @Test(expected = TlvException::class)
    fun rejectsIndefiniteLength() {
        Tlv.parse(bytes(0xC1, 0x80, 0xAA))
    }

    @Test(expected = TlvException::class)
    fun rejectsTruncatedValue() {
        // Claims length 5 but only 2 bytes follow.
        Tlv.parse(bytes(0xC1, 0x05, 0xAA, 0xBB))
    }
}
