// PlaintextKindTest.kt
// PGPony Android 4.7.0 (item 25, #67): a decrypted image is a file, a
// decrypted message is text, whatever the lenient UTF-8 decode says.

package com.pgpony.android.intent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PlaintextKindTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    private val png = bytes(0x89, 'P'.code, 'N'.code, 'G'.code, 0x0D, 0x0A, 0x1A, 0x0A) + ByteArray(64) { 'a'.code.toByte() }
    private val jpeg = bytes(0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10) + ByteArray(64) { 'b'.code.toByte() }
    private val pdf = "%PDF-1.7\nplain looking text".toByteArray()
    private val zip = bytes('P'.code, 'K'.code, 3, 4) + "inner".toByteArray()

    @Test
    fun knownBinaryFormats_areFiles() {
        for (f in listOf(png, jpeg, pdf, zip)) assertFalse(PlaintextKind.isText(f))
    }

    @Test
    fun messages_areText() {
        assertTrue(PlaintextKind.isText("A signed message.\nSecond line.".toByteArray()))
        assertTrue(PlaintextKind.isText("Привет, 你好, ¿qué tal?".toByteArray(Charsets.UTF_8)))
        assertTrue(PlaintextKind.isText(ByteArray(0)))
    }

    @Test
    fun invalidUtf8OrNul_isAFile() {
        assertFalse(PlaintextKind.isText(bytes(0x48, 0x69, 0xC3)))
        assertFalse(PlaintextKind.isText(bytes(0x48, 0x00, 0x69)))
        assertFalse(PlaintextKind.isText(bytes(0xC0, 0xAF)))
    }

    @Test
    fun extension_followsTheMagic() {
        assertEquals("png", PlaintextKind.extensionFor(png))
        assertEquals("jpg", PlaintextKind.extensionFor(jpeg))
        assertEquals("pdf", PlaintextKind.extensionFor(pdf))
        assertEquals("zip", PlaintextKind.extensionFor(zip))
        assertNull(PlaintextKind.extensionFor("text".toByteArray()))
    }
}
