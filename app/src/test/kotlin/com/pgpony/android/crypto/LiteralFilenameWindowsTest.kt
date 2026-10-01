// LiteralFilenameWindowsTest.kt
// FILES-5: a sender-chosen literal filename stays a plain base name on
// Windows too, whatever platform sanitizes it: no drive prefix, no alternate
// data stream, no reserved device name, no trailing dots or spaces.

package com.pgpony.android.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LiteralFilenameWindowsTest {

    private fun s(raw: String?) = LiteralFilename.sanitize(raw)

    @Test
    fun `drive prefixes and streams lose their colon`() {
        assertEquals("D_setup.exe", s("D:setup.exe"))
        assertEquals("C__Windows", s("\\\\?\\C:_Windows"))
        assertEquals("notes.txt_hidden", s("notes.txt:hidden"))
        assertEquals("a.txt__\$DATA", s("a.txt::\$DATA"))
        assertFalse(s("E:payload")!!.contains(':'))
    }

    @Test
    fun `characters Windows refuses become underscores`() {
        assertEquals("a_b_c_d_e_f_.txt", s("a<b>c\"d|e?f*.txt"))
    }

    @Test
    fun `device names get a prefix with or without an extension`() {
        for (name in listOf("CON", "con", "PRN", "AUX", "NUL", "nul.txt", "COM1", "com9.log", "LPT1", "lpt0.tar.gz", "CONIN\$", "Aux .txt", "COM\u00B9")) {
            val out = s(name)!!
            assertTrue("$name -> $out", out.startsWith("_"))
            assertFalse("$name -> $out", LiteralFilename.isDeviceName(out))
        }
        // Names that only start like a device are left alone.
        assertEquals("CONFIG.txt", s("CONFIG.txt"))
        assertEquals("COM10", s("COM10"))
        assertEquals("console", s("console"))
    }

    @Test
    fun `trailing dots and spaces are dropped`() {
        assertEquals("report.pdf", s("report.pdf. . "))
        assertEquals("NUL", s("NUL...")?.removePrefix("_"))
        assertNull(s("..."))
        assertNull(s(" . "))
    }

    @Test
    fun `ordinary names are unchanged`() {
        assertEquals("photo 2026-09-30.jpg", s("photo 2026-09-30.jpg"))
        assertEquals(".hidden", s(".hidden"))
        assertEquals("evil.sh", s("../../evil.sh"))
        assertNull(s(".."))
        assertNull(s(null))
    }
}
