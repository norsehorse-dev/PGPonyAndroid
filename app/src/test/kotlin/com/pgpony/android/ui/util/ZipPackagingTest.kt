// ZipPackagingTest.kt
// PGPony Android, 4.6.0: zip packaging and unwrapping are bounded and never
// produce a path from an untrusted name. An output name from a picked file's
// display name lands directly under exports/, a written entry name carries no
// separators, and extraction refuses a payload past its cap or an archive
// with too many entries.

package com.pgpony.android.ui.util

import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.SecurityLimits
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class ZipPackagingTest {

    private fun zipOf(vararg entries: Pair<String, ByteArray>): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { z ->
            for ((name, body) in entries) {
                z.putNextEntry(ZipEntry(name)); z.write(body); z.closeEntry()
            }
        }
        return bos.toByteArray()
    }

    @Test
    fun `a traversal display name stays directly under exports`() {
        val exports = Files.createTempDirectory("exports").toFile()
        try {
            for (name in listOf("../../x", "..\\..\\x", "a/../../b.gpg", "/etc/passwd.gpg")) {
                val out = ScratchFiles.safeChild(exports, "$name.zip", "encrypted.gpg.zip")
                assertEquals(name, exports.canonicalFile, out.canonicalFile.parentFile)
            }
        } finally {
            exports.deleteRecursively()
        }
    }

    @Test
    fun `a written entry name has no separators`() {
        val bos = ByteArrayOutputStream()
        ZipPackaging.writeSingleEntry(bos, "../../x.gpg") { it.write(byteArrayOf(1, 2, 3)) }
        val entry = ZipInputStream(ByteArrayInputStream(bos.toByteArray())).nextEntry!!
        assertFalse(entry.name.contains('/'))
        assertFalse(entry.name.contains('\\'))
        assertEquals("x.gpg", entry.name)
        assertEquals("encrypted.gpg", ZipPackaging.safeEntryName(".."))
    }

    @Test
    fun `a normal wrapped payload extracts intact`() {
        val body = ByteArray(10_000) { (it % 251).toByte() }
        val out = ByteArrayOutputStream()
        assertTrue(ZipPackaging.extractEntry(ByteArrayInputStream(zipOf("note.txt" to "x".toByteArray(), "m.gpg" to body)), "m.gpg", out))
        assertArrayEquals(body, out.toByteArray())
    }

    @Test
    fun `a payload that inflates past the cap is refused with bounded output`() {
        // 4 MiB of zeros deflates to a few KiB: a small archive, a large entry.
        val bomb = zipOf("m.gpg" to ByteArray(4 * 1024 * 1024))
        assertTrue(bomb.size < 64 * 1024)
        var written = 0L
        val counting = object : OutputStream() {
            override fun write(b: Int) { written++ }
            override fun write(b: ByteArray, off: Int, len: Int) { written += len }
        }
        try {
            ZipPackaging.extractEntry(ByteArrayInputStream(bomb), "m.gpg", counting, max = 1024 * 1024)
            fail("expected ResourceLimitExceeded")
        } catch (_: PGPCryptoError.ResourceLimitExceeded) {
        }
        assertTrue("stopped at the cap, wrote $written", written <= 1024 * 1024)
    }

    @Test
    fun `an archive with too many entries is refused`() {
        val many = (0..SecurityLimits.MAX_ZIP_ENTRIES).map { "f$it.txt" to ByteArray(0) }.toTypedArray()
        val z = zipOf(*many)
        try {
            ZipPackaging.listPgpEntries(ZipInputStream(ByteArrayInputStream(z)))
            fail("expected ResourceLimitExceeded")
        } catch (_: PGPCryptoError.ResourceLimitExceeded) {
        }
        try {
            ZipPackaging.extractEntry(ByteArrayInputStream(z), "missing.gpg", ByteArrayOutputStream())
            fail("expected ResourceLimitExceeded")
        } catch (_: PGPCryptoError.ResourceLimitExceeded) {
        }
    }

    @Test
    fun `a partial payload file can be removed after a refusal`() {
        val f = File.createTempFile("zip-payload", ".bin")
        try {
            f.outputStream().use {
                ZipPackaging.copyToCapped(ByteArrayInputStream(ByteArray(5000)), it, max = 1000)
            }
            fail("expected ResourceLimitExceeded")
        } catch (_: PGPCryptoError.ResourceLimitExceeded) {
            assertTrue(f.length() <= 1000)
            assertTrue(f.delete())
        }
    }
}
