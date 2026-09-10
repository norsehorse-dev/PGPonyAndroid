// ArmorExtractorTest.kt
// PGPony Android — 4.5.0 (item 19 / #58): extract armored key blocks from noisy
// shared / pasted text.

package com.pgpony.android.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ArmorExtractorTest {

    private fun pubBlock(tag: String) = buildString {
        append("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
        append("Comment: $tag\n\n")
        append("mDMEZ$tag...base64...\n")
        append("-----END PGP PUBLIC KEY BLOCK-----")
    }

    private val sigBlock = buildString {
        append("-----BEGIN PGP SIGNATURE-----\n\n")
        append("iHUEAB...sig...\n")
        append("-----END PGP SIGNATURE-----")
    }

    @Test
    fun `a clean single key block is returned unchanged`() {
        val block = pubBlock("A")
        assertEquals(block, ArmorExtractor.extractForImport(block))
    }

    @Test
    fun `surrounding page text is stripped`() {
        val block = pubBlock("A")
        val noisy = "Here is my key, from a browser view:\n\n$block\n\nThanks!\n(c) 2026 Example"
        assertEquals(block, ArmorExtractor.extractForImport(noisy))
    }

    @Test
    fun `two key blocks are both kept`() {
        val a = pubBlock("A")
        val b = pubBlock("B")
        val out = ArmorExtractor.extractForImport("prefix $a middle $b suffix")!!
        assertTrue(out.contains("Comment: A"))
        assertTrue(out.contains("Comment: B"))
        assertEquals(2, ArmorExtractor.blocks(out).size)
    }

    @Test
    fun `a key plus a signature keeps only the key`() {
        val key = pubBlock("A")
        val out = ArmorExtractor.extractForImport("$sigBlock\n\n$key")!!
        assertEquals(1, ArmorExtractor.blocks(out).size)
        assertEquals("PUBLIC KEY BLOCK", ArmorExtractor.blocks(out).first().type)
    }

    @Test
    fun `text with no armored block returns null`() {
        assertNull(ArmorExtractor.extractForImport("just some page text, no key here"))
        assertNull(ArmorExtractor.extractForImport(""))
    }

    @Test
    fun `a lone signature with no key falls back to the signature block`() {
        // No key block present, so the caller still gets something to report on
        // (it will fail downstream with a clear error rather than silently drop).
        val out = ArmorExtractor.extractForImport("noise $sigBlock noise")
        assertEquals(sigBlock, out)
    }
}
