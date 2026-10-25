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

    // 4.7.2 RC3: messageOnly, the decrypt-side extraction.

    private val msgBlock = buildString {
        append("-----BEGIN PGP MESSAGE-----\n\n")
        append("hF4DAAAAAAAAAAASAQdA...base64...\n")
        append("=AbCd\n")
        append("-----END PGP MESSAGE-----")
    }

    private val emailSignature = "Cheers\n\n------------------------------\nA Name\nname@example.org\nSomewhere"

    @Test
    fun `a clean message is returned unchanged`() {
        val input = msgBlock + "\n"
        assertTrue(input === ArmorExtractor.messageOnly(input))
        assertTrue(msgBlock === ArmorExtractor.messageOnly(msgBlock))
    }

    @Test
    fun `an email signature with a row of dashes above the message is dropped`() {
        assertEquals(msgBlock + "\n", ArmorExtractor.messageOnly(emailSignature + "\n\n" + msgBlock))
    }

    @Test
    fun `an email signature below the message is dropped`() {
        assertEquals(msgBlock + "\n", ArmorExtractor.messageOnly(msgBlock + "\n\n" + emailSignature))
    }

    @Test
    fun `the dash-dash-space signature separator above the message is dropped`() {
        assertEquals(msgBlock + "\n", ArmorExtractor.messageOnly("Thanks\n-- \nA Name\n\n" + msgBlock))
    }

    @Test
    fun `a message without its END line is returned unchanged`() {
        val partial = emailSignature + "\n\n-----BEGIN PGP MESSAGE-----\n\nhF4DAAAA"
        assertTrue(partial === ArmorExtractor.messageOnly(partial))
    }

    @Test
    fun `text without a message block is returned unchanged`() {
        val text = "just some text\n-----\nmore"
        assertTrue(text === ArmorExtractor.messageOnly(text))
    }

    @Test
    fun `the first of two messages is used`() {
        val second = msgBlock.replace("base64", "second")
        assertEquals(msgBlock + "\n", ArmorExtractor.messageOnly(msgBlock + "\n\n" + second))
    }
}
