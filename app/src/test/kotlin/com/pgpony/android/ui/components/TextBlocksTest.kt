// TextBlocksTest.kt
// PGPony Android, 4.7.1 (Play ANR): the full-text dialog lays out a long text
// as blocks in a lazy list. The blocks must join back to the exact text.

package com.pgpony.android.ui.components

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TextBlocksTest {

    @Test
    fun shortTextIsOneBlock() {
        assertEquals(listOf("hello\nworld"), TextBlocks.split("hello\nworld", 100))
    }

    @Test
    fun emptyTextIsOneEmptyBlock() {
        assertEquals(listOf(""), TextBlocks.split("", 100))
    }

    @Test
    fun blocksEndAtLineBreaksAndJoinBack() {
        val text = (1..500).joinToString("\n") { "line $it with some words in it" }
        val blocks = TextBlocks.split(text, 200)
        assertEquals(text, blocks.joinToString(""))
        assertTrue(blocks.all { it.length <= 200 })
        assertTrue(blocks.dropLast(1).all { it.endsWith("\n") })
    }

    @Test
    fun aLineLongerThanTheLimitIsCut() {
        val text = "a".repeat(1_050)
        val blocks = TextBlocks.split(text, 100)
        assertEquals(11, blocks.size)
        assertEquals(text, blocks.joinToString(""))
        assertEquals(50, blocks.last().length)
    }

    @Test
    fun mixedLongAndShortLinesJoinBack() {
        val text = "short\n" + "b".repeat(250) + "\nend\n" + "c".repeat(90)
        val blocks = TextBlocks.split(text, 100)
        assertEquals(text, blocks.joinToString(""))
        assertTrue(blocks.all { it.length <= 100 })
    }

    @Test
    fun aMegabyteSplitsQuickly() {
        val text = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n".repeat(16_384)
        val start = System.nanoTime()
        val blocks = TextBlocks.split(text)
        val ms = (System.nanoTime() - start) / 1_000_000
        assertEquals(text, blocks.joinToString(""))
        assertTrue("split took $ms ms", ms < 500)
    }
}
