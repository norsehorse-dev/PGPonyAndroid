// ArmorCommentValidatorTest.kt
// PGPony Android
//
// Unit tests for the armor "Comment:" header sanitizer/validator. These
// cover the exact strings produced for the GnuPG interop cases called out
// in the feature spec: default, custom, empty/removed, and odd
// characters (unicode/symbols/control) after validation.

package com.pgpony.android.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ArmorCommentValidatorTest {

    // ── Toggle behavior ─────────────────────────────────────────────

    @Test
    fun toggleOffAlwaysProducesNoHeader() {
        assertNull(ArmorCommentValidator.validate(include = false, raw = "anything"))
        assertNull(ArmorCommentValidator.validate(include = false, raw = ""))
        assertNull(
            ArmorCommentValidator.validate(
                include = false,
                raw = ArmorCommentDefaults.DEFAULT_COMMENT
            )
        )
    }

    // ── Default + custom strings ────────────────────────────────────

    @Test
    fun defaultStringPassesThroughUnchanged() {
        val result = ArmorCommentValidator.validate(
            include = true,
            raw = ArmorCommentDefaults.DEFAULT_COMMENT
        )
        assertEquals("PGPony - PGPony.app", result)
    }

    @Test
    fun customStringIsPreserved() {
        val result = ArmorCommentValidator.validate(include = true, raw = "Sent from my phone")
        assertEquals("Sent from my phone", result)
    }

    // ── Empty / removed while ON ────────────────────────────────────

    @Test
    fun emptyStringWhileOnProducesNoHeader() {
        assertNull(ArmorCommentValidator.validate(include = true, raw = ""))
    }

    @Test
    fun whitespaceOnlyProducesNoHeader() {
        assertNull(ArmorCommentValidator.validate(include = true, raw = "    \t   "))
    }

    @Test
    fun colonsOnlyProducesNoHeader() {
        assertNull(ArmorCommentValidator.validate(include = true, raw = ":::"))
    }

    // ── Single-line enforcement ─────────────────────────────────────

    @Test
    fun crlfCharactersAreStripped() {
        val result = ArmorCommentValidator.validate(include = true, raw = "line one\r\nline two")
        assertEquals("line oneline two", result)
        assertTrue(result!!.none { it == '\r' || it == '\n' })
    }

    @Test
    fun loneNewlinesAreStripped() {
        val result = ArmorCommentValidator.validate(include = true, raw = "a\nb\nc")
        assertEquals("abc", result)
    }

    // ── Control character + leading colon stripping ─────────────────

    @Test
    fun controlCharactersAreStripped() {
        // NUL, tab, vertical tab, bell mixed into otherwise printable text.
        val raw = "ab\u0000c\td\u000be\u0007f"
        val result = ArmorCommentValidator.validate(include = true, raw = raw)
        assertEquals("abcdef", result)
        assertTrue(result!!.none { it.isISOControl() })
    }

    @Test
    fun leadingColonIsStripped() {
        val result = ArmorCommentValidator.validate(include = true, raw = ":injected")
        assertEquals("injected", result)
    }

    @Test
    fun multipleLeadingColonsWithSpacesStripped() {
        val result = ArmorCommentValidator.validate(include = true, raw = "  : : value")
        assertEquals("value", result)
    }

    @Test
    fun interiorColonIsKept() {
        val result = ArmorCommentValidator.validate(include = true, raw = "ratio 16:9")
        assertEquals("ratio 16:9", result)
    }

    // ── Length cap ──────────────────────────────────────────────────

    @Test
    fun overlongStringIsCappedAt80() {
        val raw = "x".repeat(200)
        val result = ArmorCommentValidator.validate(include = true, raw = raw)
        assertEquals(80, result!!.length)
    }

    @Test
    fun exactly80IsKept() {
        val raw = "y".repeat(80)
        val result = ArmorCommentValidator.validate(include = true, raw = raw)
        assertEquals(80, result!!.length)
    }

    // ── Unicode / symbols survive (odd-characters interop case) ──────

    @Test
    fun unicodeAndSymbolsArePreserved() {
        val raw = "café ☕ — naïve ✓ £€¥"
        val result = ArmorCommentValidator.validate(include = true, raw = raw)
        assertEquals("café ☕ — naïve ✓ £€¥", result)
    }

    @Test
    fun capDoesNotSplitSurrogatePair() {
        // 79 ASCII chars, then a single astral emoji (2 UTF-16 units).
        // Capping at 80 would land mid-pair; the validator must drop the
        // whole emoji rather than emit a dangling high surrogate.
        val raw = "z".repeat(79) + "\uD83D\uDE00" // grinning face
        val result = ArmorCommentValidator.validate(include = true, raw = raw)!!
        assertEquals(79, result.length)
        assertTrue(result.none { Character.isHighSurrogate(it) || Character.isLowSurrogate(it) })
    }

    @Test
    fun surrogatePairKeptWhenItFits() {
        val raw = "z".repeat(78) + "\uD83D\uDE00" // 78 + 2 = 80 units, fits
        val result = ArmorCommentValidator.validate(include = true, raw = raw)!!
        assertEquals(80, result.length)
        assertTrue(result.endsWith("\uD83D\uDE00"))
    }

    // ── Combined adversarial input ──────────────────────────────────

    @Test
    fun malformedHeaderInputIsFullySanitized() {
        val raw = "  ::\r\nComment: evil\u0000\tpayload" + "!".repeat(100)
        val result = ArmorCommentValidator.validate(include = true, raw = raw)!!
        assertTrue(result.none { it == '\r' || it == '\n' || it.isISOControl() })
        assertTrue(!result.startsWith(":"))
        assertTrue(result.length <= ArmorCommentDefaults.MAX_LENGTH)
    }
}
