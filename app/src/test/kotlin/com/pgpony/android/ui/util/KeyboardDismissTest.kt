// KeyboardDismissTest.kt
// PGPony Android, 4.7.2: a tap closes the keyboard only outside every marked text field.
// 4.8.2 (#130): and a long press is not a tap, so selecting text keeps its selection.

package com.pgpony.android.ui.util

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyboardDismissTest {

    private val message = Rect(16f, 100f, 1064f, 400f)
    private val password = Rect(16f, 900f, 1064f, 1000f)

    @Test
    fun aTapInAFieldKeepsTheKeyboard() {
        assertTrue(insideAny(Offset(500f, 250f), listOf(message, password)))
        assertTrue(insideAny(Offset(20f, 950f), listOf(message, password)))
    }

    @Test
    fun aTapOutsideEveryFieldClosesIt() {
        assertFalse(insideAny(Offset(500f, 600f), listOf(message, password)))
        assertFalse(insideAny(Offset(5f, 250f), listOf(message, password)))
    }

    @Test
    fun noFieldsMeansEveryTapCloses() {
        assertFalse(insideAny(Offset(500f, 250f), emptyList()))
    }

    @Test
    fun aQuickTapIsATap() {
        assertTrue(isDismissTap(moved = false, multiTouch = false, heldMs = 90, longPressTimeoutMs = 400))
    }

    @Test
    fun aLongPressIsNotATap() {
        // #130: long-press a word in the decrypted text, then lift: the selection stays.
        assertFalse(isDismissTap(moved = false, multiTouch = false, heldMs = 400, longPressTimeoutMs = 400))
        assertFalse(isDismissTap(moved = false, multiTouch = false, heldMs = 1200, longPressTimeoutMs = 400))
    }

    @Test
    fun aDragOrTwoFingersIsNotATap() {
        assertFalse(isDismissTap(moved = true, multiTouch = false, heldMs = 90, longPressTimeoutMs = 400))
        assertFalse(isDismissTap(moved = false, multiTouch = true, heldMs = 90, longPressTimeoutMs = 400))
    }
}
