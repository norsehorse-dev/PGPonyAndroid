// KeyboardDismissTest.kt
// PGPony Android, 4.7.2: a tap closes the keyboard only outside every marked text field.

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
}
