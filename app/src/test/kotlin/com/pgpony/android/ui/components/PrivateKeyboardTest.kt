// PrivateKeyboardTest.kt
// PGPony Android, 4.8.0 RC10 (#86): the private keyboard flag is added and
// nothing else the field asked for is lost.

package com.pgpony.android.ui.components

import android.view.inputmethod.EditorInfo
import org.junit.Assert.assertEquals
import org.junit.Test

class PrivateKeyboardTest {

    @Test fun `the flag is added and the action and other flags are kept`() {
        val asked = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_FULLSCREEN
        val sent = withNoPersonalizedLearning(asked)
        assertEquals(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING, sent and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING)
        assertEquals(EditorInfo.IME_ACTION_DONE, sent and EditorInfo.IME_MASK_ACTION)
        assertEquals(EditorInfo.IME_FLAG_NO_FULLSCREEN, sent and EditorInfo.IME_FLAG_NO_FULLSCREEN)
        assertEquals(sent, withNoPersonalizedLearning(sent))
    }
}
