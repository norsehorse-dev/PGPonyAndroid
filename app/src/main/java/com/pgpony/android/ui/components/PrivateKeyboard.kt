// PrivateKeyboard.kt
// PGPony Android, 4.8.0 RC10 (#86): ask the keyboard not to learn from what is
// typed in PGPony.
//
// A tester asked for the keyboard's private (incognito) mode on PGPony's text
// fields. Android's flag for that is EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING:
// the keyboard should not add what is typed to its dictionary or history.
// Keyboards already kept passphrase fields out of their learning because those
// are password fields (KeyboardType.Password, 4.0.3); this asks for it on every
// field, messages, names and comments included. Compose has no
// KeyboardOptions field for it, so the documented way is used: intercept the
// platform text input request and OR the flag into the EditorInfo. It wraps
// PGPonyTheme's content, which is the root of every activity with text input
// (MainActivity, the OpenPGP API dialogs, the share target, process text), and
// dialogs and sheets inherit it through the composition. Always on, no
// setting: this is a privacy app. A keyboard may ignore the flag; Gboard and
// the keyboards that show an incognito mode honour it.

package com.pgpony.android.ui.components

import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.compose.runtime.Composable
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputMethodRequest

/** Every text field in [content] asks the keyboard for its private mode. */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun PrivateKeyboard(content: @Composable () -> Unit) {
    InterceptPlatformTextInput(
        interceptor = { request, nextHandler ->
            val privateRequest = object : PlatformTextInputMethodRequest {
                override fun createInputConnection(outAttributes: EditorInfo): InputConnection =
                    request.createInputConnection(outAttributes).also {
                        outAttributes.imeOptions = withNoPersonalizedLearning(outAttributes.imeOptions)
                    }
            }
            nextHandler.startInputMethod(privateRequest)
        },
        content = content
    )
}

/** [imeOptions] with the no-personalized-learning flag set; the other options are kept. */
internal fun withNoPersonalizedLearning(imeOptions: Int): Int =
    imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
