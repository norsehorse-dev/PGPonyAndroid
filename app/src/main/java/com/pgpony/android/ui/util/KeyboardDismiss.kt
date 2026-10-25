// KeyboardDismiss.kt
// PGPony Android, 4.7.2: close the keyboard when the user taps away from a text field.
//
// Compose keeps a text field focused, and the keyboard up, when the user taps something that is
// not a text field (a recipient row, a switch, a button, empty space). Android leaves dropping it
// to the app. On Encrypt and Decrypt that left the keyboard over the lower half of the screen
// while the user moved down to recipients, options and the output (user report, Oct 24).
//
// dismissKeyboardOnTap() goes on a screen's content. It watches taps in the Initial pass, so it
// sees them before any child handles them, and consumes nothing: buttons, rows and switches work
// as before. A tap (no drag beyond the touch slop, one finger) that does not land on a text field
// marked keepsKeyboard() clears focus and hides the keyboard. A scroll never closes it.
//
// Every text field inside such a screen must carry keepsKeyboard(); one without it would lose
// focus on the tap that gives it focus, and the keyboard would flicker.

package com.pgpony.android.ui.util

import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.LayoutCoordinates
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController

/** Text fields on screen that keep the keyboard when tapped. UI thread only. */
internal object KeyboardFields {
    private val fields = HashMap<Any, LayoutCoordinates>()

    fun put(id: Any, coordinates: LayoutCoordinates) { fields[id] = coordinates }
    fun remove(id: Any) { fields.remove(id) }

    fun boundsInWindow(): List<Rect> =
        fields.values.filter { it.isAttached }.map { it.boundsInWindow() }
}

/** True when [point] falls inside any of [areas]. Pure, for tests. */
internal fun insideAny(point: Offset, areas: List<Rect>): Boolean = areas.any { it.contains(point) }

/** Marks a text field: tapping it never closes the keyboard. */
fun Modifier.keepsKeyboard(): Modifier = composed {
    val id = remember { Any() }
    DisposableEffect(id) { onDispose { KeyboardFields.remove(id) } }
    onGloballyPositioned { KeyboardFields.put(id, it) }
}

/** On a screen's content: a tap outside every text field closes the keyboard. */
fun Modifier.dismissKeyboardOnTap(): Modifier = composed {
    val focusManager = LocalFocusManager.current
    val keyboard = LocalSoftwareKeyboardController.current
    val holder = remember { arrayOfNulls<LayoutCoordinates>(1) }
    this
        .onGloballyPositioned { holder[0] = it }
        .pointerInput(Unit) {
            awaitEachGesture {
                val down = awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
                val start = down.position
                var tap = true
                while (true) {
                    val event = awaitPointerEvent(PointerEventPass.Initial)
                    if (event.changes.size > 1) tap = false
                    val change = event.changes.firstOrNull { it.id == down.id } ?: break
                    if ((change.position - start).getDistance() > viewConfiguration.touchSlop) tap = false
                    if (!change.pressed) break
                }
                if (!tap) return@awaitEachGesture
                val coordinates = holder[0]?.takeIf { it.isAttached } ?: return@awaitEachGesture
                if (insideAny(coordinates.localToWindow(start), KeyboardFields.boundsInWindow())) {
                    return@awaitEachGesture
                }
                focusManager.clearFocus()
                keyboard?.hide()
            }
        }
}
