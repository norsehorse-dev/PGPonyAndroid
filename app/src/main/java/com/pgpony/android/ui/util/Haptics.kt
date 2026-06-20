// Haptics.kt
// PGPony Android
//
// Lightweight haptic helpers usable from any Composable.
//
// Why not LocalHapticFeedback? The Compose 1.7.x HapticFeedbackType enum
// only exposes LongPress and TextHandleMove, which can't distinguish
// "operation succeeded" from "tapped a button". We want a richer palette,
// so we fall through to View.performHapticFeedback with the platform
// HapticFeedbackConstants — and gate the newer constants on API level.

package com.pgpony.android.ui.util

import android.os.Build
import android.view.HapticFeedbackConstants
import android.view.View
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalView

/**
 * Callbacks bundle returned from [rememberHaptics]. Call from any onClick,
 * onSuccess, etc. without needing to thread a View through your composables.
 */
class HapticsCallbacks internal constructor(private val view: View) {

    /**
     * Strong "operation succeeded" feedback. Use after an encrypt, decrypt,
     * import, or scan completes successfully. Falls back to VIRTUAL_KEY on
     * API < 30 where CONFIRM isn't available.
     */
    fun success() {
        val constant = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            HapticFeedbackConstants.CONFIRM
        } else {
            HapticFeedbackConstants.VIRTUAL_KEY
        }
        view.performHapticFeedback(constant)
    }

    /**
     * Light tap, suitable for copy-to-clipboard and other discrete actions
     * that don't warrant a full success thump.
     */
    fun tap() {
        view.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
    }

    /**
     * Negative feedback for errors. Currently unused but exposed for
     * future call sites.
     */
    fun reject() {
        val constant = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            HapticFeedbackConstants.REJECT
        } else {
            HapticFeedbackConstants.LONG_PRESS
        }
        view.performHapticFeedback(constant)
    }
}

/**
 * Remember a [HapticsCallbacks] bound to the current Compose view. Cheap;
 * call freely from any composable that needs haptic feedback.
 */
@Composable
fun rememberHaptics(): HapticsCallbacks {
    val view = LocalView.current
    return remember(view) { HapticsCallbacks(view) }
}
