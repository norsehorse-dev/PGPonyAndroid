// TooltipState.kt
// PGPony Android
//
// SharedPreferences-backed registry of one-time tooltip flags. Each tooltip
// has a unique key like "keyring_fab", stored under "tooltip_shown_keyring_fab".
//
// Used by ScreenTooltip (Tooltip.kt) and by the "Reset Tips" row in
// SettingsScreen to wipe all tooltip flags at once.
//
// Added in Phase 4 (Tester Feedback Implementation Plan).

package com.pgpony.android.ui.components

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext

class TooltipState(private val prefs: SharedPreferences) {

    /** Returns true if the tooltip with the given key has NOT yet been shown. */
    fun shouldShow(key: String): Boolean =
        !prefs.getBoolean("tooltip_shown_$key", false)

    /** Persist that the tooltip with the given key has been shown to the user. */
    fun markShown(key: String) {
        prefs.edit().putBoolean("tooltip_shown_$key", true).apply()
    }

    /**
     * Remove every tooltip_shown_* flag so all tooltips will appear again
     * the next time the user visits each screen. Called from the
     * "Reset Tips" row in Settings.
     */
    fun resetAll() {
        val editor = prefs.edit()
        prefs.all.keys
            .filter { it.startsWith("tooltip_shown_") }
            .forEach { editor.remove(it) }
        editor.apply()
    }
}

@Composable
fun rememberTooltipState(): TooltipState {
    val context = LocalContext.current
    return remember(context) {
        TooltipState(
            context.getSharedPreferences(
                "pgpony_prefs",
                Context.MODE_PRIVATE
            )
        )
    }
}
