// OfflineMode.kt
// PGPony Android, RC1 offline switch (hard gate)
//
// One persisted flag that turns the app fully offline: no WKD lookup, no
// keyserver search or publish, no update check, no background key refresh.
// Two readers with different needs:
//
//   isEnabled(): reads the pref directly, so it is authoritative and works
//     in any process (including :remote_api) without the observable below
//     being seeded. The network choke point (HttpClientFactory) and the
//     background workers gate on this.
//   enabled: a Compose-observable mirror, seeded once in PGPonyApp and
//     updated by set(), so the Settings and onboarding UI hide the network
//     surfaces reactively the moment the switch flips.

package com.pgpony.android.network

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.pgpony.android.PGPonyApp

object OfflineMode {

    private const val PREFS = "pgpony_prefs"
    const val KEY_ENABLED = "offline_mode_enabled"
    const val DEFAULT = false

    private fun prefsOrNull() = runCatching {
        PGPonyApp.instance.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }.getOrNull()

    /** Authoritative, process-safe. The network layer and workers gate here. */
    fun isEnabled(): Boolean =
        prefsOrNull()?.getBoolean(KEY_ENABLED, DEFAULT) ?: DEFAULT

    /** Compose-observable mirror for the UI. Seeded by [initFromPrefs]. */
    var enabled by mutableStateOf(DEFAULT)
        private set

    fun initFromPrefs() {
        enabled = isEnabled()
    }

    fun set(value: Boolean) {
        prefsOrNull()?.edit()?.putBoolean(KEY_ENABLED, value)?.apply()
        enabled = value
    }
}
