// WkdLookup.kt
// PGPony Android — 4.5.0 item 21
//
// One persisted flag for whether Web Key Directory is consulted during
// email lookups. WKD is normally the FIRST source in the chain
// (WKD -> configured servers -> keys.openpgp.org); the Settings key-server
// list surfaces it as a lookup-only source (no publish target) and this
// flag lets a user drop it from the chain. Default on preserves the prior
// always-WKD behavior. Mirrors OfflineMode's process-safe pref access.

package com.pgpony.android.network

import android.content.Context
import com.pgpony.android.PGPonyApp

object WkdLookup {

    private const val PREFS = "pgpony_prefs"
    const val KEY_ENABLED = "wkd_lookup_enabled"
    const val DEFAULT = true

    private fun prefsOrNull() = runCatching {
        PGPonyApp.instance.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }.getOrNull()

    /** Authoritative, process-safe. The lookup path gates here. */
    fun isEnabled(): Boolean =
        prefsOrNull()?.getBoolean(KEY_ENABLED, DEFAULT) ?: DEFAULT

    fun set(value: Boolean) {
        prefsOrNull()?.edit()?.putBoolean(KEY_ENABLED, value)?.apply()
    }
}
