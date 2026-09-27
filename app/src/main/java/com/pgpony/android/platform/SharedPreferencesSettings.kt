// SharedPreferencesSettings.kt
// PGPony Android, 4.7.0: the Android side of the settings seam
// (data/settings/KeyValueSettings.kt). Installed first thing in
// PGPonyApp.onCreate, in every process, so the stores read and write the same
// SharedPreferences files and modes they always did.

package com.pgpony.android.platform

import android.content.Context
import android.content.SharedPreferences
import com.pgpony.android.data.settings.KeyValueSettings
import com.pgpony.android.data.settings.SettingsStores

class SharedPreferencesSettings(private val prefs: SharedPreferences) : KeyValueSettings {

    override fun getString(key: String, default: String?): String? = prefs.getString(key, default)
    override fun getBoolean(key: String, default: Boolean): Boolean = prefs.getBoolean(key, default)
    override fun getLong(key: String, default: Long): Long = prefs.getLong(key, default)
    override fun getStringSet(key: String, default: Set<String>): Set<String> =
        prefs.getStringSet(key, default)?.toSet() ?: default

    override fun putString(key: String, value: String?) = prefs.edit().putString(key, value).apply()
    override fun putBoolean(key: String, value: Boolean) = prefs.edit().putBoolean(key, value).apply()
    override fun putLong(key: String, value: Long) = prefs.edit().putLong(key, value).apply()
    override fun putStringSet(key: String, value: Set<String>) =
        prefs.edit().putStringSet(key, value.toSet()).apply()
    override fun remove(key: String) = prefs.edit().remove(key).apply()

    companion object {
        @Suppress("DEPRECATION") // MODE_MULTI_PROCESS: same use as the provider's shared reads
        fun install(context: Context) {
            val app = context.applicationContext
            SettingsStores.install { name, multiProcess ->
                val mode = if (multiProcess) Context.MODE_MULTI_PROCESS else Context.MODE_PRIVATE
                SharedPreferencesSettings(app.getSharedPreferences(name, mode))
            }
        }
    }
}
