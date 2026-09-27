// KeyValueSettings.kt
// PGPony Android, 4.7.0: the settings seam.
//
// Small settings stores (publication records, removed User ID tombstones, the
// WKD flag, the fallback strict-mode flag) used to reach SharedPreferences
// through PGPonyApp.instance. That tied portable code to Android, so PGPony
// Desktop had to exclude each file and keep a hand-written twin. This
// interface is the one place those stores touch storage. Android installs a
// SharedPreferences implementation at startup (platform/SharedPreferencesSettings);
// Desktop installs one over java.util.prefs. The stores vendor to Desktop
// verbatim.
//
// Semantics match what the stores already did: when no implementation is
// installed, or opening one fails, SettingsStores.open returns null and the
// store falls back to its default (reads) or does nothing (writes).

package com.pgpony.android.data.settings

interface KeyValueSettings {
    fun getString(key: String, default: String?): String?
    fun getBoolean(key: String, default: Boolean): Boolean
    fun getLong(key: String, default: Long): Long
    fun getStringSet(key: String, default: Set<String>): Set<String>

    fun putString(key: String, value: String?)
    fun putBoolean(key: String, value: Boolean)
    fun putLong(key: String, value: Long)
    fun putStringSet(key: String, value: Set<String>)
    fun remove(key: String)
}

/** Where a platform installs its [KeyValueSettings] implementation. */
object SettingsStores {

    /** The shared app settings file on Android ("pgpony_prefs"). */
    const val APP_PREFS = "pgpony_prefs"

    /** Opens the named store; [multiProcess] maps to MODE_MULTI_PROCESS on Android. */
    fun interface Factory {
        fun open(name: String, multiProcess: Boolean): KeyValueSettings
    }

    @Volatile
    private var factory: Factory? = null

    fun install(f: Factory) {
        factory = f
    }

    /** Test hook: forget the installed implementation. */
    fun uninstall() {
        factory = null
    }

    fun open(name: String = APP_PREFS, multiProcess: Boolean = false): KeyValueSettings? =
        runCatching { factory?.open(name, multiProcess) }.getOrNull()
}

/** A process-local store for unit tests and for callers that must not persist. */
class InMemoryKeyValueSettings : KeyValueSettings {
    private val map = java.util.concurrent.ConcurrentHashMap<String, Any>()

    override fun getString(key: String, default: String?): String? = map[key] as? String ?: default
    override fun getBoolean(key: String, default: Boolean): Boolean = map[key] as? Boolean ?: default
    override fun getLong(key: String, default: Long): Long = map[key] as? Long ?: default

    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String, default: Set<String>): Set<String> =
        (map[key] as? Set<String>)?.toSet() ?: default

    override fun putString(key: String, value: String?) {
        if (value == null) map.remove(key) else map[key] = value
    }
    override fun putBoolean(key: String, value: Boolean) { map[key] = value }
    override fun putLong(key: String, value: Long) { map[key] = value }
    override fun putStringSet(key: String, value: Set<String>) { map[key] = value.toSet() }
    override fun remove(key: String) { map.remove(key) }
}
