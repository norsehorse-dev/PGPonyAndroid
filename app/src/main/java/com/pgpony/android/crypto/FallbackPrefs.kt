// FallbackPrefs.kt
// PGPony Android - 4.2.0 RC4 workstream O3 (#34)
//
// Per-key strict-mode flag for the decryption-fallback list. RC3 shipped
// the fallback ORDER in the fallback_keys table but kept every remaining
// key as a trailing compatibility net, so nothing that decrypted before
// stopped decrypting. The #34 reporter read the issue as only-enabled
// semantics; this flag gives users that reading per key. Stored in
// SharedPreferences rather than a schema bump - one boolean per
// fingerprint, same precedent as keyring_manual_order.

package com.pgpony.android.crypto

import com.pgpony.android.data.settings.SettingsStores

object FallbackPrefs {

    private const val PREFS = SettingsStores.APP_PREFS
    private const val KEY_PREFIX = "fallback_strict_"

    private fun prefsOrNull() = SettingsStores.open(PREFS)

    fun isStrict(fingerprint: String): Boolean =
        prefsOrNull()?.getBoolean(KEY_PREFIX + fingerprint, false) ?: false

    fun setStrict(fingerprint: String, strict: Boolean) {
        prefsOrNull()?.putBoolean(KEY_PREFIX + fingerprint, strict)
    }
}
