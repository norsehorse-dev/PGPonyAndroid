package com.pgpony.android.ui.settings

import android.content.SharedPreferences

/**
 * Phase A4 — default / remembered recipient.
 *
 * A persisted preference that pre-selects the encrypt recipient so the user
 * doesn't re-pick on every encrypt (main use case: encrypting to oneself).
 * Three modes; the chosen fingerprint is matched against the live recipient
 * pool at encrypt time, so a stale/deleted key simply pre-selects nothing.
 *
 * Distinct from the `isDefault` signing identity — this is the *recipient*
 * default, not the signing key.
 */
enum class DefaultRecipientMode(val storageKey: String) {
    /** Current behavior — no pre-selection. */
    NONE("none"),
    /** Always pre-select one pinned recipient key (by fingerprint). */
    PINNED("pinned"),
    /** Pre-select the most-recently-used recipient. */
    REMEMBER_LAST("last");

    companion object {
        fun fromStorage(value: String?): DefaultRecipientMode =
            entries.firstOrNull { it.storageKey == value } ?: NONE
    }
}

/**
 * Single source of truth for the default-recipient pref keys + logic, shared
 * by SettingsViewModel (writes), EncryptDecryptViewModel and
 * ShareTargetViewModel (read the pre-selection on load).
 */
object DefaultRecipientPrefs {
    private const val KEY_MODE = "default_recipient_mode"
    private const val KEY_PINNED_FP = "default_recipient_fp"
    private const val KEY_LAST_FP = "last_recipient_fp"

    fun mode(prefs: SharedPreferences): DefaultRecipientMode =
        DefaultRecipientMode.fromStorage(prefs.getString(KEY_MODE, null))

    fun pinnedFingerprint(prefs: SharedPreferences): String? =
        prefs.getString(KEY_PINNED_FP, null)

    fun lastFingerprint(prefs: SharedPreferences): String? =
        prefs.getString(KEY_LAST_FP, null)

    fun setMode(prefs: SharedPreferences, mode: DefaultRecipientMode) {
        prefs.edit().putString(KEY_MODE, mode.storageKey).apply()
    }

    fun setPinnedFingerprint(prefs: SharedPreferences, fingerprint: String?) {
        prefs.edit().putString(KEY_PINNED_FP, fingerprint).apply()
    }

    /** Record the recipient just used, for REMEMBER_LAST. Always safe to call. */
    fun recordLastUsed(prefs: SharedPreferences, fingerprint: String?) {
        if (fingerprint.isNullOrBlank()) return
        prefs.edit().putString(KEY_LAST_FP, fingerprint).apply()
    }

    /**
     * The fingerprint to pre-select given the current mode, or null for NONE /
     * when nothing is remembered yet. Callers match this against their live
     * recipient pool (so a missing key pre-selects nothing).
     */
    fun preselectFingerprint(prefs: SharedPreferences): String? =
        when (mode(prefs)) {
            DefaultRecipientMode.NONE -> null
            DefaultRecipientMode.PINNED -> pinnedFingerprint(prefs)
            DefaultRecipientMode.REMEMBER_LAST -> lastFingerprint(prefs)
        }
}
