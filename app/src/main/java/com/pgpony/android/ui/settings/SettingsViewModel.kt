// SettingsViewModel.kt
// PGPony Android
//
// ViewModel for the Settings tab. Manages preferences via SharedPreferences
// and key stats from the repository. Matches iOS SettingsView + AppState.
//
// Phase 1 additions (v1.1.0): public showError / showSuccess so the
// Composable layer can trigger snackbars from new Support actions.

package com.pgpony.android.ui.settings

import android.content.Context
import android.content.SharedPreferences
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.ArmorCommentDefaults
import com.pgpony.android.data.ArmorCommentStore
import com.pgpony.android.notifications.KeyExpirationService
import com.pgpony.android.ui.keyring.BiometricAvailability
import com.pgpony.android.ui.keyring.BiometricGate
import com.pgpony.android.ui.theme.AppTheme
import com.pgpony.android.ui.theme.ThemeState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch

data class SettingsUiState(
    // Security
    val biometricLockEnabled: Boolean = false,
    val requireBiometricForDecrypt: Boolean = false,
    val requireBiometricForSign: Boolean = false,
    // Password Store (Phase C) — opt-in feature (default off); biometric gate default on
    val passStoreEnabled: Boolean = false,
    val requireBiometricForPassStore: Boolean = true,
    // Clipboard
    val clipboardAutoClear: Boolean = true,
    val clipboardClearSeconds: Int = 60,
    // Key stats
    val totalKeys: Int = 0,
    val totalKeyPairs: Int = 0,
    val defaultKeyName: String? = null,
    val defaultKeyFingerprint: String? = null,
    // RC5 gauntlet escalation (#16/#23 follow-up): the FULL keyring,
    // revoked keys included, so the clear-all dialog can enumerate by
    // name exactly what is about to be destroyed. recipientKeyChoices
    // filters revoked keys and is wrong for this purpose.
    val clearKeysPreview: List<com.pgpony.android.data.PGPKeyEntity> = emptyList(),
    // RC5 (Kevin): one-shot signal that a clear-all completed. The
    // screen consumes it, dismisses everything, and routes back to
    // onboarding — the app should look like a fresh install.
    val clearCompleted: Boolean = false,
    // Pro
    // Data
    val showClearConfirm: Boolean = false,
    val showClearStep2: Boolean = false,
    val isClearing: Boolean = false,
    // Messages
    val errorMessage: String? = null,
    val successMessage: String? = null,
    // ── Phase A12: appearance + reminders ──────────────────────────
    //
    // selectedTheme is the persisted theme mode (system/light/dark).
    // Read in loadPreferences from SharedPreferences key
    // "selected_theme"; written by setTheme. PGPonyTheme in
    // MainActivity reads the same pref reactively for the actual
    // color scheme switch.
    val selectedTheme: AppTheme = AppTheme.System,
    // keyExpirationRemindersEnabled controls whether
    // KeyExpirationService schedules notifications when keys near
    // expiration. Persisted to SharedPreferences key
    // "key_expiration_reminders". Default off — opt-in feature so
    // we don't request POST_NOTIFICATIONS permission unprompted.
    val keyExpirationRemindersEnabled: Boolean = false,
    // notificationPermissionGranted reflects the API 33+
    // POST_NOTIFICATIONS runtime grant. Read at view appearance to
    // surface a "Permission needed" inline hint if the user has the
    // reminders toggle on but the system permission isn't granted.
    val notificationPermissionGranted: Boolean = true,
    // ── Armor comment header (DataStore-backed) ─────────────────────
    //
    // armorCommentInclude is the master toggle ("Include comment in PGP
    // output", default ON). armorCommentText is the raw, un-sanitized
    // custom string the user typed. The actual line embedded in armored
    // output is ArmorCommentValidator.validate(include, text) — the
    // Settings screen renders that same validated value as a live
    // preview so what the user sees matches what gets written. Persisted
    // via ArmorCommentStore (DataStore); survives app restart.
    val armorCommentInclude: Boolean = true,
    val armorCommentText: String = ArmorCommentDefaults.DEFAULT_COMMENT,
    // 4.0.0 Phase 9b (iOS 7.1.x parity) — independent toggle for the
    // Comment header on user-facing public key exports (copy / share /
    // save). Default ON, matching iOS. Persisted via ArmorCommentStore
    // (DataStore) alongside the message toggle; keyserver uploads and
    // QR codes stay comment-free regardless.
    val armorCommentPubkeyInclude: Boolean = true,
    // 4.0.0 Phase 9b (iOS v7.1.1 parity) — whether closing an
    // encryption result wipes the composed inputs (message, files,
    // bundle body + attachments, passwords). Default ON preserves the
    // 3.1.0 Phase 5 always-on behavior existing installs have today.
    // Persisted to SharedPreferences key "clear_inputs_after_encrypt";
    // EncryptDecryptViewModel reads it live at each result dismissal.
    val clearInputsAfterEncrypt: Boolean = true,
    // darkvegas interop: passphrase encryption uses gpg-friendly S2K type 3 by
    // default; this opts back into Argon2id (needs GnuPG 2.4+). Default off.
    val useArgon2: Boolean = false,
    // ── Phase A4: default / remembered recipient ────────────────────────
    val defaultRecipientMode: DefaultRecipientMode = DefaultRecipientMode.NONE,
    /** Fingerprint of the pinned recipient (PINNED mode). */
    val defaultRecipientFingerprint: String? = null,
    /** Candidate recipient keys for the pinned picker (all non-revoked keys). */
    val recipientKeyChoices: List<PGPKeyEntity> = emptyList()
)

class SettingsViewModel(
    private val repo: KeyRepository,
    private val prefs: SharedPreferences
) : ViewModel() {

    private val _state = MutableStateFlow(SettingsUiState())
    val state: StateFlow<SettingsUiState> = _state.asStateFlow()

    // DataStore-backed armor comment store. Resolved from the process
    // singleton so the ViewModelFactory signature stays untouched (it
    // only knows about repo + SharedPreferences).
    private val armorStore = ArmorCommentStore.get(PGPonyApp.instance)

    init {
        loadPreferences()
        loadKeyStats()
        observeArmorComment()
    }

    // ── Armor comment header ────────────────────────────────────────
    //
    // observeArmorComment mirrors the persisted DataStore values into UI
    // state. setArmorCommentInclude / setArmorCommentText update state
    // immediately for a responsive UI, then persist asynchronously; the
    // collector above will re-emit the same persisted value (idempotent,
    // no flicker). The crypto cache (ArmorCommentHeader.current) is
    // refreshed inside the store on every write.
    private fun observeArmorComment() {
        viewModelScope.launch {
            combine(
                armorStore.includeFlow,
                armorStore.pubkeyIncludeFlow,
                armorStore.textFlow
            ) { include, pubkeyInclude, text ->
                Triple(include, pubkeyInclude, text)
            }.collect { (include, pubkeyInclude, text) ->
                _state.value = _state.value.copy(
                    armorCommentInclude = include,
                    armorCommentPubkeyInclude = pubkeyInclude,
                    armorCommentText = text
                )
            }
        }
    }

    fun setArmorCommentInclude(enabled: Boolean) {
        _state.value = _state.value.copy(armorCommentInclude = enabled)
        viewModelScope.launch { armorStore.setInclude(enabled) }
    }

    /** 4.0.0 Phase 9b — toggle the Comment header on user-facing public
     *  key exports (copy / share / save). */
    fun setArmorCommentPubkeyInclude(enabled: Boolean) {
        _state.value = _state.value.copy(armorCommentPubkeyInclude = enabled)
        viewModelScope.launch { armorStore.setPubkeyInclude(enabled) }
    }

    fun setArmorCommentText(text: String) {
        _state.value = _state.value.copy(armorCommentText = text)
        viewModelScope.launch { armorStore.setText(text) }
    }

    /** 4.0.0 Phase 9b (iOS v7.1.1 parity) — toggle the auto-wipe of
     *  composed inputs when an encryption result is closed. Read live
     *  by EncryptDecryptViewModel at each dismissal, so the change
     *  applies to the very next result close. */
    fun setClearInputsAfterEncrypt(enabled: Boolean) {
        prefs.edit().putBoolean("clear_inputs_after_encrypt", enabled).apply()
        _state.value = _state.value.copy(clearInputsAfterEncrypt = enabled)
    }

    /** darkvegas interop: opt into Argon2id passphrase protection. Off by
     *  default so PGPony files open in stock gpg on Linux. */
    fun setUseArgon2(enabled: Boolean) {
        prefs.edit().putBoolean("use_argon2", enabled).apply()
        _state.value = _state.value.copy(useArgon2 = enabled)
    }

    /** RC5 P3 (#23): public so SettingsScreen can re-read persisted
     *  preferences on entry. The onboarding biometric toggle (slide 5)
     *  writes `biometric_lock` directly to prefs, and this ViewModel is
     *  constructed BEFORE onboarding runs, so its init-time snapshot can
     *  go stale: the Settings switch then shows off while the lock is
     *  actually armed. Re-reading on screen entry keeps the UI truthful
     *  for any pref mutated outside this ViewModel. */
    fun loadPreferences() {
        _state.value = _state.value.copy(
            biometricLockEnabled = prefs.getBoolean("biometric_lock", false),
            requireBiometricForDecrypt = prefs.getBoolean("biometric_decrypt", false),
            requireBiometricForSign = prefs.getBoolean("biometric_sign", false),
            passStoreEnabled = prefs.getBoolean("pass_store_enabled", false),
            requireBiometricForPassStore = prefs.getBoolean("biometric_pass_store", true),
            clipboardAutoClear = prefs.getBoolean("clipboard_auto_clear", true),
            clipboardClearSeconds = prefs.getInt("clipboard_clear_seconds", 60),
            // 4.0.0 Phase 9b — auto-wipe toggle; default ON preserves the
            // 3.1.0 always-on behavior.
            clearInputsAfterEncrypt = prefs.getBoolean("clear_inputs_after_encrypt", true),
            useArgon2 = prefs.getBoolean("use_argon2", false),
            // ── Phase A12: theme + reminders persisted prefs ────
            selectedTheme = AppTheme.fromStorage(prefs.getString("selected_theme", null)),
            keyExpirationRemindersEnabled = prefs.getBoolean("key_expiration_reminders", false),
            // Phase A4 — default/remembered recipient.
            defaultRecipientMode = DefaultRecipientPrefs.mode(prefs),
            defaultRecipientFingerprint = DefaultRecipientPrefs.pinnedFingerprint(prefs)
        )
    }

    // ── Phase A12: theme picker ─────────────────────────────────────
    //
    // setTheme persists the user's pick to "selected_theme" and updates
    // state. The actual color scheme application happens in
    // MainActivity.PGPonyTheme which re-reads the pref on each
    // composition — so a theme change here triggers a UI refresh via
    // the state copy alone (Settings screen reads state.selectedTheme;
    // the Composable graph recomposes; PGPonyTheme re-reads prefs).
    //
    // Phase A12 Fix1: also write to ThemeState.current. This is the
    // observable MutableState that PGPonyTheme actually subscribes to.
    // Without this line the SharedPreferences write goes through but
    // PGPonyTheme never gets a recomposition signal, so the theme
    // only changes on next activity launch. With it the entire
    // composition tree below PGPonyTheme re-themes instantly.
    fun setTheme(theme: AppTheme) {
        prefs.edit().putString("selected_theme", theme.storageKey).apply()
        _state.value = _state.value.copy(selectedTheme = theme)
        ThemeState.current.value = theme
    }

    // ── Phase A12: key-expiration reminders ─────────────────────────
    //
    // setKeyExpirationReminders flips the persisted toggle. The
    // actual notification scheduling is handled by KeyExpirationService
    // — Settings UI calls service.scheduleReminders(...) after toggling
    // on, and service.cancelAll() after toggling off. We don't do that
    // here because the service needs Context (and access to the key
    // repository), which the UI layer has but the ViewModel doesn't
    // by default. Same pattern as A11's setBiometricLock.
    //
    // updateNotificationPermissionGranted is a passive setter the UI
    // calls after the system permission dialog returns so the
    // Settings screen can render a "Grant permission" hint inline
    // when the toggle is on but the runtime grant is missing.
    fun setKeyExpirationReminders(context: Context, enabled: Boolean) {
        prefs.edit().putBoolean("key_expiration_reminders", enabled).apply()
        _state.value = _state.value.copy(keyExpirationRemindersEnabled = enabled)
        // Schedule or cancel alarms in the background. The repository
        // fetch + AlarmManager calls are both cheap but not free, so
        // off-thread is appropriate. Caller (SettingsScreen toggle
        // onCheckedChange) is responsible for handling the
        // POST_NOTIFICATIONS runtime permission on API 33+ before
        // calling this with enabled=true — without the grant,
        // alarms will still schedule but the eventual notify() will
        // be silently dropped by the system.
        viewModelScope.launch {
            val keys = repo.getAllKeys()
            if (enabled) {
                KeyExpirationService.scheduleReminders(context, keys)
            } else {
                KeyExpirationService.cancelAll(context, keys)
            }
        }
    }

    fun updateNotificationPermissionGranted(granted: Boolean) {
        _state.value = _state.value.copy(notificationPermissionGranted = granted)
    }

    fun loadKeyStats() {
        viewModelScope.launch {
            val all = repo.getAllKeys()
            val pairs = all.filter { it.isKeyPair }
            val defaultKey = repo.getDefaultKey()
            _state.value = _state.value.copy(
                totalKeys = all.size,
                totalKeyPairs = pairs.size,
                clearKeysPreview = all,
                defaultKeyName = defaultKey?.let {
                    it.userName.ifBlank { it.userEmail }
                },
                defaultKeyFingerprint = defaultKey?.shortFingerprint,
                // Phase A4 — pinned-recipient candidates: any non-revoked key
                // with a usable public half (the same pool the encrypt picker
                // offers as a recipient).
                recipientKeyChoices = all.filter {
                    !it.isRevoked && (!it.isCardBacked || it.armoredPublicKey != null)
                }
            )
        }
    }

    // ── Phase A4: default / remembered recipient ────────────────────────

    fun setDefaultRecipientMode(mode: DefaultRecipientMode) {
        DefaultRecipientPrefs.setMode(prefs, mode)
        // Picking PINNED with no key chosen yet defaults to the current
        // default key (usually the user's own), the common "encrypt to me" case.
        if (mode == DefaultRecipientMode.PINNED &&
            _state.value.defaultRecipientFingerprint == null
        ) {
            val fallback = _state.value.recipientKeyChoices.firstOrNull {
                it.isKeyPair
            }?.fingerprint
            if (fallback != null) {
                DefaultRecipientPrefs.setPinnedFingerprint(prefs, fallback)
                _state.value = _state.value.copy(
                    defaultRecipientMode = mode,
                    defaultRecipientFingerprint = fallback,
                )
                return
            }
        }
        _state.value = _state.value.copy(defaultRecipientMode = mode)
    }

    fun setDefaultRecipientKey(fingerprint: String) {
        DefaultRecipientPrefs.setPinnedFingerprint(prefs, fingerprint)
        _state.value = _state.value.copy(defaultRecipientFingerprint = fingerprint)
    }

    // ── Security ───────────────────────────────────────────────────────

    fun setBiometricLock(context: Context, enabled: Boolean) {
        // Phase A11: capability gate. Setting the flag to true is
        // only meaningful if the device can actually authenticate.
        // If biometric (or device credential) isn't available, we
        // refuse the request and surface an actionable error message
        // instead of silently flipping a flag that would lock the
        // user out at next launch. The disable path (enabled=false)
        // is always allowed — no capability check needed to unlock.
        //
        // Context is passed in by the UI layer (SettingsScreen reads
        // it from LocalContext.current) rather than threaded through
        // the constructor — keeps the ViewModelFactory untouched.
        if (enabled) {
            val availability = BiometricGate.canAuthenticate(context)
            if (availability != BiometricAvailability.Available) {
                _state.value = _state.value.copy(
                    errorMessage = context.getString(R.string.settings_biometric_unavailable_error)
                )
                return
            }
        }
        prefs.edit().putBoolean("biometric_lock", enabled).apply()
        _state.value = _state.value.copy(biometricLockEnabled = enabled)
        if (!enabled) {
            prefs.edit().putBoolean("biometric_decrypt", false).apply()
            _state.value = _state.value.copy(requireBiometricForDecrypt = false)
        }
    }

    fun setRequireBiometricForDecrypt(enabled: Boolean) {
        prefs.edit().putBoolean("biometric_decrypt", enabled).apply()
        _state.value = _state.value.copy(requireBiometricForDecrypt = enabled)
    }

    fun setRequireBiometricForSign(enabled: Boolean) {
        prefs.edit().putBoolean("biometric_sign", enabled).apply()
        _state.value = _state.value.copy(requireBiometricForSign = enabled)
    }

    // ── Password Store (Phase C) ───────────────────────────────────────

    fun setPassStoreEnabled(enabled: Boolean) {
        prefs.edit().putBoolean("pass_store_enabled", enabled).apply()
        _state.value = _state.value.copy(passStoreEnabled = enabled)
    }

    fun setRequireBiometricForPassStore(enabled: Boolean) {
        prefs.edit().putBoolean("biometric_pass_store", enabled).apply()
        _state.value = _state.value.copy(requireBiometricForPassStore = enabled)
    }

    // ── Clipboard ──────────────────────────────────────────────────────

    fun setClipboardAutoClear(enabled: Boolean) {
        prefs.edit().putBoolean("clipboard_auto_clear", enabled).apply()
        _state.value = _state.value.copy(clipboardAutoClear = enabled)
    }

    fun setClipboardClearSeconds(seconds: Int) {
        prefs.edit().putInt("clipboard_clear_seconds", seconds).apply()
        _state.value = _state.value.copy(clipboardClearSeconds = seconds)
    }

    // ── Data ───────────────────────────────────────────────────────────

    fun showClearConfirm() {
        _state.value = _state.value.copy(showClearConfirm = true)
    }

    fun showClearStep2() {
        _state.value = _state.value.copy(showClearConfirm = false, showClearStep2 = true)
    }

    fun dismissClear() {
        _state.value = _state.value.copy(showClearConfirm = false, showClearStep2 = false)
    }

    fun clearAllData() {
        viewModelScope.launch {
            _state.value = _state.value.copy(isClearing = true, showClearStep2 = false)
            try {
                val allKeys = repo.getAllKeys()
                for (key in allKeys) {
                    repo.deleteKey(key)
                }
                // RC5 (Kevin): reinstall semantics. Wipe the whole prefs
                // file — onboarding_completed, biometric_lock, theme,
                // cache durations, fallback strict flags, all of it —
                // and drop any held provider passphrases. The app then
                // routes back to onboarding exactly like a fresh
                // install (the screen consumes clearCompleted below).
                prefs.edit().clear().apply()
                com.pgpony.android.provider.ProviderPassphraseCache.clearAll()
                // #2.1: clear the provider process's cache too.
                com.pgpony.android.provider.ProviderCacheClearReceiver.requestClearAll()
                // Fresh default state, not a patch of the old one: every
                // pref-backed field must read as factory-new, and the
                // dialog flags must drop so the gauntlet dismisses.
                _state.value = SettingsUiState(clearCompleted = true)
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isClearing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.settings_data_clear_error_format, e.message ?: "")
                )
            }
        }
    }

    /** RC5 (Kevin): the screen acknowledges the clear-all completion
     *  after routing to onboarding, so the signal fires exactly once. */
    fun consumeClearCompleted() {
        _state.value = _state.value.copy(clearCompleted = false)
    }

    // ── Snackbar helpers (Phase 1) ─────────────────────────────────────
    // Public so the Composable can surface errors/successes from
    // non-VM actions like external intents.

    fun showError(message: String) {
        _state.value = _state.value.copy(errorMessage = message)
    }

    fun showSuccess(message: String) {
        _state.value = _state.value.copy(successMessage = message)
    }

    fun clearError() { _state.value = _state.value.copy(errorMessage = null) }
    fun clearSuccess() { _state.value = _state.value.copy(successMessage = null) }
}
