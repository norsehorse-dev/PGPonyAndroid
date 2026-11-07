// AppReset.kt
// PGPony Android 4.7.0 (item 32): the complete reset behind Clear All Data and
// the duress wipe, moved out of SettingsViewModel so both run the same code.
//
// Item 33's reset (live keys and Recently Deleted, the secure store and its
// hardware key, every database table, pgpony_prefs, held passphrases, the card
// PIN cache, the provider process's caches) plus what it still left: the
// Keystore crypto-erase first, the DataStore settings (armor comment, key
// servers), the session policy file, the app lock, scratch and export files,
// held provider plaintext, folder grants (Password Store), expiry reminders and
// posted notifications, the clipboard, the background key refresh job, the
// fingerprint unlock key and the passphrase hold service; since 4.8.0 RC7
// (item 1) also the SSH-only keys. Every step runs even
// when an earlier one fails; the first failure is returned for Clear All Data
// to report. The app language is reset by [resetAppLocale], on the main thread.

package com.pgpony.android.data

import android.content.Context
import android.content.Intent
import com.pgpony.android.PGPonyApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

object AppReset {

    /** Who resets, which decides what is re-initialized afterwards. */
    enum class Mode {
        /** Settings > Clear All Data: the app keeps running, so the observable
         *  settings and the key refresh schedule are set up again as on a fresh
         *  install. */
        CLEAR_ALL_DATA,
        /** The duress or wrong-PIN wipe, or its resume at startup: a restart (or
         *  the rest of onCreate) follows, so nothing on screen is touched here. */
        WIPE
    }

    private inline fun MutableList<Exception>.attempt(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            add(e)
        }
    }

    /** Reset the app to a fresh install. Main process only. */
    suspend fun resetAll(context: Context, mode: Mode): Exception? = withContext(Dispatchers.IO) {
        val app = context.applicationContext
        val pgpony = PGPonyApp.instance
        val failures = mutableListOf<Exception>()

        // Crypto-erase before anything slower, so an interruption leaves only
        // ciphertext nothing can open.
        failures.attempt { pgpony.secureKeyStore.cryptoErase() }
        failures.attempt { com.pgpony.android.lock.AppLockBiometricKey.delete() }

        // Expiry reminders name keys; cancel them while the rows still exist.
        failures.attempt {
            val keys = pgpony.keyRepository.getAllKeys() + pgpony.keyRepository.getDeletedKeys()
            com.pgpony.android.notifications.KeyExpirationService.cancelAll(app, keys)
        }

        // Posted notifications (an expiry reminder names its key).
        failures.attempt { androidx.core.app.NotificationManagerCompat.from(app).cancelAll() }

        // 4.7.0 (item 33): live keys and Recently Deleted together, then the
        // whole secure store with its hardware wrapping key.
        failures.attempt { pgpony.keyRepository.clearAllKeys() }
        // 4.8.0 RC7 (item 1): SSH-only keys. They sit in the secure store, so
        // cryptoErase and wipeAll already cover them; deleting them by name as
        // well keeps that true if they ever move.
        failures.attempt { pgpony.sshKeyStore.deleteAll() }
        // Provider and SSH approvals (allowed_api_clients), Autocrypt peers and
        // every other table.
        failures.attempt { pgpony.database.clearAllTables() }

        // Settings: the whole prefs file (onboarding_completed, biometric_lock,
        // theme, cache durations, Password Store list, and the rest).
        failures.attempt {
            app.getSharedPreferences("pgpony_prefs", Context.MODE_PRIVATE).edit().clear().commit()
        }
        failures.attempt { ArmorCommentStore.get(app).clearAll() }
        failures.attempt { com.pgpony.android.keyserver.KeyServerDirectory.get(app).clearAll() }
        failures.attempt {
            val policy = com.pgpony.android.session.SessionPolicy.POLICY_FILE
            File(app.filesDir, policy).delete()
            File(app.filesDir, "$policy.tmp").delete()
        }
        failures.attempt { com.pgpony.android.lock.AppLock.clear(app) }
        failures.attempt { com.pgpony.android.crypto.SigningSubkeyPins.clearAll() } // 4.7.0 (item 46)

        // Held secrets in this process, then the provider process's.
        failures.attempt { com.pgpony.android.provider.ProviderPassphraseCache.clearAll() }
        failures.attempt { com.pgpony.android.session.InAppPassphraseCache.clearAll() }
        failures.attempt { com.pgpony.android.crypto.card.CardPinCache.clear() }
        failures.attempt { com.pgpony.android.provider.ProviderCacheClearReceiver.requestClearAll() }
        failures.attempt { com.pgpony.android.provider.PassphraseHoldService.stop(app) }

        // Plaintext and exports on disk.
        failures.attempt { com.pgpony.android.ui.util.ScratchFiles.clearAll(app) }
        failures.attempt { com.pgpony.android.ui.util.ScratchFiles.clearExports(app) }
        failures.attempt {
            File(app.cacheDir, com.pgpony.android.provider.HOLD_DIR_NAME).listFiles()?.forEach { it.delete() }
            app.cacheDir.listFiles()?.forEach { f ->
                if (f.isFile && f.name.startsWith("pgpony_cardenc_")) f.delete()
            }
        }

        // Folder grants (a linked Password Store) would outlive the reset.
        failures.attempt {
            val resolver = app.contentResolver
            resolver.persistedUriPermissions.forEach { perm ->
                var flags = 0
                if (perm.isReadPermission) flags = flags or Intent.FLAG_GRANT_READ_URI_PERMISSION
                if (perm.isWritePermission) flags = flags or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                runCatching { resolver.releasePersistableUriPermission(perm.uri, flags) }
            }
        }

        // Copied plaintext or a passphrase would outlive the reset, and on the
        // wipe path the process ends before the auto-clear runs. Which app put
        // the current clip there cannot be told reliably (Compose copies carry
        // no mark), so the clipboard is cleared.
        failures.attempt {
            com.pgpony.android.ui.util.ClipboardService.cancelCountdown()
            val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as? android.content.ClipboardManager
            if (cm != null) {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    cm.clearPrimaryClip()
                } else {
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
                }
            }
        }

        // The background key refresh job outlives the prefs it was set up from.
        failures.attempt {
            androidx.work.WorkManager.getInstance(app)
                .cancelUniqueWork(com.pgpony.android.sync.KeyRefreshScheduler.WORK_NAME)
        }

        if (mode == Mode.CLEAR_ALL_DATA) {
            // The observable settings read the cleared prefs again, and the
            // refresh job is scheduled the way a fresh install's first start
            // does (PGPonyApp.onCreate), which the wipe path gets from its restart.
            failures.attempt { com.pgpony.android.ui.theme.ThemeState.initFromPrefs(app) }
            failures.attempt { com.pgpony.android.network.OfflineMode.initFromPrefs() }
            failures.attempt { com.pgpony.android.sync.KeyRefreshScheduler.apply(app) }
        }

        failures.firstOrNull()
    }

    /**
     * Drop the per-app language, back to the system's, as on a fresh install.
     * Main thread; may recreate the open activities.
     */
    fun resetAppLocale() {
        runCatching {
            // Only when one is set, so nothing is recreated for no change.
            if (!androidx.appcompat.app.AppCompatDelegate.getApplicationLocales().isEmpty()) {
                androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(
                    androidx.core.os.LocaleListCompat.getEmptyLocaleList()
                )
            }
        }
    }

    /**
     * The :remote_api process's part of a pending wipe: its in-memory secrets
     * and its foreground service. The persistent reset stays with the main
     * process, so a provider restart can never overlap a fresh setup.
     */
    fun clearProcessSecrets(context: Context) {
        val app = context.applicationContext
        runCatching { com.pgpony.android.provider.ProviderPassphraseCache.clearAll() }
        runCatching { com.pgpony.android.session.InAppPassphraseCache.clearAll() }
        runCatching { com.pgpony.android.crypto.card.CardPinCache.clear() }
        runCatching { com.pgpony.android.provider.PassphraseHoldService.stop(app) }
    }
}
