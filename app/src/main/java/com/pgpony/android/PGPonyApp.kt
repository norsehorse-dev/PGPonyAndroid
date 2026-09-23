// PGPonyApp.kt
// PGPony Android

package com.pgpony.android

import android.app.Application
import android.os.Build
import androidx.room.Room
import com.pgpony.android.contacts.ContactsService
import com.pgpony.android.data.MIGRATION_1_2
import com.pgpony.android.data.MIGRATION_2_3
import com.pgpony.android.data.MIGRATION_3_4
import com.pgpony.android.data.MIGRATION_4_5
import com.pgpony.android.data.MIGRATION_5_6
import com.pgpony.android.data.MIGRATION_6_7
import com.pgpony.android.data.MIGRATION_7_8
import com.pgpony.android.data.MIGRATION_8_9
import com.pgpony.android.data.MIGRATION_9_10
import com.pgpony.android.autocrypt.AutocryptPeerStore
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.SecureKeyStore
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.notifications.KeyExpirationService
import com.pgpony.android.ui.theme.ThemeState
import com.pgpony.android.ui.util.ScratchFiles
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class PGPonyApp : Application() {

    lateinit var database: PGPDatabase
        private set

    lateinit var secureKeyStore: SecureKeyStore
        private set

    // 4.5.3 (#57): serializes background recovery-wrap writes off the UI thread.
    private val recoveryExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()

    lateinit var keyRepository: KeyRepository
    lateinit var autocryptPeerStore: AutocryptPeerStore
        private set

    lateinit var contactsService: ContactsService
        private set

    override fun onCreate() {
        super.onCreate()

        // Register Bouncy Castle as the #1 security provider
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        // Initialize Room database
        // Phase A6: schema bumped to v2 to add revocation columns.
        // HW Phase 0/1: schema bumped to v3 to add card-backed columns.
        // MIGRATION_1_2 / MIGRATION_2_3 / MIGRATION_3_4 declared in data/RoomMigrations.kt.
        // 3.0.0-KS1: schema bumped to v5 for keyserver activity timestamps (MIGRATION_4_5).
        // 4.0.0 Succession Phase 1: schema bumped to v6 for the OpenPGP API
        // provider's allowed_api_clients table (MIGRATION_5_6).
        database = Room.databaseBuilder(
            applicationContext,
            PGPDatabase::class.java,
            "pgpony.db"
        )
            .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9, MIGRATION_9_10)
            // #2.1: the :remote_api provider process opens this same DB, so
            // invalidations must cross processes to keep both views coherent
            // (e.g. a consent revocation in the main app reaching a running
            // provider process).
            .enableMultiInstanceInvalidation()
            .build()

        // Initialize secure key storage
        secureKeyStore = SecureKeyStore.getInstance(applicationContext)

        // 4.5.3 (#57): when an in-app unlock proves a passphrase good, add the
        // key's SecureKeyStore recovery wrap in the background so it survives a
        // hardware-keystore wipe. Runs in both processes; harmless in either.
        com.pgpony.android.session.InAppPassphraseCache.onVerifiedUnlock = { fp, pass ->
            recoveryExecutor.execute {
                val chars = pass.toCharArray()
                try { secureKeyStore.ensureRecoveryWrap(fp, chars) } catch (_: Exception) {} finally { chars.fill('\u0000') }
            }
        }

        // Initialize repository (bridges crypto + storage + database)
        keyRepository = KeyRepository(
            dao = database.keyDao(),
            store = secureKeyStore,
            // RC3 §N (#34)
            fallbackDao = database.fallbackKeyDao(),
            signingDefaultsDao = database.signingDefaultsDao()
        )

        // 4.0.0 Phase 4 — Autocrypt peer-state store (OpenPGP API).
        autocryptPeerStore = AutocryptPeerStore.create(database.autocryptPeerDao(), keyRepository)

        // Initialize contacts service
        contactsService = ContactsService.getInstance(applicationContext)

        instance = this

        // #2.1: the OpenPGP API service and its provider activities run in a
        // dedicated :remote_api process (see AndroidManifest) so a
        // background-kill ROM that freezes the main app process cannot freeze
        // a bound decrypt. That process needs the crypto + storage wired
        // above, but MUST NOT run the main-process-only startup below: it
        // would re-clear the shared scratch dir (wiping an in-progress
        // main-process encrypt/decrypt), open DataStore from a second process
        // (not multi-process safe), and double-register receivers and
        // re-schedule alarms.
        if (isRemoteApiProcess()) {
            // 4.6.0 (item 17.2): plaintext held for an integrity check that a
            // crash or kill interrupted is debris; drop it before serving.
            runCatching {
                java.io.File(cacheDir, com.pgpony.android.provider.HOLD_DIR_NAME).listFiles()?.forEach { it.delete() }
            }
            // This process holds API passphrases (ProviderPassphraseCache) and
            // card PINs. Clear them the way the main process does: on an
            // explicit clear/invalidation broadcast, and on device lock.
            // Registered here so the provider self-clears even when the main
            // process has been killed by an aggressive ROM (the #2.1 case).
            androidx.core.content.ContextCompat.registerReceiver(
                this,
                com.pgpony.android.provider.ProviderCacheClearReceiver(),
                android.content.IntentFilter(
                    com.pgpony.android.provider.ProviderCacheClearReceiver.ACTION_CLEAR
                ),
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
            )
            androidx.core.content.ContextCompat.registerReceiver(
                this,
                com.pgpony.android.session.SessionLockReceiver(),
                android.content.IntentFilter(android.content.Intent.ACTION_SCREEN_OFF),
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
            )
            return
        }

        // 4.0.4: the streaming Encrypt/Decrypt file paths write their output
        // to cacheDir/scratch. Anything still there at app start is debris
        // from a crash or a kill, and for a decrypt it is plaintext, so drop
        // it before the first screen opens. Main process only (see above).
        ScratchFiles.clearAll(applicationContext)
        // 4.6.0 (item 17.3): exports/ holds buffered decrypted files and
        // unprotected key exports written for a share; none outlives a launch.
        ScratchFiles.clearExports(applicationContext)

        // ── Armor comment header: seed + keep the crypto cache fresh ───
        //
        // The customizable "Comment:" header for armored encrypt/sign
        // output is persisted in DataStore. The crypto layer reads it
        // synchronously from ArmorCommentHeader.current, so we start a
        // collector here that mirrors the persisted DataStore value into
        // that cache on every cold start and whenever it changes. This
        // is what makes the setting survive an app restart.
        com.pgpony.android.data.ArmorCommentStore
            .get(this)
            .startCaching(applicationScope)

        // ── Phase A12: notification channel + reminder re-schedule ─────
        //
        // The channel must exist before any notification can be posted —
        // create it on every launch (idempotent). The reminder
        // re-schedule pass handles two cases:
        //   1. Fresh install: nothing to re-schedule yet, no-op.
        //   2. App data cleared / device restored from backup: prior
        //      AlarmManager schedule was wiped along with the rest of
        //      the process state. We need to rebuild it.
        // The pref check ensures we don't touch alarms for users who
        // haven't opted in. The DB read happens off-thread so it
        // doesn't block app startup.
        KeyExpirationService.createNotificationChannel(applicationContext)
        // §5.6.9 (Piotr): sideload update-check channel + a throttled launch
        // check. The service self-gates on install source, the opt-in
        // pref, and a once-a-day throttle, so this is a no-op on F-Droid /
        // Play installs or when the user has not opted in.
        com.pgpony.android.update.UpdateCheckService.createNotificationChannel(applicationContext)
        // §3 (#15): device-lock listener that clears held secrets when the
        // session policy is "until the phone locks". SCREEN_OFF is a
        // protected system broadcast; NOT_EXPORTED keeps it API-34-safe.
        androidx.core.content.ContextCompat.registerReceiver(
            this,
            com.pgpony.android.session.SessionLockReceiver(),
            android.content.IntentFilter(android.content.Intent.ACTION_SCREEN_OFF),
            androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
        )
        applicationScope.launch {
            try {
                com.pgpony.android.update.UpdateCheckService.checkForUpdate(applicationContext)
            } catch (e: Exception) {
                // best-effort; a failed check just tries again next launch
            }
        }
        // §5.6.1 recycle bin: purge keys binned past the retention window.
        applicationScope.launch {
            try {
                keyRepository.purgeExpiredDeleted(
                    com.pgpony.android.data.repository.KeyRepository.RECYCLE_BIN_RETENTION_MS
                )
            } catch (e: Exception) {
                // best-effort; retried next launch
            }
        }

        // ── Phase A12 Fix1: bootstrap observable theme state ───────────
        //
        // Seeds ThemeState.current from SharedPreferences so the very
        // first composition of PGPonyTheme reads the persisted theme.
        // Must happen before MainActivity.setContent runs — onCreate is
        // the right hook since Application.onCreate fires before any
        // Activity.onCreate. Idempotent; safe to call again.
        ThemeState.initFromPrefs(applicationContext)
        // RC1 offline switch: seed the observable so the network UI hides
        // correctly on the first composition.
        com.pgpony.android.network.OfflineMode.initFromPrefs()
        // A14 Picker — seed LanguageState from AppCompat's persisted locale
        // list (or detect from device on first install). Done here so any
        // Composable that reads LanguageState.current during the first
        // recomposition already sees the correct value — no flash of
        // wrong-language UI on cold start.
        com.pgpony.android.i18n.LanguageState.initFromAppCompat(applicationContext)

        val prefs = applicationContext.getSharedPreferences(
            "pgpony_prefs",
            MODE_PRIVATE
        )
        if (prefs.getBoolean("key_expiration_reminders", false)) {
            applicationScope.launch {
                try {
                    val keys = keyRepository.getAllKeys()
                    KeyExpirationService.scheduleReminders(applicationContext, keys)
                } catch (e: Exception) {
                    // best-effort; user can toggle off+on in Settings
                    // to force a manual re-schedule
                }
            }
        }

        // ── 4.0.0 Phase 1 (iOS v7.1.1 F3): duplicate-row sweep ─────────
        //
        // One-time collapse of duplicate keyring rows left behind by
        // pre-3.1.0 imports (the offline-primary card-linking bug fixed
        // forward in 3.1.0 Phase 7 A1 created duplicate card-contact
        // rows on existing installs; the creation path is fixed but the
        // rows remain). Run-once via a pgpony_prefs flag inside the
        // service; the DB walk happens off-thread on applicationScope
        // so cold start is untouched. Same launch pattern as the
        // reminder re-schedule above.
        applicationScope.launch {
            try {
                keyRepository.runDedupeSweepIfNeeded(prefs)
                keyRepository.revalidateStoredCertificatesIfNeeded(prefs)
            } catch (e: Exception) {
                // best-effort; the run-once flag is only set on a clean
                // pass, so a failed sweep retries on the next launch
            }
        }

        // ── 4.0.0 Phase 5 — background keyserver refresh ───────────────
        //
        // Apply the current schedule on every cold start: schedules the
        // periodic KeyRefreshWorker when enabled (play defaults ON, foss
        // OFF — §6 Q4), cancels it when not. Idempotent (unique periodic
        // work), so re-applying each launch is cheap and self-heals after
        // an app-data clear or reboot.
        try {
            com.pgpony.android.sync.KeyRefreshScheduler.apply(applicationContext)
        } catch (e: Exception) {
            // WorkManager unavailable (very rare) — non-fatal.
        }
    }

    /**
     * True when this is the dedicated :remote_api process that hosts the
     * OpenPGP API service and its provider activities (#2.1). Used to skip
     * the main-process-only startup in onCreate. The suffix must match the
     * android:process value in AndroidManifest.
     */
    private fun isRemoteApiProcess(): Boolean =
        currentProcessName() == "$packageName:remote_api"

    /**
     * Current process name, across API 26+. Application.getProcessName() is
     * API 28; below that /proc/self/cmdline carries the name (null-padded).
     */
    private fun currentProcessName(): String? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Application.getProcessName()
        } else {
            try {
                java.io.File("/proc/self/cmdline").readText()
                    .substringBefore('\u0000').trim().ifEmpty { null }
            } catch (_: Exception) {
                null
            }
        }

    /**
     * Process-scoped CoroutineScope for fire-and-forget background work
     * that should outlive any individual screen / ViewModel — e.g. the
     * reminder re-schedule pass in onCreate, future telemetry,
     * one-time migration tasks.
     */
    val applicationScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    companion object {
        lateinit var instance: PGPonyApp
            private set
    }
}
