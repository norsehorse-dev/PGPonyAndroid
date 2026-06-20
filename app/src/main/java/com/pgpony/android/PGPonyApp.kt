// PGPonyApp.kt
// PGPony Android

package com.pgpony.android

import android.app.Application
import androidx.room.Room
import com.pgpony.android.contacts.ContactsService
import com.pgpony.android.data.MIGRATION_1_2
import com.pgpony.android.data.MIGRATION_2_3
import com.pgpony.android.data.MIGRATION_3_4
import com.pgpony.android.data.MIGRATION_4_5
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.SecureKeyStore
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.notifications.KeyExpirationService
import com.pgpony.android.ui.theme.ThemeState
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

    lateinit var keyRepository: KeyRepository
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
        // MIGRATION_1_2 / MIGRATION_2_3 / MIGRATION_3_4 declared in data/PGPKeyEntity.kt.
        // 3.0.0-KS1: schema bumped to v5 for keyserver activity timestamps (MIGRATION_4_5).
        database = Room.databaseBuilder(
            applicationContext,
            PGPDatabase::class.java,
            "pgpony.db"
        )
            .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5)
            .build()

        // Initialize secure key storage
        secureKeyStore = SecureKeyStore.getInstance(applicationContext)

        // Initialize repository (bridges crypto + storage + database)
        keyRepository = KeyRepository(
            dao = database.keyDao(),
            store = secureKeyStore
        )

        // Initialize contacts service
        contactsService = ContactsService.getInstance(applicationContext)

        instance = this

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

        // ── Phase A12 Fix1: bootstrap observable theme state ───────────
        //
        // Seeds ThemeState.current from SharedPreferences so the very
        // first composition of PGPonyTheme reads the persisted theme.
        // Must happen before MainActivity.setContent runs — onCreate is
        // the right hook since Application.onCreate fires before any
        // Activity.onCreate. Idempotent; safe to call again.
        ThemeState.initFromPrefs(applicationContext)
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
