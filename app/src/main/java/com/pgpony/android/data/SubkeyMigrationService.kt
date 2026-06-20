// SubkeyMigrationService.kt
// PGPony Android
//
// One-shot job that runs on first launch after upgrade to v1.5.0
// (Phase A1). Walks every PGPKeyEntity in the keyring, reads its
// armored public-key material from SecureKeyStore, parses it via
// Bouncy Castle, and inserts one PgpSubkeyEntity row per public key
// in the ring (including the primary itself, marked isPrimary).
//
// Idempotent: gated on a SharedPreferences flag `subkeys_migrated`.
// Safe to call on every launch — completes instantly if the flag is
// set OR if the keyring is empty.
//
// Failure handling: a single bad key (missing material, corrupt
// armor, unrecognized algorithm) is logged and skipped. The migration
// continues with the remaining keys and the flag is still set on
// completion, so the failed key won't block the whole keyring.
//
// Matches iOS Phase 1 SubkeyMigrationService.swift behavior.
//
// Added in Phase A1 (Subkey Model Refactor).

package com.pgpony.android.data

import android.content.SharedPreferences
import android.util.Log
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SubkeyCapability
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import java.util.UUID

class SubkeyMigrationService(
    private val keyDao: PGPKeyDao,
    private val subkeyDao: PGPSubkeyDao,
    private val store: SecureKeyStore,
    private val prefs: SharedPreferences,
    private val crypto: PGPCryptoService = PGPCryptoService.shared
) {

    sealed class State {
        /** No migration has been attempted yet this app launch. */
        object NotStarted : State()
        /** Currently walking keys; `current` is 1-indexed. */
        data class InProgress(val current: Int, val total: Int) : State()
        /** Migration succeeded (or wasn't needed). Safe to show the UI. */
        object Complete : State()
        /** Migration crashed entirely. Logged; UI may still proceed. */
        data class Failed(val error: String) : State()
    }

    private val _state = MutableStateFlow<State>(State.NotStarted)
    val state: StateFlow<State> = _state.asStateFlow()

    /**
     * Run the migration if it hasn't already completed. Safe to call
     * on every app launch; no-op once `FLAG_MIGRATED` is set.
     *
     * Caller is responsible for running this on Dispatchers.IO — the
     * function suspends because Room DAO calls suspend.
     */
    suspend fun migrateIfNeeded() {
        if (prefs.getBoolean(FLAG_MIGRATED, false)) {
            _state.value = State.Complete
            return
        }

        try {
            val allKeys = keyDao.getAllKeys()
            if (allKeys.isEmpty()) {
                // Brand-new install or empty keyring — nothing to walk.
                prefs.edit().putBoolean(FLAG_MIGRATED, true).apply()
                _state.value = State.Complete
                return
            }

            allKeys.forEachIndexed { index, key ->
                _state.value = State.InProgress(current = index + 1, total = allKeys.size)
                try {
                    populateSubkeysFor(key)
                } catch (e: Exception) {
                    Log.w(
                        TAG,
                        "Subkey population failed for ${key.fingerprint}: ${e.message}",
                        e
                    )
                    // Carry on with the remaining keys
                }
            }

            prefs.edit().putBoolean(FLAG_MIGRATED, true).apply()
            _state.value = State.Complete
        } catch (e: Exception) {
            Log.e(TAG, "Subkey migration failed", e)
            _state.value = State.Failed(e.message ?: "Unknown error")
        }
    }

    /**
     * Re-run the migration from scratch, ignoring the FLAG_MIGRATED
     * flag. Used for testing and for the future "reset subkey graph"
     * Settings entry. Drops every existing pgp_subkeys row first.
     */
    suspend fun forceRebuild() {
        prefs.edit().putBoolean(FLAG_MIGRATED, false).apply()
        subkeyDao.deleteAll()
        migrateIfNeeded()
    }

    // ── Internals ─────────────────────────────────────────────────────

    private suspend fun populateSubkeysFor(key: PGPKeyEntity) {
        // Drop any partial rows for this key (handles process-kill
        // mid-migration). After this call, the table is clean for the
        // re-population below.
        subkeyDao.deleteByPrimaryKeyId(key.id)

        val publicKeyData = store.loadPublicKey(key.fingerprint)
            ?: run {
                Log.w(TAG, "No stored public key material for ${key.fingerprint}; skipping")
                return
            }

        val ring = try {
            crypto.importKeyData(publicKeyData).publicKeyRing
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse stored public key for ${key.fingerprint}: ${e.message}")
            null
        } ?: return

        val rows = subkeyRowsFor(ring, primaryKeyId = key.id)
        if (rows.isNotEmpty()) {
            subkeyDao.insertAll(rows)
        }
    }

    private fun subkeyRowsFor(ring: PGPPublicKeyRing, primaryKeyId: String): List<PgpSubkeyEntity> {
        val out = mutableListOf<PgpSubkeyEntity>()
        var isPrimary = true
        for (pubKey in ring.publicKeys) {
            try {
                out.add(buildRow(pubKey, primaryKeyId, isPrimary))
            } catch (e: Exception) {
                Log.w(TAG, "Skipping subkey ${formatFingerprint(pubKey)} of $primaryKeyId: ${e.message}")
            }
            isPrimary = false
        }
        return out
    }

    private fun buildRow(
        pubKey: PGPPublicKey,
        primaryKeyId: String,
        isPrimary: Boolean
    ): PgpSubkeyEntity {
        val algorithm = crypto.detectAlgorithm(pubKey)
        val capabilities = SubkeyCapability.fromPgpPublicKey(
            pubKey = pubKey,
            algorithm = algorithm,
            isPrimary = isPrimary
        )
        val expiresAtMs = pubKey.validSeconds.takeIf { it > 0L }?.let { secs ->
            pubKey.creationTime.time + secs * 1000L
        }
        return PgpSubkeyEntity(
            id = UUID.randomUUID().toString(),
            primaryKeyId = primaryKeyId,
            fingerprint = formatFingerprint(pubKey),
            keyId = String.format("%016X", pubKey.keyID),
            algorithm = algorithm,
            creationTime = pubKey.creationTime.time,
            expirationTime = expiresAtMs,
            capabilities = capabilities,
            isRevoked = pubKey.hasRevocation(),
            revokedAt = null  // Full revocation timestamp tracking is Phase A6
        )
    }

    private fun formatFingerprint(pubKey: PGPPublicKey): String =
        pubKey.fingerprint.joinToString("") { String.format("%02X", it) }

    companion object {
        private const val TAG = "SubkeyMigration"
        const val FLAG_MIGRATED = "subkeys_migrated"
    }
}
