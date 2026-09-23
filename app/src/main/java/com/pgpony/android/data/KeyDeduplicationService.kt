// KeyDeduplicationService.kt
// PGPony Android — 4.0.0 Phase 1
//
// Android port of iOS v7.1.1 F3 (KeyringDeduplicationService.swift).
//
// The fingerprint is the identity: no two pgp_keys rows may share one.
// Every external-import path funnels through KeyRepository, and the
// repository consults this service before inserting. On a match the
// import either reports "already in keyring", upgrades a public-only
// row to a key pair in place (handled by the repository, which owns
// the SecureKeyStore secret write), pairs onto a card-backed row
// (repository card branch, HW 1.5), or merges the newer public
// material into the existing row — so a re-import doubles as a manual
// refresh. Phase 2's keyserver refresh reuses [merge] directly, and
// Phase 5's backup restore + Phase 7's background refresh both build
// on the same semantics.
//
// Also owns the one-time sweep that collapses duplicate rows created
// by pre-3.1.0 imports — specifically the offline-primary card-linking
// bug (fixed forward in 3.1.0 Phase 7 A1) that inserted a duplicate
// card-contact row next to the real keyring entry. The creation path
// was fixed; existing installs still carry the rows. Run-once via a
// SharedPreferences flag (precedent: SubkeyMigrationService's
// `subkeys_migrated` flag), safe to call on every launch.
//
// iOS → Android divergences, all deliberate:
//   • Subkey re-derivation on merge: N/A. The pgp_subkeys table was
//     never wired into PGPDatabase (see the A6 cleanup note in
//     KeyringViewModel.loadKeys); Android subkey display derives from
//     the stored ring bytes, which the merge replaces — so subkeys
//     are current by construction.
//   • Keychain material moves in the sweep: N/A by construction.
//     SecureKeyStore lowercases the fingerprint in its storage key,
//     so case-variant duplicate rows already SHARE their stored
//     material. The sweep must therefore delete losers through the
//     DAO only — never store.deleteKeys — or the keeper loses its
//     bytes too.
//   • absorb() also carries card-backing fields and revocation flags
//     off a losing row (iOS doesn't). Card fields because the A1 bug
//     specifically produced duplicate CARD rows — dropping the card
//     link during the collapse would undo the user's pairing.
//     Revocation because a key either row considered revoked should
//     stay flagged revoked; losing that flag is safety-negative.
//   • Trust on public-only → pair upgrade stays untouched (iOS raises
//     to ultimate). Android never auto-assigns ULTIMATE anywhere —
//     generateKey and fresh pair imports both leave the UNKNOWN
//     default — so raising it here would be internally inconsistent.

package com.pgpony.android.data

import android.content.SharedPreferences
import android.util.Log
import org.bouncycastle.openpgp.PGPPublicKeyRing

class KeyDeduplicationService(
    private val dao: PGPKeyDao,
    private val store: SecureKeyStore
) {

    enum class DuplicateResolution {
        /** The imported material is byte-identical to what's stored — nothing new. */
        ALREADY_IN_KEYRING,
        /** The imported material differed; it was merged into the existing row. */
        MERGED_NEW_MATERIAL
    }

    companion object {
        /** Run-once flag for the duplicate-collapse sweep. */
        const val SWEEP_FLAG_KEY = "pgpony_4_0_dedupe_sweep_done_r2"
        /** Run-once flag for the 4.6.0 stored-certificate re-validation. */
        const val REVALIDATE_FLAG_KEY = "pgpony_4_6_cert_binding_revalidated"
        private const val TAG = "KeyringDedup"

        /**
         * item 24 (#55, lukascomer): a keyserver refresh must not silently
         * downgrade a primary key's expiry. True when taking [fetchedExpiresAtMs]
         * over [existingExpiresAtMs] would remove an expiry the stored key already
         * carries, or shorten it. Adding an expiry where there was none, extending
         * one, or matching it is not a downgrade.
         */
        internal fun isExpiryDowngrade(existingExpiresAtMs: Long?, fetchedExpiresAtMs: Long?): Boolean {
            val existing = existingExpiresAtMs ?: return false
            return fetchedExpiresAtMs == null || fetchedExpiresAtMs < existing
        }

        /**
         * Canonical form for fingerprint equality: bare lowercase hex.
         * Every producer in the app emits bare hex (BC's
         * Hex.toHexString, V4Fingerprint); whitespace is stripped
         * defensively in case a display-formatted fingerprint
         * (formattedFingerprint chunks by 4 with spaces) ever reaches
         * an import path. Mirrors iOS
         * KeyringDeduplicationService.normalize.
         */
        fun normalize(fingerprint: String): String =
            fingerprint.lowercase().filter { !it.isWhitespace() }
    }

    // ── Matching ───────────────────────────────────────────────────────

    /**
     * The existing keyring row for this fingerprint, if any. Fast path
     * is the DAO's exact-match query (every producer emits consistent
     * bare hex, so this hits in practice); the fallback scans the full
     * keyring under [normalize] to catch case or formatting variants.
     * Keyrings are small (tens of rows), so the scan is in-memory and
     * import-time only — same tradeoff iOS makes instead of forcing
     * the normalization into a predicate.
     */
    suspend fun findExisting(fingerprint: String): PGPKeyEntity? {
        val target = normalize(fingerprint)
        if (target.isEmpty()) return null
        dao.getByFingerprint(fingerprint)?.let { return it }
        return dao.getAllKeys().firstOrNull { normalize(it.fingerprint) == target }
    }

    // ── Duplicate resolution ───────────────────────────────────────────

    /**
     * Handle an external import that matched an existing row and
     * carries no secret upgrade (the secret-arriving-for-public-only
     * path is handled by KeyRepository, which owns the SecureKeyStore
     * secret write). Byte-identical public material resolves to
     * ALREADY_IN_KEYRING; anything else merges. Returns the row to
     * surface to the UI — the untouched original for
     * ALREADY_IN_KEYRING, the updated row for MERGED_NEW_MATERIAL.
     */
    suspend fun resolveDuplicate(
        existing: PGPKeyEntity,
        newPublicRing: PGPPublicKeyRing,
        newArmoredPublicKey: String?,
        newExpiresAtMs: Long?
    ): Pair<PGPKeyEntity, DuplicateResolution> {
        val fetchedBytes = newPublicRing.encoded
        val stored = store.loadPublicKey(existing.fingerprint)
        // 4.6.0 (items 17.1 and 12): a verified union of the stored and fetched
        // copies, not a replacement. See CertificateMerge.
        val newBytes = if (stored != null && stored.isNotEmpty()) {
            com.pgpony.android.crypto.CertificateMerge.merge(
                stored = stored,
                fetched = fetchedBytes,
                isKeyPair = existing.isKeyPair,
                removedUserIds = RemovedUserIdStore.removed(existing.fingerprint)
            )
        } else {
            com.pgpony.android.crypto.CertificateBindings.sanitized(fetchedBytes)
        }
        if (stored != null && stored.isNotEmpty() &&
            (newBytes.contentEquals(stored) ||
                newBytes.contentEquals(com.pgpony.android.crypto.CertificateBindings.sanitized(stored)))
        ) {
            return existing to DuplicateResolution.ALREADY_IN_KEYRING
        }
        // item 24 guard: never let a fetched copy strip or shorten a primary
        // expiry the stored key already has. A published revocation is scanned
        // separately upstream (KeyRefreshService), so this does not suppress one.
        if (isExpiryDowngrade(existing.expiresAt, newExpiresAtMs)) {
            return existing to DuplicateResolution.ALREADY_IN_KEYRING
        }
        // The cached armor and expiry follow the merged certificate, not the
        // fetched copy. Key pairs keep their own expiry (local is authoritative).
        val unionRing = runCatching {
            org.bouncycastle.openpgp.PGPPublicKeyRing(
                newBytes, org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()
            )
        }.getOrNull()
        val unionArmored = unionRing?.let {
            runCatching { com.pgpony.android.crypto.PGPCryptoService.shared.exportArmoredPublicKey(it) }.getOrNull()
        } ?: newArmoredPublicKey
        val unionExpiresAt = when {
            existing.isKeyPair -> existing.expiresAt
            unionRing != null -> unionRing.publicKey.validSeconds.takeIf { it > 0 }?.let {
                unionRing.publicKey.creationTime.time + it * 1000L
            }
            else -> newExpiresAtMs
        }
        val merged = merge(
            existing = existing,
            publicKeyBytes = newBytes,
            armoredPublicKey = unionArmored,
            expiresAtMs = unionExpiresAt
        )
        return merged to DuplicateResolution.MERGED_NEW_MATERIAL
    }

    /**
     * Merge newer public material into an existing row. Updates the
     * SecureKeyStore public bytes, the cached armored key, and the
     * expiration date. Preserves trust level, contact link, secret key
     * material, notes, identity fields (userID/name/email), default
     * flag, usage counters, and card-backing — everything the entity
     * copy() doesn't name. Persists via dao.update and returns the
     * updated row. Phase 2's keyserver refresh calls this directly.
     *
     * The armored cache only updates when the incoming armor is
     * non-empty and contains no PRIVATE block — armoredPublicKey feeds
     * QR sheets and share actions, which must never leak secret
     * material (same guard as iOS merge(into:)).
     */
    suspend fun merge(
        existing: PGPKeyEntity,
        publicKeyBytes: ByteArray,
        armoredPublicKey: String?,
        expiresAtMs: Long?
    ): PGPKeyEntity {
        if (publicKeyBytes.isNotEmpty()) {
            store.storePublicKey(existing.fingerprint, publicKeyBytes)
        }
        val newArmored = armoredPublicKey
            ?.takeIf { it.isNotEmpty() && !it.contains("PRIVATE") }
            ?: existing.armoredPublicKey
        val merged = existing.copy(
            armoredPublicKey = newArmored,
            expiresAt = expiresAtMs
        )
        dao.update(merged)
        return merged
    }

    // ── One-time certificate re-validation (4.6.0 item 17.1) ──────────

    /**
     * Stored public certificates written before 4.6.0 were never checked for
     * binding signatures, so a subkey, User ID or revocation that its primary
     * never made may already be on disk. Rewrite each stored certificate in
     * its verified form (CertificateBindings.sanitize) when that removes
     * anything, and refresh the cached armor to match. Selection paths already
     * ignore unbound components at use time; this makes storage and display
     * agree. Run-once via [REVALIDATE_FLAG_KEY]; only certificates that change
     * are rewritten, so an untouched keyring causes no writes at all.
     */
    suspend fun revalidateStoredCertificatesIfNeeded(prefs: SharedPreferences) {
        if (prefs.getBoolean(REVALIDATE_FLAG_KEY, false)) return
        var rewritten = 0
        for (entity in dao.getAllKeys()) {
            val raw = store.loadPublicKey(entity.fingerprint) ?: continue
            val clean = com.pgpony.android.crypto.CertificateBindings.sanitized(raw)
            if (packetCount(clean) == packetCount(raw)) continue
            store.storePublicKey(entity.fingerprint, clean)
            val armored = runCatching {
                com.pgpony.android.crypto.PGPCryptoService.shared.exportArmoredPublicKey(
                    org.bouncycastle.openpgp.PGPPublicKeyRing(
                        clean, org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()
                    )
                )
            }.getOrNull()
            if (armored != null && !entity.armoredPublicKey.isNullOrEmpty()) {
                dao.update(entity.copy(armoredPublicKey = armored))
            }
            rewritten++
        }
        if (rewritten > 0) Log.d(TAG, "re-validation rewrote $rewritten certificate(s)")
        prefs.edit().putBoolean(REVALIDATE_FLAG_KEY, true).apply()
    }

    /** Packets other than local trust packets, which never carry meaning here. */
    private fun packetCount(raw: ByteArray): Int =
        com.pgpony.android.crypto.CertificateBindings.packets(raw).count { it.tag != 12 }

    // ── One-time duplicate sweep ───────────────────────────────────────

    /**
     * Collapse duplicate rows created by pre-3.1.0 imports so each
     * fingerprint has exactly one row. Keeps the row with secret
     * material, else a card link, else the most local metadata;
     * absorbs contact links, trust, counters, card backing, and
     * revocation flags off removed rows. Run-once via [SWEEP_FLAG_KEY]
     * — safe to call on every launch. Deletion goes through the DAO
     * only: rows in a group share SecureKeyStore material (the store
     * lowercases fingerprints), so store.deleteKeys here would strip
     * the keeper's bytes as well.
     */
    suspend fun runSweepIfNeeded(prefs: SharedPreferences) {
        if (prefs.getBoolean(SWEEP_FLAG_KEY, false)) return
        val all = dao.getAllKeys()
        val groups = all.groupBy { normalize(it.fingerprint) }
        var removed = 0
        for ((normalized, rows) in groups) {
            if (normalized.isEmpty() || rows.size < 2) continue
            var keeper = rows.maxByOrNull { score(it) } ?: continue
            for (loser in rows) {
                if (loser.id == keeper.id) continue
                keeper = absorb(loser, keeper)
                dao.delete(loser)
                removed++
            }
            // A group can hold a public-only keeper next to a pair row
            // (or private material stored under the shared lowercase
            // key by a since-deleted variant). If the material exists,
            // the surviving row should say so.
            if (!keeper.isKeyPair &&
                rows.any { it.isKeyPair } &&
                store.hasPrivateKey(keeper.fingerprint)
            ) {
                keeper = keeper.copy(isKeyPair = true)
            }
            dao.update(keeper)
        }
        if (removed > 0) {
            Log.d(TAG, "sweep collapsed $removed duplicate row(s)")
        }
        prefs.edit().putBoolean(SWEEP_FLAG_KEY, true).apply()
    }

    /**
     * Ranking for which duplicate survives: secret material first,
     * then a hardware-key link, then accumulated local metadata.
     * Mirrors iOS score() minus the subkey-count term (no subkey rows
     * on Android — see the header note).
     */
    private fun score(entity: PGPKeyEntity): Int {
        var score = 0
        if (entity.isKeyPair) score += 1_000_000
        if (entity.isCardBacked) score += 100_000
        if (entity.contactId != null) score += 10_000
        score += trustRank(entity.trustLevel) * 1_000
        if (entity.isDefault) score += 500
        if (!entity.armoredPublicKey.isNullOrEmpty()) score += 100
        score += minOf(entity.decryptUseCount, 9)
        return score
    }

    private fun trustRank(level: TrustLevel): Int =
        TrustLevel.entries.indexOf(level)

    /**
     * Copy contact links, trust, counters, card backing, and
     * revocation state worth keeping off a row that is about to be
     * deleted. Returns the updated keeper (entity is immutable — the
     * caller persists the final copy once after all absorbs).
     */
    private fun absorb(loser: PGPKeyEntity, keeper: PGPKeyEntity): PGPKeyEntity {
        var updated = keeper
        if (updated.contactId == null && loser.contactId != null) {
            updated = updated.copy(
                contactId = loser.contactId,
                contactName = loser.contactName,
                contactPhotoUri = loser.contactPhotoUri
            )
        }
        if (trustRank(loser.trustLevel) > trustRank(updated.trustLevel)) {
            updated = updated.copy(trustLevel = loser.trustLevel)
        }
        if (loser.isDefault && !updated.isDefault) {
            updated = updated.copy(isDefault = true)
        }
        if (loser.decryptUseCount > updated.decryptUseCount) {
            updated = updated.copy(decryptUseCount = loser.decryptUseCount)
        }
        if (loser.keyServerUploaded && !updated.keyServerUploaded) {
            updated = updated.copy(keyServerUploaded = true)
        }
        updated = updated.copy(
            lastUploadedAt = laterOf(updated.lastUploadedAt, loser.lastUploadedAt),
            lastCheckedAt = laterOf(updated.lastCheckedAt, loser.lastCheckedAt)
        )
        if (updated.armoredPublicKey.isNullOrEmpty() && !loser.armoredPublicKey.isNullOrEmpty()) {
            updated = updated.copy(armoredPublicKey = loser.armoredPublicKey)
        }
        if (updated.notes.isNullOrEmpty() && !loser.notes.isNullOrEmpty()) {
            updated = updated.copy(notes = loser.notes)
        }
        if (!updated.isCardBacked && loser.isCardBacked) {
            updated = updated.copy(
                isCardBacked = true,
                cardSerial = loser.cardSerial,
                cardAid = loser.cardAid,
                cardManufacturer = loser.cardManufacturer,
                cardSigFingerprint = loser.cardSigFingerprint,
                cardDecFingerprint = loser.cardDecFingerprint,
                cardAuthFingerprint = loser.cardAuthFingerprint
            )
        }
        if (!updated.isRevoked && loser.isRevoked) {
            updated = updated.copy(
                isRevoked = true,
                revokedAt = loser.revokedAt,
                revocationReason = loser.revocationReason
            )
        }
        if (updated.revocationCertificate == null && loser.revocationCertificate != null) {
            updated = updated.copy(revocationCertificate = loser.revocationCertificate)
        }
        return updated
    }

    private fun laterOf(a: Long?, b: Long?): Long? = when {
        a == null -> b
        b == null -> a
        else -> maxOf(a, b)
    }
}
