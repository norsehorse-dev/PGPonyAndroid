// KeyRefreshService.kt
// PGPony Android — 4.0.0 Phase 2
//
// Android port of iOS v7.1.1 F5 (KeyDetailView.refreshFromKeyServer),
// housed at the repository level rather than in the ViewModel precisely
// so 4.0.0 Phase 7's background KeyRefreshWorker calls the exact same
// tested pipeline; KeyDetailViewModel is a thin caller.
//
// The pipeline, in order:
//   1. Fetch armored material by fingerprint
//      (KeyServerRepository.fetchByFingerprint — added alongside this
//      service; unlike searchByFingerprint it THROWS on transport
//      failure so "no network" never reads as "not published").
//   2. Parse via PGPCryptoService and run the MANDATORY fingerprint
//      verification: the fetched key's computed fingerprint must equal
//      the stored key's under KeyDeduplicationService.normalize, or
//      nothing is changed — never trust the keyserver response blindly.
//   3. Merge through the Phase 1 engine
//      (KeyRepository.mergeFetchedPublicMaterial →
//      KeyDeduplicationService.resolveDuplicate), which updates the
//      stored public bytes, armored cache, and expiration while
//      preserving trust level, contact link, secret material, notes,
//      and card backing. Keyservers only ever return public material,
//      and the merge path never writes secrets — so refreshing a
//      card-backed or software key pair is safe by construction.
//   4. Ask CertificateBindings.verifiedKeyRevocation for a key
//      revocation (type 0x20) that the primary itself made, that
//      verifies and that is in effect now, and apply isRevoked /
//      revokedAt / revocationReason from that revocation only. An
//      unverified or foreign 0x20 in the fetched copy changes nothing.
//   5. Stamp lastCheckedAt on the attempt.
//
// iOS → Android divergences, all deliberate:
//   • lastCheckedAt is stamped on EVERY attempt, including transport
//     failure (iOS skips the stamp on generic errors). Android's KS1
//     check-only path already stamps on error ("Still record the
//     attempt"), so the refresh follows the platform's own precedent.
//   • Fingerprint computation uses BouncyCastle ring APIs directly
//     (PGPCryptoService.importArmoredKey) and the revocation check uses
//     the engine's verified certificate report instead of iOS's dual
//     ObjectivePGP + native packet walk.

package com.pgpony.android.data

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.network.KeyServerRepository

/**
 * Outcome of one refresh attempt. Ordered here roughly by how the UI
 * reports them; RevokedUpstream wins over Merged when both happened
 * (matching iOS's message precedence).
 */
sealed class KeyRefreshResult {
    /** Fetched material is byte-identical to what's stored. */
    data class UpToDate(val entity: PGPKeyEntity) : KeyRefreshResult()

    /** Newer material was merged into the stored row. */
    data class Merged(val entity: PGPKeyEntity) : KeyRefreshResult()

    /** The keyserver copy carries a key-revocation signature; the
     *  revocation has been applied to the row. [alsoMerged] reports
     *  whether the material itself changed too (the message leads with
     *  the revocation either way). */
    data class RevokedUpstream(
        val entity: PGPKeyEntity,
        val alsoMerged: Boolean
    ) : KeyRefreshResult()

    /** The keyserver answered but has no key for this fingerprint. */
    data class NotFound(val entity: PGPKeyEntity) : KeyRefreshResult()

    /** The keyserver returned key material whose computed fingerprint
     *  does not match this key. Nothing was changed. */
    data class FingerprintMismatch(val entity: PGPKeyEntity) : KeyRefreshResult()

    /** Transport or parse failure. lastCheckedAt is still stamped
     *  (KS1 precedent — the attempt is recorded). */
    data class Failed(val entity: PGPKeyEntity, val detail: String) : KeyRefreshResult()

    /** The fingerprint has no keyring row — a Phase 7 worker edge case
     *  (key deleted between scheduling and execution). */
    object KeyMissing : KeyRefreshResult()
}

class KeyRefreshService(
    private val repo: KeyRepository,
    private val keyServer: KeyServerRepository = KeyServerRepository(),
    private val crypto: PGPCryptoService = PGPCryptoService.shared
) {

    /**
     * Run the full refresh pipeline for [fingerprint]. Never throws —
     * every failure mode maps to a [KeyRefreshResult] case so both the
     * detail screen and the Phase 7 worker handle outcomes uniformly.
     */
    suspend fun refresh(fingerprint: String): KeyRefreshResult {
        val existing = repo.getByFingerprint(fingerprint)
            ?: return KeyRefreshResult.KeyMissing

        // 1. Fetch. Transport failures throw (unlike searchByFingerprint)
        //    so airplane mode reads as a failure, not "not published".
        val armored = try {
            keyServer.fetchByFingerprint(existing.fingerprint)
        } catch (e: Exception) {
            repo.markKeyServerChecked(existing.fingerprint)
            return KeyRefreshResult.Failed(
                reload(existing),
                e.message ?: e.javaClass.simpleName
            )
        }
        if (armored.isNullOrBlank()) {
            repo.markKeyServerChecked(existing.fingerprint)
            return KeyRefreshResult.NotFound(reload(existing))
        }
        return processFetchedArmored(existing, armored)
    }

    /**
     * 4.0.0 Phase 5 — process an ALREADY-FETCHED armored copy of the key
     * through the identical verify → merge → revocation-scan → stamp
     * pipeline. The background worker (KeyRefreshWorker) fetches from each
     * enabled server itself and calls this per copy, so a revocation
     * published on ANY server propagates. [existing] is re-read by the
     * caller between servers so each merge builds on the last.
     */
    suspend fun processFetchedArmored(
        existing: PGPKeyEntity,
        armored: String
    ): KeyRefreshResult {
        // 2. Parse + mandatory fingerprint verification.
        val parsed = try {
            crypto.importArmoredKey(armored)
        } catch (e: Exception) {
            repo.markKeyServerChecked(existing.fingerprint)
            return KeyRefreshResult.Failed(
                reload(existing),
                "Could not parse the keyserver response: ${e.message}"
            )
        }
        val fetchedRing = parsed.publicKeyRing
        if (fetchedRing == null ||
            KeyDeduplicationService.normalize(parsed.fingerprint) !=
            KeyDeduplicationService.normalize(existing.fingerprint)
        ) {
            repo.markKeyServerChecked(existing.fingerprint)
            return KeyRefreshResult.FingerprintMismatch(reload(existing))
        }

        // 3. Merge via the Phase 1 engine. Expiration derives from the
        //    fetched primary with the same validSeconds pattern the
        //    import paths use.
        val fetchedExpiresAtMs = fetchedRing.publicKey?.let { key ->
            val validSec = key.getValidSeconds()
            if (validSec > 0) (key.creationTime.time + validSec * 1000) else null
        }
        val (merged, changed) = repo.mergeFetchedPublicMaterial(
            existing = existing,
            fetchedRing = fetchedRing,
            fetchedArmored = armored,
            fetchedExpiresAtMs = fetchedExpiresAtMs
        )

        // 4. Revocation check on the fetched certificate. Only applied
        //    when the row isn't already flagged; a locally revoked key
        //    stays revoked regardless of what the keyserver says. Only a
        //    revocation the primary made, that verifies and that is in
        //    effect counts (CertificateBindings.verifiedKeyRevocation);
        //    its own creation time and reason code are recorded.
        var result: PGPKeyEntity = merged
        var revocationApplied = false
        if (!merged.isRevoked) {
            val rev = CertificateBindings.verifiedKeyRevocation(fetchedRing)
            if (rev != null) {
                val reason = rev.reason?.let { code ->
                    RevocationReason.entries.firstOrNull { it.rfcCode == code }
                }
                repo.markRevokedFromUpstream(
                    fingerprint = merged.fingerprint,
                    revokedAtMs = if (rev.createdMs > 0L) rev.createdMs else System.currentTimeMillis(),
                    reason = reason
                )?.let {
                    result = it
                    revocationApplied = true
                }
            }
        }

        // 5. Stamp the attempt and report.
        repo.markKeyServerChecked(result.fingerprint)
        val finalEntity = reload(result)
        return when {
            revocationApplied ->
                KeyRefreshResult.RevokedUpstream(finalEntity, alsoMerged = changed)
            changed -> KeyRefreshResult.Merged(finalEntity)
            else -> KeyRefreshResult.UpToDate(finalEntity)
        }
    }

    /** Re-read the row so the caller gets post-stamp state. */
    private suspend fun reload(entity: PGPKeyEntity): PGPKeyEntity =
        repo.getByFingerprint(entity.fingerprint) ?: entity
}
