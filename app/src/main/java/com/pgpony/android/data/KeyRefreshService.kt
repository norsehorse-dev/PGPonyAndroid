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
//   4. Scan the fetched primary for a key-revocation signature
//      (tag 2, type 0x20) and apply isRevoked / revokedAt /
//      revocationReason when the upstream copy is revoked.
//   5. Stamp lastCheckedAt on the attempt.
//
// iOS → Android divergences, all deliberate:
//   • lastCheckedAt is stamped on EVERY attempt, including transport
//     failure (iOS skips the stamp on generic errors). Android's KS1
//     check-only path already stamps on error ("Still record the
//     attempt"), so the refresh follows the platform's own precedent.
//   • Fingerprint computation and the revocation scan use BouncyCastle
//     ring APIs directly (PGPCryptoService.importArmoredKey /
//     getSignaturesOfType) instead of iOS's dual ObjectivePGP + native
//     packet walk — BC reads every key shape PGPony supports.

package com.pgpony.android.data

import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.network.KeyServerRepository
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature

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

        // 4. Revocation scan on the fetched primary. Only applied when
        //    the row isn't already flagged — a locally revoked key stays
        //    revoked regardless of what the keyserver says.
        var result: PGPKeyEntity = merged
        var revocationApplied = false
        if (!merged.isRevoked) {
            val revSig = findKeyRevocationSignature(fetchedRing)
            if (revSig != null) {
                val reason = revocationReasonCode(revSig)?.let { code ->
                    RevocationReason.entries.firstOrNull { it.rfcCode == code }
                }
                repo.markRevokedFromUpstream(
                    fingerprint = merged.fingerprint,
                    revokedAtMs = revSig.creationTime?.time ?: System.currentTimeMillis(),
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

    /**
     * The first key-revocation signature (tag 2, type 0x20) on the
     * fetched ring's primary key, or null when the upstream copy isn't
     * revoked. BC's getSignaturesOfType does the packet filtering iOS's
     * native walk performs by hand.
     */
    private fun findKeyRevocationSignature(ring: PGPPublicKeyRing): PGPSignature? {
        // 4.6.0 (item 17.1): only a revocation the primary itself made, and
        // that verifies, counts. The verified view drops every other 0x20.
        val view = com.pgpony.android.crypto.CertificateBindings.verified(ring)
        val report = view.report
        if (report != null && report.supported && !report.primaryRevoked) return null
        val primary = view.ring.publicKey ?: return null
        val sigs = primary.getSignaturesOfType(PGPSignature.KEY_REVOCATION) ?: return null
        while (sigs.hasNext()) {
            (sigs.next() as? PGPSignature)?.let { return it }
        }
        return null
    }

    /**
     * RFC 4880 §5.2.3.23 Reason for Revocation code off the signature's
     * subpackets (hashed preferred, unhashed fallback — same order iOS
     * scans), or null when the signer didn't include one.
     */
    private fun revocationReasonCode(sig: PGPSignature): Int? {
        val packet = sig.hashedSubPackets
            ?.getSubpacket(SignatureSubpacketTags.REVOCATION_REASON)
            ?: sig.unhashedSubPackets
                ?.getSubpacket(SignatureSubpacketTags.REVOCATION_REASON)
        return (packet as? org.bouncycastle.bcpg.sig.RevocationReason)
            ?.revocationReason?.toInt()
    }
}
