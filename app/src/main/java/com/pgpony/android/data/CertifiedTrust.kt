// CertifiedTrust.kt
// PGPony Android 4.8.0 RC8 (#115): the trust level every surface shows, with
// certifications by your own Ultimate keys taken into account (the rule is in
// crypto/TrustFromCertification). A certification vouches for one User ID, so
// the answers are kept per User ID: a key shows Verified only when the User ID
// shown for it is certified, and an address check needs a certified User ID
// with that address.
//
// The stored trustLevel stays what the user set; nothing derived is written
// over it, so a backup, a merge of duplicate rows or the trust picker keep
// working on the user's own choice, and revoking or deleting the certifying
// key (or the certification) drops the key back on the next refresh.
//
// When an answer is checked again: when the key's certificate or local
// certifications change, when the set of your Ultimate keys (or one of their
// certificates) changes, or when the answer's own time runs out (the earliest
// of the certification's, the certifier's and the key's expiry, or when a
// certification dated ahead of the clock would count). A positive answer whose
// time has run out is no longer shown, even on a screen left open. Every
// keyring read carries an order taken before the read, so a request holding
// an older read never brings back a demoted or deleted Ultimate key. Changes are
// read from SecureKeyStore.blobStamp (file times and sizes), which every
// process sees, so the OpenPGP provider in :remote_api notices a certification
// made or withdrawn in the app and the other way round; an in-process counter
// catches two writes inside one file-time tick.
//
// KeyRepository.getAllKeys starts a refresh in the background and returns at
// once, so a list or a card operation never waits on signature checks. The
// answers sit in Compose state, so a screen showing a key's trust redraws when
// they land. A caller that needs the answer now (the provider's confirmed
// checks, Key Details) asks KeyRepository.ensureCertifiedTrust for the keys
// involved.

package com.pgpony.android.data

import androidx.compose.runtime.mutableStateOf
import com.pgpony.android.crypto.TrustFromCertification
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

object CertifiedTrust {

    /** Your key that certified a User ID, named for Key Details. */
    data class Certifier(val fingerprint: String, val label: String)

    /**
     * Why a key shows Verified, for Key Details: the key that certified the
     * User ID shown, and the certified User IDs when not all of the key's
     * User IDs are (null when all are).
     */
    data class Verification(val certifierLabel: String, val onlyUserIds: List<String>?)

    /**
     * What is published for one key: certified User ID to its certifier,
     * whether every bound User ID is certified, and when it stops holding.
     */
    private data class Vouched(val byUserId: Map<String, Certifier>, val all: Boolean, val validUntilMs: Long?)

    /**
     * The OpenPGP provider's signature result for a confirmed key: the User ID
     * to report as primary and the User IDs to list as confirmed.
     */
    data class Confirmation(val primaryUserId: String, val confirmedUserIds: List<String>)

    /** Target fingerprint (upper case) to what your keys vouch for on it. */
    private val byTarget = mutableStateOf<Map<String, Vouched>>(emptyMap())

    /** Per-fingerprint write counter, bumped by SecureKeyStore in this process. */
    private val generations = ConcurrentHashMap<String, Long>()

    private data class CertifierRow(val fingerprint: String, val stamp: String)

    /** What a cached answer for one key depends on, besides time. */
    private data class Inputs(val stamp: String, val certifiers: List<CertifierRow>)

    private class Answer(
        val inputs: Inputs,
        /** User ID to certifier fingerprint (upper case). */
        val byUserId: Map<String, String>,
        val boundCount: Int,
        val validUntilMs: Long?,
        /** Order of the keyring read it was worked out from, so an answer from
         *  an older read never replaces one from a newer read. */
        val seq: Long
    )

    private val answers = ConcurrentHashMap<String, Answer>()
    private val seqs = AtomicLong()
    /** The newest keyring read seen, with its order: what is published follows it. */
    private val latestKeys = AtomicReference<Pair<Long, List<PGPKeyEntity>>>(0L to emptyList())
    private val publishLock = Any()

    /**
     * Order for a keyring read. Take it BEFORE reading the keys and pass it to
     * [refresh] or [refreshLater] with them, so a request holding an older
     * read (a demoted or deleted Ultimate key still in it) never wins over a
     * newer one.
     */
    fun nextSeq(): Long = seqs.incrementAndGet()

    private fun norm(fingerprint: String): String = fingerprint.filterNot { it.isWhitespace() }.uppercase()

    /** [fingerprint]'s stored certificate or local certifications changed in this process. */
    fun invalidate(fingerprint: String) {
        generations.merge(norm(fingerprint), 1L) { a, b -> a + b }
    }

    // ── Reading ─────────────────────────────────────────────────────────

    /** [key]'s certified User IDs and who certified each; empty unless its stored level may be raised. */
    fun certifiedUserIds(key: PGPKeyEntity): Map<String, Certifier> {
        if (!TrustFromCertification.canRaise(key.trustLevel, key.isOwnKey)) return emptyMap()
        val vouched = byTarget.value[norm(key.fingerprint)] ?: return emptyMap()
        // An answer whose time has passed no longer holds, even before the
        // next refresh replaces it.
        val until = vouched.validUntilMs
        if (until != null && System.currentTimeMillis() >= until) return emptyMap()
        return vouched.byUserId
    }

    /** The certifier of the User ID the app shows for [key], or null. */
    private fun shownCertifier(key: PGPKeyEntity, certified: Map<String, Certifier>): Certifier? =
        certified[key.userID] ?: certified.entries.firstOrNull { it.key.trim() == key.userID.trim() }?.value

    /** The level to show for [key]. */
    fun effective(key: PGPKeyEntity): TrustLevel {
        val certified = certifiedUserIds(key)
        return TrustFromCertification.effective(key.trustLevel, key.isOwnKey, shownCertifier(key, certified) != null)
    }

    /** Why [key] shows Verified through a certification, or null when it does not. */
    fun verificationFor(key: PGPKeyEntity): Verification? {
        val certified = certifiedUserIds(key)
        val shown = shownCertifier(key, certified) ?: return null
        val all = byTarget.value[norm(key.fingerprint)]?.all == true
        return Verification(shown.label, if (all) null else certified.keys.toList())
    }

    /**
     * The OpenPGP provider's "confirmed" for [key]: a level the user set to
     * Verified or Ultimate, as before; otherwise a certified User ID whose
     * address is [address], or, with no address to match, the User ID shown
     * for the key certified.
     */
    fun isConfirmedFor(key: PGPKeyEntity, address: String?): Boolean {
        if (key.trustLevel == TrustLevel.VERIFIED || key.trustLevel == TrustLevel.ULTIMATE) return true
        val certified = certifiedUserIds(key)
        if (certified.isEmpty()) return false
        return if (!address.isNullOrBlank()) {
            TrustFromCertification.certifiesAddress(certified.keys, address)
        } else {
            shownCertifier(key, certified) != null
        }
    }

    /**
     * The User IDs the provider's signature result reports for [key] when it
     * is confirmed ([isConfirmedFor] true), from [ringUserIds] (the User IDs
     * on its certificate); null when it is not confirmed. A level the user set
     * to Verified or Ultimate confirms every User ID with the shown one as
     * primary, as before. Otherwise only the certified User IDs are confirmed,
     * and the primary reported is the certified one with [address] (or the
     * shown one, when certified and there is no address to match).
     */
    fun confirmationFor(key: PGPKeyEntity, ringUserIds: List<String>, address: String?): Confirmation? {
        if (key.trustLevel == TrustLevel.VERIFIED || key.trustLevel == TrustLevel.ULTIMATE) {
            return Confirmation(key.userID, ringUserIds)
        }
        val certified = certifiedUserIds(key)
        val confirmed = ringUserIds.filter { it in certified }
        if (confirmed.isEmpty()) return null
        val primary = if (!address.isNullOrBlank()) {
            confirmed.firstOrNull { TrustFromCertification.certifiesAddress(listOf(it), address) }
        } else {
            confirmed.firstOrNull { it == key.userID || it.trim() == key.userID.trim() }
        } ?: return null
        return Confirmation(primary, confirmed)
    }

    // ── Refreshing ──────────────────────────────────────────────────────

    /** Your keys that may vouch for others: Ultimate, not revoked, not expired. */
    private fun ownUltimate(keys: List<PGPKeyEntity>): List<PGPKeyEntity> =
        keys.filter { TrustFromCertification.mayVouch(it.trustLevel, it.isOwnKey, it.isRevoked, it.isExpired) }
            .sortedBy { norm(it.fingerprint) }

    /** Short name for "Verified by your key ...": the name, else the email, else the key ID. */
    private fun labelOf(key: PGPKeyEntity): String =
        key.userName.ifBlank { key.userEmail }.ifBlank { key.shortFingerprint }

    private class Request(
        val seq: Long,
        val keys: List<PGPKeyEntity>,
        val loadRing: (String) -> PGPPublicKeyRing?,
        val loadLocal: (String) -> List<Pair<String, PGPSignature>>,
        val stamp: (String) -> String
    )

    private val worker = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val pending = AtomicReference<Request?>(null)
    private val working = AtomicBoolean(false)

    /**
     * Start a refresh for [keys] (read after taking [seq] from [nextSeq])
     * without waiting for it; a newer request replaces one not yet started.
     */
    fun refreshLater(
        seq: Long,
        keys: List<PGPKeyEntity>,
        loadRing: (String) -> PGPPublicKeyRing?,
        loadLocal: (String) -> List<Pair<String, PGPSignature>>,
        stamp: (String) -> String
    ) {
        val request = Request(seq, keys, loadRing, loadLocal, stamp)
        pending.updateAndGet { old -> if (old != null && old.seq > seq) old else request }
        drain()
    }

    private fun drain() {
        if (!working.compareAndSet(false, true)) return
        worker.launch {
            try {
                while (true) {
                    val r = pending.getAndSet(null) ?: break
                    try {
                        refresh(r.seq, r.keys, null, r.loadRing, r.loadLocal, r.stamp)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        // Shown trust stays as it was; the next read tries again.
                    }
                }
            } finally {
                working.set(false)
                if (pending.get() != null) drain()
            }
        }
    }

    /**
     * Bring the answers up to date for [keys] (the live keyring, read after
     * taking [seq] from [nextSeq]), checking only the keys in [only]
     * (fingerprints) when given. [loadRing] reads a stored certificate,
     * [loadLocal] a key's local-only certifications as (User ID, signature),
     * [stamp] what changes when either is rewritten.
     */
    suspend fun refresh(
        seq: Long,
        keys: List<PGPKeyEntity>,
        only: Collection<String>?,
        loadRing: (String) -> PGPPublicKeyRing?,
        loadLocal: (String) -> List<Pair<String, PGPSignature>>,
        stamp: (String) -> String
    ): Unit = withContext(Dispatchers.Default) {
        // What is published follows the newest keyring read, whichever
        // request finishes last.
        latestKeys.updateAndGet { old -> if (old.first > seq) old else seq to keys }
        val nowMs = System.currentTimeMillis()
        val owners = ownUltimate(keys)
        val wanted = only?.map { norm(it) }?.toSet()
        fun stampOf(fp: String) = "${generations[norm(fp)] ?: 0L}/${stamp(fp)}"
        val certifierRows = owners.map { CertifierRow(norm(it.fingerprint), stampOf(it.fingerprint)) }
        val targets = keys.filter { !it.isOwnKey && (wanted == null || norm(it.fingerprint) in wanted) }
        // Inputs are read before any certificate is, so a write that lands
        // during the work below shows up as a change on the next refresh.
        val stale = targets.mapNotNull { t ->
            val inputs = Inputs(stampOf(t.fingerprint), certifierRows)
            val old = answers[norm(t.fingerprint)]
            val current = old != null && old.inputs == inputs && (old.validUntilMs == null || nowMs < old.validUntilMs)
            if (current) null else t to inputs
        }
        if (stale.isNotEmpty()) {
            val vouchers: List<Pair<String, TrustFromCertification.Voucher>> = owners.mapNotNull { e ->
                val ring = runCatching { loadRing(e.fingerprint) }.getOrNull() ?: return@mapNotNull null
                val v = TrustFromCertification.voucherOf(ring, nowMs) ?: return@mapNotNull null
                norm(e.fingerprint) to v
            }
            for ((t, inputs) in stale) {
                val finding = if (vouchers.isEmpty()) TrustFromCertification.Finding.NONE else runCatching {
                    loadRing(t.fingerprint)?.let { ring ->
                        TrustFromCertification.findings(ring, loadLocal(t.fingerprint), vouchers.map { it.second }, nowMs)
                    }
                }.getOrNull() ?: TrustFromCertification.Finding.NONE
                val byUserId = finding.byUserId.mapNotNull { (uid, key) ->
                    vouchers.firstOrNull { it.second.primary === key }?.first?.let { uid to it }
                }.toMap()
                val answer = Answer(inputs, byUserId, finding.boundUserIds.size, finding.validUntilMs, seq)
                answers.compute(norm(t.fingerprint)) { _, old -> if (old != null && old.seq > seq) old else answer }
            }
        }
        publish()
    }

    /** Wakes [publish] when the earliest shown answer runs out, so an open screen drops it. */
    private var expiryJob: Job? = null

    /** Rebuild the shown answers from the newest keyring read and every answer held. */
    private fun publish() {
        synchronized(publishLock) {
            val keys = latestKeys.get().second
            val nowMs = System.currentTimeMillis()
            val live = keys.filter { !it.isOwnKey }.map { norm(it.fingerprint) }.toSet()
            answers.keys.retainAll(live)
            val ownerByFp = ownUltimate(keys).associateBy { norm(it.fingerprint) }
            val next = HashMap<String, Vouched>()
            var nextExpiry = Long.MAX_VALUE
            for (fp in live) {
                val a = answers[fp] ?: continue
                val until = a.validUntilMs
                if (until != null && nowMs >= until) continue
                val byUserId = a.byUserId.mapNotNull { (uid, certFp) ->
                    ownerByFp[certFp]?.let { uid to Certifier(it.fingerprint, labelOf(it)) }
                }.toMap()
                if (byUserId.isEmpty()) continue
                next[fp] = Vouched(byUserId, byUserId.size >= a.boundCount, until)
                if (until != null) nextExpiry = minOf(nextExpiry, until)
            }
            if (next != byTarget.value) byTarget.value = next
            expiryJob?.cancel()
            expiryJob = if (nextExpiry == Long.MAX_VALUE) null else worker.launch {
                delay((nextExpiry - System.currentTimeMillis()).coerceAtLeast(0L) + 1L)
                publish()
            }
        }
    }
}
