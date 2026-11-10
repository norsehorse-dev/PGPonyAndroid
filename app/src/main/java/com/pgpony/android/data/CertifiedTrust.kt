// CertifiedTrust.kt
// PGPony Android 4.8.0 RC8 (#115): the trust level every surface shows, with
// certifications by your own Ultimate keys taken into account (the rule is in
// crypto/TrustFromCertification). RC10 (#115): and through trusted
// introducers, so the answers come from the whole keyring at once
// (TrustFromCertification.graph). A certification vouches for one User ID, so
// the answers are kept per User ID: a key shows Verified only when the User ID
// shown for it is valid, and an address check needs a valid User ID with that
// address.
//
// The stored trustLevel stays what the user set; nothing derived is written
// over it, so a backup, a merge of duplicate rows or the trust picker keep
// working on the user's own choice, and revoking or deleting a key on the path
// (or a certification) drops the key back on the next refresh.
//
// When the answers are worked out again: when any key's certificate or local
// certifications change, when any key's stored level, revocation or expiry
// changes, or when the earliest time along any path runs out (a certification,
// a trust signature or a key expiring, or a certification dated ahead of the
// clock coming due). Any change anywhere redoes the whole keyring: an answer
// can depend on keys several steps away, and the keyring is small. Rings are
// kept between runs while their stamp holds. A User ID whose path has run out
// is no longer shown, even on a screen left open. Every keyring read carries
// an order taken before the read, so a request holding an older read never
// brings back a demoted or deleted key. Changes are read from
// SecureKeyStore.blobStamp (file times and sizes), which every process sees,
// so the OpenPGP provider in :remote_api notices a certification made or
// withdrawn in the app and the other way round; an in-process counter catches
// two writes inside one file-time tick.
//
// KeyRepository.getAllKeys starts a refresh in the background and returns at
// once, so a list or a card operation never waits on signature checks. The
// answers sit in Compose state, so a screen showing a key's trust redraws when
// they land. A caller that needs the answer now (the provider's confirmed
// checks, Key Details) asks KeyRepository.ensureCertifiedTrust.

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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

object CertifiedTrust {

    /**
     * The key that made a User ID valid, named for Key Details. [introducerFor]
     * is the label of your key at the top of the chain when [fingerprint] is a
     * trusted introducer rather than one of your Ultimate keys; null when it is
     * yours. [untilMs]: when this stops holding (null: no limit).
     */
    data class Certifier(
        val fingerprint: String,
        val label: String,
        val introducerFor: String?,
        val untilMs: Long?
    )

    /**
     * Why a key shows Verified, for Key Details: the key that certified the
     * User ID shown (and, when it is a trusted introducer, your key it is an
     * introducer for), and the valid User IDs when not all of the key's User
     * IDs are (null when all are).
     */
    data class Verification(val certifierLabel: String, val introducerFor: String?, val onlyUserIds: List<String>?)

    /** What is published for one key: valid User ID to its certifier, and whether every bound User ID is valid. */
    private data class Vouched(val byUserId: Map<String, Certifier>, val all: Boolean)

    /**
     * The OpenPGP provider's signature result for a confirmed key: the User ID
     * to report as primary and the User IDs to list as confirmed.
     */
    data class Confirmation(val primaryUserId: String, val confirmedUserIds: List<String>)

    /** Target fingerprint (upper case) to what is vouched for on it. */
    private val byTarget = mutableStateOf<Map<String, Vouched>>(emptyMap())

    /** Per-fingerprint write counter, bumped by SecureKeyStore in this process. */
    private val generations = ConcurrentHashMap<String, Long>()

    /** Everything about one key the answers depend on, besides time. */
    private data class Row(
        val fingerprint: String,
        val stamp: String,
        val trust: TrustLevel,
        val isOwnKey: Boolean,
        val isRevoked: Boolean,
        val isExpired: Boolean
    )

    /** The answers for the whole keyring, the rows they came from, and the order of that keyring read. */
    private class Answer(val rows: List<Row>, val seq: Long, val graph: TrustFromCertification.Graph)

    @Volatile private var answer: Answer? = null
    private val answerLock = Any()

    /** A ring as read for one stamp, with its local-only certifications. */
    private class Loaded(val stamp: String, val ring: PGPPublicKeyRing?, val local: List<Pair<String, PGPSignature>>)

    private val rings = ConcurrentHashMap<String, Loaded>()

    private val seqs = AtomicLong()
    /** The newest keyring read seen, with its order: what is published follows it. */
    private val latestKeys = AtomicReference<Pair<Long, List<PGPKeyEntity>>>(0L to emptyList())
    private val publishLock = Any()

    /**
     * Order for a keyring read. Take it BEFORE reading the keys and pass it to
     * [refresh] or [refreshLater] with them, so a request holding an older
     * read (a demoted or deleted key still in it) never wins over a newer one.
     */
    fun nextSeq(): Long = seqs.incrementAndGet()

    private fun norm(fingerprint: String): String = fingerprint.filterNot { it.isWhitespace() }.uppercase()

    /** [fingerprint]'s stored certificate or local certifications changed in this process. */
    fun invalidate(fingerprint: String) {
        generations.merge(norm(fingerprint), 1L) { a, b -> a + b }
    }

    // ── Reading ─────────────────────────────────────────────────────────

    /** [key]'s valid User IDs and who certified each; empty unless its stored level may be raised. */
    fun certifiedUserIds(key: PGPKeyEntity): Map<String, Certifier> {
        if (!TrustFromCertification.canRaise(key.trustLevel)) return emptyMap()
        val vouched = byTarget.value[norm(key.fingerprint)] ?: return emptyMap()
        // A User ID whose path has run out no longer holds, even before the
        // next refresh replaces it.
        val nowMs = System.currentTimeMillis()
        return vouched.byUserId.filterValues { c -> c.untilMs == null || nowMs < c.untilMs }
    }

    /** The certifier of the User ID the app shows for [key], or null. */
    private fun shownCertifier(key: PGPKeyEntity, certified: Map<String, Certifier>): Certifier? =
        certified[key.userID] ?: certified.entries.firstOrNull { it.key.trim() == key.userID.trim() }?.value

    /** The level to show for [key]. */
    fun effective(key: PGPKeyEntity): TrustLevel {
        val certified = certifiedUserIds(key)
        return TrustFromCertification.effective(key.trustLevel, shownCertifier(key, certified) != null)
    }

    /** Why [key] shows Verified through a certification, or null when it does not. */
    fun verificationFor(key: PGPKeyEntity): Verification? {
        val certified = certifiedUserIds(key)
        val shown = shownCertifier(key, certified) ?: return null
        val vouched = byTarget.value[norm(key.fingerprint)]
        val all = vouched?.all == true && certified.size == vouched.byUserId.size
        return Verification(shown.label, shown.introducerFor, if (all) null else certified.keys.toList())
    }

    /**
     * The OpenPGP provider's "confirmed" for [key]: a level the user set to
     * Verified or Ultimate, as before; otherwise a valid User ID whose address
     * is [address], or, with no address to match, the User ID shown for the
     * key valid.
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
     * is confirmed, from [ringUserIds] (the User IDs on its certificate); null
     * when it is not confirmed. A level the user set to Verified or Ultimate
     * confirms every User ID with the shown one as primary, as before.
     * Otherwise only the valid User IDs are confirmed, and the primary
     * reported is the valid one with [address] (or the shown one, when valid
     * and there is no address to match).
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

    /** Short name for Key Details: the name, else the email, else the key ID. */
    private fun labelOf(key: PGPKeyEntity): String =
        key.userName.ifBlank { key.userEmail }.ifBlank { key.shortFingerprint }

    private class Loaders(
        val loadRing: (String) -> PGPPublicKeyRing?,
        val loadLocal: (String) -> List<Pair<String, PGPSignature>>,
        val stamp: (String) -> String
    )

    private class Request(val seq: Long, val keys: List<PGPKeyEntity>, val loaders: Loaders)

    private val worker = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val pending = AtomicReference<Request?>(null)
    private val working = AtomicBoolean(false)
    /** The loaders of the last refresh, so a refresh can run again when an answer runs out. */
    private val lastLoaders = AtomicReference<Loaders?>(null)

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
        val request = Request(seq, keys, Loaders(loadRing, loadLocal, stamp))
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
                        run(r.seq, r.keys, r.loaders)
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
     * taking [seq] from [nextSeq]). [only] is kept for callers that name the
     * keys they need; since RC10 the whole keyring is worked out together, as
     * one key's answer can depend on keys several steps away. [loadRing] reads
     * a stored certificate, [loadLocal] a key's local-only certifications as
     * (User ID, signature), [stamp] what changes when either is rewritten.
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun refresh(
        seq: Long,
        keys: List<PGPKeyEntity>,
        only: Collection<String>?,
        loadRing: (String) -> PGPPublicKeyRing?,
        loadLocal: (String) -> List<Pair<String, PGPSignature>>,
        stamp: (String) -> String
    ): Unit = run(seq, keys, Loaders(loadRing, loadLocal, stamp))

    /** One computation at a time (RC10 review): concurrent runs shared parsed signatures. */
    private val computeMutex = Mutex()

    /** Edges kept between runs, so one changed key re-checks only its own edges. */
    private val edgeCache = TrustFromCertification.EdgeCache()

    /** How long a failed run's empty answer stands before the next try. */
    private const val RETRY_AFTER_FAILURE_MS = 60_000L

    /** The answer held already covers [rows] at [nowMs], or a newer read has answered. */
    private fun answered(rows: List<Row>, seq: Long, nowMs: Long): Boolean {
        val current = answer ?: return false
        if (current.seq > seq) return true
        val checkAgainAt = current.graph.checkAgainAtMs
        return current.rows == rows && (checkAgainAt == null || nowMs < checkAgainAt)
    }

    private suspend fun run(seq: Long, keys: List<PGPKeyEntity>, loaders: Loaders): Unit = withContext(Dispatchers.Default) {
        lastLoaders.set(loaders)
        // What is published follows the newest keyring read, whichever
        // request finishes last.
        latestKeys.updateAndGet { old -> if (old.first > seq) old else seq to keys }
        fun stampOf(fp: String) = "${generations[norm(fp)] ?: 0L}/${loaders.stamp(fp)}"
        // Rows are read before any certificate is, so a write that lands
        // during the work below shows up as a change on the next refresh.
        val rows = keys.map {
            Row(norm(it.fingerprint), stampOf(it.fingerprint), it.trustLevel, it.isOwnKey, it.isRevoked, it.isExpired)
        }.sortedBy { it.fingerprint }
        if (!answered(rows, seq, System.currentTimeMillis())) {
            computeMutex.withLock {
                // Another caller may have answered while this one waited.
                val nowMs = System.currentTimeMillis()
                if (!answered(rows, seq, nowMs)) {
                    val graph = try {
                        compute(keys, rows, loaders, nowMs)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        // Fail closed: nothing raised until a run succeeds.
                        TrustFromCertification.Graph(emptyMap(), emptyMap(), nowMs + RETRY_AFTER_FAILURE_MS)
                    }
                    synchronized(answerLock) {
                        val held = answer
                        if (held == null || held.seq <= seq) answer = Answer(rows, seq, graph)
                    }
                }
            }
        }
        // The same rows from a newer read: the answer stands for that read too.
        synchronized(answerLock) {
            val held = answer
            if (held != null && held.seq < seq && held.rows == rows) answer = Answer(rows, seq, held.graph)
        }
        publish()
    }

    private fun compute(keys: List<PGPKeyEntity>, rows: List<Row>, loaders: Loaders, nowMs: Long): TrustFromCertification.Graph {
        val stampByFp = rows.associate { it.fingerprint to it.stamp }
        val inputs = keys.map { e ->
            val fp = norm(e.fingerprint)
            val st = stampByFp[fp] ?: ""
            val loaded = rings[fp]?.takeIf { it.stamp == st } ?: Loaded(
                st,
                runCatching { loaders.loadRing(e.fingerprint) }.getOrNull(),
                runCatching { loaders.loadLocal(e.fingerprint) }.getOrDefault(emptyList())
            ).also { rings[fp] = it }
            TrustFromCertification.KeyInput(
                fingerprint = fp,
                ring = loaded.ring,
                local = loaded.local,
                isRoot = TrustFromCertification.mayVouch(e.trustLevel, e.isOwnKey, e.isRevoked, e.isExpired),
                mayIntroduce = TrustFromCertification.mayIntroduce(e.trustLevel, e.isRevoked, e.isExpired),
                stamp = st
            )
        }
        rings.keys.retainAll(stampByFp.keys)
        edgeCache.retain(stampByFp.keys)
        return TrustFromCertification.graph(inputs, nowMs, edgeCache)
    }

    /** Wakes a refresh when the earliest answer runs out, so an open screen follows it. */
    private var expiryJob: Job? = null

    /**
     * Rebuild the shown answers from the newest keyring read and the newest
     * answer. Every key on a path must still qualify in the newest read (the
     * root one of your Ultimate keys, each introducer below it allowed to
     * introduce), so a path through a key just marked Don't use or Unverified
     * is not shown even before the answer is worked out again.
     */
    private fun publish() {
        synchronized(publishLock) {
            val (seq, keys) = latestKeys.get()
            val graph = answer?.graph
            val byFp = keys.associateBy { norm(it.fingerprint) }
            val next = HashMap<String, Vouched>()
            if (graph != null) {
                for ((fp, uids) in graph.valid) {
                    if (fp !in byFp) continue
                    val byUserId = uids.mapNotNull { (uid, path) ->
                        val chain = path.chain.map { byFp[it] ?: return@mapNotNull null }
                        val root = chain.firstOrNull() ?: return@mapNotNull null
                        val certifier = byFp[path.certifierFingerprint] ?: return@mapNotNull null
                        if (!TrustFromCertification.mayVouch(root.trustLevel, root.isOwnKey, root.isRevoked, root.isExpired)) {
                            return@mapNotNull null
                        }
                        if (chain.drop(1).any { !TrustFromCertification.mayIntroduce(it.trustLevel, it.isRevoked, it.isExpired) }) {
                            return@mapNotNull null
                        }
                        val viaIntroducer = path.certifierFingerprint != path.rootFingerprint
                        uid to Certifier(
                            certifier.fingerprint,
                            labelOf(certifier),
                            if (viaIntroducer) labelOf(root) else null,
                            path.untilMs
                        )
                    }.toMap()
                    if (byUserId.isEmpty()) continue
                    next[fp] = Vouched(byUserId, byUserId.size >= (graph.boundCount[fp] ?: Int.MAX_VALUE))
                }
            }
            if (next != byTarget.value) byTarget.value = next
            expiryJob?.cancel()
            val wakeAt = graph?.checkAgainAtMs
            expiryJob = if (wakeAt == null) null else worker.launch {
                delay((wakeAt - System.currentTimeMillis()).coerceAtLeast(0L) + 1L)
                val loaders = lastLoaders.get() ?: return@launch
                val (latestSeq, latest) = latestKeys.get()
                try {
                    // Same read as before, worked out again for the new time.
                    run(maxOf(latestSeq, seq), latest, loaders)
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    // The next keyring read tries again.
                }
            }
        }
    }
}
