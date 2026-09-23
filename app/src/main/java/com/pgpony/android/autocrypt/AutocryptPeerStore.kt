// AutocryptPeerStore.kt
// PGPony Android — 4.0.0 Phase 4 (Autocrypt)
//
// The Autocrypt Level 1 peer-state machine behind the OpenPGP API's
// ACTION_UPDATE_AUTOCRYPT_PEER / ACTION_QUERY_AUTOCRYPT_STATUS. Email
// clients parse Autocrypt + Autocrypt-Gossip headers and hand us the
// per-peer update; we persist the timestamps + prefer-encrypt flag, and
// import the key material into the keyring so the existing by-email
// resolution finds it at encrypt time. Read back as an encryption
// RECOMMENDATION for the composer.
//
// Update rules (Autocrypt Level 1 §"Updating Autocrypt Peer State"):
//   • last-seen only ever advances.
//   • an Autocrypt header updates the key only when its effective date is
//     newer than the stored autocrypt timestamp.
//   • gossip is lower priority: newer-than-stored-gossip only, and never
//     bumps last-seen.
//
// Key import is behind [AutocryptKeyImporter] so the state machine is
// unit-testable without a live keyring; [create] wires the real one.

package com.pgpony.android.autocrypt

import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.AutocryptPeerDao
import com.pgpony.android.data.AutocryptPeerEntity
import com.pgpony.android.data.repository.KeyRepository

/** Encryption recommendation for a peer (maps to OpenPGP-API status). */
enum class AutocryptRecommendation { DISCOURAGE, AVAILABLE, MUTUAL }

/** Imports Autocrypt keydata into the keyring, returning the fingerprint. */
fun interface AutocryptKeyImporter {
    /** Import [keyData] only as a key FOR [addr]; return its fingerprint or null. */
    suspend fun import(addr: String, keyData: ByteArray): String?
}

class AutocryptPeerStore(
    private val dao: AutocryptPeerDao,
    private val importer: AutocryptKeyImporter
) {
    companion object {
        // A key not reaffirmed by a message within this window drops from
        // "available" back to "discourage" (Autocrypt recency guidance).
        private const val AUTOCRYPT_GAP_MS = 35L * 24 * 60 * 60 * 1000 // 35 days

        /** Production store: import via [PGPCryptoService] + [KeyRepository]. */
        fun create(
            dao: AutocryptPeerDao,
            repo: KeyRepository,
            crypto: PGPCryptoService = PGPCryptoService.shared
        ): AutocryptPeerStore = AutocryptPeerStore(dao) { addr, keyData ->
            // Autocrypt keydata is raw OpenPGP key packets; explode handles
            // binary or armored and yields one re-armored ring per key.
            //
            // 4.6.0 (item 17.4): the keydata is supplied by whoever sent the
            // mail (or wrote the gossip line, or called the API). Import at
            // most ONE ring, and only when every User ID on it is exactly
            // [addr], so a header cannot plant a key that carries someone
            // else's address. The row is marked Autocrypt-origin, which keeps
            // it from ever joining a user-managed key for the same address as
            // an extra recipient (see PGPonyOpenPgpService.encryptOp).
            for (ring in crypto.explodeToArmoredKeys(keyData)) {
                if (!isKeyFor(addr, ring)) continue
                return@AutocryptPeerStore runCatching {
                    repo.importArmoredKeyDetailed(ring, fromAutocrypt = true)
                }.getOrNull()?.entity?.fingerprint
            }
            null
        }

        /**
         * 4.6.0 (item 17.4): may [armoredRing] be taken as [addr]'s key? A
         * public key only, with at least one User ID its primary certified,
         * and every certified User ID exactly [addr] (works for composite
         * keys too, since the check reads raw packets).
         */
        internal fun isKeyFor(addr: String, armoredRing: String): Boolean {
            val raw = runCatching { com.pgpony.android.crypto.pqc.CompositeSigPacket.dearmor(armoredRing) }
                .getOrNull() ?: return false
            if (com.pgpony.android.crypto.CertificateBindings.packets(raw).any { it.tag == 5 || it.tag == 7 }) return false
            val report = com.pgpony.android.crypto.CertificateBindings.analyze(raw) ?: return false
            val uids = report.certifiedUserIds
            val want = normAddr(addr)
            return uids.isNotEmpty() && uids.all { normAddr(it) == want }
        }

        /** The bare, lowercased address in a User ID or peer id. */
        internal fun normAddr(id: String): String =
            id.substringAfterLast('<').substringBefore('>').trim().ifEmpty { id.trim() }.lowercase()
    }

    private fun norm(id: String): String =
        id.substringAfterLast('<').substringBefore('>').trim().ifEmpty { id.trim() }.lowercase()

    // ── Updates ──────────────────────────────────────────────────────

    /** Heard from the peer, but no usable Autocrypt key — advance last-seen. */
    suspend fun updateLastSeen(peerId: String, effectiveMs: Long) {
        val id = norm(peerId)
        val cur = dao.get(id) ?: AutocryptPeerEntity(id)
        if (effectiveMs > cur.lastSeen) dao.upsert(cur.copy(lastSeen = effectiveMs))
    }

    /** Apply an Autocrypt header carrying key material. */
    suspend fun updateKey(peerId: String, effectiveMs: Long, keyData: ByteArray, isMutual: Boolean) {
        val id = norm(peerId)
        val cur = dao.get(id) ?: AutocryptPeerEntity(id)
        val lastSeen = maxOf(cur.lastSeen, effectiveMs)
        if (effectiveMs < cur.autocryptTimestamp) {
            // Older than what we have — only last-seen may advance.
            if (lastSeen != cur.lastSeen) dao.upsert(cur.copy(lastSeen = lastSeen))
            return
        }
        val fp = importer.import(id, keyData)
        dao.upsert(
            cur.copy(
                lastSeen = lastSeen,
                autocryptTimestamp = effectiveMs,
                autocryptKeyFingerprint = fp ?: cur.autocryptKeyFingerprint,
                isMutual = isMutual
            )
        )
    }

    /** Apply an Autocrypt-Gossip key (lower priority; no last-seen bump). */
    suspend fun updateGossipKey(peerId: String, effectiveMs: Long, keyData: ByteArray) {
        val id = norm(peerId)
        val cur = dao.get(id) ?: AutocryptPeerEntity(id)
        if (effectiveMs < cur.gossipTimestamp) return
        val fp = importer.import(id, keyData)
        dao.upsert(
            cur.copy(
                gossipTimestamp = effectiveMs,
                gossipKeyFingerprint = fp ?: cur.gossipKeyFingerprint
            )
        )
    }

    /**
     * 4.6.0 (item 17.4): the key Autocrypt designates for [peerId], the one an
     * Autocrypt-origin recipient is encrypted to: the header key when there is
     * one, otherwise the gossip key. Null when nothing is recorded.
     */
    suspend fun designatedKeyFingerprint(peerId: String): String? {
        val cur = dao.get(norm(peerId)) ?: return null
        return cur.autocryptKeyFingerprint ?: cur.gossipKeyFingerprint
    }

    // ── Ingest from PGPony's own decrypt ─────────────────────────────

    /**
     * Ingest Autocrypt state from an email PGPony decrypted itself.
     * [rawEmail] is the outer message (headers + multipart/encrypted)
     * carrying the sender's `Autocrypt:` header; [decryptedContent] is the
     * decrypted inner MIME, which may carry `Autocrypt-Gossip:` headers for
     * other recipients. No-op when neither is present or has headers. The
     * effective date is the message's Date header (falling back to now).
     */
    suspend fun ingestEmail(rawEmail: String?, decryptedContent: String?) {
        val now = System.currentTimeMillis()
        val effective = rawEmail
            ?.let { AutocryptHeader.extractHeaders(it, "Date").firstOrNull() }
            ?.let { parseEmailDate(it) } ?: now

        if (rawEmail != null) {
            val fromAddr = AutocryptHeader.extractHeaders(rawEmail, "From")
                .firstOrNull()?.let { addrOf(it) }
            for (hv in AutocryptHeader.extractHeaders(rawEmail, "Autocrypt")) {
                val p = AutocryptHeader.parseValue(hv) ?: continue
                // Only trust an Autocrypt header whose addr matches From.
                if (fromAddr == null || p.addr.equals(fromAddr, ignoreCase = true)) {
                    updateKey(p.addr, effective, p.keyData, p.isMutual)
                }
            }
        }
        if (decryptedContent != null) {
            for (hv in AutocryptHeader.extractHeaders(decryptedContent, "Autocrypt-Gossip")) {
                val p = AutocryptHeader.parseValue(hv) ?: continue
                updateGossipKey(p.addr, effective, p.keyData)
            }
        }
    }

    private fun addrOf(from: String): String =
        from.substringAfterLast('<').substringBefore('>').trim().ifEmpty { from.trim() }.lowercase()

    private fun parseEmailDate(s: String): Long? = runCatching {
        val fmt = java.text.SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss Z", java.util.Locale.US)
        fmt.isLenient = true
        fmt.parse(s.trim())?.time
    }.getOrNull()

    // ── Recommendation ───────────────────────────────────────────────

    /**
     * Autocrypt recommendation for one peer (Autocrypt Level 1
     * §"Provide a recommendation for message encryption"):
     *   • a fresh Autocrypt key → AVAILABLE (MUTUAL if the peer prefers it),
     *   • a stale key (last message > 35 days newer than the key) or a
     *     gossip-only key → DISCOURAGE,
     *   • no peer state at all → DISCOURAGE (whether a key exists via other
     *     means is the caller's concern; it reports UNAVAILABLE when there
     *     is no key anywhere).
     */
    suspend fun recommendation(peerId: String): AutocryptRecommendation {
        val p = dao.get(norm(peerId)) ?: return AutocryptRecommendation.DISCOURAGE
        return when {
            p.autocryptKeyFingerprint != null -> {
                val stale = p.lastSeen - p.autocryptTimestamp > AUTOCRYPT_GAP_MS
                when {
                    stale -> AutocryptRecommendation.DISCOURAGE
                    p.isMutual -> AutocryptRecommendation.MUTUAL
                    else -> AutocryptRecommendation.AVAILABLE
                }
            }
            else -> AutocryptRecommendation.DISCOURAGE
        }
    }
}
