// RecipientReview.kt
// PGPony Android 4.7.0 (item 41, #25)
//
// The rules behind the provider's recipient review, kept free of Android types
// so they can be unit tested. When a mail app asks PGPony to encrypt to an
// address it has no usable key for, the provider opens
// ProviderRecipientReviewActivity instead of failing the send (OpenKeychain's
// "Please review the list of recipients"). The client then re-runs the same
// operation with EXTRA_KEY_IDS_SELECTED, and these rules decide which of those
// ids may join the recipients already resolved.
//
// Item 10 holds throughout: a key marked Don't use is never offered and never
// accepted from EXTRA_KEY_IDS_SELECTED, and an address whose only key is
// marked Don't use is shown as such rather than as missing.

package com.pgpony.android.provider

import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.TrustLevel

internal object RecipientReview {

    /** Why an address (or a key id the client sent) did not resolve. */
    enum class Reason { MISSING, DONT_USE }

    /**
     * The outcome of honoring EXTRA_KEY_IDS_SELECTED: the keys to encrypt to,
     * one per fingerprint, and the ids that were refused (not in the keyring,
     * revoked, marked Don't use, or expired while expired keys are not allowed).
     */
    data class Selection(val accepted: List<PGPKeyEntity>, val refused: List<Long>)

    /** The 64-bit key id the OpenPGP API uses for [key], or null if unparseable. */
    fun keyIdOf(key: PGPKeyEntity): Long? =
        runCatching { java.lang.Long.parseUnsignedLong(key.longKeyId, 16) }.getOrNull()

    fun formatKeyId(id: Long): String = String.format(java.util.Locale.ROOT, "0x%016X", id)

    /** 4.7.0 RC6 (item 67): fingerprints compared without case or spaces. */
    fun normalizeFingerprint(fp: String): String = fp.replace(" ", "").uppercase(java.util.Locale.ROOT)

    /**
     * 4.7.0 RC6 (item 67, #25): the keys a request already includes, as the
     * two parallel extras the review receives, keyed by normalized
     * fingerprint. Pairs past the shorter array, and blank entries, are
     * dropped; the first label for a fingerprint wins.
     */
    fun includedMap(fingerprints: Array<String>?, labels: Array<String>?): Map<String, String> {
        if (fingerprints == null || labels == null) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (i in 0 until minOf(fingerprints.size, labels.size)) {
            val fp = normalizeFingerprint(fingerprints[i])
            val label = labels[i].trim()
            if (fp.isEmpty() || label.isEmpty()) continue
            out.putIfAbsent(fp, label)
        }
        return out
    }

    /**
     * Why an address resolved to no usable key. [hadCandidate] is whether
     * recipient lookup found any usable key for it (a key whose ring then
     * failed to load still counts as missing). [keysForAddress] is every key
     * that carries the address: if none was usable and one of them is a live
     * key marked Don't use, the address is Don't use, not missing.
     */
    fun reasonForAddress(hadCandidate: Boolean, keysForAddress: List<PGPKeyEntity>): Reason =
        if (!hadCandidate && keysForAddress.any { !it.isRevoked && it.trustLevel == TrustLevel.DONT_USE }) {
            Reason.DONT_USE
        } else {
            Reason.MISSING
        }

    /**
     * Whether the send should stop for the review screen: something did not
     * resolve, the client did not ask for opportunistic encryption (that keeps
     * OPPORTUNISTIC_MISSING_KEYS so "encrypt if possible" stays silent), and
     * this is not already the re-run after a review.
     */
    fun needsReview(unresolvedCount: Int, opportunistic: Boolean, hasSelection: Boolean): Boolean =
        unresolvedCount > 0 && !opportunistic && !hasSelection

    /** 4.8.1: what GET_KEY_IDS answers with. */
    enum class KeyIdsStep {
        /** The ids the request's addresses resolved to, as they are. */
        ANSWER,
        /** Those ids plus the selection the client sent back (or a recalled one). */
        ANSWER_SELECTION,
        /** The recipient review, for addresses with no usable key. */
        REVIEW,
        /** The public key picker: the request named no addresses at all. */
        PICK
    }

    /**
     * 4.8.1: GET_KEY_IDS with no user ids (the extra absent or an empty array)
     * asks the person to pick public keys, as OpenKeychain does, so a client
     * that only wants "a key from the key app" gets one. Before this it got
     * success with no ids. Opportunistic requests stay silent, and a request
     * that names addresses takes exactly the 4.7.0 path (items 41, 56, 67).
     */
    fun keyIdsStep(userIdCount: Int, opportunistic: Boolean, hasSelection: Boolean, unresolvedCount: Int): KeyIdsStep =
        when {
            opportunistic -> KeyIdsStep.ANSWER
            hasSelection -> KeyIdsStep.ANSWER_SELECTION
            userIdCount == 0 -> KeyIdsStep.PICK
            needsReview(unresolvedCount, opportunistic = false, hasSelection = false) -> KeyIdsStep.REVIEW
            else -> KeyIdsStep.ANSWER
        }

    /**
     * 4.8.1: picks from an earlier review are reused only for a request that
     * names addresses. A request with none always shows the picker.
     */
    fun mayRecall(userIdCount: Int, opportunistic: Boolean): Boolean = userIdCount > 0 && !opportunistic

    /** A key the review may offer, and the only kind EXTRA_KEY_IDS_SELECTED may name. */
    fun isOfferable(key: PGPKeyEntity, allowExpired: Boolean): Boolean =
        !key.isRevoked &&
            key.deletedAt == null &&
            key.trustLevel != TrustLevel.DONT_USE &&
            (allowExpired || !key.isExpired) &&
            keyIdOf(key) != null

    /**
     * The keys the review lists: public keys and the user's own keys, one row
     * per fingerprint, keys on the sender's address first, then by name.
     */
    fun offeredKeys(all: List<PGPKeyEntity>, allowExpired: Boolean, senderEmail: String?): List<PGPKeyEntity> =
        all.filter { isOfferable(it, allowExpired) }
            .distinctBy { it.fingerprint.uppercase() }
            .sortedWith(
                compareByDescending<PGPKeyEntity> {
                    !senderEmail.isNullOrBlank() && it.userEmail.equals(senderEmail, ignoreCase = true)
                }.thenBy { it.userName.ifBlank { it.userEmail }.lowercase() }
                    .thenBy { it.userEmail.lowercase() }
            )

    /**
     * The fingerprint to tick when the review opens: the client's signing key
     * when it is offered, otherwise the user's own key on the sending address
     * (the default key first), otherwise nothing.
     */
    fun preselect(offered: List<PGPKeyEntity>, signKeyId: Long, senderEmail: String?): String? {
        if (signKeyId != 0L) {
            offered.firstOrNull { keyIdOf(it) == signKeyId }?.let { return it.fingerprint }
        }
        if (senderEmail.isNullOrBlank()) return null
        val own = offered.filter {
            (it.isKeyPair || it.isCardBacked) && it.userEmail.equals(senderEmail, ignoreCase = true)
        }
        return (own.firstOrNull { it.isDefault } ?: own.firstOrNull())?.fingerprint
    }

    /** Search: name, email or User ID, or at least four hex digits of the fingerprint. */
    fun matchesQuery(key: PGPKeyEntity, query: String): Boolean {
        val q = query.trim()
        if (q.isEmpty()) return true
        if (key.userName.contains(q, ignoreCase = true) ||
            key.userEmail.contains(q, ignoreCase = true) ||
            key.userID.contains(q, ignoreCase = true)
        ) return true
        val hex = q.removePrefix("0x").removePrefix("0X").replace(" ", "")
        return hex.length >= 4 && hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' } &&
            key.fingerprint.contains(hex, ignoreCase = true)
    }

    /** The key ids the review returns for the ticked fingerprints, in list order, each once. */
    fun selectedKeyIds(offered: List<PGPKeyEntity>, chosenFingerprints: Set<String>): LongArray =
        offered.filter { it.fingerprint in chosenFingerprints }
            .mapNotNull { keyIdOf(it) }
            .distinct()
            .toLongArray()

    /**
     * Resolve EXTRA_KEY_IDS_SELECTED against the keyring. Every id must name an
     * offerable key; any other id is refused, so a stale or altered request
     * never encrypts to a key the review would not have shown.
     */
    fun resolveSelected(selected: LongArray, all: List<PGPKeyEntity>, allowExpired: Boolean): Selection {
        val accepted = LinkedHashMap<String, PGPKeyEntity>()
        val refused = mutableListOf<Long>()
        for (id in selected.distinct()) {
            val key = all.firstOrNull { keyIdOf(it) == id && isOfferable(it, allowExpired) }
            if (key == null) {
                refused += id
            } else if (!accepted.containsKey(key.fingerprint.uppercase())) {
                accepted[key.fingerprint.uppercase()] = key
            }
        }
        return Selection(accepted.values.toList(), refused)
    }

    /**
     * GET_KEY_IDS after a review: the ids already resolved from the addresses,
     * then the accepted picks, each id once, in that order.
     */
    fun mergeKeyIds(resolvedIds: List<Long>, accepted: List<PGPKeyEntity>): LongArray =
        (resolvedIds + accepted.mapNotNull { keyIdOf(it) }).distinct().toLongArray()

    /** The accepted keys not already among the recipients resolved for this send. */
    fun notYetResolved(resolvedFingerprints: Collection<String>, accepted: List<PGPKeyEntity>): List<PGPKeyEntity> {
        val have = resolvedFingerprints.map { it.uppercase() }.toSet()
        return accepted.filter { it.fingerprint.uppercase() !in have }
    }
}

/**
 * 4.7.0 (item 56, #25): what the user picked in the recipient review, so one
 * send does not ask again. FairEmail asks for key ids when Encrypt is tapped,
 * again when the message is sent, and again when it saves an encrypted draft,
 * each time with the addresses and without the earlier picks, so the review
 * opened two or three times and forgot the choice in between.
 *
 * Kept in memory in the provider process only, per calling app and per exact
 * set of addresses the review covered, for [ttlMs]. A recalled answer goes
 * through the same checks as a fresh one (RecipientReview.resolveSelected).
 * [lastPicks] preselects the earlier picks when the addresses change. Cleared
 * with the provider's passphrase cache (clear-all and device lock).
 */
class RecipientReviewMemory(
    private val ttlMs: Long = 30L * 60_000L,
    private val now: () -> Long = { System.currentTimeMillis() }
) {
    private class Entry(val ids: LongArray, val at: Long)

    private val byAddresses = HashMap<String, Entry>()
    private val lastByPackage = HashMap<String, Entry>()

    private fun keyOf(callingPackage: String, addresses: Collection<String>): String =
        callingPackage + "\u0000" + addresses
            .map { it.substringAfterLast('<').substringBefore('>').trim().ifEmpty { it.trim() }.lowercase() }
            .distinct().sorted().joinToString("\u0000")

    private fun prune() {
        val cutoff = now() - ttlMs
        byAddresses.values.removeAll { it.at < cutoff }
        lastByPackage.values.removeAll { it.at < cutoff }
    }

    @Synchronized
    fun remember(callingPackage: String, addresses: Collection<String>, ids: LongArray) {
        if (addresses.isEmpty() || ids.isEmpty()) return
        val entry = Entry(ids.copyOf(), now())
        byAddresses[keyOf(callingPackage, addresses)] = entry
        lastByPackage[callingPackage] = entry
    }

    @Synchronized
    fun recall(callingPackage: String, addresses: Collection<String>): LongArray? {
        if (addresses.isEmpty()) return null
        prune()
        return byAddresses[keyOf(callingPackage, addresses)]?.ids?.copyOf()
    }

    @Synchronized
    fun lastPicks(callingPackage: String): LongArray? {
        prune()
        return lastByPackage[callingPackage]?.ids?.copyOf()
    }

    @Synchronized
    fun clear() {
        byAddresses.clear()
        lastByPackage.clear()
    }

    companion object {
        val shared = RecipientReviewMemory()
    }
}
