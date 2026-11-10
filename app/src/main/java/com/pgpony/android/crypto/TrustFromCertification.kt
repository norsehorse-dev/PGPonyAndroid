// TrustFromCertification.kt
// PGPony Android 4.8.0 RC8 (#115): a key certified by one of your own key
// pairs at Ultimate shows as Verified, the way gpg gives validity to a key that
// an ultimately trusted key certified. 4.8.0 RC10 (#115): trust signatures
// carry that on through trusted introducers, as in gpg.
//
// Before RC8, a key's trust was only ever what the user set (or Ultimate for a
// key pair made here). A certification that came in with an import was listed
// in Key Details but never changed the level.
//
// The rule, kept apart from storage so it runs on the JVM in tests:
//   * Only a stored Unknown is raised, and only to Verified. Unknown is the
//     import default; every other level is one the user chose and stays:
//     Unverified, Verified, Ultimate and Don't use. Since RC10 this holds for
//     your own key pairs too: one left at Unknown is raised like a public key.
//   * Roots are your own keys set to Ultimate. A root's certification of a
//     User ID makes that User ID valid.
//   * Trusted introducers (RC10): a root's certification that is a trust
//     signature (subpacket 5) with level L of at least 1 and amount of at
//     least 120 (full trust) makes the certified key an introducer of depth
//     L. An introducer's certifications make User IDs valid like a root's,
//     and its own trust signatures of level m make further introducers of
//     depth min(m, L - 1). An introducer of depth 0 vouches for nothing. A
//     key the user set to Unverified or Don't use is never an introducer.
//     Partial trust (amount below 120) does not count: there is no marginal
//     arithmetic. A trust signature that carries a Regular Expression
//     (subpacket 6) does not make an introducer at all, because the scoping it
//     asks for is not implemented here; the certification itself still makes
//     its User ID valid. A plain certification by a key that is not a root
//     never vouches (gpg without ownertrust). Depth is capped at
//     [MAX_DEPTH], and cycles end because a key is visited again only for a
//     greater depth.
//   * A certification vouches for one User ID, not the whole key. The level
//     shown for a key is raised only when the User ID the app shows for it is
//     valid, and a check for an address (the OpenPGP provider) needs a valid
//     User ID with that address.
//   * A counting certification is a 0x10 to 0x13 over that User ID, made by
//     the certifier's PRIMARY key (matched by issuer fingerprint, or by key ID
//     when it carries none, then verified under that primary). Its creation
//     time is hashed, not in the future and not before the certifier existed;
//     it has not expired; it carries no critical subpacket we do not
//     understand; and its digest is SHA-2 or SHA-3. SHA-1 and RIPEMD-160 never
//     count, at any date (SignaturePolicy.isStrongDigest). Of a certifier's
//     certifications of one User ID, the newest that verifies is the one in
//     force (its trust signature, if any, included), and it alone is held to
//     these rules: if it fails them (an expired demotion, say), nothing from
//     that certifier counts on that User ID, and an older one never comes
//     back.
//   * A verified 0x30 by the same certifier over the same User ID, made at or
//     after a certification, withdraws it. Any digest counts for that: a
//     withdrawal only ever lowers trust.
//   * The User ID must be bound by the key's owner now: it has a verified
//     self-certification, is not revoked, and is not bound only with a weak
//     hash (4.7.0 item 27: a weak-only User ID never counts toward Verified).
//   * Roots and introducers must be usable now: their primary is not revoked
//     and not expired. A revoked or expired key is never raised.
//
// Each answer carries the time to check it again: the earliest of the expiry
// of every certification, trust signature and key along its path, or the time
// a certification turned away only for being dated ahead of the clock would
// count. Nothing here is written to storage: CertifiedTrust keeps the answers,
// so revoking or deleting a key on the path, or withdrawing a certification,
// drops the key back to its stored level.

package com.pgpony.android.crypto

import com.pgpony.android.data.TrustLevel
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import java.util.Date

object TrustFromCertification {

    /** The deepest chain of trusted introducers followed below a root. */
    const val MAX_DEPTH = 8

    /** gpg's full trust amount; anything less is partial and does not count. */
    const val FULL_TRUST = 120

    private const val NEVER = Long.MAX_VALUE

    private val CERTIFICATION_TYPES = setOf(
        PGPSignature.DEFAULT_CERTIFICATION,
        PGPSignature.NO_CERTIFICATION,
        PGPSignature.CASUAL_CERTIFICATION,
        PGPSignature.POSITIVE_CERTIFICATION
    )

    /** A usable root or introducer, and when its primary expires (null: never). */
    class Voucher(val primary: PGPPublicKey, val expiresAtMs: Long?)

    /**
     * What your roots vouch for on one key directly: each certified User ID
     * with the root that certified it, the User IDs its owner binds now, and
     * when to check again (null: no time limit). A positive answer stops
     * holding then.
     */
    class Finding(
        val byUserId: Map<String, PGPPublicKey>,
        val boundUserIds: Set<String>,
        val validUntilMs: Long?
    ) {
        companion object {
            val NONE = Finding(emptyMap(), emptySet(), null)
        }
    }

    /**
     * What one certifier says about one key: the User IDs its certifications
     * in force make valid (to when; [NEVER] for no limit), the best trust
     * signature level among them that may make an introducer (0: none) and
     * to when, a re-check time for a future-dated certification, and how many
     * User IDs the key binds.
     */
    class Edge(
        val certified: Map<String, Long>,
        val trustLevel: Int,
        val trustUntilMs: Long,
        val retryAtMs: Long?,
        val boundCount: Int
    ) {
        /** When this edge may read differently (something in it expires or comes due); [NEVER] for no limit. */
        val changesAtMs: Long
            get() = minOf(certified.values.minOrNull() ?: NEVER, if (trustLevel > 0) trustUntilMs else NEVER, retryAtMs ?: NEVER)

        companion object {
            val NONE = Edge(emptyMap(), 0, NEVER, null, 0)
        }
    }

    /**
     * Edges kept between runs (RC10 review): keyed by both keys' fingerprints
     * and stamps, and used only until the edge's own [Edge.changesAtMs], so a
     * run after one key changes re-checks only the edges that touch it.
     */
    class EdgeCache {
        private class Entry(val edge: Edge, val changesAtMs: Long)
        private val entries = java.util.concurrent.ConcurrentHashMap<String, Entry>()

        internal fun get(key: String, nowMs: Long): Edge? = entries[key]?.takeIf { nowMs < it.changesAtMs }?.edge
        internal fun put(key: String, edge: Edge) { entries[key] = Entry(edge, edge.changesAtMs) }

        /** Drop edges of keys no longer in the keyring (fingerprints upper case). */
        fun retain(fingerprints: Set<String>) {
            entries.keys.removeIf { k -> k.split('>').any { side -> side.substringBefore('/') !in fingerprints } }
        }

        val size: Int get() = entries.size
    }

    /** A stored level a certification may raise: Unknown, on any key (your own key pairs included since RC10). */
    fun canRaise(stored: TrustLevel): Boolean = stored == TrustLevel.UNKNOWN

    /**
     * A root: one of your keys (a key pair or a card key), set to Ultimate,
     * not revoked and not expired. A key pair made in PGPony starts at
     * Ultimate; an imported key pair starts at Unknown, like gpg, and is a
     * root once you set it to Ultimate.
     */
    fun mayVouch(trust: TrustLevel, isOwnKey: Boolean, isRevoked: Boolean, isExpired: Boolean): Boolean =
        isOwnKey && trust == TrustLevel.ULTIMATE && !isRevoked && !isExpired

    /**
     * A key that a trust signature may make an introducer: not revoked, not
     * expired, and not set by the user to Don't use or Unverified (a level the
     * user set stands, so a key they have not verified never vouches).
     */
    fun mayIntroduce(trust: TrustLevel, isRevoked: Boolean, isExpired: Boolean): Boolean =
        trust != TrustLevel.DONT_USE && trust != TrustLevel.UNVERIFIED && !isRevoked && !isExpired

    /** The level every surface shows. [shownUserIdValid]: the User ID shown for the key is valid. */
    fun effective(stored: TrustLevel, shownUserIdValid: Boolean): TrustLevel =
        if (shownUserIdValid && canRaise(stored)) TrustLevel.VERIFIED else stored

    /** The address in a User ID, the same way recipient lookup reads it. */
    fun emailOf(userId: String): String =
        userId.substringAfterLast('<').substringBefore('>').trim().ifEmpty { userId.trim() }

    /** One of [certifiedUserIds] carries [address] (any case). */
    fun certifiesAddress(certifiedUserIds: Collection<String>, address: String): Boolean {
        val want = emailOf(address)
        if (want.isEmpty()) return false
        return certifiedUserIds.any { emailOf(it).equals(want, ignoreCase = true) }
    }

    /** [ring]'s primary as a voucher if it may vouch now: readable, not revoked, not expired. */
    fun voucherOf(ring: PGPPublicKeyRing, nowMs: Long): Voucher? {
        val report = CertificateBindings.analyze(ring) ?: return null
        if (!report.supported || report.primaryRevoked) return null
        val expires = report.primaryExpiresAtMs
        if (expires != null && nowMs >= expires) return null
        return Voucher(ring.publicKey, expires)
    }

    fun isUsableCertifier(ring: PGPPublicKeyRing, nowMs: Long): Boolean = voucherOf(ring, nowMs) != null

    // ── One certifier on one key ─────────────────────────────────────────

    /** [target]'s User IDs with every signature on them, the local-only ones included. */
    private fun sigsByUserId(target: PGPPublicKeyRing, local: List<Pair<String, PGPSignature>>): LinkedHashMap<String, List<PGPSignature>> {
        val primary = target.publicKey
        val out = LinkedHashMap<String, List<PGPSignature>>()
        for (uid in primary.userIDs.asSequence()) {
            val onKey = primary.getSignaturesForID(uid)?.asSequence()?.toList().orEmpty()
            out[uid] = onKey + local.filter { it.first == uid }.map { it.second }
        }
        return out
    }

    /** What [certifier] says about [target] under the rule above. */
    fun edge(
        target: PGPPublicKeyRing,
        local: List<Pair<String, PGPSignature>>,
        certifier: Voucher,
        nowMs: Long
    ): Edge {
        val primary = target.publicKey
        if (certifier.primary.fingerprint.contentEquals(primary.fingerprint)) return Edge.NONE
        val sigs = sigsByUserId(target, local)
        // Cheap pass first: the binding analysis below is the expensive part.
        if (sigs.values.none { list -> list.any { issuedBy(it, certifier.primary) } }) return Edge.NONE
        val report = CertificateBindings.analyze(target) ?: return Edge.NONE
        if (!report.supported) return Edge.NONE
        // A revoked or expired key is never raised: it shows as Revoked or
        // Expired anyway, and an answer that ended in the past would be
        // checked again on every refresh.
        val keyExpires = report.primaryExpiresAtMs
        if (report.primaryRevoked || (keyExpires != null && nowMs >= keyExpires)) return Edge.NONE
        val bound = report.certifiedUserIds - report.weakUserIds
        val certified = LinkedHashMap<String, Long>()
        var trustLevel = 0
        var trustUntil = NEVER
        var retry: Long? = null
        val certifierUntil = certifier.expiresAtMs ?: NEVER
        for ((uid, list) in sigs) {
            if (uid !in bound) continue
            val inForce = inForce(list.filter { issuedBy(it, certifier.primary) }, uid, primary, certifier.primary, nowMs)
            if (inForce.retryAtMs != null) retry = minOf(retry ?: NEVER, inForce.retryAtMs)
            val sig = inForce.signature ?: continue
            val until = minOf(inForce.untilMs, certifierUntil, keyExpires ?: NEVER)
            certified[uid] = until
            val level = introducerLevel(sig)
            if (level > trustLevel) {
                trustLevel = level
                trustUntil = until
            } else if (level == trustLevel && level > 0) {
                trustUntil = maxOf(trustUntil, until)
            }
        }
        return Edge(certified, trustLevel, trustUntil, retry, bound.size)
    }

    /**
     * The level a certification in force makes its key an introducer at: its
     * trust signature's level when the amount is full and there is no Regular
     * Expression to honour, else 0. Capped at [MAX_DEPTH].
     */
    private fun introducerLevel(sig: PGPSignature): Int {
        val hashed = sig.hashedSubPackets ?: return 0
        val trust = hashed.trust ?: return 0
        if (trust.trustAmount < FULL_TRUST || trust.depth < 1) return 0
        // RC10 (#115): the Regular Expression scoping is not implemented, so a
        // trust signature limited by one makes no introducer at all.
        if (hashed.hasSubpacket(SignatureSubpacketTags.REG_EXP)) return 0
        return minOf(trust.depth, MAX_DEPTH)
    }

    /**
     * The direct answer for [target] from [vouchers] (your roots): each
     * certified User ID with the root that certified it. Introducers are
     * followed by [graph]; this covers one step.
     */
    fun findings(
        target: PGPPublicKeyRing,
        local: List<Pair<String, PGPSignature>>,
        vouchers: List<Voucher>,
        nowMs: Long
    ): Finding {
        val byUserId = LinkedHashMap<String, PGPPublicKey>()
        val untilByUid = HashMap<String, Long>()
        var bound: Set<String>? = null
        var retry = NEVER
        for (v in vouchers) {
            val e = edge(target, local, v, nowMs)
            if (e.retryAtMs != null) retry = minOf(retry, e.retryAtMs)
            if (e.boundCount > 0 && bound == null) {
                bound = CertificateBindings.analyze(target)?.let { it.certifiedUserIds - it.weakUserIds }
            }
            for ((uid, until) in e.certified) {
                if (uid !in byUserId) byUserId[uid] = v.primary
                // Holds while any of your keys still vouches for it.
                untilByUid[uid] = maxOf(untilByUid[uid] ?: Long.MIN_VALUE, until)
            }
        }
        val validUntil = minOf(untilByUid.values.minOrNull() ?: NEVER, retry)
        return Finding(byUserId, bound.orEmpty(), validUntil.takeIf { it != NEVER })
    }

    // ── The whole keyring (RC10) ─────────────────────────────────────────

    /** One key of the keyring for [graph]. [fingerprint] is upper-case hex. */
    class KeyInput(
        val fingerprint: String,
        val ring: PGPPublicKeyRing?,
        val local: List<Pair<String, PGPSignature>>,
        /** One of your keys at Ultimate ([mayVouch]). */
        val isRoot: Boolean,
        /** A trust signature may make it an introducer ([mayIntroduce]). */
        val mayIntroduce: Boolean,
        /** What changes when the key's certificate or local certifications do (for [EdgeCache]). */
        val stamp: String = ""
    )

    /**
     * Why one User ID is valid: the key that certified it, the root at the
     * top of the chain, every key on the chain from the root down to the
     * certifier ([chain], root first), and to when (null: no limit).
     */
    class Path(val certifierFingerprint: String, val rootFingerprint: String, val untilMs: Long?, val chain: List<String>)

    /**
     * Every valid User ID in the keyring (target fingerprint to User ID to
     * path), how many User IDs each such key binds, and when to work it all
     * out again (null: no time limit).
     */
    class Graph(
        val valid: Map<String, Map<String, Path>>,
        val boundCount: Map<String, Int>,
        val checkAgainAtMs: Long?
    ) {
        companion object {
            val EMPTY = Graph(emptyMap(), emptyMap(), null)
        }
    }

    private class Introducer(val depth: Int, val untilMs: Long, val chain: List<String>, val voucher: Voucher)

    /**
     * Walk from your roots through trusted introducers, best depth first.
     * [cache] keeps edges between runs. A key whose signatures cannot be read
     * or checked adds no edge; it never stops the walk (RC10 review).
     */
    fun graph(keys: List<KeyInput>, nowMs: Long, cache: EdgeCache? = null): Graph {
        val byFp = keys.filter { it.ring != null }.associateBy { it.fingerprint.uppercase() }
        // Which keys carry signatures from which issuer (fingerprint, or key ID when a signature names no fingerprint).
        val index = HashMap<String, MutableSet<String>>()
        for ((fp, k) in byFp) {
            runCatching {
                for (list in sigsByUserId(k.ring!!, k.local).values) {
                    for (s in list) index.getOrPut(issuerKey(s)) { HashSet() }.add(fp)
                }
            }
        }
        val introducers = HashMap<String, Introducer>()
        val queue = ArrayDeque<String>()
        for ((fp, k) in byFp) {
            if (!k.isRoot) continue
            val v = runCatching { voucherOf(k.ring!!, nowMs) }.getOrNull() ?: continue
            introducers[fp] = Introducer(MAX_DEPTH + 1, v.expiresAtMs ?: NEVER, listOf(fp), v)
            queue.addLast(fp)
        }
        val valid = HashMap<String, HashMap<String, Path>>()
        val boundCount = HashMap<String, Int>()
        val edges = HashMap<Pair<String, String>, Edge>()
        var checkAgain = NEVER
        // Each key re-enters only for a greater depth, so this is a backstop.
        var budget = (byFp.size + 1) * (MAX_DEPTH + 2)
        while (queue.isNotEmpty() && budget-- > 0) {
            val iFp = queue.removeFirst()
            val node = introducers[iFp] ?: continue
            val issuer = byFp[iFp] ?: continue
            val targets = HashSet<String>()
            index[iFp]?.let { targets.addAll(it) }
            index[keyIdKey(node.voucher.primary.keyID)]?.let { targets.addAll(it) }
            for (tFp in targets) {
                if (tFp == iFp) continue
                val target = byFp[tFp] ?: continue
                val e = edges.getOrPut(iFp to tFp) {
                    val key = "$iFp/${issuer.stamp}>$tFp/${target.stamp}"
                    cache?.get(key, nowMs) ?: (runCatching { edge(target.ring!!, target.local, node.voucher, nowMs) }
                        .getOrDefault(Edge.NONE)).also { cache?.put(key, it) }
                }
                if (e.retryAtMs != null) checkAgain = minOf(checkAgain, e.retryAtMs)
                if (e.certified.isNotEmpty()) boundCount[tFp] = e.boundCount
                for ((uid, certUntil) in e.certified) {
                    val until = minOf(certUntil, node.untilMs)
                    checkAgain = minOf(checkAgain, until)
                    val uids = valid.getOrPut(tFp) { HashMap() }
                    val cur = uids[uid]
                    if (cur == null || until > (cur.untilMs ?: NEVER)) {
                        uids[uid] = Path(iFp, node.chain.first(), until.takeIf { it != NEVER }, node.chain)
                    }
                }
                if (e.trustLevel < 1 || target.isRoot || !target.mayIntroduce) continue
                val depth = minOf(e.trustLevel, node.depth - 1)
                if (depth < 1) continue
                val current = introducers[tFp]
                if (current != null && current.depth >= depth) continue
                val v = runCatching { voucherOf(target.ring!!, nowMs) }.getOrNull() ?: continue
                val until = minOf(e.trustUntilMs, node.untilMs, v.expiresAtMs ?: NEVER)
                checkAgain = minOf(checkAgain, until)
                introducers[tFp] = Introducer(depth, until, node.chain + tFp, v)
                queue.addLast(tFp)
            }
        }
        return Graph(valid, boundCount, checkAgain.takeIf { it != NEVER })
    }

    // ── Signatures ──────────────────────────────────────────────────────

    /**
     * The certification in force among [sigs] (all from [certifier]) of
     * [uid], with its expiry ([NEVER] for none). RC10 review: it is the
     * newest certification that verifies, as gpg reads it, and only that one
     * is then held to the rules (digest, expiry, critical subpackets, made
     * after the certifier); when it fails them, or a withdrawal made at or
     * after it exists, nothing from this certifier is in force on [uid]. So
     * an expired newer certification never lets an older trust signature
     * back. [retryAtMs]: the earliest time a certification turned away only
     * for being dated in the future stops being so.
     */
    private class InForce(val signature: PGPSignature?, val untilMs: Long, val retryAtMs: Long?)

    private fun inForce(
        sigs: List<PGPSignature>,
        uid: String,
        target: PGPPublicKey,
        certifier: PGPPublicKey,
        nowMs: Long
    ): InForce {
        if (sigs.isEmpty()) return InForce(null, NEVER, null)
        var newest: PGPSignature? = null
        var retry: Long? = null
        val now = Date(nowMs)
        for (s in sigs) {
            if (s.signatureType !in CERTIFICATION_TYPES) continue
            if (s.version < 4) continue
            val created = s.hashedSubPackets?.signatureCreationTime ?: continue
            if (!verifies(s, uid, target, certifier)) continue
            if (SignaturePolicy.isFromTheFuture(created, now)) {
                retry = minOf(retry ?: NEVER, SignaturePolicy.notFromTheFutureAtMs(created))
                continue
            }
            if (newest == null || created.time > newest.creationTime.time) newest = s
        }
        val sig = newest ?: return InForce(null, NEVER, retry)
        val withdrawn = sigs.any {
            it.signatureType == PGPSignature.CERTIFICATION_REVOCATION &&
                it.creationTime.time >= sig.creationTime.time &&
                verifies(it, uid, target, certifier)
        }
        if (withdrawn || !isAcceptable(sig, certifier, nowMs)) return InForce(null, NEVER, retry)
        val expSeconds = sig.hashedSubPackets?.signatureExpirationTime ?: 0L
        val until = if (expSeconds > 0) sig.creationTime.time + expSeconds * 1000L else NEVER
        return InForce(sig, until, retry)
    }

    /** Every check but the future-dated one, which [inForce] handles to know when to look again. */
    private fun isAcceptable(sig: PGPSignature, certifier: PGPPublicKey, nowMs: Long): Boolean {
        if (sig.version < 4) return false
        val hashed = sig.hashedSubPackets ?: return false
        val created = hashed.signatureCreationTime ?: return false
        if (!SignaturePolicy.isStrongDigest(sig.hashAlgorithm)) return false
        if (SignaturePolicy.isExpired(sig, Date(nowMs))) return false
        if (SignaturePolicy.hasCriticalUnknown(sig)) return false
        return created.time >= certifier.creationTime.time
    }

    private fun issuerFingerprint(sig: PGPSignature): ByteArray? =
        sig.hashedSubPackets?.issuerFingerprint?.fingerprint
            ?: sig.unhashedSubPackets?.issuerFingerprint?.fingerprint

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02X".format(it) }

    private fun keyIdKey(keyId: Long): String = "K" + String.format("%016X", keyId)

    /** Index key for a signature's issuer: its fingerprint, or its key ID when it names none. */
    private fun issuerKey(sig: PGPSignature): String = issuerFingerprint(sig)?.let { hex(it) } ?: keyIdKey(sig.keyID)

    /** Matched by issuer fingerprint when the signature names one, else by key ID. */
    private fun issuedBy(sig: PGPSignature, key: PGPPublicKey): Boolean {
        val fp = issuerFingerprint(sig)
        return if (fp != null) fp.contentEquals(key.fingerprint) else sig.keyID == key.keyID
    }

    /**
     * RC10 review: Bouncy Castle keeps the verifier inside the PGPSignature
     * (init, then verify), and the same parsed signature can be checked from
     * two threads at once (a background refresh and a provider call), so each
     * check holds the signature for its duration.
     */
    private fun verifies(sig: PGPSignature, uid: String, target: PGPPublicKey, signer: PGPPublicKey): Boolean = runCatching {
        synchronized(sig) {
            sig.init(BcPGPContentVerifierBuilderProvider(), signer)
            sig.verifyCertification(uid, target)
        }
    }.getOrDefault(false)
}
