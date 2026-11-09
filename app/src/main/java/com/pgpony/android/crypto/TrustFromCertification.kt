// TrustFromCertification.kt
// PGPony Android 4.8.0 RC8 (#115): a public key certified by one of your own
// key pairs at Ultimate shows as Verified, the way gpg gives validity to a key
// that an ultimately trusted key certified.
//
// Before this, a key's trust was only ever what the user set (or Ultimate for
// a key pair made here). A certification that came in with an import (a key
// server, a file) was listed in Key Details but never changed the level, and
// certifying a key in PGPony only offered a button to mark it Verified by
// hand. So a key carrying your own Ultimate key's certification still showed
// as not verified.
//
// The rule, kept apart from storage so it runs on the JVM in tests:
//   * Only a stored Unknown on someone else's key is raised, and only to
//     Verified. Unknown is the import default; every other level is one the
//     user chose and stays: Unverified, Verified, Ultimate and Don't use.
//     Your own keys are never raised.
//   * A certification vouches for one User ID, not the whole key. The level
//     shown for a key is raised only when the User ID the app shows for it is
//     certified, and a check for an address (the OpenPGP provider) needs a
//     certified User ID with that address. Otherwise anyone you certified
//     could add a self-signed "CEO <ceo@corp>" User ID and have it show as
//     verified.
//   * The certification is a 0x10 to 0x13 over that User ID, made by the
//     certifier's PRIMARY key (matched by issuer fingerprint, or by key ID
//     when it carries none, then verified under that primary). Its creation
//     time is hashed, not in the future and not before the certifier existed;
//     it has not expired; it carries no critical subpacket we do not
//     understand; and its digest is SHA-2 or SHA-3. SHA-1 and RIPEMD-160 never
//     count, at any date (SignaturePolicy.isStrongDigest).
//   * A verified 0x30 by the same certifier over the same User ID, made at or
//     after the certification, withdraws it. Any digest counts for that: a
//     withdrawal only ever lowers trust.
//   * The User ID must be bound by the key's owner now: it has a verified
//     self-certification, is not revoked, and is not bound only with a weak
//     hash (4.7.0 item 27: a weak-only User ID never counts toward Verified).
//   * The certifier must be usable now: its primary is not revoked and not
//     expired. The caller passes only your own keys whose trust is Ultimate.
//   * A revoked or expired key is never raised; it shows as Revoked or
//     Expired on its own.
//
// Each answer carries the time to check it again: the earliest of the
// certification's expiry, the certifier's and the key's, or the time a
// certification turned away only for being dated ahead of the clock would
// count. A cache drops a positive answer once that time passes. Nothing here is written to storage: CertifiedTrust
// keeps the answers, so revoking or deleting the certifying key, or
// withdrawing the certification, drops the key back to its stored level.

package com.pgpony.android.crypto

import com.pgpony.android.data.TrustLevel
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import java.util.Date

object TrustFromCertification {

    private val CERTIFICATION_TYPES = setOf(
        PGPSignature.DEFAULT_CERTIFICATION,
        PGPSignature.NO_CERTIFICATION,
        PGPSignature.CASUAL_CERTIFICATION,
        PGPSignature.POSITIVE_CERTIFICATION
    )

    /** One of your Ultimate keys, usable now, and when its primary expires (null: never). */
    class Voucher(val primary: PGPPublicKey, val expiresAtMs: Long?)

    /**
     * What your keys vouch for on one key: each certified User ID with the
     * key that certified it, the User IDs its owner binds now, and when to
     * check again (null: no time limit). A positive answer stops holding then.
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

    /** A stored level a certification may raise: Unknown, on a key that is not yours. */
    fun canRaise(stored: TrustLevel, isOwnKey: Boolean): Boolean =
        !isOwnKey && stored == TrustLevel.UNKNOWN

    /**
     * One of your keys whose certifications may raise others: yours (a key
     * pair or a card key), set to Ultimate, not revoked and not expired. A key
     * pair made in PGPony starts at Ultimate; an imported key pair starts at
     * Unknown, like gpg, and counts once you set it to Ultimate.
     */
    fun mayVouch(trust: TrustLevel, isOwnKey: Boolean, isRevoked: Boolean, isExpired: Boolean): Boolean =
        isOwnKey && trust == TrustLevel.ULTIMATE && !isRevoked && !isExpired

    /** The level every surface shows. [shownUserIdCertified]: the User ID shown for the key is certified. */
    fun effective(stored: TrustLevel, isOwnKey: Boolean, shownUserIdCertified: Boolean): TrustLevel =
        if (shownUserIdCertified && canRaise(stored, isOwnKey)) TrustLevel.VERIFIED else stored

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

    /**
     * Which of [target]'s bound User IDs [vouchers] certify under the rule
     * above. [local] holds the local-only certifications kept beside the
     * certificate (User ID, signature).
     */
    fun findings(
        target: PGPPublicKeyRing,
        local: List<Pair<String, PGPSignature>>,
        vouchers: List<Voucher>,
        nowMs: Long
    ): Finding {
        val primary = target.publicKey
        val candidates = vouchers.filterNot { it.primary.fingerprint.contentEquals(primary.fingerprint) }
        if (candidates.isEmpty()) return Finding.NONE
        val sigsByUid = LinkedHashMap<String, List<PGPSignature>>()
        for (uid in primary.userIDs.asSequence()) {
            val onKey = primary.getSignaturesForID(uid)?.asSequence()?.toList().orEmpty()
            sigsByUid[uid] = onKey + local.filter { it.first == uid }.map { it.second }
        }
        // Cheap pass first: most keys carry nothing from your keys at all, and
        // the binding analysis below is the expensive part.
        val anyFromCandidate = sigsByUid.values.any { sigs -> sigs.any { s -> candidates.any { issuedBy(s, it.primary) } } }
        if (!anyFromCandidate) return Finding.NONE
        val report = CertificateBindings.analyze(target) ?: return Finding.NONE
        if (!report.supported) return Finding.NONE
        // A revoked or expired key is never raised: it shows as Revoked or
        // Expired anyway, and an answer that ended in the past would be
        // checked again on every refresh.
        val keyExpires = report.primaryExpiresAtMs
        if (report.primaryRevoked || (keyExpires != null && nowMs >= keyExpires)) return Finding.NONE
        val bound = report.certifiedUserIds - report.weakUserIds
        val byUserId = LinkedHashMap<String, PGPPublicKey>()
        var validUntil = keyExpires ?: Long.MAX_VALUE
        // A certification turned away only for a creation time ahead of the
        // clock may count later; check again then.
        var retryAt = Long.MAX_VALUE
        for ((uid, sigs) in sigsByUid) {
            if (uid !in bound) continue
            // Holds while any of your keys still vouches for it.
            var uidUntil: Long? = null
            for (c in candidates) {
                val count = countsUntil(sigs.filter { issuedBy(it, c.primary) }, uid, primary, c.primary, nowMs)
                if (count.retryAtMs != null) retryAt = minOf(retryAt, count.retryAtMs)
                val until = count.untilMs ?: continue
                val withKey = minOf(until, c.expiresAtMs ?: Long.MAX_VALUE)
                if (uid !in byUserId) byUserId[uid] = c.primary
                uidUntil = maxOf(uidUntil ?: Long.MIN_VALUE, withKey)
            }
            if (uidUntil != null) validUntil = minOf(validUntil, uidUntil)
        }
        if (byUserId.isEmpty()) return Finding(emptyMap(), bound, retryAt.takeIf { it != Long.MAX_VALUE })
        return Finding(byUserId, bound, minOf(validUntil, retryAt).takeIf { it != Long.MAX_VALUE })
    }

    /**
     * [untilMs]: when the latest-lasting counting certification expires
     * (Long.MAX_VALUE for never), null when none counts or a later withdrawal
     * covers them all. [retryAtMs]: the earliest time a certification turned
     * away only for being dated in the future stops being so, or null.
     */
    private class Count(val untilMs: Long?, val retryAtMs: Long?)

    private fun countsUntil(
        sigs: List<PGPSignature>,
        uid: String,
        target: PGPPublicKey,
        certifier: PGPPublicKey,
        nowMs: Long
    ): Count {
        if (sigs.isEmpty()) return Count(null, null)
        val withdrawals by lazy {
            sigs.filter { it.signatureType == PGPSignature.CERTIFICATION_REVOCATION && verifies(it, uid, target, certifier) }
                .map { it.creationTime.time }
        }
        var best: Long? = null
        var retry: Long? = null
        val now = Date(nowMs)
        for (s in sigs) {
            if (s.signatureType !in CERTIFICATION_TYPES) continue
            if (!isAcceptable(s, certifier, nowMs)) continue
            if (!verifies(s, uid, target, certifier)) continue
            val created = s.creationTime
            if (SignaturePolicy.isFromTheFuture(created, now)) {
                val at = SignaturePolicy.notFromTheFutureAtMs(created)
                retry = minOf(retry ?: Long.MAX_VALUE, at)
                continue
            }
            if (withdrawals.any { it >= created.time }) continue
            val expSeconds = s.hashedSubPackets?.signatureExpirationTime ?: 0L
            val until = if (expSeconds > 0) created.time + expSeconds * 1000L else Long.MAX_VALUE
            best = maxOf(best ?: Long.MIN_VALUE, until)
        }
        return Count(best, retry)
    }

    /** Every check but the future-dated one, which [countsUntil] handles to know when to look again. */
    private fun isAcceptable(sig: PGPSignature, certifier: PGPPublicKey, nowMs: Long): Boolean {
        if (sig.version < 4) return false
        val hashed = sig.hashedSubPackets ?: return false
        val created = hashed.signatureCreationTime ?: return false
        if (!SignaturePolicy.isStrongDigest(sig.hashAlgorithm)) return false
        if (SignaturePolicy.isExpired(sig, Date(nowMs))) return false
        if (SignaturePolicy.hasCriticalUnknown(sig)) return false
        return created.time >= certifier.creationTime.time
    }

    /** Matched by issuer fingerprint when the signature names one, else by key ID. */
    private fun issuedBy(sig: PGPSignature, key: PGPPublicKey): Boolean {
        val fp = sig.hashedSubPackets?.issuerFingerprint?.fingerprint
            ?: sig.unhashedSubPackets?.issuerFingerprint?.fingerprint
        return if (fp != null) fp.contentEquals(key.fingerprint) else sig.keyID == key.keyID
    }

    private fun verifies(sig: PGPSignature, uid: String, target: PGPPublicKey, signer: PGPPublicKey): Boolean = runCatching {
        sig.init(BcPGPContentVerifierBuilderProvider(), signer)
        sig.verifyCertification(uid, target)
    }.getOrDefault(false)
}
