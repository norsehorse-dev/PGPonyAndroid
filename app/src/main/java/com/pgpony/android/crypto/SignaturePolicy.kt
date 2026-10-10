// SignaturePolicy.kt
// PGPony Android, 4.6.0 (items 17.1 and 17.10): which hash algorithms a
// signature may use to be accepted at verify time.
//
// Signing already restricts itself to SHA-2; verification used to accept any
// digest Bouncy Castle could compute, including MD5, SHA-1 and RIPEMD-160.
// The cutoffs follow Sequoia's StandardPolicy, so a message or key that a
// current Sequoia or GnuPG accepts is not turned away here:
//
//   * MD5 is never accepted.
//   * Data signatures (0x00 / 0x01 and the standalone / timestamp types) need
//     collision resistance: SHA-1 and RIPEMD-160 are accepted only when the
//     signature was made before 2013-02-01.
//   * Key signatures (self-certifications, bindings, revocations) only need
//     second-preimage resistance: SHA-1 and RIPEMD-160 are accepted when made
//     before 2023-02-01, which keeps older GnuPG 1.x keys loading.
//   * The SHA-2 and SHA-3 family is always accepted. An unknown algorithm id
//     is refused.
//
// A signature whose creation time lies far in the future is refused as well
// (more than a day ahead of the device clock, to tolerate clock skew), and
// v3 signatures are refused (no signer in the app produces or needs them).
//
// 3.0.0 (5d-1): a data signature also needs its creation time in the hashed
// area, and a critical hashed subpacket that is not understood (an unknown
// type, or any notation) makes it invalid, as RFC 9580 5.2.3.7 requires.
//
// A data signature whose hashed signature expiration time (subpacket 3) has
// passed is no longer accepted: the signer limited how long it counts.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.openpgp.PGPSignature
import java.util.Date

object SignaturePolicy {

    /** 2013-02-01T00:00:00Z. */
    private const val SHA1_DATA_CUTOFF_MS = 1_359_676_800_000L
    /** 2023-02-01T00:00:00Z. */
    private const val SHA1_KEY_CUTOFF_MS = 1_675_209_600_000L
    /** Clock-skew allowance for a creation time ahead of the device clock. */
    private const val FUTURE_SKEW_MS = 24L * 60 * 60 * 1000

    private val STRONG = setOf(
        HashAlgorithmTags.SHA224, HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA384,
        HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA3_256, HashAlgorithmTags.SHA3_512
    )
    private val LEGACY = setOf(HashAlgorithmTags.SHA1, HashAlgorithmTags.RIPEMD160)

    /** Data-signature digest check. [createdMs] null means unknown (treated as recent). */
    fun isAcceptableDataDigest(hashAlg: Int, createdMs: Long?): Boolean = when (hashAlg) {
        in STRONG -> true
        in LEGACY -> createdMs != null && createdMs < SHA1_DATA_CUTOFF_MS
        else -> false
    }

    /** Key-signature digest check (self-certifications, bindings, revocations). */
    fun isAcceptableCertificationDigest(hashAlg: Int, createdMs: Long? = null): Boolean = when (hashAlg) {
        in STRONG -> true
        in LEGACY -> createdMs == null || createdMs < SHA1_KEY_CUTOFF_MS
        else -> false
    }

    /**
     * 4.7.0 (item 27, #67): a User ID self-certification or revocation that
     * fails [isAcceptableCertificationDigest] only because it uses SHA-1 or
     * RIPEMD-160 after the key-signature cutoff. Such a User ID is kept with a
     * weak-hash mark rather than dropped, so an older key keeps its name. MD5
     * and unknown algorithms are never in this set.
     */
    fun isWeakCertificationDigest(hashAlg: Int, createdMs: Long?): Boolean =
        hashAlg in LEGACY && !isAcceptableCertificationDigest(hashAlg, createdMs)

    /** True when [created] lies more than the skew allowance ahead of [now]. */
    fun isFromTheFuture(created: Date, now: Date = Date()): Boolean =
        created.time > now.time + FUTURE_SKEW_MS

    /**
     * Full verify-time gate for a data signature that has already passed its
     * cryptographic check: version, digest and creation time. A false result
     * means the signature must be reported as not verified.
     */
    fun isAcceptableDataSignature(sig: PGPSignature, now: Date = Date()): Boolean {
        if (sig.version < 4) return false
        // 3.0.0 (5d-1): the creation time must be in the hashed area (one in
        // the unhashed area is not covered by the signature), and a hashed
        // subpacket marked critical that is not understood (an unknown type,
        // or any notation) invalidates the signature (RFC 9580 5.2.3.7).
        val hashed = sig.hashedSubPackets ?: return false
        if (hashed.signatureCreationTime == null) return false
        if (hasCriticalUnknown(sig)) return false
        val created = sig.creationTime
        if (isFromTheFuture(created, now)) return false
        if (isExpired(sig, now)) return false
        return isAcceptableDataDigest(sig.hashAlgorithm, created.time)
    }

    /**
     * The signature carries a hashed signature expiration time (subpacket 3)
     * and it has passed at [now]. Zero means "never expires"; an expiration
     * in the unhashed area is not covered by the signature and is ignored.
     */
    fun isExpired(sig: PGPSignature, now: Date = Date()): Boolean {
        val hashed = sig.hashedSubPackets ?: return false
        val created = hashed.signatureCreationTime ?: return false
        return isExpiredAt(created.time, hashed.signatureExpirationTime, now.time)
    }

    /** [createdMs] plus [expirySeconds] (0 or less: never) is at or before [nowMs]. */
    fun isExpiredAt(createdMs: Long, expirySeconds: Long, nowMs: Long): Boolean =
        expirySeconds > 0 && nowMs >= createdMs + expirySeconds * 1000L

    /** A hashed subpacket of [sig] is critical and not understood (see
     *  CertificateBindings.KNOWN_SUBPACKETS; every notation counts). */
    fun hasCriticalUnknown(sig: PGPSignature): Boolean {
        val hashed = sig.hashedSubPackets ?: return false
        return hashed.toArray().any {
            it.isCritical && (it.type == SignatureSubpacketTags.NOTATION_DATA || it.type !in CertificateBindings.KNOWN_SUBPACKETS)
        }
    }
}
