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

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
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
        val created = sig.creationTime
        if (isFromTheFuture(created, now)) return false
        return isAcceptableDataDigest(sig.hashAlgorithm, created.time)
    }
}
