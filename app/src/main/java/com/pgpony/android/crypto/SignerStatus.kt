// SignerStatus.kt
// PGPony Android — 4.5.0 (item 11 / Finding C): signer trust evaluation.
//
// A cryptographically valid signature is not the same as a trustworthy one.
// RevocationService and KeyExpirationService can PRODUCE revocations and
// expiries but nothing CONSULTS them at verify time, so a signature from a
// revoked, expired, or non-signing key still shows a green "Verified".
//
// SignerEvaluator closes that gap: after the crypto check passes, it grades
// the signer key and returns a SignerStatus. Only VERIFIED means "valid AND
// the key is good"; every other non-INVALID value is a valid signature whose
// key should not be trusted. The guiding constraint (hardening plan) is that
// no legitimate message may start being rejected, so a key with no key-flags
// subpacket at all is treated as sign-capable, and a key that expired only
// AFTER it signed stays VERIFIED (its signature was valid when made).

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPKeyFlags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import java.util.Date

enum class SignerStatus {
    /** No signature present. */
    NONE,
    /** Cryptographically valid AND the signer key is unrevoked, unexpired, sign-flagged. */
    VERIFIED,
    /** Valid signature, but the signer key (or its primary) is revoked. */
    REVOKED_KEY,
    /** Valid signature, but the signer key was already expired when it signed. */
    EXPIRED_KEY,
    /** Valid signature from a key whose key flags exclude signing. */
    NOT_SIGNING_KEY,
    /** Signer key is not in the supplied keyrings. */
    UNKNOWN_SIGNER,
    /** The cryptographic check failed. */
    INVALID
}

object SignerEvaluator {

    /**
     * Grade the signer of an already-crypto-verified signature. Call only
     * after the signature's own cryptographic check has passed; on a failed
     * check the caller sets [SignerStatus.INVALID] directly.
     */
    fun evaluate(keyID: Long, sigCreationTime: Date, rings: List<PGPPublicKeyRing>): SignerStatus {
        val ring = rings.firstOrNull { it.getPublicKey(keyID) != null }
            ?: return SignerStatus.UNKNOWN_SIGNER
        val signingKey = ring.getPublicKey(keyID) ?: return SignerStatus.UNKNOWN_SIGNER
        val primary = ring.publicKey
        if (primary.hasRevocation() || signingKey.hasRevocation()) return SignerStatus.REVOKED_KEY
        if (isExpiredAt(primary, sigCreationTime) || isExpiredAt(signingKey, sigCreationTime)) {
            return SignerStatus.EXPIRED_KEY
        }
        if (!hasSignFlag(signingKey)) return SignerStatus.NOT_SIGNING_KEY
        return SignerStatus.VERIFIED
    }

    /** Plain-English reason for a non-VERIFIED status, for the clear-signed path. */
    fun reason(status: SignerStatus): String = when (status) {
        SignerStatus.REVOKED_KEY     -> "Signer key has been revoked"
        SignerStatus.EXPIRED_KEY     -> "Signer key was expired when it signed"
        SignerStatus.NOT_SIGNING_KEY -> "Signer key is not allowed to sign"
        SignerStatus.INVALID         -> "Signature did not match the content"
        SignerStatus.UNKNOWN_SIGNER  -> "Signer key is not in your keyring"
        SignerStatus.NONE            -> "No signature present"
        SignerStatus.VERIFIED        -> "Verified"
    }

    /** True if [key] carries an expiry and it had already elapsed at [at]. A key
     *  that expires only after [at] is not counted, so a signature made while the
     *  key was valid stays trusted even once the key later lapses. */
    private fun isExpiredAt(key: PGPPublicKey, at: Date): Boolean {
        val secs = key.validSeconds
        if (secs <= 0L) return false
        return at.time >= key.creationTime.time + secs * 1000L
    }

    /** True unless the key carries key-flags that exclude signing. A key with no
     *  key-flags subpacket anywhere is treated as sign-capable (no legitimate
     *  message rejected); only an explicit non-signing flag set yields false. */
    private fun hasSignFlag(key: PGPPublicKey): Boolean {
        var sawFlags = false
        val sigs = key.signatures
        while (sigs.hasNext()) {
            val vector = sigs.next().hashedSubPackets ?: continue
            val flags = vector.keyFlags
            if (flags != 0) {
                sawFlags = true
                if (flags and PGPKeyFlags.CAN_SIGN != 0) return true
            }
        }
        return !sawFlags
    }
}
