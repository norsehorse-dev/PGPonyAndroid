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
//
// 4.6.0 (item 17.1): the grade now runs on the certificate's verified view
// (CertificateBindings). A subkey only speaks for a primary when a verified
// 0x18 binding from that primary exists and, because it signs, a verified
// 0x19 back-signature from the subkey; revocations and expiry are read only
// from signatures that verified. When the same signing key appears on more
// than one ring, the ring it is validly bound to is the one graded (and the
// one whose identity is shown), so a key grafted onto another certificate
// cannot borrow that certificate's name. The data signature itself must pass
// SignaturePolicy (document type, digest, creation time).
//
// 3.0.0 (checkpoint 5d-1): the grade is taken at the signature's time from
// every verified self-signature (CertificateBindings.Report.signerValidityAt),
// not only from the newest one: a signature older than its key is
// PREDATES_KEY, one made while no self-signature made the certificate valid is
// NOT_VALID_AT_TIME, and a soft revocation (superseded, retired) no longer
// reaches back to signatures made before it. Hard revocations still do.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPKeyFlags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
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
    INVALID,
    /** 4.6.0: the signing subkey is not validly bound to any certificate that
     *  carries it (no verified 0x18 binding, or no verified 0x19 back-signature). */
    UNBOUND_SIGNER,
    /** 4.6.0: the signature uses a digest, version or creation time that the
     *  verify policy no longer accepts (see SignaturePolicy). */
    WEAK_SIGNATURE,
    /** 3.0.0: the signature claims to be older than the key that made it. */
    PREDATES_KEY,
    /** 3.0.0: a valid signature from a weak key (RSA under 2048 bits, DSA),
     *  reported only when KeyPolicy.strict is set; otherwise such a signature
     *  is VERIFIED and the caller shows the weak-key warning. */
    WEAK_KEY,
    /** 3.0.0: no self-signature made the signer's certificate valid at the
     *  time of the signature (a binding that had expired, say). */
    NOT_VALID_AT_TIME
}

object SignerEvaluator {

    /** Data-signature types a message or file signature may carry. */
    private val DOCUMENT_TYPES = setOf(PGPSignature.BINARY_DOCUMENT, PGPSignature.CANONICAL_TEXT_DOCUMENT)

    /**
     * Grade the signer of an already-crypto-verified signature. Call only
     * after the signature's own cryptographic check has passed; on a failed
     * check the caller sets [SignerStatus.INVALID] directly.
     */
    fun evaluate(keyID: Long, sigCreationTime: Date, rings: List<PGPPublicKeyRing>): SignerStatus {
        val containing = rings.filter { it.getPublicKey(keyID) != null }
        if (containing.isEmpty()) return SignerStatus.UNKNOWN_SIGNER
        val view = validSignerView(keyID, containing)
        if (view == null) {
            // Bound but not back-signed: a subkey whose flags exclude signing
            // (an encryption subkey, say) is reported as such; anything else is
            // a signing key without the back-signature that ties it here.
            val bound = containing.asSequence().map { CertificateBindings.verified(it) }.firstOrNull { v ->
                val k = v.ring.getPublicKey(keyID) ?: return@firstOrNull false
                v.report?.subkeyByFingerprint(fpHex(k))?.bound == true
            }
            val key = bound?.ring?.getPublicKey(keyID)
            return if (key != null && !hasSignFlag(key)) SignerStatus.NOT_SIGNING_KEY else SignerStatus.UNBOUND_SIGNER
        }
        val ring = view.ring
        val report = view.report
        val signingKey = ring.getPublicKey(keyID) ?: return SignerStatus.UNBOUND_SIGNER
        val graded = grade(ring, report, signingKey, sigCreationTime)
        // 3.0.0 (5d-3): a weak signing key is read-only; strict callers refuse it.
        if (graded == SignerStatus.VERIFIED && KeyPolicy.strict && KeyPolicy.isWeak(signingKey, ring.publicKey)) {
            return SignerStatus.WEAK_KEY
        }
        return graded
    }

    private fun grade(
        ring: PGPPublicKeyRing,
        report: CertificateBindings.Report?,
        signingKey: PGPPublicKey,
        sigCreationTime: Date
    ): SignerStatus {
        val primary = ring.publicKey
        val at = sigCreationTime.time
        if (report != null && report.supported) {
            // 3.0.0 (5d-1): judged at the signature's time from the verified
            // self-signatures (CertificateBindings.Report.signerValidityAt).
            return when (report.signerValidityAt(fpHex(signingKey), at)) {
                CertificateBindings.SignerValidity.VALID -> SignerStatus.VERIFIED
                CertificateBindings.SignerValidity.PREDATES_KEY -> SignerStatus.PREDATES_KEY
                CertificateBindings.SignerValidity.NOT_VALID -> SignerStatus.NOT_VALID_AT_TIME
                CertificateBindings.SignerValidity.EXPIRED -> SignerStatus.EXPIRED_KEY
                CertificateBindings.SignerValidity.REVOKED -> SignerStatus.REVOKED_KEY
                CertificateBindings.SignerValidity.NOT_SIGNING -> SignerStatus.NOT_SIGNING_KEY
                CertificateBindings.SignerValidity.UNBOUND -> SignerStatus.UNBOUND_SIGNER
            }
        }
        if (at < primary.creationTime.time || at < signingKey.creationTime.time) return SignerStatus.PREDATES_KEY
        if (primary.hasRevocation() || signingKey.hasRevocation()) return SignerStatus.REVOKED_KEY
        if (isExpiredAt(primary, sigCreationTime) || isExpiredAt(signingKey, sigCreationTime)) {
            return SignerStatus.EXPIRED_KEY
        }
        if (!hasSignFlag(signingKey)) return SignerStatus.NOT_SIGNING_KEY
        return SignerStatus.VERIFIED
    }

    /**
     * Full grade for a data signature whose cryptographic check already
     * passed: the signature itself must be a document signature that passes
     * [SignaturePolicy], then the signer is graded as in [evaluate].
     */
    fun evaluate(sig: PGPSignature, rings: List<PGPPublicKeyRing>): SignerStatus =
        evaluate(sig, sig.keyID, rings)

    /**
     * 3.0.0 (5d-1): as above, for a signature that verified under the key
     * [signerKeyID], which need not be the key its issuer subpacket names.
     */
    fun evaluate(sig: PGPSignature, signerKeyID: Long, rings: List<PGPPublicKeyRing>): SignerStatus {
        if (sig.signatureType !in DOCUMENT_TYPES) return SignerStatus.INVALID
        if (!SignaturePolicy.isAcceptableDataSignature(sig)) return SignerStatus.WEAK_SIGNATURE
        return evaluate(signerKeyID, sig.creationTime, rings)
    }

    /** Uppercase hex fingerprint of [key], the identity the reports use. */
    internal fun fpHex(key: PGPPublicKey): String =
        org.bouncycastle.util.encoders.Hex.toHexString(key.fingerprint).uppercase()

    /**
     * The ring among [rings] that [keyID] is a valid signer for (the primary
     * itself, or a bound, back-signed subkey), as its verified view. Null
     * when no ring binds the key. A certificate that cannot be analysed at
     * all does not qualify (fail closed); one whose primary algorithm has no
     * verifier here keeps the pre-4.6.0 behaviour.
     */
    fun validSignerView(keyID: Long, rings: List<PGPPublicKeyRing>): CertificateBindings.Verified? {
        for (r in rings) {
            if (r.getPublicKey(keyID) == null) continue
            val v = CertificateBindings.verified(r)
            val report = v.report ?: continue
            val k = v.ring.getPublicKey(keyID) ?: continue
            if (report.isValidSignerKey(fpHex(k))) return v
        }
        return null
    }

    /** The original ring that validly carries [keyID] as a signer, for identity display. */
    fun signerRing(keyID: Long, rings: List<PGPPublicKeyRing>): PGPPublicKeyRing? {
        val v = validSignerView(keyID, rings) ?: return null
        val primaryId = v.ring.publicKey.keyID
        return rings.firstOrNull { it.publicKey.keyID == primaryId && it.getPublicKey(keyID) != null } ?: v.ring
    }

    /**
     * Encrypt-side gate: may [key] (from [view]'s ring) receive a message?
     * The primary must be unrevoked and unexpired now; a subkey must also be
     * bound by a verified 0x18, unrevoked and unexpired, matched by
     * fingerprint. A certificate that cannot be analysed allows only its
     * primary (fail closed for subkeys).
     */
    fun isUsableEncryptionKey(view: CertificateBindings.Verified, key: PGPPublicKey, now: Date = Date()): Boolean {
        // 3.0.0 (5d-3): weak keys are read-only; nothing new is encrypted to them.
        if (KeyPolicy.isWeak(key, view.ring.publicKey)) return false
        val ring = view.ring
        val report = view.report
        val primary = ring.publicKey
        if (report != null && report.supported) {
            return report.isUsableEncryptionKey(fpHex(key), now.time)
        }
        if (report == null && !key.isMasterKey) return false
        if (primary.hasRevocation()) return false
        if (!key.isMasterKey && key.hasRevocation()) return false
        if (isExpiredAt(primary, now)) return false
        if (!key.isMasterKey && isExpiredAt(key, now)) return false
        return true
    }

    /** Plain-English reason for a non-VERIFIED status, for the clear-signed path. */
    fun reason(status: SignerStatus): String = when (status) {
        SignerStatus.REVOKED_KEY     -> "Signer key has been revoked"
        SignerStatus.EXPIRED_KEY     -> "Signer key was expired when it signed"
        SignerStatus.NOT_SIGNING_KEY -> "Signer key is not allowed to sign"
        SignerStatus.INVALID         -> "Signature did not match the content"
        SignerStatus.UNKNOWN_SIGNER  -> "Signer key is not in your keyring"
        SignerStatus.UNBOUND_SIGNER  -> "Signer key is not certified by the key it claims to belong to"
        SignerStatus.WEAK_SIGNATURE  -> "Signature uses an algorithm or date that is no longer accepted"
        SignerStatus.PREDATES_KEY    -> "Signature is dated before the key that made it existed"
        SignerStatus.WEAK_KEY        -> "Signer key is too weak to trust (RSA under 2048 bits, or DSA)"
        SignerStatus.NOT_VALID_AT_TIME -> "Signer key was not valid when it signed"
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

    /** True unless the key's NEWEST key-flags-bearing self-signature excludes
     *  signing. A key with no key-flags subpacket anywhere is treated as
     *  sign-capable (no legitimate message rejected). Reading only the newest
     *  signature means a later binding that dropped the Sign flag wins over an
     *  older one that had it. */
    private fun hasSignFlag(key: PGPPublicKey): Boolean {
        var newest: PGPSignature? = null
        val sigs = key.signatures
        while (sigs.hasNext()) {
            val sig = sigs.next() as? PGPSignature ?: continue
            val type = sig.signatureType
            val selfType = if (key.isMasterKey) {
                type == PGPSignature.DIRECT_KEY || type in PGPSignature.DEFAULT_CERTIFICATION..PGPSignature.POSITIVE_CERTIFICATION
            } else {
                type == PGPSignature.SUBKEY_BINDING
            }
            if (!selfType) continue
            // Only the key's own signatures count; a third-party certification
            // on a User ID says nothing about this key's capabilities.
            if (key.isMasterKey && sig.keyID != key.keyID) continue
            val flags = sig.hashedSubPackets?.keyFlags ?: 0
            if (flags == 0) continue
            if (newest == null || sig.creationTime.after(newest.creationTime)) newest = sig
        }
        val n = newest ?: return true
        return (n.hashedSubPackets.keyFlags and PGPKeyFlags.CAN_SIGN) != 0
    }
}
