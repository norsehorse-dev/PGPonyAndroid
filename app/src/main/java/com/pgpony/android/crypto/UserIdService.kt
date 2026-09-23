// UserIdService.kt
// PGPony Android — 4.2.0 RC3 workstream I (#29 multiple identities)
//
// Add, revoke, and re-prioritize User IDs on an existing software key
// pair. Same load -> sign -> reassemble shape as RevocationService and
// KeyExpirationService, reusing their exact BC idioms:
//
//   • Self-certifications: PGPSignatureGenerator.generateCertification
//     (String, PGPPublicKey) -> PGPPublicKey.addCertification, the
//     same POSITIVE_CERTIFICATION path KeyExpirationService already
//     uses to re-sign every UID when expiry changes.
//   • Revocation: PGPSignature.CERTIFICATION_REVOCATION (0x30), a
//     narrower sibling of RevocationService's KEY_REVOCATION (0x20) —
//     same reason-subpacket handling, different signature type and a
//     (String, PGPPublicKey) certification overload instead of the
//     bare-pubkey one, since the revocation is over one UID, not the
//     whole key.
//   • Primary-UID flag: PGPSignatureSubpacketGenerator.setPrimaryUserID.
//     BC signatures are immutable, so changing which UID is primary
//     always means reissuing self-certs (remove old, add new) for
//     every UID whose primary flag needs to change, never patching a
//     subpacket in place. KeyExpirationService.copyUserIdSubpackets
//     already carries an existing primary flag forward when reissuing
//     for expiry; this file's own copyUserIdSubpackets does the same
//     but takes the target flag as a caller-supplied override so add/
//     revoke/promote can each say what they want it to become.
//
// Card-backed keys are out of scope, matching the same scope line
// ClassicalSubkeyGen (workstream H) drew: software key pairs only.
// A card's primary is the signing key for its own self-certs, and NFC
// signing for UID edits is a separate surgery not needed for #29.
//
// Scope note: this file only edits self-certifications the primary
// key issues over its own UIDs. Third-party certifications (other
// people's signatures on this key's UIDs) are untouched by every
// operation here — add/revoke/promote all only ever add or supersede
// signatures where primary.keyID == signer.keyID.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.sig.Features
import org.bouncycastle.bcpg.sig.RevocationReasonTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider

class UserIdService private constructor() {

    companion object {
        val shared = UserIdService()
    }

    sealed class UserIdError(message: String) : Exception(message) {
        class PassphraseRequired : UserIdError("Signing key requires a passphrase")
        class InvalidPassphrase : UserIdError("Incorrect passphrase for key")
        class UnsupportedKey(reason: String) : UserIdError(reason)
        class AlreadyExists(reason: String) : UserIdError(reason)
        class NotFound(reason: String) : UserIdError(reason)
        class Failed(reason: String) : UserIdError(reason)
    }

    data class UpdatedRings(
        val publicRing: PGPPublicKeyRing,
        val secretRing: PGPSecretKeyRing
    )

    /** §5.6.7 (Play review): a human-readable key notation (RFC 9580
     *  §5.2.3.24), name@domain=value, on the primary UID self-cert. */
    data class Notation(val name: String, val value: String)

    /**
     * Add [userId] as a new self-certified identity on [secretRing].
     * If [makePrimary] is true, the previously-primary UID (explicit
     * via its IsPrimaryUserId subpacket, or implicitly the first UID
     * if none is flagged — matching how generation never sets the
     * subpacket for a lone UID) has its self-cert reissued without
     * the flag, so exactly one UID stays primary.
     */
    fun addUserId(
        secretRing: PGPSecretKeyRing,
        publicRing: PGPPublicKeyRing,
        userId: String,
        makePrimary: Boolean,
        passphrase: String?
    ): UpdatedRings {
        if (userId.isBlank()) {
            throw UserIdError.UnsupportedKey("User ID cannot be blank")
        }
        var primary = publicRing.publicKey
        if (primary.userIDs.asSequence().any { it == userId }) {
            throw UserIdError.AlreadyExists("This key already has that User ID")
        }

        val primarySecret = secretRing.secretKey
        val privateKey = extractPrivate(primarySecret, passphrase)
        val signerBuilder = BcPGPContentSignerBuilder(primarySecret.publicKey.algorithm, HashAlgorithmTags.SHA256)
        fun signer() = PGPSignatureGenerator(signerBuilder, primary).apply { init(PGPSignature.POSITIVE_CERTIFICATION, privateKey) }

        val representative = representativeSelfCert(primary)

        if (makePrimary) {
            val currentPrimaryUid = currentPrimaryUserId(primary)
            if (currentPrimaryUid != null) {
                primary = reissueSelfCert(primary, currentPrimaryUid, isPrimary = false, signer = ::signer)
            }
        } else {
            // Bug (Bart, Sep 2026): the new UID's self-cert is stamped "now". If
            // no existing UID carries an explicit IsPrimaryUserId flag (the usual
            // case, since generation never flags a lone UID), keyservers and gpg
            // fall back to "newest self-sig wins" and show the just-added address
            // as primary, even though the user did not ask for that. Pin the
            // current primary by reissuing its self-cert WITH the flag, so the
            // explicit flag beats recency and the original stays primary. A UID
            // that is already explicitly flagged needs nothing.
            val currentPrimaryUid = currentPrimaryUserId(primary)
            val alreadyExplicit = currentPrimaryUid != null &&
                latestSelfCert(primary, currentPrimaryUid)?.hashedSubPackets?.isPrimaryUserID == true
            if (currentPrimaryUid != null && !alreadyExplicit) {
                primary = reissueSelfCert(primary, currentPrimaryUid, isPrimary = true, signer = ::signer)
            }
        }

        val sub = PGPSignatureSubpacketGenerator()
        copyUserIdSubpackets(representative?.hashedSubPackets, makePrimary, sub)
        val gen = signer()
        gen.setHashedSubpackets(sub.generate())
        val newCert = gen.generateCertification(userId, primary)
        primary = PGPPublicKey.addCertification(primary, userId, newCert)

        return reassemble(secretRing, publicRing, primary)
    }

    /**
     * §5.6.7: the human-readable notations on the primary UID's latest
     * self-cert. Empty when the key has none or no resolvable primary UID.
     */
    fun readNotations(primary: PGPPublicKey): List<Notation> {
        val primaryUid = currentPrimaryUserId(primary) ?: return emptyList()
        val cert = latestSelfCert(primary, primaryUid) ?: return emptyList()
        val occ = cert.hashedSubPackets?.notationDataOccurrences ?: return emptyList()
        return occ.filter { it.isHumanReadable }.map { Notation(it.notationName, it.notationValue) }
    }

    /**
     * §5.6.7: replace the primary UID's notation set with [notations] and
     * reissue its self-cert, preserving key flags, preferred algorithms,
     * features, key-expiry, and the primary-UID flag. Human-readable flag is
     * set; names must contain '@' (RFC 9580). Rides the same reassemble path
     * as addUserId, so composite rings round-trip too (the validation matrix
     * confirms v4, v6, and both composite forms).
     */
    fun setNotations(
        secretRing: PGPSecretKeyRing,
        publicRing: PGPPublicKeyRing,
        notations: List<Notation>,
        passphrase: String?
    ): UpdatedRings {
        notations.firstOrNull { !it.name.contains('@') }?.let {
            throw UserIdError.UnsupportedKey("Notation name must contain '@': ${it.name}")
        }
        val primary = publicRing.publicKey
        val primaryUid = currentPrimaryUserId(primary)
            ?: throw UserIdError.UnsupportedKey("Key has no primary User ID")
        val primarySecret = secretRing.secretKey
        val privateKey = extractPrivate(primarySecret, passphrase)
        val signerBuilder = BcPGPContentSignerBuilder(primarySecret.publicKey.algorithm, HashAlgorithmTags.SHA256)
        val existing = latestSelfCert(primary, primaryUid)
        val isPrimaryFlag = existing?.hashedSubPackets?.isPrimaryUserID ?: false
        val sub = PGPSignatureSubpacketGenerator()
        copyUserIdSubpackets(existing?.hashedSubPackets, isPrimaryFlag, sub)
        for (n in notations) {
            sub.setNotationData(false, true, n.name, n.value)
        }
        val gen = PGPSignatureGenerator(signerBuilder, primary).apply {
            init(PGPSignature.POSITIVE_CERTIFICATION, privateKey)
        }
        gen.setHashedSubpackets(sub.generate())
        val newCert = gen.generateCertification(primaryUid, primary)
        var updated = primary
        if (existing != null) updated = PGPPublicKey.removeCertification(updated, primaryUid, existing)
        updated = PGPPublicKey.addCertification(updated, primaryUid, newCert)
        return reassemble(secretRing, publicRing, updated)
    }

    /**
     * Revoke [userId] with a CERTIFICATION_REVOCATION signature. This
     * adds a revocation certification alongside the existing self-cert
     * (matching gpg's `revuid`) — the UID and its original self-cert
     * stay in the ring, verifiers are expected to honor the revocation.
     * Refuses to revoke the last remaining non-revoked UID: a key with
     * zero valid identities is not a state the UI should produce by
     * accident.
     */
    fun revokeUserId(
        secretRing: PGPSecretKeyRing,
        publicRing: PGPPublicKeyRing,
        userId: String,
        reason: com.pgpony.android.data.RevocationReason,
        comment: String?,
        passphrase: String?
    ): UpdatedRings {
        var primary = publicRing.publicKey
        if (primary.userIDs.asSequence().none { it == userId }) {
            throw UserIdError.NotFound("This key has no such User ID")
        }
        val liveUids = primary.userIDs.asSequence().filter { !isRevoked(primary, it) }.toList()
        if (liveUids.size <= 1 && liveUids.contains(userId)) {
            throw UserIdError.UnsupportedKey("Cannot revoke the only remaining User ID on this key")
        }

        val primarySecret = secretRing.secretKey
        val privateKey = extractPrivate(primarySecret, passphrase)
        val signerBuilder = BcPGPContentSignerBuilder(primarySecret.publicKey.algorithm, HashAlgorithmTags.SHA256)
        val gen = PGPSignatureGenerator(signerBuilder, primary).apply { init(PGPSignature.CERTIFICATION_REVOCATION, privateKey) }

        val sub = PGPSignatureSubpacketGenerator()
        sub.setIssuerFingerprint(false, primary)
        sub.setRevocationReason(false, reasonToTag(reason), comment ?: "")
        gen.setHashedSubpackets(sub.generate())

        val revSig = gen.generateCertification(userId, primary)
        primary = PGPPublicKey.addCertification(primary, userId, revSig)

        return reassemble(secretRing, publicRing, primary)
    }

    /**
     * Remove [userId] from the key locally: strip the User ID and its
     * self-certifications from the ring. Local only, like a subkey remove:
     * it tells no correspondent, and anyone who already holds the public key
     * keeps the UID. Use revokeUserId to retire a UID that has been shared.
     * Blocks removing the last User ID, which would leave the key with no
     * identity. Structural only, so no passphrase is needed.
     */
    fun removeUserId(
        secretRing: PGPSecretKeyRing,
        publicRing: PGPPublicKeyRing,
        userId: String
    ): UpdatedRings {
        val primary = publicRing.publicKey
        if (primary.userIDs.asSequence().none { it == userId }) {
            throw UserIdError.NotFound("This key has no such User ID")
        }
        if (primary.userIDs.asSequence().count() <= 1) {
            throw UserIdError.UnsupportedKey("Cannot remove the only User ID on this key")
        }
        val stripped = PGPPublicKey.removeCertification(primary, userId)
            ?: throw UserIdError.Failed("Failed to remove the User ID")
        return reassemble(secretRing, publicRing, stripped)
    }

    /**
     * Make [userId] the primary identity: reissue its self-cert with
     * IsPrimaryUserId set, and reissue the self-cert of whichever UID
     * currently carries that flag (if any) without it. A no-op flag
     * flip on an otherwise-unpromoted key still reissues both certs
     * with a fresh timestamp, matching gpg's own `primary` command.
     */
    fun setPrimaryUserId(
        secretRing: PGPSecretKeyRing,
        publicRing: PGPPublicKeyRing,
        userId: String,
        passphrase: String?
    ): UpdatedRings {
        var primary = publicRing.publicKey
        if (primary.userIDs.asSequence().none { it == userId }) {
            throw UserIdError.NotFound("This key has no such User ID")
        }
        if (isRevoked(primary, userId)) {
            throw UserIdError.UnsupportedKey("Cannot make a revoked User ID primary")
        }

        val primarySecret = secretRing.secretKey
        val privateKey = extractPrivate(primarySecret, passphrase)
        val signerBuilder = BcPGPContentSignerBuilder(primarySecret.publicKey.algorithm, HashAlgorithmTags.SHA256)
        fun signer() = PGPSignatureGenerator(signerBuilder, primary).apply { init(PGPSignature.POSITIVE_CERTIFICATION, privateKey) }

        val currentPrimaryUid = currentPrimaryUserId(primary)
        if (currentPrimaryUid != null && currentPrimaryUid != userId) {
            primary = reissueSelfCert(primary, currentPrimaryUid, isPrimary = false, signer = ::signer)
        }
        // 4.6.0 (item 9): clear the flag from every other User ID too, so Make
        // Primary also repairs a key that carries more than one primary flag
        // (the state the publish check refuses).
        for (other in primaryFlaggedLiveUserIds(primary)) {
            if (other != userId) primary = reissueSelfCert(primary, other, isPrimary = false, signer = ::signer)
        }
        primary = reissueSelfCert(primary, userId, isPrimary = true, signer = ::signer)

        return reassemble(secretRing, publicRing, primary)
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private fun reassemble(secretRing: PGPSecretKeyRing, publicRing: PGPPublicKeyRing, updatedPrimary: PGPPublicKey): UpdatedRings {
        val newPublicRing = PGPPublicKeyRing.insertPublicKey(publicRing, updatedPrimary)
        val newSecretRing = PGPSecretKeyRing.replacePublicKeys(secretRing, newPublicRing)
        return UpdatedRings(newPublicRing, newSecretRing)
    }

    private fun reissueSelfCert(
        primary: PGPPublicKey,
        userId: String,
        isPrimary: Boolean,
        signer: () -> PGPSignatureGenerator
    ): PGPPublicKey {
        val existing = latestSelfCert(primary, userId)
        val sub = PGPSignatureSubpacketGenerator()
        copyUserIdSubpackets(existing?.hashedSubPackets, isPrimary, sub)
        val gen = signer()
        gen.setHashedSubpackets(sub.generate())
        val newCert = gen.generateCertification(userId, primary)
        var updated = primary
        if (existing != null) {
            updated = PGPPublicKey.removeCertification(updated, userId, existing)
        }
        return PGPPublicKey.addCertification(updated, userId, newCert)
    }

    /**
     * The UID currently flagged IsPrimaryUserId on its latest self-cert,
     * or the first UID if none is explicitly flagged — matching how
     * PGPCryptoService never sets the subpacket for a lone UID at
     * generation time, so a fresh key's single UID is only implicitly
     * primary. Public: also used by KeyDetailViewModel.deriveUserIds to
     * label the PRIMARY badge correctly, replacing an earlier string-
     * match against the entity's cached userID field that could disagree
     * with the ring's actual primary-UID subpacket (RC3 §17.2 I bug).
     */
    /**
     * 4.6.0 (item 9): the live (unrevoked) User IDs whose newest self-
     * certification carries the primary-User-ID flag. More than one means the
     * key's primary identity is ambiguous to anyone who fetches it.
     */
    fun primaryFlaggedLiveUserIds(primary: PGPPublicKey): List<String> =
        primary.userIDs.asSequence().toList().filter { uid ->
            if (isRevoked(primary, uid)) return@filter false
            var newest: PGPSignature? = null
            primary.getSignaturesForID(uid)?.forEach { sig ->
                if (sig.keyID != primary.keyID) return@forEach
                if (sig.signatureType in PGPSignature.DEFAULT_CERTIFICATION..PGPSignature.POSITIVE_CERTIFICATION) {
                    if (newest == null || sig.creationTime.after(newest!!.creationTime)) newest = sig
                }
            }
            newest?.hashedSubPackets?.isPrimaryUserID == true
        }

    fun currentPrimaryUserId(primary: PGPPublicKey): String? {
        val uids = primary.userIDs.asSequence().toList()
        for (uid in uids) {
            val cert = latestSelfCert(primary, uid)
            if (cert?.hashedSubPackets?.isPrimaryUserID == true) return uid
        }
        return uids.firstOrNull()
    }

    /** A representative self-cert to carry forward key flags / preferred
     *  algorithms / features when issuing a brand-new UID's cert — the
     *  current primary's cert if one exists, else any existing UID's. */
    private fun representativeSelfCert(primary: PGPPublicKey): PGPSignature? {
        val primaryUid = currentPrimaryUserId(primary) ?: return null
        return latestSelfCert(primary, primaryUid)
    }

    private fun latestSelfCert(primary: PGPPublicKey, userId: String): PGPSignature? {
        var latest: PGPSignature? = null
        primary.getSignaturesForID(userId)?.forEach { sig ->
            if (sig.keyID == primary.keyID && sig.signatureType == PGPSignature.POSITIVE_CERTIFICATION) {
                if (latest == null || sig.creationTime.after(latest!!.creationTime)) latest = sig
            }
        }
        return latest
    }

    /** Public: also used by KeyDetailViewModel.deriveUserIds to decide
     *  whether a UID row shows a REVOKED badge and hides its action
     *  buttons. */
    fun isRevoked(primary: PGPPublicKey, userId: String): Boolean {
        var newestCert: PGPSignature? = null
        var newestRevocation: PGPSignature? = null
        primary.getSignaturesForID(userId)?.forEach { sig ->
            if (sig.keyID != primary.keyID) return@forEach
            when (sig.signatureType) {
                PGPSignature.POSITIVE_CERTIFICATION, PGPSignature.CASUAL_CERTIFICATION,
                PGPSignature.NO_CERTIFICATION, PGPSignature.DEFAULT_CERTIFICATION -> {
                    if (newestCert == null || sig.creationTime.after(newestCert!!.creationTime)) newestCert = sig
                }
                PGPSignature.CERTIFICATION_REVOCATION -> {
                    if (newestRevocation == null || sig.creationTime.after(newestRevocation!!.creationTime)) newestRevocation = sig
                }
            }
        }
        val cert = newestCert ?: return false
        val revocation = newestRevocation ?: return false
        return revocation.creationTime.after(cert.creationTime)
    }

    private fun copyUserIdSubpackets(
        old: PGPSignatureSubpacketVector?,
        isPrimary: Boolean,
        gen: PGPSignatureSubpacketGenerator
    ) {
        if (old != null) {
            if (old.keyFlags != 0) gen.setKeyFlags(false, old.keyFlags)
            old.preferredSymmetricAlgorithms?.takeIf { it.isNotEmpty() }
                ?.let { gen.setPreferredSymmetricAlgorithms(false, it) }
            old.preferredHashAlgorithms?.takeIf { it.isNotEmpty() }
                ?.let { gen.setPreferredHashAlgorithms(false, it) }
            old.preferredCompressionAlgorithms?.takeIf { it.isNotEmpty() }
                ?.let { gen.setPreferredCompressionAlgorithms(false, it) }
            old.features?.let { f ->
                if (f.supportsModificationDetection()) {
                    gen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION)
                }
            }
            val expirySeconds = old.keyExpirationTime
            if (expirySeconds > 0L) gen.setKeyExpirationTime(false, expirySeconds)
        }
        if (isPrimary) gen.setPrimaryUserID(false, true)
    }

    private fun reasonToTag(reason: com.pgpony.android.data.RevocationReason): Byte = when (reason) {
        com.pgpony.android.data.RevocationReason.NO_REASON       -> RevocationReasonTags.NO_REASON
        com.pgpony.android.data.RevocationReason.SUPERSEDED      -> RevocationReasonTags.KEY_SUPERSEDED
        com.pgpony.android.data.RevocationReason.COMPROMISED     -> RevocationReasonTags.KEY_COMPROMISED
        com.pgpony.android.data.RevocationReason.RETIRED         -> RevocationReasonTags.KEY_RETIRED
        com.pgpony.android.data.RevocationReason.USER_ID_INVALID -> RevocationReasonTags.USER_NO_LONGER_VALID
    }

    private fun extractPrivate(
        primarySecret: org.bouncycastle.openpgp.PGPSecretKey,
        passphrase: String?
    ): PGPPrivateKey {
        return try {
            val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
                .build((passphrase ?: "").toCharArray())
            primarySecret.extractPrivateKey(decryptor)
        } catch (e: PGPException) {
            if (passphrase.isNullOrEmpty()) throw UserIdError.PassphraseRequired()
            throw UserIdError.InvalidPassphrase()
        }
    }
}
