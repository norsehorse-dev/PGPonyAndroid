// KeyExpirationService.kt
// PGPony Android — key expiration editing
//
// Changes the expiration of an existing key by rebuilding its self
// certifications and subkey binding signatures with a new Key Expiration
// Time subpacket. Mirrors RevocationService's load → sign → reassemble
// shape, but instead of adding a revocation it supersedes the existing
// self-sigs/bindings (remove old, add fresh, current timestamp).
//
// Two signing paths:
//   • Software key pair — sign with the primary secret key (passphrase if
//     protected).
//   • Card-backed key  — the card's primary IS the signing key, so the new
//     self-cert and every subkey binding are signed on the card. One PIN is
//     cached for the whole operation (CardPGPContentSigner re-verifies per
//     signature internally; the card is tapped/held once).
//
// CORRECTNESS NOTES (verify with gpg after building):
//   • The Key Expiration Time subpacket is RELATIVE TO EACH KEY'S CREATION
//     TIME (RFC 4880 §5.2.3.6), not "now". We compute desiredExpiryEpoch −
//     keyCreationEpoch per key (primary and each subkey).
//   • Editing expiration does NOT change the fingerprint — the fingerprint
//     derives from the public-key packet, not its signatures.
//   • Existing capability subpackets (key flags, preferred algorithms,
//     features, primary-UID) are copied forward so renewing doesn't strip
//     capabilities; only the expiry subpacket is overridden.
//   • 4.7.0 (item 53, #86): an edit has a [Target]. The primary's expiry
//     re-signs only its live User IDs (a revoked one keeps its revocation),
//     and touches subkeys only when asked, and then only the ones valid now.
//     A subkey's expiry re-signs that subkey's binding alone. Before, every
//     subkey got the primary's date, which brought expired subkeys back.
//   • Sign-capable SUBKEYS (v6 keys have one): the software path rebuilds
//     their binding with the required embedded primary-key back-signature
//     (0x19) made BY the subkey, so the new expiry lands on the signing subkey
//     too (issue #4). The card path still skips them, since the card cannot
//     sign as the subkey.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.card.CardPGPContentSignerBuilder
import com.pgpony.android.crypto.card.OpenPgpCardSession
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyFlags
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder

class KeyExpirationService private constructor() {

    companion object {
        val shared = KeyExpirationService()
    }

    sealed class ExpirationError(message: String) : Exception(message) {
        class PassphraseRequired : ExpirationError("Signing key requires a passphrase")
        class InvalidPassphrase : ExpirationError("Incorrect passphrase for key")
        class UnsupportedKey(reason: String) : ExpirationError(reason)
        class Failed(reason: String) : ExpirationError(reason)
    }

    /** 4.7.0 (item 53, #86): what an expiration edit changes. */
    sealed class Target {
        /** The primary key: every live User ID's self-certification. With
         *  [currentSubkeys], also the binding of each subkey that is valid
         *  now (bound, not revoked, not expired); never the others. */
        data class Primary(val currentSubkeys: Boolean = false) : Target()
        /** One subkey's binding, and nothing else. */
        data class Subkey(val keyId: Long) : Target()
        /** 4.7.0 (item 51, #86): re-sign every live User ID and every
         *  subkey binding that is not revoked with a current hash, each
         *  keeping its own expiry. Nothing expires or comes back to life. */
        object Refresh : Target()
    }

    /**
     * 4.7.0 (item 51, #86): [refreshSelfSignatures]'s result: the rings and
     * the subkeys it brought back (left out of the certificate only because
     * their binding or back-signature used SHA-1 after the cutoff, and whose
     * secret is in [secretRing]).
     */
    class Refreshed(val rings: UpdatedRings, val restoredSubkeys: List<String>)

    /**
     * 4.7.0 (item 51, #86): Refresh self-signatures on a software key pair.
     * A subkey the stored certificate lacks but [secretRing] still carries,
     * whose only problem is a weak-hash binding (SubkeyAdmission WEAK_HASH,
     * verified apart from the hash), is put back first; holding its secret is
     * what makes that safe, since the SHA-1 risk is a binding forged over a
     * subkey someone else controls. Then every live User ID and every subkey
     * binding not revoked is re-signed with SHA-256, keeping each expiry.
     */
    fun refreshSelfSignatures(
        secretRing: PGPSecretKeyRing,
        publicRing: PGPPublicKeyRing,
        passphrase: String?
    ): Refreshed {
        var base = publicRing
        val restored = mutableListOf<String>()
        val fromSecret = PGPPublicKeyRing(secretRing.publicKeys.asSequence().toList())
        val weak = SubkeyAdmission.leftOut(fromSecret.encoded)
            .filter { it.issue == SubkeyAdmission.Issue.WEAK_HASH }
            .map { it.subkey.fingerprintHex.uppercase() }.toSet()
        for (pub in fromSecret.publicKeys) {
            if (pub.isMasterKey) continue
            val fp = org.bouncycastle.util.encoders.Hex.toHexString(pub.fingerprint).uppercase()
            if (fp !in weak || base.getPublicKey(pub.fingerprint) != null) continue
            val sec = secretRing.getSecretKey(pub.keyID) ?: continue
            if (OfflineStub.isStub(sec)) continue
            base = PGPPublicKeyRing.insertPublicKey(base, pub)
            restored += fp
        }
        val rings = setExpirationSoftware(secretRing, base, null, passphrase, Target.Refresh)
        return Refreshed(rings, restored)
    }

    /** A signing subkey's binding needs a back-signature made by the subkey,
     *  which the card path cannot make. */
    val CARD_SIGNING_SUBKEY_MESSAGE = "A signing subkey's expiry cannot be changed with the security key"
    val SUBKEY_NOT_FOUND_MESSAGE = "That subkey is not on this key"

    /** Result of an expiration edit. secretRing is null for card-backed keys. */
    data class UpdatedRings(
        val publicRing: PGPPublicKeyRing,
        val secretRing: PGPSecretKeyRing?
    )

    /**
     * Software path: rebuild [publicRing]'s expiry, signing with the primary
     * secret key from [secretRing]. [expiresAtEpochSeconds] null = never.
     * Returns the updated public ring plus a secret ring whose public
     * material carries the new signatures.
     */
    fun setExpirationSoftware(
        secretRing: PGPSecretKeyRing,
        publicRing: PGPPublicKeyRing,
        expiresAtEpochSeconds: Long?,
        passphrase: String?,
        target: Target = Target.Primary()
    ): UpdatedRings {
        val primarySecret = secretRing.secretKey
        val privateKey = extractPrivate(primarySecret, passphrase)
        val signerBuilder = BcPGPContentSignerBuilder(
            primarySecret.publicKey.algorithm,
            HashAlgorithmTags.SHA256
        )
        val newPublic = try {
            rebuildExpiration(publicRing, expiresAtEpochSeconds, secretRing, passphrase, target) { type ->
                PonySigGen(signerBuilder, primarySecret.publicKey).apply { init(type, privateKey) }
            }
        } catch (e: ExpirationError) {
            throw e
        } catch (e: Exception) {
            throw ExpirationError.Failed(e.message ?: "Could not update expiration")
        }
        val newSecret = PGPSecretKeyRing.replacePublicKeys(secretRing, newPublic)
        return UpdatedRings(newPublic, newSecret)
    }

    /**
     * Card path: rebuild [publicRing]'s expiry, signing each new self-cert /
     * subkey binding on the card. The card's primary key is the signer.
     * [pin] is the raw PW1 bytes; runs inside an NFC operation.
     */
    /** The card's signature slot does not hold this key's primary. */
    val CARD_PRIMARY_MISSING_MESSAGE = "The primary key is not in this security key's signature slot, so the expiry cannot be changed with it"

    fun setExpirationCard(
        session: OpenPgpCardSession,
        publicRing: PGPPublicKeyRing,
        expiresAtEpochSeconds: Long?,
        pin: ByteArray,
        target: Target = Target.Primary()
    ): UpdatedRings {
        val primaryPublic = publicRing.publicKey
        // 4.7.0 RC4 (item 13 review): every signature here is the primary's,
        // so the card's signature slot has to hold the primary. A card whose
        // signature slot holds a subkey (subkeys moved, primary kept elsewhere)
        // would sign self-signatures that never verify.
        val sigSlot = runCatching { session.getApplicationRelatedData().sigFingerprint }.getOrNull()
        val primaryHex = org.bouncycastle.util.encoders.Hex.toHexString(primaryPublic.fingerprint)
        if (sigSlot == null || !sigSlot.equals(primaryHex, ignoreCase = true)) {
            throw com.pgpony.android.crypto.card.OpenPgpCardException.Malformed(CARD_PRIMARY_MISSING_MESSAGE)
        }
        val newPublic = try {
            rebuildExpiration(publicRing, expiresAtEpochSeconds, null, null, target) { type ->
                PonySigGen(CardPGPContentSignerBuilder(session, pin, primaryPublic), primaryPublic).apply {
                    init(type, PGPPrivateKey(primaryPublic.keyID, primaryPublic.publicKeyPacket, null))
                }
            }
        } catch (e: ExpirationError) {
            throw e
        } catch (e: PGPException) {
            val cause = e.cause
            if (cause is com.pgpony.android.crypto.card.OpenPgpCardException) throw cause
            throw ExpirationError.Failed(e.message ?: "Could not update expiration on card")
        }
        return UpdatedRings(newPublic, null)
    }

    // ── Core rebuild ────────────────────────────────────────────────────

    private fun rebuildExpiration(
        publicRing: PGPPublicKeyRing,
        expiresAtEpochSeconds: Long?,
        secretRing: PGPSecretKeyRing?,
        passphrase: String?,
        target: Target,
        makeGenerator: (Int) -> PonySigGen
    ): PGPPublicKeyRing {
        var primary = publicRing.publicKey

        // 1. The primary: rebuild each live user-ID self-certification. A
        //    revoked User ID is left as it is, so its revocation stands.
        val userIDs = mutableListOf<String>()
        if (target is Target.Primary || target is Target.Refresh) primary.userIDs.forEach { userIDs.add(it) }
        val primaryExpiry = if (target is Target.Primary) relativeExpirySeconds(expiresAtEpochSeconds, primary) else null
        for (uid in userIDs) {
            if (UserIdService.shared.isRevoked(primary, uid)) continue
            val existing = selfCertFor(primary, uid)
            // Refresh keeps each User ID's own expiry.
            val uidExpiry = if (target is Target.Refresh) existing?.hashedSubPackets?.keyExpirationTime?.takeIf { it > 0 } else primaryExpiry
            val gen = makeGenerator(PGPSignature.POSITIVE_CERTIFICATION)
            val sub = PGPSignatureSubpacketGenerator()
            copyUserIdSubpackets(existing?.hashedSubPackets, uidExpiry, sub)
            gen.setHashedSubpackets(sub.generate())
            val newCert = gen.generateCertification(uid, primary)
            if (existing != null) {
                primary = PGPPublicKey.removeCertification(primary, uid, existing)
            }
            primary = PGPPublicKey.addCertification(primary, uid, newCert)
        }

        var newRing = PGPPublicKeyRing.insertPublicKey(publicRing, primary)

        // 2. Subkey bindings: the one asked for, or with Primary(currentSubkeys)
        //    each subkey valid now. Expired and revoked subkeys are never touched.
        val nowMs = System.currentTimeMillis()
        val subkeyIds = mutableListOf<Long>()
        publicRing.publicKeys.forEach { sub ->
            if (sub.isMasterKey) return@forEach
            val wanted = when (target) {
                is Target.Subkey -> sub.keyID == target.keyId
                is Target.Primary -> target.currentSubkeys && isCurrent(sub, nowMs)
                // Expiry is kept, so an expired subkey stays expired.
                Target.Refresh -> !sub.hasRevocation() && subkeyBindingFor(sub) != null
            }
            if (wanted) subkeyIds.add(sub.keyID)
        }
        if (target is Target.Subkey && subkeyIds.isEmpty()) {
            throw ExpirationError.UnsupportedKey(SUBKEY_NOT_FOUND_MESSAGE)
        }
        for (id in subkeyIds) {
            var subkey = newRing.getPublicKey(id) ?: continue
            val oldBinding = subkeyBindingFor(subkey)
            val subExpiry = if (target is Target.Refresh)
                oldBinding?.hashedSubPackets?.keyExpirationTime?.takeIf { it > 0 }
            else relativeExpirySeconds(expiresAtEpochSeconds, subkey)
            val signCapable = oldBinding != null && hasSignFlag(oldBinding.hashedSubPackets)

            val newBinding = if (signCapable) {
                // issue #4 (SecTec): a signing subkey's binding needs an embedded
                // 0x19 primary-key back-signature made BY the subkey. Only the
                // software path holds the subkey's secret to make it; the card
                // path cannot, so it leaves the signing subkey untouched.
                if (secretRing == null) {
                    if (target is Target.Subkey) throw ExpirationError.UnsupportedKey(CARD_SIGNING_SUBKEY_MESSAGE)
                    continue
                }
                // A signing subkey whose secret is not here (a stub, or on a
                // card, item 55) cannot make its back-signature; Refresh and
                // "also current subkeys" pass over it instead of failing.
                if (target !is Target.Subkey) {
                    val subSecret = secretRing.getSecretKey(subkey.keyID)
                    if (subSecret == null || OfflineStub.isStub(subSecret)) continue
                }
                buildSigningSubkeyBinding(primary, subkey, oldBinding, subExpiry, secretRing, passphrase, makeGenerator)
            } else {
                val gen = makeGenerator(PGPSignature.SUBKEY_BINDING)
                val sub = PGPSignatureSubpacketGenerator()
                copySubkeySubpackets(oldBinding?.hashedSubPackets, subExpiry, sub)
                gen.setHashedSubpackets(sub.generate())
                gen.generateCertification(primary, subkey)
            }
            if (oldBinding != null) {
                subkey = PGPPublicKey.removeCertification(subkey, oldBinding)
            }
            subkey = PGPPublicKey.addCertification(subkey, newBinding)
            newRing = PGPPublicKeyRing.insertPublicKey(newRing, subkey)
        }

        return newRing
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    /** Seconds from a key's creation to the desired absolute expiry, or null
     *  for "never". Throws if the expiry would precede the key's creation. */
    private fun relativeExpirySeconds(expiresAtEpochSeconds: Long?, key: PGPPublicKey): Long? {
        if (expiresAtEpochSeconds == null) return null
        val creationSeconds = key.creationTime.time / 1000L
        val rel = expiresAtEpochSeconds - creationSeconds
        if (rel <= 0L) {
            throw ExpirationError.UnsupportedKey("Expiration date is before the key's creation date.")
        }
        return rel
    }

    /** Bound, not revoked and not expired at [nowMs]. */
    private fun isCurrent(sub: PGPPublicKey, nowMs: Long): Boolean {
        if (sub.hasRevocation()) return false
        if (subkeyBindingFor(sub) == null) return false
        val secs = sub.validSeconds
        return secs <= 0L || sub.creationTime.time + secs * 1000L > nowMs
    }

    /** The newest self-certification (0x10 to 0x13) on [userID]; a revocation
     *  is not one (4.7.0 item 53: it was picked and then removed). */
    private fun selfCertFor(primary: PGPPublicKey, userID: String): PGPSignature? {
        var latest: PGPSignature? = null
        primary.getSignaturesForID(userID).forEach { sig ->
            if (sig.keyID == primary.keyID &&
                sig.signatureType in PGPSignature.DEFAULT_CERTIFICATION..PGPSignature.POSITIVE_CERTIFICATION) {
                if (latest == null || sig.creationTime.after(latest!!.creationTime)) latest = sig
            }
        }
        return latest
    }

    private fun subkeyBindingFor(subkey: PGPPublicKey): PGPSignature? {
        var latest: PGPSignature? = null
        subkey.signatures.forEach { sig ->
            if (sig.signatureType == PGPSignature.SUBKEY_BINDING) {
                if (latest == null || sig.creationTime.after(latest!!.creationTime)) latest = sig
            }
        }
        return latest
    }

    private fun hasSignFlag(vector: PGPSignatureSubpacketVector?): Boolean {
        if (vector == null) return false
        return (vector.keyFlags and PGPKeyFlags.CAN_SIGN) != 0
    }

    /** Subpackets a new self-signature sets itself; everything else on the
     *  old one is carried forward as it was, critical bit included. */
    private val RESET_TAGS = setOf(
        SignatureSubpacketTags.CREATION_TIME,
        SignatureSubpacketTags.KEY_EXPIRE_TIME,
        SignatureSubpacketTags.ISSUER_KEY_ID,
        SignatureSubpacketTags.ISSUER_FINGERPRINT,
        SignatureSubpacketTags.EMBEDDED_SIGNATURE
    )

    /**
     * 4.7.0 (item 53): carry every hashed subpacket of the old self-signature
     * forward (preferences, features, key server preferences, notations, the
     * primary User ID flag), then set the new expiry. The old copy kept a short
     * list and dropped the rest, so an expiry change took a v6 key's SEIPDv2
     * feature and AEAD preferences off its User IDs and left a subkey binding
     * with key flags only.
     */
    private fun carryForward(
        old: PGPSignatureSubpacketVector?,
        expirySeconds: Long?,
        gen: PGPSignatureSubpacketGenerator
    ) {
        old?.toArray()?.forEach { packet ->
            if (packet.type !in RESET_TAGS) gen.addCustomSubpacket(packet)
        }
        if (expirySeconds != null) gen.setKeyExpirationTime(false, expirySeconds)
    }

    private fun copyUserIdSubpackets(
        old: PGPSignatureSubpacketVector?,
        expirySeconds: Long?,
        gen: PGPSignatureSubpacketGenerator
    ) = carryForward(old, expirySeconds, gen)

    private fun copySubkeySubpackets(
        old: PGPSignatureSubpacketVector?,
        expirySeconds: Long?,
        gen: PGPSignatureSubpacketGenerator
    ) = carryForward(old, expirySeconds, gen)

    /**
     * issue #4: rebuild a signing subkey's binding signature carrying the new
     * expiry, with the required embedded 0x19 primary-key back-signature made
     * BY the subkey (RFC 9580 5.2.3.34). Binding is signed by the primary via
     * [makeBindingGenerator]; the back-signature is signed by the subkey's own
     * secret from [secretRing].
     */
    private fun buildSigningSubkeyBinding(
        primary: PGPPublicKey,
        subkey: PGPPublicKey,
        oldBinding: PGPSignature?,
        expirySeconds: Long?,
        secretRing: PGPSecretKeyRing,
        passphrase: String?,
        makeBindingGenerator: (Int) -> PonySigGen
    ): PGPSignature {
        val subSecret = secretRing.getSecretKey(subkey.keyID)
            ?: throw ExpirationError.UnsupportedKey("Missing secret material for the signing subkey")
        val subPrivate = extractPrivate(subSecret, passphrase)
        val backGen = PonySigGen(
            BcPGPContentSignerBuilder(subkey.algorithm, HashAlgorithmTags.SHA256), subkey
        )
        backGen.init(PGPSignature.PRIMARYKEY_BINDING, subPrivate)
        val backSig = backGen.generateCertification(primary, subkey)

        val bindGen = makeBindingGenerator(PGPSignature.SUBKEY_BINDING)
        val hashed = PGPSignatureSubpacketGenerator()
        copySubkeySubpackets(oldBinding?.hashedSubPackets, expirySeconds, hashed)
        hashed.setEmbeddedSignature(false, backSig)
        bindGen.setHashedSubpackets(hashed.generate())
        return bindGen.generateCertification(primary, subkey)
    }

    private fun extractPrivate(
        primarySecret: org.bouncycastle.openpgp.PGPSecretKey,
        passphrase: String?
    ): PGPPrivateKey {
        // 4.7.0 (item 22): an offline primary has no secret to sign with.
        OfflineStub.requireSecret(primarySecret)
        // An Argon2 S2K outside the policy is refused before any KDF runs.
        enforceArgon2Policy(primarySecret.s2K)
        return try {
            val decryptor = com.pgpony.android.crypto.SecretKeyUnlock.decryptor(passphrase)
            primarySecret.extractPrivateKey(decryptor)
        } catch (e: PGPException) {
            if (passphrase.isNullOrEmpty()) throw ExpirationError.PassphraseRequired()
            throw ExpirationError.InvalidPassphrase()
        }
    }
}
