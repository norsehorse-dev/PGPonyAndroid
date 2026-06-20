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
//   • Sign-capable SUBKEYS are skipped: their bindings require an embedded
//     primary-key back-signature (0x19) made BY the subkey, which the card
//     can't produce and which is out of scope here. PGPony-generated keys
//     have no signing subkey, so this path is not normally hit.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.card.CardPGPContentSignerBuilder
import com.pgpony.android.crypto.card.OpenPgpCardSession
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.sig.Features
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyFlags
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
        passphrase: String?
    ): UpdatedRings {
        val primarySecret = secretRing.secretKey
        val privateKey = extractPrivate(primarySecret, passphrase)
        val signerBuilder = BcPGPContentSignerBuilder(
            primarySecret.publicKey.algorithm,
            HashAlgorithmTags.SHA256
        )
        val newPublic = try {
            rebuildExpiration(publicRing, expiresAtEpochSeconds) { type ->
                PGPSignatureGenerator(signerBuilder, primarySecret.publicKey).apply { init(type, privateKey) }
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
    fun setExpirationCard(
        session: OpenPgpCardSession,
        publicRing: PGPPublicKeyRing,
        expiresAtEpochSeconds: Long?,
        pin: ByteArray
    ): UpdatedRings {
        val primaryPublic = publicRing.publicKey
        val newPublic = try {
            rebuildExpiration(publicRing, expiresAtEpochSeconds) { type ->
                PGPSignatureGenerator(CardPGPContentSignerBuilder(session, pin, primaryPublic), primaryPublic).apply {
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
        makeGenerator: (Int) -> PGPSignatureGenerator
    ): PGPPublicKeyRing {
        var primary = publicRing.publicKey
        val primaryExpiry = relativeExpirySeconds(expiresAtEpochSeconds, primary)

        // 1. Rebuild every user-ID self-certification on the primary.
        val userIDs = mutableListOf<String>()
        primary.userIDs.forEach { userIDs.add(it) }
        for (uid in userIDs) {
            val existing = selfCertFor(primary, uid)
            val gen = makeGenerator(PGPSignature.POSITIVE_CERTIFICATION)
            val sub = PGPSignatureSubpacketGenerator()
            copyUserIdSubpackets(existing?.hashedSubPackets, primaryExpiry, sub)
            gen.setHashedSubpackets(sub.generate())
            val newCert = gen.generateCertification(uid, primary)
            if (existing != null) {
                primary = PGPPublicKey.removeCertification(primary, uid, existing)
            }
            primary = PGPPublicKey.addCertification(primary, uid, newCert)
        }

        var newRing = PGPPublicKeyRing.insertPublicKey(publicRing, primary)

        // 2. Rebuild each (non-signing) subkey binding signature.
        val subkeyIds = mutableListOf<Long>()
        publicRing.publicKeys.forEach { if (!it.isMasterKey) subkeyIds.add(it.keyID) }
        for (id in subkeyIds) {
            var subkey = newRing.getPublicKey(id) ?: continue
            val oldBinding = subkeyBindingFor(subkey)
            // Skip sign-capable subkeys (would need a 0x19 back-signature).
            if (oldBinding != null && hasSignFlag(oldBinding.hashedSubPackets)) continue

            val subExpiry = relativeExpirySeconds(expiresAtEpochSeconds, subkey)
            val gen = makeGenerator(PGPSignature.SUBKEY_BINDING)
            val sub = PGPSignatureSubpacketGenerator()
            copySubkeySubpackets(oldBinding?.hashedSubPackets, subExpiry, sub)
            gen.setHashedSubpackets(sub.generate())
            val newBinding = gen.generateCertification(primary, subkey)
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

    private fun selfCertFor(primary: PGPPublicKey, userID: String): PGPSignature? {
        var latest: PGPSignature? = null
        primary.getSignaturesForID(userID).forEach { sig ->
            if (sig.keyID == primary.keyID) {
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

    private fun copyUserIdSubpackets(
        old: PGPSignatureSubpacketVector?,
        expirySeconds: Long?,
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
            if (old.isPrimaryUserID) gen.setPrimaryUserID(false, true)
            old.features?.let { f ->
                if (f.supportsModificationDetection()) {
                    gen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION)
                }
            }
        }
        if (expirySeconds != null) gen.setKeyExpirationTime(false, expirySeconds)
    }

    private fun copySubkeySubpackets(
        old: PGPSignatureSubpacketVector?,
        expirySeconds: Long?,
        gen: PGPSignatureSubpacketGenerator
    ) {
        if (old != null && old.keyFlags != 0) gen.setKeyFlags(false, old.keyFlags)
        if (expirySeconds != null) gen.setKeyExpirationTime(false, expirySeconds)
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
            if (passphrase.isNullOrEmpty()) throw ExpirationError.PassphraseRequired()
            throw ExpirationError.InvalidPassphrase()
        }
    }
}
