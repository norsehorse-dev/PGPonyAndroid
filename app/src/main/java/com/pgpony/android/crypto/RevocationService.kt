// RevocationService.kt
// PGPony Android — Phase A6
//
// Generates and applies OpenPGP key revocation certificates. Two
// related operations, both implemented on top of Bouncy Castle's
// PGPSignatureGenerator with signature type KEY_REVOCATION (0x20):
//
//   1. generateRevocationCertificate(secRing, reason, comment, passphrase)
//      → produces an ASCII-armored RFC 4880 signature packet (a
//      "revocation certificate" — same wire shape as any signature,
//      but with type=0x20). Designed to be either pre-cached at key
//      creation time OR generated fresh when the user revokes through
//      KeyDetailScreen. The output is an armored block standard
//      OpenPGP tools (GnuPG, etc.) will accept via `gpg --import`.
//
//   2. applyRevocation(pubRing, armoredCert) → updates the public key
//      ring by attaching the revocation signature to the primary key.
//      The resulting ring serializes to armored form that any
//      OpenPGP-aware verifier will treat as revoked. Used by the
//      KeyDetailScreen revoke flow to update PGPKeyEntity's cached
//      armoredPublicKey after revocation.
//
// Why we have this separate from SigningService:
// - Signing service emits BINARY_DOCUMENT and CANONICAL_TEXT_DOCUMENT
//   sigs over user content. Revocation signs over the primary key's
//   public-key packet body. Different inputs, different code paths
//   for hash input setup. Keeping them separate avoids growing
//   SigningService into a one-stop "all OpenPGP signatures" class.
// - Revocation needs to write the issuer-fingerprint subpacket AND
//   the reason-for-revocation subpacket; signing only the former.
// - iOS has its own SigningService.generateKeyRevocation method but
//   on Android the BC abstractions are different enough (BC handles
//   subpacket assembly itself instead of iOS's hand-rolled byte
//   slinging) that keeping the revocation logic close to the
//   subpacket-generator setup reads cleaner.

package com.pgpony.android.crypto

import com.pgpony.android.data.RevocationReason
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.sig.RevocationReasonTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

// ── Phase A7 Fix: ASCII armor configuration ────────────────────────────

/**
 * Strip the default Version header from BC's armored output and
 * replace it with a Comment header. See the matching extension in
 * PGPCryptoService.kt for the full rationale — tl;dr bcpg-jdk18on:
 * 1.78.1 emits "Version: BCPG v@RELEASE_NAME@" with an unsubstituted
 * placeholder, AND BC's ArmoredOutputStream drops the RFC-required
 * blank-line separator when the header map is empty. Adding a
 * benign Comment kills both birds.
 *
 * Duplicated rather than imported because both files are in the
 * `com.pgpony.android.crypto` package and the helper is small;
 * cross-file references for a 4-line method would be more friction
 * than the duplication.
 *
 * Caller can override the Comment by calling setHeader("Comment", ...)
 * AFTER stripVersion — this is what generateRevocationCertificate
 * does to write "Comment: Revocation certificate" instead.
 */
private fun ArmoredOutputStream.stripVersion(): ArmoredOutputStream = apply {
    setHeader("Version", null)
    setHeader("Comment", "PGPony Android")
}

// ── Errors ─────────────────────────────────────────────────────────────

sealed class RevocationError(message: String) : Exception(message) {
    /** Signing key is encrypted with a passphrase; caller didn't supply one. */
    class PassphraseRequired : RevocationError("Signing key requires a passphrase")
    /** Caller supplied a passphrase but BC couldn't decrypt the secret key with it. */
    class InvalidPassphrase : RevocationError("Incorrect passphrase for signing key")
    /** The key ring has no primary secret key, or the algorithm is unsupported. */
    class UnsupportedKey(reason: String) : RevocationError(reason)
    /** Generic BC failure during signature generation or application. */
    class GenerationFailed(reason: String) : RevocationError(reason)
}

// ── Service ────────────────────────────────────────────────────────────

class RevocationService private constructor() {

    companion object {
        val shared = RevocationService()

        /** Map our enum to BC's RFC-4880 numeric code. BC's
         *  RevocationReasonTags constants happen to match RFC §5.2.3.23 so
         *  this is a direct conversion. */
        private fun reasonToTag(reason: RevocationReason): Byte = when (reason) {
            RevocationReason.NO_REASON       -> RevocationReasonTags.NO_REASON
            RevocationReason.SUPERSEDED      -> RevocationReasonTags.KEY_SUPERSEDED
            RevocationReason.COMPROMISED     -> RevocationReasonTags.KEY_COMPROMISED
            RevocationReason.RETIRED         -> RevocationReasonTags.KEY_RETIRED
            RevocationReason.USER_ID_INVALID -> RevocationReasonTags.USER_NO_LONGER_VALID
        }
    }

    /**
     * Generate an armored revocation certificate for the supplied
     * secret key ring. The cert is a single ASCII-armored signature
     * packet (BEGIN/END PGP PUBLIC KEY BLOCK headers replaced with
     * BEGIN/END PGP SIGNATURE in some tooling; BC's armored output
     * uses BEGIN PGP PUBLIC KEY BLOCK for compatibility with `gpg
     * --import-options merge-only --import`).
     *
     * @param passphrase null or empty for unprotected keys; otherwise
     *                   the secret key's S2K passphrase.
     */
    fun generateRevocationCertificate(
        secretKeyRing: PGPSecretKeyRing,
        reason: RevocationReason,
        comment: String?,
        passphrase: String?
    ): String {
        val secretKey = secretKeyRing.secretKey
            ?: throw RevocationError.UnsupportedKey(
                "No primary secret key in supplied ring"
            )

        // 1. Unlock the private key.
        val privateKey = try {
            val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
                .build((passphrase ?: "").toCharArray())
            secretKey.extractPrivateKey(decryptor)
        } catch (e: PGPException) {
            // Same s2KUsage disambiguation pattern SigningService uses
            // (0 = unencrypted, so any failure here is structural).
            if (secretKey.s2KUsage.toInt() != 0) {
                if (passphrase.isNullOrEmpty()) throw RevocationError.PassphraseRequired()
                throw RevocationError.InvalidPassphrase()
            }
            throw RevocationError.GenerationFailed(
                e.message ?: "Failed to unlock signing key"
            )
        }

        // 2. Build the signature generator. The signing algorithm is
        //    whatever the primary key uses; SHA-256 hash is RFC 4880
        //    recommended and works for both Ed25519 and RSA.
        val sigGen = try {
            PGPSignatureGenerator(
                BcPGPContentSignerBuilder(
                    secretKey.publicKey.algorithm,
                    HashAlgorithmTags.SHA256
                ),
                secretKey.publicKey
            )
        } catch (e: Exception) {
            throw RevocationError.GenerationFailed(
                "Could not construct signer for algorithm ${secretKey.publicKey.algorithm}: ${e.message}"
            )
        }

        try {
            sigGen.init(PGPSignature.KEY_REVOCATION, privateKey)
        } catch (e: Exception) {
            throw RevocationError.GenerationFailed(
                "Could not initialize signature generator: ${e.message}"
            )
        }

        // 3. Hashed subpackets:
        //    • Issuer fingerprint (matches our SigningService output —
        //      gives verifiers the precise signer ID even when only the
        //      64-bit key ID is otherwise available).
        //    • Revocation reason (RFC §5.2.3.23 — the whole point of
        //      this packet).
        val subpacketGen = PGPSignatureSubpacketGenerator()
        subpacketGen.setIssuerFingerprint(false, secretKey.publicKey)
        subpacketGen.setRevocationReason(
            /* isCritical = */ false,
            /* reason     = */ reasonToTag(reason),
            /* description= */ comment.orEmpty()
        )
        sigGen.setHashedSubpackets(subpacketGen.generate())

        // 4. Generate the signature OVER the primary public key. BC's
        //    generateCertification(publicKey) overload knows to emit a
        //    direct-on-primary-key signature, which is what
        //    KEY_REVOCATION requires per RFC 4880 §5.2.1.
        val sig: PGPSignature = try {
            sigGen.generateCertification(secretKey.publicKey)
        } catch (e: Exception) {
            throw RevocationError.GenerationFailed(
                "Signature generation failed: ${e.message}"
            )
        }

        // 5. Armor + return. We use the standard PUBLIC KEY BLOCK
        //    header even though the contents are just a signature
        //    packet — GnuPG's `--import` will pick up the revocation
        //    correctly either way, and using PUBLIC KEY BLOCK lets us
        //    optionally bundle the primary key + revocation in a
        //    future export-with-revocation flow.
        val bytes = ByteArrayOutputStream()
        ArmoredOutputStream(bytes).stripVersion().use { armored ->
            armored.setHeader("Comment", "Revocation certificate")
            sig.encode(armored)
        }
        return bytes.toString(Charsets.UTF_8.name())
    }

    /**
     * Apply a previously-generated armored revocation certificate to a
     * public key ring. The resulting ring carries the revocation as a
     * self-signature on the primary key, exactly how `gpg --import` of
     * a revocation cert would update a stored public key.
     *
     * The caller is responsible for storing the updated armored output
     * (typically by writing to PGPKeyEntity.armoredPublicKey and
     * persisting via the secure key store's update path).
     */
    fun applyRevocation(
        publicKeyRing: PGPPublicKeyRing,
        armoredCertificate: String
    ): PGPPublicKeyRing {
        val sig = try {
            parseFirstSignature(armoredCertificate)
        } catch (e: Exception) {
            throw RevocationError.GenerationFailed(
                "Could not parse revocation certificate: ${e.message}"
            )
        }

        if (sig.signatureType != PGPSignature.KEY_REVOCATION) {
            throw RevocationError.GenerationFailed(
                "Supplied certificate is not a key-revocation signature " +
                        "(type=${sig.signatureType}); expected ${PGPSignature.KEY_REVOCATION}"
            )
        }

        val primary = publicKeyRing.publicKey
        val updatedPrimary: PGPPublicKey = try {
            PGPPublicKey.addCertification(primary, sig)
        } catch (e: Exception) {
            throw RevocationError.GenerationFailed(
                "Could not attach revocation to primary key: ${e.message}"
            )
        }

        return PGPPublicKeyRing.insertPublicKey(publicKeyRing, updatedPrimary)
    }

    /**
     * Re-armor a (possibly modified) public key ring. Convenience for
     * the repo layer — after applyRevocation produces an updated ring
     * we need to serialize it back to text for storage.
     */
    fun armorPublicKeyRing(ring: PGPPublicKeyRing): String {
        val bytes = ByteArrayOutputStream()
        ArmoredOutputStream(bytes).stripVersion().use { armored -> ring.encode(armored) }
        return bytes.toString(Charsets.UTF_8.name())
    }

    /** Parse the first PGPSignature packet from an armored cert. */
    private fun parseFirstSignature(armored: String): PGPSignature {
        val ais = ArmoredInputStream(
            ByteArrayInputStream(armored.toByteArray(Charsets.UTF_8))
        )
        val fact = JcaPGPObjectFactory(ais)
        val obj = fact.nextObject()
            ?: error("Armored block contained no PGP object")
        val sigList = obj as? PGPSignatureList
            ?: error("Expected PGPSignatureList, got ${obj.javaClass.simpleName}")
        if (sigList.isEmpty) error("Signature list is empty")
        return sigList.get(0)
    }
}
