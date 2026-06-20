// VerifyService.kt
// PGPony Android
//
// Phase A3: signature verification service. Three jobs:
//   1. Detect what flavor of PGP-armored content was pasted (so the UI
//      can route encrypted-vs-clear-signed-vs-detached-sig-alone).
//   2. Verify clear-signed messages — extract cleartext, verify against
//      the signature, return a typed result the UI can render directly.
//   3. Verify detached signatures against supplied signed bytes (for the
//      future file-verify flow; not surfaced in UI until Phase A10).
//
// Verification of encrypted-AND-signed messages is handled by the
// existing PGPCryptoService.decryptArmored — it parses one-pass-signature
// packets inline while decrypting. VerifyService only handles cases
// where the input is NOT encrypted. The DecryptScreen ViewModel decides
// which path to call based on detectInputType.
//
// "Unknown signer" handling — the headline new capability:
// when the signature carries an issuer-fingerprint subpacket (RFC 4880bis
// type 33, always present on PGPony-emitted v4 signatures and required
// on v6) we can identify the claimed signer fingerprint even when their
// key isn't in the local keyring. VerificationResult.UnknownSigner
// returns that fingerprint so the UI can offer to fetch the key from
// WKD/keyserver via SignerLookupSheet, then re-verify after import.
//
// Added in Phase A3.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import java.io.ByteArrayInputStream

// ── Input type ─────────────────────────────────────────────────────────

/** What flavor of PGP content was pasted into the Decrypt input field. */
enum class SignedInputType {
    /** -----BEGIN PGP MESSAGE----- — encrypted (may also be signed). */
    ENCRYPTED,
    /** -----BEGIN PGP SIGNED MESSAGE----- — RFC 4880 §7 clear-signed text. */
    CLEAR_SIGNED,
    /** -----BEGIN PGP SIGNATURE----- with no signed content alongside it. */
    DETACHED_SIGNATURE,
    /** No recognizable PGP framing found. */
    UNKNOWN
}

// ── Verification result ────────────────────────────────────────────────

/**
 * Outcome of a verification attempt. The UI renders a 4-state banner
 * mapping 1:1 to these cases:
 *
 *   Verified      → green  "Signed by Alice <alice@example.com>"
 *   Invalid       → red    "Signature did not match the content"
 *   UnknownSigner → yellow "Signature from unknown key, tap to look up"
 *   Unsigned      → gray   "Decrypted, but no signature attached"
 */
sealed class VerificationResult {

    /** Signature present, signer in keyring, signature verifies. */
    data class Verified(
        /** 16 hex chars — RFC 4880 long key ID from the signature packet. */
        val signerKeyID: String,
        /** Full fingerprint of the signer's primary key, hex uppercase. */
        val signerFingerprint: String,
        /** Best-effort display name parsed from the signer's user ID. */
        val signerName: String?,
        /** Best-effort email parsed from the signer's user ID. */
        val signerEmail: String?,
        /** For clear-signed input: the verified plaintext (dash-unescaped). */
        val signedContent: String?
    ) : VerificationResult()

    /** Signature present, signer in keyring, but verification failed. */
    data class Invalid(
        val reason: String,
        val signerKeyID: String?,
        /** For clear-signed: the content we attempted to verify, so the UI
         *  can still show it alongside the failure banner. */
        val signedContent: String?
    ) : VerificationResult()

    /** Signature present and structurally valid, but signer's key is not
     *  in the local keyring. The UI uses [claimedFingerprint] to look up
     *  the signer via WKD/keyserver and re-verify after import. */
    data class UnknownSigner(
        val signerKeyID: String,
        /** From the issuer-fingerprint subpacket (RFC 4880bis type 33).
         *  Null only for very old signatures without this subpacket; the
         *  UI should fall back to [signerKeyID] for keyserver search but
         *  warn the user that the lookup is less precise. */
        val claimedFingerprint: String?,
        val signedContent: String?
    ) : VerificationResult()

    /** Decrypted (or read) content has no signature attached. Renders as
     *  a subtle gray badge — not an error, just informational. */
    data class Unsigned(
        val content: String
    ) : VerificationResult()
}

// ── Service ────────────────────────────────────────────────────────────

class VerifyService private constructor() {

    companion object {
        val shared = VerifyService()

        private const val BEGIN_MESSAGE = "-----BEGIN PGP MESSAGE-----"
        private const val BEGIN_SIGNED = "-----BEGIN PGP SIGNED MESSAGE-----"
        private const val BEGIN_SIGNATURE = "-----BEGIN PGP SIGNATURE-----"
    }

    // ── Input classification ──────────────────────────────────────────

    /**
     * Inspect [text] for PGP armor markers and return the most specific
     * type it matches. Order matters: clear-signed messages contain BOTH
     * a SIGNED MESSAGE marker AND a SIGNATURE marker, so we check for
     * the SIGNED MESSAGE form first to avoid mis-classifying as detached.
     */
    fun detectInputType(text: String): SignedInputType {
        val t = text.trim()
        return when {
            t.isEmpty()                  -> SignedInputType.UNKNOWN
            t.contains(BEGIN_SIGNED)     -> SignedInputType.CLEAR_SIGNED
            t.contains(BEGIN_MESSAGE)    -> SignedInputType.ENCRYPTED
            t.contains(BEGIN_SIGNATURE)  -> SignedInputType.DETACHED_SIGNATURE
            else                         -> SignedInputType.UNKNOWN
        }
    }

    // ── Clear-signed verification ─────────────────────────────────────

    /**
     * Verify an RFC 4880 §7 clear-signed message against the supplied
     * public key rings. Returns one of:
     *   • Verified — signer in keyring, hash matches
     *   • Invalid — parsing succeeded, signer in keyring, but verify failed
     *   • UnknownSigner — parsing succeeded, signer not in keyring
     *   • Invalid (with parsing reason) — input malformed
     *
     * The "find signer key" lookup is by long key ID from the signature
     * packet. The "claimed fingerprint" carried in the issuer-fingerprint
     * subpacket is preserved on UnknownSigner so the UI can use the more
     * precise identifier when fetching from a keyserver.
     */
    fun verifyClearSigned(
        armored: String,
        publicKeyRings: List<PGPPublicKeyRing>
    ): VerificationResult {
        val components = ClearSignedParser.parse(armored)
            ?: return VerificationResult.Invalid(
                reason = "Could not parse the clear-signed message frame",
                signerKeyID = null,
                signedContent = null
            )

        val sig = try {
            parseFirstSignature(components.signatureBlock)
        } catch (e: Exception) {
            return VerificationResult.Invalid(
                reason = "Could not parse signature block: ${e.message}",
                signerKeyID = null,
                signedContent = components.cleartext
            )
        }

        val keyIdHex = String.format("%016X", sig.keyID)
        val claimedFingerprint = extractClaimedFingerprint(sig)

        val signerKey = findSignerKey(sig.keyID, publicKeyRings)
        if (signerKey == null) {
            return VerificationResult.UnknownSigner(
                signerKeyID = keyIdHex,
                claimedFingerprint = claimedFingerprint,
                signedContent = components.cleartext
            )
        }

        val verified = try {
            sig.init(BcPGPContentVerifierBuilderProvider(), signerKey)
            // RFC 9580 §7.1 excludes exactly ONE line terminator — the one
            // immediately before the signature. ClearSignedParser already
            // strips it from components.cleartext, and canonicalizeForClearSign
            // ALSO drops one trailing empty line; feeding the parsed cleartext
            // straight in therefore double-strips and silently deletes a
            // genuine trailing blank line from the hash, so any message ending
            // in a blank line fails to verify (e.g. RFC 9580 A.6, and PGPony's
            // own such messages). Re-add the single terminator the parser
            // removed so the canonicalizer excludes exactly one.
            val canonical = SigningService.shared.canonicalizeForClearSign(components.cleartext + "\n")
            sig.update(canonical, 0, canonical.size)
            sig.verify()
        } catch (e: Exception) {
            return VerificationResult.Invalid(
                reason = "Verification error: ${e.message}",
                signerKeyID = keyIdHex,
                signedContent = components.cleartext
            )
        }

        if (!verified) {
            return VerificationResult.Invalid(
                reason = "Signature does not match the signed content",
                signerKeyID = keyIdHex,
                signedContent = components.cleartext
            )
        }

        // Resolve identity: walk the rings, find one containing this
        // signing key, pull its primary key's user ID for display.
        val (signerName, signerEmail, signerFingerprint) =
            resolveSignerIdentity(sig.keyID, publicKeyRings)

        return VerificationResult.Verified(
            signerKeyID = keyIdHex,
            signerFingerprint = signerFingerprint,
            signerName = signerName,
            signerEmail = signerEmail,
            signedContent = components.cleartext
        )
    }

    // ── Detached verification (no UI surface yet) ─────────────────────

    /**
     * Verify a detached signature against the supplied signed bytes.
     * Not currently wired to UI — Phase A10's file-verify flow will use
     * this — but the API is here so the contract is stable and the
     * unit-test coverage applies.
     */
    fun verifyDetached(
        signatureArmored: String,
        signedBytes: ByteArray,
        publicKeyRings: List<PGPPublicKeyRing>
    ): VerificationResult {
        val sig = try {
            parseFirstSignature(signatureArmored)
        } catch (e: Exception) {
            return VerificationResult.Invalid(
                reason = "Could not parse signature: ${e.message}",
                signerKeyID = null,
                signedContent = null
            )
        }
        return verifyParsedSignature(sig, signedBytes, publicKeyRings)
    }

    /**
     * Phase A3 (DIVERGES) — binary `.sig` overload. A detached signature
     * downloaded alongside a release artifact is usually a raw binary
     * signature packet (`.sig`), not ASCII-armored (`.asc`). This overload
     * sniffs the bytes and parses either form via [parseFirstSignatureBytes],
     * then runs the identical verify core. The armored-String overload above
     * stays for the pasted/clear-signed text path.
     */
    fun verifyDetached(
        signatureBytes: ByteArray,
        signedBytes: ByteArray,
        publicKeyRings: List<PGPPublicKeyRing>
    ): VerificationResult {
        val sig = try {
            parseFirstSignatureBytes(signatureBytes)
        } catch (e: Exception) {
            return VerificationResult.Invalid(
                reason = "Could not parse signature: ${e.message}",
                signerKeyID = null,
                signedContent = null
            )
        }
        return verifyParsedSignature(sig, signedBytes, publicKeyRings)
    }

    /**
     * Shared verify core for both detached overloads: resolve the signer in
     * the supplied rings, run the cryptographic check over [signedBytes], and
     * map to PASS / FAIL / UNKNOWN-SIGNER.
     */
    private fun verifyParsedSignature(
        sig: PGPSignature,
        signedBytes: ByteArray,
        publicKeyRings: List<PGPPublicKeyRing>
    ): VerificationResult {
        val keyIdHex = String.format("%016X", sig.keyID)
        val claimedFingerprint = extractClaimedFingerprint(sig)

        val signerKey = findSignerKey(sig.keyID, publicKeyRings)
            ?: return VerificationResult.UnknownSigner(
                signerKeyID = keyIdHex,
                claimedFingerprint = claimedFingerprint,
                signedContent = null
            )

        val verified = try {
            sig.init(BcPGPContentVerifierBuilderProvider(), signerKey)
            sig.update(signedBytes)
            sig.verify()
        } catch (e: Exception) {
            return VerificationResult.Invalid(
                reason = "Verification error: ${e.message}",
                signerKeyID = keyIdHex,
                signedContent = null
            )
        }

        if (!verified) {
            return VerificationResult.Invalid(
                reason = "Signature does not match the supplied content",
                signerKeyID = keyIdHex,
                signedContent = null
            )
        }

        val (signerName, signerEmail, signerFingerprint) =
            resolveSignerIdentity(sig.keyID, publicKeyRings)

        return VerificationResult.Verified(
            signerKeyID = keyIdHex,
            signerFingerprint = signerFingerprint,
            signerName = signerName,
            signerEmail = signerEmail,
            signedContent = null
        )
    }

    // ── Helpers ───────────────────────────────────────────────────────

    /**
     * Parse the first PGPSignature from an armored signature block.
     * Throws on parse failure (caller catches and converts to Invalid).
     */
    private fun parseFirstSignature(armoredSignatureBlock: String): PGPSignature {
        val ais = ArmoredInputStream(
            ByteArrayInputStream(armoredSignatureBlock.toByteArray(Charsets.UTF_8))
        )
        val fact = JcaPGPObjectFactory(ais)
        val obj = fact.nextObject()
            ?: error("Signature block parsed to null — armor markers present but no PGP object inside")
        val sigList = obj as? PGPSignatureList
            ?: error("Expected PGPSignatureList, got ${obj.javaClass.simpleName}")
        if (sigList.isEmpty) error("Signature list is empty")
        return sigList.get(0)
    }

    /**
     * Phase A3 — parse the first PGPSignature from raw `.sig` bytes, handling
     * BOTH ASCII-armored (`.asc`) and binary signature packets. Sniffs for the
     * armor header; if absent, reads the bytes as a raw packet stream.
     */
    private fun parseFirstSignatureBytes(bytes: ByteArray): PGPSignature {
        val armored = run {
            val head = String(bytes.copyOf(minOf(bytes.size, 64)), Charsets.US_ASCII)
            head.contains("-----BEGIN PGP")
        }
        val input = if (armored) {
            ArmoredInputStream(ByteArrayInputStream(bytes))
        } else {
            ByteArrayInputStream(bytes)
        }
        val fact = JcaPGPObjectFactory(input)
        val obj = fact.nextObject()
            ?: error("Signature parsed to null — no PGP object found in the .sig bytes")
        val sigList = obj as? PGPSignatureList
            ?: error("Expected PGPSignatureList, got ${obj.javaClass.simpleName}")
        if (sigList.isEmpty) error("Signature list is empty")
        return sigList.get(0)
    }

    /**
     * Search the supplied rings for a public key matching [keyId]. Walks
     * every ring's full key list (primary + subkeys) because the signer
     * may have signed with a subkey while the user only knows the primary
     * fingerprint in their keyring listing.
     */
    private fun findSignerKey(
        keyId: Long,
        rings: List<PGPPublicKeyRing>
    ): PGPPublicKey? {
        for (ring in rings) {
            val match = ring.getPublicKey(keyId)
            if (match != null) return match
        }
        return null
    }

    /**
     * Pull the claimed fingerprint from a signature's issuer-fingerprint
     * subpacket if present (RFC 4880bis type 33, always emitted by
     * SigningService since Phase A2). Returns the fingerprint as
     * uppercase hex without separators, or null if the subpacket is
     * absent (would only happen for older signatures from non-PGPony
     * producers).
     */
    private fun extractClaimedFingerprint(sig: PGPSignature): String? {
        val hashed = sig.hashedSubPackets ?: return null
        val issuerFp = hashed.issuerFingerprint ?: return null
        return bytesToHex(issuerFp.fingerprint)
    }

    /**
     * Resolve a key ID to a display name, email, and primary-key
     * fingerprint by walking the supplied rings. Returns nulls/empty if
     * the key isn't found (shouldn't happen since we already checked,
     * but defensive).
     */
    private fun resolveSignerIdentity(
        keyId: Long,
        rings: List<PGPPublicKeyRing>
    ): Triple<String?, String?, String> {
        for (ring in rings) {
            if (ring.getPublicKey(keyId) == null) continue
            val primary = ring.publicKey
            val userId = primary.userIDs.asSequence().firstOrNull()
            val (name, email) = parseUserId(userId)
            val fp = bytesToHex(primary.fingerprint)
            return Triple(name, email, fp)
        }
        return Triple(null, null, "")
    }

    /**
     * Parse "Name <email@example.com>" into (name, email). Returns
     * (userId, null) if there's no angle-bracketed email, (null, email)
     * if the userId is just an email, or (null, null) for null input.
     */
    private fun parseUserId(userId: String?): Pair<String?, String?> {
        if (userId.isNullOrBlank()) return null to null
        val match = Regex("(.*?)\\s*<(.+)>").matchEntire(userId.trim())
        if (match != null) {
            val name = match.groupValues[1].trim().ifEmpty { null }
            val email = match.groupValues[2].trim().ifEmpty { null }
            return name to email
        }
        // No angle brackets — treat as either a bare email or a bare name.
        return if (userId.contains("@")) null to userId.trim() else userId.trim() to null
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02X".format(it) }
}
