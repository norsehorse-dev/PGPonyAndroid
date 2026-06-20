// SigningService.kt
// PGPony Android
//
// Native v4 signing via Bouncy Castle's PGPSignatureGenerator, producing:
//   • Clear-signed text (RFC 4880 §7) — "-----BEGIN PGP SIGNED MESSAGE-----"
//   • Detached signatures (RFC 4880 §5.2.3) — armored or binary
//
// Why this is a separate service vs. extending PGPCryptoService:
// signing has its own error surface (passphrase + no-signing-key), its own
// hash-algorithm parameter, and a different output framing (clear-sign
// dash-escaping + Hash header). Phases A3 (verify UI), A5 (sign-as picker),
// A6 (revocation signatures), and A7 (private key export) all attach to
// this service rather than further bloating PGPCryptoService.
//
// Algorithm coverage (mirrors iOS Phase 2a):
//   • RSA v4         — BC's PGPSignatureGenerator handles directly
//   • Ed25519 v4     — BC's PGPSignatureGenerator handles directly (algo 22)
//   • RSA v6 / Ed25519 v6 — out of scope (would need bcpg v6 support; Android
//                          drops v6 generation per project plan, import-only)
//
// Subkey-vs-primary selection: A2 uses `secretKeyRing.secretKey` (the primary)
// for every signature. This is correct for every key shape PGPony generates
// (RSA primary = C+S+E, Ed25519 primary = C+S). Phase A5 adds a proper
// SubkeyCapability-based picker for imported keys whose primary may be
// certify-only with a separate sign-capable subkey.
//
// Added in Phase A2.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ArmoredOutputStream
import com.pgpony.android.data.ArmorCommentHeader
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import java.io.ByteArrayOutputStream
import java.io.OutputStream

// ── Errors ─────────────────────────────────────────────────────────────

sealed class SigningError(message: String) : Exception(message) {
    /** Signing key is encrypted with a passphrase; caller didn't supply one. */
    class PassphraseRequired : SigningError("Passphrase required to unlock signing key")
    /** Caller supplied a passphrase but BC couldn't decrypt the secret key with it. */
    class InvalidPassphrase : SigningError("Incorrect passphrase for signing key")
    /** Key ring has no signing-capable secret key. Shouldn't happen for PGPony-generated keys. */
    class NoSigningKey : SigningError("No signing-capable key found in key ring")
    /** Underlying BC failure, wrapped so the UI layer doesn't import BC types. */
    class SigningFailed(msg: String) : SigningError("Signing failed: $msg")
}

// ── Service ────────────────────────────────────────────────────────────

class SigningService private constructor() {

    companion object {
        val shared = SigningService()

        /** Default hash for new signatures. RFC 4880 §9.4 recommends SHA-256 minimum. */
        const val DEFAULT_HASH_ALGORITHM: Int = HashAlgorithmTags.SHA256
    }

    // ── Clear-Sign (RFC 4880 §7) ──────────────────────────────────────

    /**
     * Produce an RFC 4880 §7 clear-signed text message. Output looks like:
     *
     *   -----BEGIN PGP SIGNED MESSAGE-----
     *   Hash: SHA256
     *
     *   <dash-escaped message body>
     *   -----BEGIN PGP SIGNATURE-----
     *
     *   <base64 signature>
     *   =CRC24
     *   -----END PGP SIGNATURE-----
     *
     * Dash-escaping of lines that begin with "-" is handled by BC's
     * `ArmoredOutputStream.beginClearText(hashAlgorithm)`. The signature is
     * computed over the CANONICAL form of the input (CRLF line endings,
     * trailing whitespace per line stripped) per RFC 4880 §5.2.4 — that
     * canonical form is what we feed into the signature generator's
     * `update()` calls; the original (un-canonicalized) text is what gets
     * written to the armored output for display.
     */
    fun signClear(
        text: String,
        secretKeyRing: PGPSecretKeyRing,
        passphrase: String? = null,
        hashAlgorithm: Int = DEFAULT_HASH_ALGORITHM
    ): String {
        val signingKey = pickSigningKey(secretKeyRing)
        val sigGen = buildSignatureGenerator(
            signingKey = signingKey,
            passphrase = passphrase,
            hashAlgorithm = hashAlgorithm,
            signatureType = PGPSignature.CANONICAL_TEXT_DOCUMENT
        )

        val out = ByteArrayOutputStream()
        val armored = ArmoredOutputStream(out).stripVersion()

        try {
            armored.beginClearText(hashAlgorithm)

            // Display side: write the user's text exactly as supplied so
            // line breaks and dash-escaping land naturally via BC's
            // ArmoredOutputStream clear-text writer. Guarantee a trailing
            // newline so "-----BEGIN PGP SIGNATURE-----" starts on its own
            // line — without it BC glues the delimiter onto the last line
            // of text and verifiers can't find the boundary. The signed
            // bytes are the canonical form below (final line ending
            // excluded per §7.1), so adding a display newline does not
            // change the signature.
            val displayText = if (text.endsWith("\n")) text else text + "\n"
            val textBytes = displayText.toByteArray(Charsets.UTF_8)
            armored.write(textBytes)

            // Hash side: feed CANONICAL bytes into the signature generator.
            // RFC 4880 §5.2.4: line endings normalized to <CR><LF>, trailing
            // whitespace removed per line. BC does NOT canonicalize for us;
            // the caller is responsible.
            val canonical = canonicalizeForClearSign(text)
            sigGen.update(canonical, 0, canonical.size)

            armored.endClearText()

            val sigOut = BCPGOutputStream(armored)
            sigGen.generate().encode(sigOut)
            sigOut.close()
        } catch (e: PGPException) {
            throw SigningError.SigningFailed(e.message ?: "PGP error")
        } finally {
            armored.close()
        }

        return out.toString(Charsets.UTF_8)
    }

    // ── Detached Signature (RFC 4880 §5.2.3) ──────────────────────────

    /**
     * Produce a detached signature over `data`. When `armor` is true (the
     * default), the output is the ASCII-armored "-----BEGIN PGP SIGNATURE-----"
     * block; when false, the raw binary signature packet.
     *
     * Uses `BINARY_DOCUMENT` (signature type 0x00) — appropriate for arbitrary
     * byte data. For signing UTF-8 text where the verifier should canonicalize
     * line endings, use `signClear` instead.
     */
    fun signDetached(
        data: ByteArray,
        secretKeyRing: PGPSecretKeyRing,
        passphrase: String? = null,
        hashAlgorithm: Int = DEFAULT_HASH_ALGORITHM,
        armor: Boolean = true
    ): ByteArray {
        val signingKey = pickSigningKey(secretKeyRing)
        val sigGen = buildSignatureGenerator(
            signingKey = signingKey,
            passphrase = passphrase,
            hashAlgorithm = hashAlgorithm,
            signatureType = PGPSignature.BINARY_DOCUMENT
        )

        sigGen.update(data, 0, data.size)

        val out = ByteArrayOutputStream()
        val target: OutputStream = if (armor) ArmoredOutputStream(out).stripVersion() else out
        try {
            val sigOut = BCPGOutputStream(target)
            sigGen.generate().encode(sigOut)
            sigOut.close()
        } catch (e: PGPException) {
            throw SigningError.SigningFailed(e.message ?: "PGP error")
        } finally {
            if (target is ArmoredOutputStream) target.close()
        }

        return out.toByteArray()
    }

    // ── Internals ─────────────────────────────────────────────────────

    /**
     * Build a `PGPSignatureGenerator` initialized with the unlocked private
     * key + standard hashed subpackets (issuer fingerprint, type 33). Throws
     * `SigningError.PassphraseRequired` or `InvalidPassphrase` for predictable
     * UI handling.
     *
     * Note: the issuer-fingerprint subpacket is required on RFC 9580 v6
     * signatures and STRONGLY RECOMMENDED on v4 (GnuPG 2.4.4+ uses it for
     * key disambiguation when multiple keys share a 64-bit key ID prefix).
     * Phase A3 verify path relies on it for the "unknown signer" fingerprint
     * the lookup sheet uses to fetch from WKD/keyserver.
     */
    private fun buildSignatureGenerator(
        signingKey: PGPSecretKey,
        passphrase: String?,
        hashAlgorithm: Int,
        signatureType: Int
    ): PGPSignatureGenerator {
        val privateKey = try {
            val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
                .build((passphrase ?: "").toCharArray())
            signingKey.extractPrivateKey(decryptor)
        } catch (e: PGPException) {
            // BC throws a generic PGPException for both "no passphrase
            // supplied for encrypted key" and "wrong passphrase". The
            // s2KUsage check disambiguates: 0 means the secret key was
            // stored unencrypted, so any failure can't be a passphrase
            // issue; non-zero means it IS encrypted, so passphrase is
            // the most likely cause.
            if (signingKey.s2KUsage.toInt() != 0) {
                if (passphrase.isNullOrEmpty()) throw SigningError.PassphraseRequired()
                throw SigningError.InvalidPassphrase()
            }
            throw SigningError.SigningFailed(e.message ?: "Failed to unlock signing key")
        }

        val sigGen = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(signingKey.publicKey.algorithm, hashAlgorithm),
            signingKey.publicKey
        )
        sigGen.init(signatureType, privateKey)

        val subpacketGen = PGPSignatureSubpacketGenerator()
        // false = not critical; recipient ignores if they don't understand.
        // For issuer fingerprint, non-critical is correct (RFC 4880bis).
        subpacketGen.setIssuerFingerprint(false, signingKey.publicKey)
        sigGen.setHashedSubpackets(subpacketGen.generate())

        return sigGen
    }

    /**
     * Pick the secret key from `ring` that should be used to produce the
     * signature. Delegates to PGPCryptoService.pickSigningSecretKey, which
     * prefers a signing-capable subkey (Sign key flag) and falls back to the
     * primary only if it advertises Sign. Necessary for v6 keys, whose primary
     * is cert-only and whose signing lives on a dedicated subkey.
     */
    private fun pickSigningKey(ring: PGPSecretKeyRing): PGPSecretKey {
        return PGPCryptoService.shared.pickSigningSecretKey(ring)
            ?: throw SigningError.NoSigningKey()
    }

    /**
     * Canonicalize text for the clear-sign hash per RFC 4880 §7.1 + §5.2.4:
     *   • Line endings normalized to <CR><LF>
     *   • Trailing whitespace (spaces, tabs, CRs) stripped per line
     *   • Trailing line terminator excluded ("the line terminating sequence
     *     at the end of the cleartext is excluded from the signed data" —
     *     §7.1)
     *
     * This matches BC's standard clearsign verification loop, which emits
     * `lineSeparator` BEFORE each subsequent line (not AFTER each line),
     * so the resulting canonical form has CRLF between every adjacent line
     * pair and no terminator after the last line.
     *
     * Examples:
     *   "foo\nbar\nbaz\n"  -> "foo\r\nbar\r\nbaz"
     *   "foo\nbar\nbaz"    -> "foo\r\nbar\r\nbaz"
     *   "foo   \nbar"      -> "foo\r\nbar"
     *   "foo"              -> "foo"
     */
    internal fun canonicalizeForClearSign(text: String): ByteArray {
        val lines = text.split("\n").map { it.trimEnd(' ', '\t', '\r') }
        // Drop a trailing empty element produced by a trailing newline in
        // the input. After this step, joining with CRLF yields no trailing
        // CRLF, which is what §7.1 requires.
        val effective = if (lines.isNotEmpty() && lines.last().isEmpty()) {
            lines.dropLast(1)
        } else {
            lines
        }
        return effective.joinToString("\r\n").toByteArray(Charsets.UTF_8)
    }
}

// Match PGPCryptoService.stripVersion: replace BC's default
// "Version: BCPG v@RELEASE_NAME@" armor header (the @RELEASE_NAME@
// placeholder leaks because this BC build wasn't release-stamped)
// with the user-configured "Comment:" header. ArmorCommentHeader.current
// holds the already-validated value, or null when the user has turned
// the comment off or cleared it — in which case no Comment header is
// written. All sign / clear-sign / detached-sign output flows through
// here, which keeps the setting consistent with PGPCryptoService.
private fun ArmoredOutputStream.stripVersion(): ArmoredOutputStream = apply {
    setHeader("Version", null)
    val comment = ArmorCommentHeader.current
    if (!comment.isNullOrEmpty()) {
        setHeader("Comment", comment)
    } else {
        setHeader("Comment", null)
    }
}
