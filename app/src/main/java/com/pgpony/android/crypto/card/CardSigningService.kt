// CardSigningService.kt
// PGPony Android — HW Phase 2b
//
// Card-backed counterpart to SigningService. Produces the SAME output
// framing (RFC 4880 §7 clearsign, §5.2.3 detached) using the identical
// canonicalization and issuer-fingerprint subpacket — the only difference
// is the signature value comes from the card (via CardPGPContentSigner)
// instead of an unlocked local secret key.
//
// The whole operation must run while the card is in the field, so callers
// invoke this from inside an NFC reader operation lambda (binder thread)
// with a live, selected OpenPgpCardSession. The card's public key must be
// PAIRED into the keyring first (Phase 1.5) — that's where we get the
// PGPPublicKey needed to build the signature packet.

package com.pgpony.android.crypto.card

import com.pgpony.android.crypto.SigningService
import org.bouncycastle.bcpg.ArmoredOutputStream
import com.pgpony.android.data.ArmorCommentHeader
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import java.io.ByteArrayOutputStream
import java.io.OutputStream

// Match PGPCryptoService.stripVersion: replace BC's default
// "Version: BCPG v@RELEASE_NAME@" armor header (the @RELEASE_NAME@
// placeholder isn't substituted in the Android build) with the
// user-configured "Comment:" header. ArmorCommentHeader.current holds
// the already-validated value, or null when the comment is off/cleared
// (no Comment header written). Keeps card-backed sign and
// encrypt-and-sign output consistent with the software path.
private fun ArmoredOutputStream.stripVersion(): ArmoredOutputStream = apply {
    setHeader("Version", null)
    val comment = ArmorCommentHeader.current
    if (!comment.isNullOrEmpty()) {
        setHeader("Comment", comment)
    } else {
        setHeader("Comment", null)
    }
}

class CardSigningService private constructor() {

    companion object {
        val shared = CardSigningService()
    }

    /**
     * Clear-sign [text] with the card key behind [publicKey]. Mirrors
     * SigningService.signClear: writes the original text to the armored
     * clear-text section and feeds the CANONICAL bytes to the signature
     * generator. [pin] is the raw PW1 bytes. Returns the armored
     * "-----BEGIN PGP SIGNED MESSAGE-----" block.
     */
    fun signClear(
        session: OpenPgpCardSession,
        publicKey: PGPPublicKey,
        pin: ByteArray,
        text: String
    ): String {
        val sigGen = buildGenerator(session, publicKey, pin, PGPSignature.CANONICAL_TEXT_DOCUMENT)

        val out = ByteArrayOutputStream()
        val armored = ArmoredOutputStream(out).stripVersion()
        try {
            armored.beginClearText(HashAlgorithmTags.SHA256)
            val textBytes = text.toByteArray(Charsets.UTF_8)
            armored.write(textBytes)
            // RFC 4880 §7: the signature armor must start on its own line.
            // BC doesn't insert a separator when the cleartext doesn't end
            // in a newline, which glues "msg-----BEGIN PGP SIGNATURE-----"
            // and makes the output unparseable. This terminator is NOT part
            // of the signed data (canonicalizeForClearSign already excludes
            // the trailing line ending), so the signature still matches.
            if (textBytes.isEmpty() || textBytes.last() != '\n'.code.toByte()) {
                armored.write('\n'.code)
            }

            val canonical = SigningService.shared.canonicalizeForClearSign(text)
            sigGen.update(canonical, 0, canonical.size)

            armored.endClearText()

            val sigOut = BCPGOutputStream(armored)
            sigGen.generate().encode(sigOut)
            sigOut.close()
        } catch (e: PGPException) {
            throw unwrap(e)
        } finally {
            armored.close()
        }
        return out.toString(Charsets.UTF_8)
    }

    /**
     * Detached signature over [data] (BINARY_DOCUMENT). Armored by default.
     */
    fun signDetached(
        session: OpenPgpCardSession,
        publicKey: PGPPublicKey,
        pin: ByteArray,
        data: ByteArray,
        armor: Boolean = true
    ): ByteArray {
        val sigGen = buildGenerator(session, publicKey, pin, PGPSignature.BINARY_DOCUMENT)
        sigGen.update(data, 0, data.size)

        val out = ByteArrayOutputStream()
        val target: OutputStream = if (armor) ArmoredOutputStream(out).stripVersion() else out
        try {
            val sigOut = BCPGOutputStream(target)
            sigGen.generate().encode(sigOut)
            sigOut.close()
        } catch (e: PGPException) {
            throw unwrap(e)
        } finally {
            if (target is ArmoredOutputStream) target.close()
        }
        return out.toByteArray()
    }

    // ── Internals ─────────────────────────────────────────────────────

    private fun buildGenerator(
        session: OpenPgpCardSession,
        publicKey: PGPPublicKey,
        pin: ByteArray,
        signatureType: Int
    ): PGPSignatureGenerator {
        val sigGen = PGPSignatureGenerator(CardPGPContentSignerBuilder(session, pin, publicKey), publicKey)

        // BC's init() only reads keyID off this key and hands it to our
        // builder (which ignores it). The public key packet gives the
        // generator the algorithm/version context for the packet header.
        val stub = PGPPrivateKey(publicKey.keyID, publicKey.publicKeyPacket, null)
        sigGen.init(signatureType, stub)

        val sub = PGPSignatureSubpacketGenerator()
        sub.setIssuerFingerprint(false, publicKey)
        sigGen.setHashedSubpackets(sub.generate())

        return sigGen
    }

    /**
     * BC may wrap an exception thrown from getSignature() (e.g. a wrong
     * PIN) in a PGPException. Surface the underlying card error so the UI
     * shows "Wrong PIN — N tries remaining" rather than a generic failure.
     */
    private fun unwrap(e: PGPException): OpenPgpCardException {
        val cause = e.cause
        return if (cause is OpenPgpCardException) cause
        else OpenPgpCardException.Communication(e.message ?: "Signing failed", e)
    }
}
