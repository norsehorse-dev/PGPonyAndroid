// CardPrimarySigner.kt
// PGPony Android 4.8.0 (#71): the primary key's edits signed on an OpenPGP card.
//
// After Move to security key put the primary into the card's Signature slot,
// the phone keeps only a divert-to-card stub for it, and every edit the primary
// signs (User IDs, subkey bindings, expiry, refresh, subkey revocation) had no
// key to sign with. This opens a PrimarySigner whose signatures come from the
// card through CardPGPContentSigner, the same bridge data signing uses: the
// phone hashes, the card runs PSO:COMPUTE DIGITAL SIGNATURE with the Signature
// slot key (RSA DigestInfo, ECDSA, EdDSA).
//
// PIN rules: CardPGPContentSigner sends VERIFY PW1 (81) right before every
// PSO:CDS. A card whose "PW1 valid for one PSO:CDS" byte (DO C4) is set drops
// the verification after each signature, so an edit that makes several
// signatures (expiry over several User IDs, a refresh) verifies again for each
// one, all within the one card session the user taps for. That is how the
// card expiry change and card certification already sign more than once.

package com.pgpony.android.crypto.card

import com.pgpony.android.crypto.PrimarySigner
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.util.encoders.Hex

object CardPrimarySigner {

    /** The card's Signature slot does not hold this key's primary. */
    const val PRIMARY_MISSING_MESSAGE =
        "The primary key is not in this security key's signature slot, so this change cannot be made with it"

    /**
     * A signer for [primaryPublic] on the card in [session], which must be
     * selected. Checks first that the card's Signature slot holds the primary
     * (a card holding only subkeys would make self-signatures that never
     * verify) and throws [OpenPgpCardException.Malformed] with
     * [PRIMARY_MISSING_MESSAGE] when it does not. [pin] is the raw PW1.
     */
    fun open(session: OpenPgpCardSession, pin: ByteArray, primaryPublic: PGPPublicKey): PrimarySigner {
        val sigSlot = runCatching { session.getApplicationRelatedData().sigFingerprint }.getOrNull()
        if (!slotHolds(sigSlot, primaryPublic.fingerprint)) {
            throw OpenPgpCardException.Malformed(PRIMARY_MISSING_MESSAGE)
        }
        return PrimarySigner.external(primaryPublic, CardPGPContentSignerBuilder(session, pin, primaryPublic))
    }

    /** True when [slotFingerprintHex] names [fingerprint]. */
    fun slotHolds(slotFingerprintHex: String?, fingerprint: ByteArray): Boolean {
        val slot = slotFingerprintHex?.filterNot { it.isWhitespace() } ?: return false
        return slot.equals(Hex.toHexString(fingerprint), ignoreCase = true)
    }

    /**
     * Runs [edit] and reports a card failure (a wrong PIN, a lost tag) as the
     * card's own exception. Bouncy Castle wraps an exception thrown inside
     * getSignature() in a PGPException, which the UI would show as a generic
     * failure instead of "Wrong PIN" with the tries left.
     */
    fun <T> unwrapping(edit: () -> T): T = try {
        edit()
    } catch (e: PGPException) {
        throw cardCause(e) ?: e
    } catch (e: RuntimeException) {
        throw cardCause(e) ?: e
    }

    private fun cardCause(e: Throwable): OpenPgpCardException? {
        var c: Throwable? = e.cause
        var depth = 0
        while (c != null && depth < 8) {
            if (c is OpenPgpCardException) return c
            c = c.cause
            depth++
        }
        return null
    }
}
