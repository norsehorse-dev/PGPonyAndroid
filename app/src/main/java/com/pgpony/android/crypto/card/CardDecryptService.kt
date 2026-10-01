// CardDecryptService.kt
// PGPony Android — HW Phase 3b
//
// Decrypt a PGP message addressed to the card's encryption (cv25519) key.
// Mirrors PGPCryptoService.decrypt's parsing (JcaPGPObjectFactory →
// PGPEncryptedDataList → matching PKESK → getDataStream → literal data) and
// only swaps the decryptor factory for the card-backed one.
//
// Runs inside an NFC operation (binder thread, card present): VERIFY PW1
// (0x82 / "other", which authorizes PSO:DECIPHER and — unlike the signature
// PIN — is NOT consumed per-op), then BC decrypts, calling into the card
// for the ECDH step. The card's public key ring must be PAIRED so we can
// match the PKESK key ID and read the ECDH KDF parameters.

package com.pgpony.android.crypto.card

import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import com.pgpony.android.crypto.ContentWalker
import com.pgpony.android.crypto.MessageGrammar
import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.SecurityLimits
import com.pgpony.android.crypto.SignerStatus
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CardDecryptService private constructor() {

    companion object {
        val shared = CardDecryptService()
    }

    /**
     * Decrypt [armored] (an ASCII-armored or binary PGP message) using the
     * card's encryption key. Returns the recovered plaintext as UTF-8.
     * See [decryptBytes] for the binary file-mode variant.
     */
    fun decrypt(
        session: OpenPgpCardSession,
        pubRing: PGPPublicKeyRing,
        pin: ByteArray,
        armored: String,
        verificationKeys: List<PGPPublicKeyRing>? = null
    ): CardDecryptResult = decryptBytes(
        session, pubRing, pin, armored.toByteArray(Charsets.UTF_8), verificationKeys
    )

    /**
     * Byte-oriented decrypt for file mode: [encrypted] may be binary
     * (armor=false). Returns the recovered bytes plus the literal-data
     * filename embedded at encrypt time (used to suggest an output name).
     *
     * If [verificationKeys] is supplied and the message carries an embedded
     * one-pass signature, the signature is verified against the matching
     * signer key (mirrors the software decrypt path) and the result is
     * reported in the returned [CardDecryptResult].
     */
    fun decryptBytes(
        session: OpenPgpCardSession,
        pubRing: PGPPublicKeyRing,
        pin: ByteArray,
        encrypted: ByteArray,
        verificationKeys: List<PGPPublicKeyRing>? = null
    ): CardDecryptResult {
        // PW1 in "other" mode authorizes PSO:DECIPHER. Verify once up front.
        session.verify(OpenPgpCard.PW1_OTHER, pin)

        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(encrypted))
        val encList = findEncryptedData(JcaPGPObjectFactory(decoder))
            ?: throw OpenPgpCardException.Malformed("No encrypted data found in the message.")

        // 4.1.0 - PKESK selection now covers hidden recipients.
        //
        // `gpg -R` writes the PKESK with an all-zero key ID (RFC 9580 5.1's
        // wildcard) so an interceptor learns nothing about who the message is
        // for. Selection here was a single exact match on obj.keyID, so a
        // wildcard packet matched nothing and the user was told the message
        // "isn't encrypted to this card's key" - which, for a card that could
        // in fact open it, was simply false. The software path grew this fix
        // in 4.0.5 (PGPCryptoService.resolvePkesk); this is its card twin.
        val pkesks = encList.encryptedDataObjects
            .asSequence()
            .filterIsInstance<PGPPublicKeyEncryptedData>()
            .toList()

        var pked: PGPPublicKeyEncryptedData? = null
        var encKey: PGPPublicKey? = null
        var clearStream: java.io.InputStream? = null
        var sawWildcard = false

        // Pass 1 - addressed packets. Unchanged behaviour and cost: no card
        // operation happens until a packet has been chosen.
        for (obj in pkesks) {
            if (obj.keyID == WILDCARD_KEY_ID) {
                sawWildcard = true
                continue
            }
            val k = pubRing.getPublicKey(obj.keyID) ?: continue
            pked = obj
            encKey = k
            break
        }

        // Pass 2 - hidden recipients. Trial each wildcard packet against the
        // card ring's encryption-capable public keys.
        //
        // Why a trial is sound on a card: RFC 6637 binds the recipient's
        // fingerprint and algorithm attributes into the KDF, so the CANDIDATE
        // public key decides the KEK even though the shared secret always
        // comes from the one private key the card holds. A wrong candidate
        // therefore derives a wrong KEK and BouncyCastle rejects the unwrapped
        // session key on its checksum - it cannot yield plaintext.
        //
        // Cost is one PSO:DECIPHER per trial. PW1 in "other" mode is NOT
        // consumed per operation, so the VERIFY above covers every attempt and
        // no retry counter is touched. Rings normally carry exactly one
        // encryption key, so the "trial" is usually a single attempt.
        //
        // Caveat, for the day a ring has two: the v3 PKESK checksum is what
        // makes a wrong candidate fail HERE. A v6 PKESK carries no checksum -
        // SEIPDv2's AEAD tag is what authenticates it - so a wrong candidate
        // on a v6 message opens a stream that fails during the read instead,
        // surfacing as a decryption error rather than a skipped candidate.
        // Correctness is unaffected either way: no wrong key yields plaintext.
        if (pked == null && sawWildcard) {
            outer@ for (obj in pkesks) {
                if (obj.keyID != WILDCARD_KEY_ID) continue
                for (candidate in encryptionCandidates(pubRing)) {
                    val stream = try {
                        obj.getDataStream(CardPublicKeyDataDecryptorFactory(session, candidate))
                    } catch (e: PGPException) {
                        // Wrong key for this packet: the expected outcome of a
                        // trial, and silent by design. A card that left the
                        // field is NOT that, and must not be retried against
                        // the next candidate.
                        val cause = e.cause
                        if (cause is OpenPgpCardException.TagLost) throw cause
                        null
                    } catch (e: OpenPgpCardException.TagLost) {
                        throw e
                    } catch (e: OpenPgpCardException) {
                        // The card refused this particular unwrap (bad SW).
                        // Same meaning as above: try the next candidate.
                        null
                    }
                    if (stream != null) {
                        pked = obj
                        encKey = candidate
                        clearStream = stream
                        break@outer
                    }
                }
            }
        }

        val chosen = pked
        val chosenKey = encKey
        if (chosen == null || chosenKey == null) {
            throw OpenPgpCardException.Malformed(
                if (sawWildcard)
                    "This message hides its recipient, and this card's key did not open it."
                else
                    "This message isn't encrypted to this card's key."
            )
        }

        try {
            // Pass 2 already holds an open stream; pass 1 opens one here, which
            // is where the card operation happens for an addressed message.
            val clear = clearStream
                ?: chosen.getDataStream(CardPublicKeyDataDecryptorFactory(session, chosenKey))

            // A legacy packet without integrity protection is refused before
            // its content is read.
            val aead = chosen.isAEAD()
            val protected = chosen.isIntegrityProtected() || aead
            if (!protected) {
                throw OpenPgpCardException.Malformed("Message has no integrity protection and was rejected.")
            }

            // The whole decrypted packet stream is read first (bounded), so the
            // integrity check below runs before any of the content is parsed.
            val plain = readCapped(clear)

            // INTEGRITY GATE. The plaintext has been fully read, so the SEIPD
            // protection can now be checked: validate SEIPDv1's MDC / confirm
            // SEIPDv2's AEAD tag via verify(). Without this a tampered message
            // would pass as a clean card decrypt.
// 3.1.0 Phase 7 Fix2 (origin: Token2 test, gpg 2.5 message):
            // GnuPG with AEAD-capable keys emits the LibrePGP "tag 20"
            // OCB packet. BC's isIntegrityProtected() is tag-18-only
            // (false for tag 20) and its verify() THROWS for tag 20 —
            // but AEAD authenticates every chunk during the stream
            // read; a tampered message throws before reaching this
            // gate. So: tag 20 counts as protected, and skips the
            // MDC-oriented verify(). SEIPDv2 (isAEAD + tag 18) keeps
            // using verify(), which BC short-circuits to true.
            val intact = try {
                if (aead && !chosen.isIntegrityProtected()) true else chosen.verify()
            } catch (ie: PGPException) { false }
            if (!intact) {
                throw OpenPgpCardException.Malformed(
                    "Integrity check failed - the message may have been tampered with."
                )
            }
            return readContent(plain, verificationKeys)
        } catch (e: PGPException) {
            val cause = e.cause
            if (cause is OpenPgpCardException) throw cause
            throw OpenPgpCardException.Communication(e.message ?: "Decryption failed", e)
        }
    }

    /** The decrypted packet stream [clear], read whole up to the in-memory cap. */
    private fun readCapped(clear: java.io.InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(1 shl 16)
        var total = 0L
        while (true) {
            val n = clear.read(buf)
            if (n < 0) break
            total += n
            if (total > SecurityLimits.MAX_MESSAGE_PLAINTEXT_BYTES)
                throw PGPCryptoError.ResourceLimitExceeded("decrypted message exceeds size cap")
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    /**
     * RFC 9580 5.1's wildcard key ID. `gpg -R` writes it in place of the
     * recipient's key ID so the message does not disclose who it is for;
     * a receiver that sees it is expected to try its own keys against the
     * packet. Mirrors PGPCryptoService's constant of the same name.
     */
    private val WILDCARD_KEY_ID = 0L

    /**
     * The card ring's encryption-capable public keys, subkeys first.
     *
     * Order affects cost, not correctness: on the offline-primary layouts
     * PGPony pairs, the decryption key is always a subkey, so trying subkeys
     * first means the ordinary case succeeds on the first attempt.
     */
    private fun encryptionCandidates(ring: PGPPublicKeyRing): List<PGPPublicKey> {
        val subkeys = mutableListOf<PGPPublicKey>()
        val primaries = mutableListOf<PGPPublicKey>()
        val keys = ring.publicKeys
        while (keys.hasNext()) {
            val k = keys.next()
            if (!k.isEncryptionKey) continue
            if (k.isMasterKey) primaries.add(k) else subkeys.add(k)
        }
        return subkeys + primaries
    }

    private fun findEncryptedData(factory: JcaPGPObjectFactory): PGPEncryptedDataList? {
        var obj = factory.nextObject()
        while (obj != null) {
            if (obj is PGPEncryptedDataList) return obj
            obj = factory.nextObject()
        }
        return null
    }

    /**
     * The decrypted packet bytes [plain] read into a result: checked against
     * the message grammar (MessageGrammar, the same check the software path
     * runs), then walked by the shared [ContentWalker], so the card path
     * returns the one literal and the same graded signer status as a software
     * decrypt. Any structural problem is [OpenPgpCardException.Malformed].
     */
    internal fun readContent(
        plain: ByteArray,
        verificationKeys: List<PGPPublicKeyRing>?
    ): CardDecryptResult {
        val checked = try {
            MessageGrammar.normalizePlaintext(plain)
        } catch (e: MessageGrammar.Truncated) {
            throw OpenPgpCardException.Malformed("The decrypted message is malformed (truncated packet).")
        } catch (e: MessageGrammar.Malformed) {
            throw OpenPgpCardException.Malformed("The decrypted message is malformed (${e.message}).")
        }
        val sink = ContentWalker.MemorySink()
        val walked = ContentWalker.walk(
            JcaPGPObjectFactory(ByteArrayInputStream(checked)),
            verificationKeys,
            sink,
            malformed = { OpenPgpCardException.Malformed("The decrypted message is malformed ($it).") },
            noLiteral = { OpenPgpCardException.Malformed("No readable content after decryption.") }
        )
        return CardDecryptResult(
            data = sink.bytes(),
            filename = walked.filename,
            hadSignature = walked.hasSignature,
            signerKnown = walked.signerKnown,
            signatureVerified = walked.signerStatus == SignerStatus.VERIFIED,
            signerKeyID = walked.signerKeyID
                ?: walked.firstOnePassKeyID?.let { String.format("%016X", it) },
            signerStatus = walked.signerStatus,
            signerWeakKey = walked.signerWeakKey,
            signatureKeyIDRaw = walked.signatureKeyIDRaw,
            signaturePackets = walked.signaturePackets,
            signingKeyFingerprint = walked.signingKeyFingerprint,
            signerPrimaryFingerprint = walked.signerPrimaryFingerprint
        )
    }
}

/** Plaintext bytes recovered from a card-decrypted message, plus the
 *  original filename embedded in the literal-data packet (null if none),
 *  and one-pass signature verification info (when verification keys were
 *  supplied to the decrypt call). */
data class CardDecryptResult(
    val data: ByteArray,
    val filename: String?,
    val hadSignature: Boolean = false,
    val signerKnown: Boolean = false,
    /** True only when [signerStatus] is VERIFIED. */
    val signatureVerified: Boolean = false,
    val signerKeyID: String? = null,
    /** The signer grade, exactly as the software path reports it
     *  (DecryptResult.signerStatus): verified, unknown signer, invalid,
     *  revoked, expired, and so on. Callers show this, not a bare boolean. */
    val signerStatus: SignerStatus = SignerStatus.NONE,
    /** Label of the signer key when it verified but is weak ("RSA 1024"). */
    val signerWeakKey: String? = null,
    /** Raw key id from the signature packets, held or not. */
    val signatureKeyIDRaw: Long? = null,
    /** Every signature packet in the message, encoded, in order. */
    val signaturePackets: List<ByteArray> = emptyList(),
    /** Fingerprint (hex uppercase) of the exact key the graded signature
     *  verified under; null when no held key's signature verified. */
    val signingKeyFingerprint: String? = null,
    /** Primary fingerprint (hex uppercase) of the certificate that validly
     *  holds that key; null when unknown. */
    val signerPrimaryFingerprint: String? = null
)
