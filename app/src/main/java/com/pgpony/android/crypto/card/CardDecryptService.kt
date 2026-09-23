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

import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPLiteralData
import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.SecurityLimits
import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
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
            val result = readLiteralAndVerify(JcaPGPObjectFactory(clear), verificationKeys)

            // INTEGRITY GATE. readLiteralAndVerify has fully read the plaintext,
            // so the SEIPD protection can now be checked: reject a legacy
            // unprotected packet (isIntegrityProtected() == false), and validate
            // SEIPDv1's MDC / confirm SEIPDv2's AEAD tag via verify(). Without
            // this a tampered message would pass as a clean card decrypt.
// 3.1.0 Phase 7 Fix2 (origin: Token2 test, gpg 2.5 message):
            // GnuPG with AEAD-capable keys emits the LibrePGP "tag 20"
            // OCB packet. BC's isIntegrityProtected() is tag-18-only
            // (false for tag 20) and its verify() THROWS for tag 20 —
            // but AEAD authenticates every chunk during the stream
            // read; a tampered message throws before reaching this
            // gate. So: tag 20 counts as protected, and skips the
            // MDC-oriented verify(). SEIPDv2 (isAEAD + tag 18) keeps
            // using verify(), which BC short-circuits to true.
            val aead = chosen.isAEAD()
            val protected = chosen.isIntegrityProtected() || aead
            val intact = protected && try {
                if (aead && !chosen.isIntegrityProtected()) true else chosen.verify()
            } catch (ie: PGPException) { false }
            if (!intact) {
                throw OpenPgpCardException.Malformed(
                    if (!protected) "Message has no integrity protection and was rejected."
                    else "Integrity check failed - the message may have been tampered with."
                )
            }
            return result
        } catch (e: PGPException) {
            val cause = e.cause
            if (cause is OpenPgpCardException) throw cause
            throw OpenPgpCardException.Communication(e.message ?: "Decryption failed", e)
        }
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

    private fun findPublicKey(keyID: Long, rings: List<PGPPublicKeyRing>): PGPPublicKey? {
        for (ring in rings) {
            ring.getPublicKey(keyID)?.let { return it }
        }
        return null
    }

    /**
     * Walk the decrypted packet stream: recover the literal data and, if an
     * embedded one-pass signature is present and [verificationKeys] is given,
     * verify it against the signer's key. Mirrors PGPCryptoService's software
     * verification loop so the Decrypt tab shows the same verified-signer
     * banner whether the message was decrypted in software or on the card.
     */
    private fun readLiteralAndVerify(
        factory: JcaPGPObjectFactory,
        verificationKeys: List<PGPPublicKeyRing>?,
        depth: Int = 0
    ): CardDecryptResult {
        var data: ByteArray? = null
        var filename: String? = null
        var hadSignature = false
        var signerKnown = false
        var signatureVerified = false
        var signerKeyID: String? = null
        var onePassSig: PGPOnePassSignature? = null

        var obj = factory.nextObject()
        while (obj != null) {
            when (obj) {
                // GnuPG/BC wrap the whole signed structure (one-pass sig +
                // literal + signature) inside the compressed packet, so
                // recursing re-reads them together — same as the software path.
                is PGPCompressedData -> {
                    if (depth >= SecurityLimits.MAX_DECOMPRESSION_DEPTH)
                        throw PGPCryptoError.ResourceLimitExceeded("compression nesting exceeds depth cap")
                    return readLiteralAndVerify(JcaPGPObjectFactory(obj.dataStream), verificationKeys, depth + 1)
                }
                is PGPOnePassSignatureList -> {
                    if (obj.size() > 0) {
                        hadSignature = true
                        val ops = obj[0]
                        signerKeyID = String.format("%016X", ops.keyID)
                        val signerPubKey = verificationKeys?.let { findPublicKey(ops.keyID, it) }
                        if (signerPubKey != null) {
                            ops.init(BcPGPContentVerifierBuilderProvider(), signerPubKey)
                            onePassSig = ops
                            signerKnown = true
                        }
                    }
                }
                is PGPLiteralData -> {
                    filename = com.pgpony.android.crypto.LiteralFilename.sanitize(obj.fileName) // 4.6.0 (item 17.3)
                    val out = ByteArrayOutputStream()
                    val buf = ByteArray(4096)
                    var len: Int
                    var total = 0L
                    val ins = obj.inputStream
                    while (ins.read(buf).also { len = it } >= 0) {
                        total += len
                        if (total > SecurityLimits.MAX_MESSAGE_PLAINTEXT_BYTES)
                            throw PGPCryptoError.ResourceLimitExceeded("decrypted message exceeds size cap")
                        out.write(buf, 0, len)
                        onePassSig?.update(buf, 0, len)
                    }
                    data = out.toByteArray()
                }
                is PGPSignatureList -> {
                    if (onePassSig != null && obj.size() > 0) {
                        // 4.6.0 (item 17.1): graded like the software path, so a
                        // valid signature from an unbound, revoked or expired
                        // signer (or a weak digest) is not reported as verified.
                        val sig = obj[0]
                        signatureVerified = sig.keyID == onePassSig.keyID &&
                            onePassSig.verify(sig) &&
                            com.pgpony.android.crypto.SignerEvaluator.evaluate(
                                sig, verificationKeys ?: emptyList()
                            ) == com.pgpony.android.crypto.SignerStatus.VERIFIED
                    }
                }
            }
            obj = factory.nextObject()
        }
        val d = data ?: throw OpenPgpCardException.Malformed("No readable content after decryption.")
        return CardDecryptResult(
            data = d,
            filename = filename,
            hadSignature = hadSignature,
            signerKnown = signerKnown,
            signatureVerified = signatureVerified,
            signerKeyID = signerKeyID
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
    val signatureVerified: Boolean = false,
    val signerKeyID: String? = null
)
