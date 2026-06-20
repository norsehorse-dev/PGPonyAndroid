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

        var pked: PGPPublicKeyEncryptedData? = null
        var encKey: PGPPublicKey? = null
        for (obj in encList.encryptedDataObjects) {
            if (obj !is PGPPublicKeyEncryptedData) continue
            val k = pubRing.getPublicKey(obj.keyID)
            if (k != null) {
                pked = obj
                encKey = k
                break
            }
        }
        if (pked == null || encKey == null) {
            throw OpenPgpCardException.Malformed("This message isn't encrypted to this card's key.")
        }

        try {
            val factory = CardPublicKeyDataDecryptorFactory(session, encKey)
            val clear = pked.getDataStream(factory)
            val result = readLiteralAndVerify(JcaPGPObjectFactory(clear), verificationKeys)

            // INTEGRITY GATE. readLiteralAndVerify has fully read the plaintext,
            // so the SEIPD protection can now be checked: reject a legacy
            // unprotected packet (isIntegrityProtected() == false), and validate
            // SEIPDv1's MDC / confirm SEIPDv2's AEAD tag via verify(). Without
            // this a tampered message would pass as a clean card decrypt.
            val protected = pked.isIntegrityProtected()
            val intact = protected && try { pked.verify() } catch (ie: PGPException) { false }
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
        verificationKeys: List<PGPPublicKeyRing>?
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
                is PGPCompressedData ->
                    return readLiteralAndVerify(JcaPGPObjectFactory(obj.dataStream), verificationKeys)
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
                    filename = obj.fileName.takeIf { it.isNotEmpty() }
                    val out = ByteArrayOutputStream()
                    val buf = ByteArray(4096)
                    var len: Int
                    val ins = obj.inputStream
                    while (ins.read(buf).also { len = it } >= 0) {
                        out.write(buf, 0, len)
                        onePassSig?.update(buf, 0, len)
                    }
                    data = out.toByteArray()
                }
                is PGPSignatureList -> {
                    if (onePassSig != null && obj.size() > 0) {
                        signatureVerified = onePassSig.verify(obj[0])
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
