// CardPGPContentSigner.kt
// PGPony Android — HW Phase 2b
//
// The bridge that lets BouncyCastle build a standard OpenPGP signature
// packet whose actual signing step happens on the smartcard.
//
// BC's PGPSignatureGenerator drives a PGPContentSigner: it writes the
// message + the signature trailer to getOutputStream() (which we hash with
// a local SHA-256 MessageDigest), then calls getSignature() once to obtain
// the signature value. We intercept that final step: VERIFY PW1 then
// PSO:CDS on the card over the formatted digest, and hand BC back the raw
// card output. BC then encodes it into MPIs by key algorithm:
//   • EdDSA-legacy (22): BC splits the card's 64-byte R‖S into two MPIs.
//   • RSA (1/2/3): BC wraps the card's raw signature as a single MPI.
// (ECDSA is not supported here — the card returns r‖s but BC expects DER.)
//
// Hash is fixed at SHA-256 to match CardSigningFormat's DigestInfo prefix
// and PGPony's default signing hash.

package com.pgpony.android.crypto.card

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.PGPContentSigner
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import java.io.OutputStream
import java.security.MessageDigest

/**
 * Drop-in replacement for BcPGPContentSignerBuilder that signs on the card.
 * The [privateKey] passed to [build] (BC hands us the stub we init the
 * generator with) is ignored — all key context comes from [publicKey].
 */
class CardPGPContentSignerBuilder(
    private val session: OpenPgpCardSession,
    private val pin: ByteArray,
    private val publicKey: PGPPublicKey
) : PGPContentSignerBuilder {

    override fun build(signatureType: Int, privateKey: PGPPrivateKey?): PGPContentSigner =
        CardPGPContentSigner(signatureType, session, pin, publicKey)
}

class CardPGPContentSigner(
    private val signatureType: Int,
    private val session: OpenPgpCardSession,
    private val pin: ByteArray,
    private val publicKey: PGPPublicKey
) : PGPContentSigner {

    private val digest = MessageDigest.getInstance("SHA-256")

    private val sink = object : OutputStream() {
        override fun write(b: Int) {
            digest.update(b.toByte())
        }
        override fun write(b: ByteArray, off: Int, len: Int) {
            digest.update(b, off, len)
        }
    }

    override fun getOutputStream(): OutputStream = sink

    // BC calls getDigest() and getSignature() once each (after all data is
    // written). MessageDigest.digest() resets the instance, so finalize
    // exactly once and cache it — both methods read the same bytes.
    private var finalized: ByteArray? = null

    private fun finalizedDigest(): ByteArray {
        var d = finalized
        if (d == null) {
            d = digest.digest()
            finalized = d
        }
        return d
    }

    /**
     * The message digest BC embeds for the 2-octet quick-check field. Must
     * be the SAME hash bytes we sign on the card.
     */
    override fun getDigest(): ByteArray = finalizedDigest()

    /**
     * Finalize the hash and have the card sign it. VERIFY immediately
     * precedes PSO:CDS with nothing in between, which satisfies the card's
     * "signature PIN forced" mode (PW1/0x81 access is consumed by the one
     * PSO:CDS). May throw OpenPgpCardException (e.g. WrongPin) — that
     * propagates out through BC to the caller's try/catch.
     */
    override fun getSignature(): ByteArray {
        val d = finalizedDigest()
        session.verify(OpenPgpCard.PW1_SIGN, pin)
        val input = CardSigningFormat.prepareInput(publicKey.algorithm, d)
        return session.signDigest(input)
    }

    override fun getType(): Int = signatureType
    override fun getHashAlgorithm(): Int = HashAlgorithmTags.SHA256
    override fun getKeyAlgorithm(): Int = publicKey.algorithm
    override fun getKeyID(): Long = publicKey.keyID
}
