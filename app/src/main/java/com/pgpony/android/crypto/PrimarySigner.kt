// PrimarySigner.kt
// PGPony Android 4.8.0 (#71): who makes the primary key's signatures for a key
// edit.
//
// Every edit that the primary key signs (a User ID's self-certification 0x13, a
// User ID revocation 0x30, a subkey binding 0x18, a subkey revocation 0x28, the
// re-signed self-signatures of an expiry change or a refresh) builds its packet
// the same way; only the signing step differs. On a key pair the primary's
// secret is unlocked with the passphrase and Bouncy Castle signs on the phone.
// On a key whose primary sits in an OpenPGP card's Signature slot (Move to
// security key with the primary, or a key generated on the card), the hash is
// still computed on the phone and the card makes the signature through
// CardPGPContentSigner (PSO:COMPUTE DIGITAL SIGNATURE), which is how data
// signatures are made on a card. The edit code takes a PrimarySigner and does
// not know which of the two it has, so tests can drive the card path with a
// software key.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder

/**
 * 4.8.0 (#71): makes signature generators for [publicKey], the primary key.
 * [privateKey] is what Bouncy Castle is initialised with: the unlocked primary
 * on the software path, a placeholder carrying only the key ID and public
 * packet on the card path (CardPGPContentSignerBuilder ignores it).
 */
class PrimarySigner(
    val publicKey: PGPPublicKey,
    private val builder: PGPContentSignerBuilder,
    private val privateKey: PGPPrivateKey,
    /** True when the signatures are made off the phone (on a card). */
    val external: Boolean
) {

    /** A generator for one signature of [signatureType] by the primary. */
    fun generator(signatureType: Int): PonySigGen =
        PonySigGen(builder, publicKey).apply { init(signatureType, privateKey) }

    companion object {
        /**
         * The software path: [privateKey] is the unlocked primary. SHA-256, raised
         * by EcCurveOid.signatureHash for an ECDSA primary on a longer curve
         * (4.8.0, 4l) and for Ed448.
         */
        fun software(publicKey: PGPPublicKey, privateKey: PGPPrivateKey): PrimarySigner =
            PrimarySigner(
                publicKey,
                BcPGPContentSignerBuilder(publicKey.algorithm, EcCurveOid.signatureHash(publicKey, HashAlgorithmTags.SHA256)),
                privateKey,
                external = false
            )

        /**
         * A signer that holds no secret on the phone, such as the card's
         * CardPGPContentSignerBuilder. Bouncy Castle's init() only reads the key
         * ID and public packet off the private key it is given, so a placeholder
         * with no secret material stands in for it, as CardSigningService does.
         */
        fun external(publicKey: PGPPublicKey, builder: PGPContentSignerBuilder): PrimarySigner =
            PrimarySigner(
                publicKey,
                builder,
                PGPPrivateKey(publicKey.keyID, publicKey.publicKeyPacket, null),
                external = true
            )
    }
}

/**
 * 4.8.0 (#71): the rings after an edit signed through a [PrimarySigner].
 * [secretRing] is the stored secret ring with the new public material (stubs
 * stay stubs), or null when no secret ring is stored for the key, as for a key
 * generated on a card.
 */
data class SignedEdit(val publicRing: PGPPublicKeyRing, val secretRing: PGPSecretKeyRing?) {
    companion object {
        /**
         * [publicRing] plus [secretRing] carrying its public material. A secret
         * key the public ring does not hold (left out on load) is kept as it
         * was rather than failing the edit, which replacePublicKeys would do.
         */
        fun of(publicRing: PGPPublicKeyRing, secretRing: PGPSecretKeyRing?): SignedEdit {
            if (secretRing == null) return SignedEdit(publicRing, null)
            val keys = secretRing.secretKeys.asSequence().map { sk ->
                val pub = publicRing.getPublicKey(sk.keyID)
                if (pub == null) sk else PGPSecretKey.replacePublicKey(sk, pub)
            }.toList()
            return SignedEdit(publicRing, PGPSecretKeyRing(keys))
        }
    }
}
