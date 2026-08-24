// CompositeSignSuite.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// The shared parameter model for the post-quantum composite SIGNATURE
// schemes, the signing counterpart of CompositeSuite (which models the
// ML-KEM composite KEMs). RFC 9980 Table 1 registers two composite signature
// code points, both v6-only:
//
//   IETF (RFC 9980):
//     algo 30  ML-DSA-65 + Ed25519   (MUST)
//     algo 31  ML-DSA-87 + Ed448     (SHOULD)
//
// Unlike the ML-KEM composite, RFC 9980 defines NO LibrePGP v5 variant for
// composite signatures: composite ML-DSA MUST be used only with v6 keys and
// v6 signatures (Sections 5.3.1, 5.3.2). A LibrePGP composite signature, if
// one is wanted, would come from a separate specification, not this one.
//
// Byte layout, all fixed-length with the EdDSA component FIRST (RFC 9980
// Sections 5.3.1 and 5.3.2, lengths from Tables 6 and 7):
//
//   public key material:  EdDSA public  || ML-DSA public
//   secret key material:  EdDSA secret  || ML-DSA seed (32 octets, xi)
//   signature value:      EdDSA sig     || ML-DSA sig
//
// The ML-DSA secret is the 32-octet FIPS-204 seed xi, expanded through
// ML-DSA.KeyGen_internal before use. Both component signatures are made over
// the SAME standard v6 dataDigest (RFC 9580 Section 5.2.4); there is no extra
// domain separation. A verifier MUST validate both components.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters

/**
 * The EdDSA half of a composite signature. Lengths are the fixed RFC 8032
 * encodings from RFC 9980 Table 6. [oidTail] is the DER object-identifier
 * body as it appears where an EdDSA curve is named in a key packet.
 */
enum class EdDsaCurve(
    val pubLen: Int,
    val secretLen: Int,
    val sigLen: Int,
    val oidTail: ByteArray
) {
    ED25519(32, 32, 64, byteArrayOf(0x2b, 0x65, 0x70)),
    ED448(57, 57, 114, byteArrayOf(0x2b, 0x65, 0x71))
}

/**
 * The ML-DSA half. Public and signature lengths are the FIPS-204 encodings
 * from RFC 9980 Table 7; the secret is the 32-octet seed for both levels.
 */
enum class MldsaLevel(
    val params: MLDSAParameters,
    val pubLen: Int,
    val sigLen: Int,
    val seedLen: Int = 32
) {
    MLDSA65(MLDSAParameters.ml_dsa_65, 1952, 3309),
    MLDSA87(MLDSAParameters.ml_dsa_87, 2592, 4627)
}

/**
 * A composite signature parameter set: the OpenPGP algorithm id and the
 * EdDSA + ML-DSA pair it combines. RFC 9980 registers exactly these two, and
 * both are v6-only.
 */
enum class CompositeSignSuite(
    val algId: Int,
    val eddsa: EdDsaCurve,
    val mldsa: MldsaLevel
) {
    MLDSA65_ED25519(30, EdDsaCurve.ED25519, MldsaLevel.MLDSA65),
    MLDSA87_ED448(31, EdDsaCurve.ED448, MldsaLevel.MLDSA87);

    /** Composite public-key material length: EdDSA public || ML-DSA public. */
    val compositePubLen: Int get() = eddsa.pubLen + mldsa.pubLen

    /** Composite secret material length: EdDSA secret || ML-DSA seed. */
    val compositeSecretLen: Int get() = eddsa.secretLen + mldsa.seedLen

    /** Composite signature length: EdDSA signature || ML-DSA signature. */
    val compositeSigLen: Int get() = eddsa.sigLen + mldsa.sigLen

    /** Split composite public material into (eddsaPublic, mldsaPublic). */
    fun splitPublic(material: ByteArray): Pair<ByteArray, ByteArray> {
        require(material.size == compositePubLen) {
            "composite public key is ${material.size} octets, expected $compositePubLen"
        }
        return material.copyOfRange(0, eddsa.pubLen) to
            material.copyOfRange(eddsa.pubLen, compositePubLen)
    }

    /** Split composite secret material into (eddsaSecret, mldsaSeed). */
    fun splitSecret(material: ByteArray): Pair<ByteArray, ByteArray> {
        require(material.size == compositeSecretLen) {
            "composite secret key is ${material.size} octets, expected $compositeSecretLen"
        }
        return material.copyOfRange(0, eddsa.secretLen) to
            material.copyOfRange(eddsa.secretLen, compositeSecretLen)
    }

    /** Split a composite signature into (eddsaSignature, mldsaSignature). */
    fun splitSignature(value: ByteArray): Pair<ByteArray, ByteArray> {
        require(value.size == compositeSigLen) {
            "composite signature is ${value.size} octets, expected $compositeSigLen"
        }
        return value.copyOfRange(0, eddsa.sigLen) to
            value.copyOfRange(eddsa.sigLen, compositeSigLen)
    }

    /** EdDSA component first, then ML-DSA, as RFC 9980 requires. */
    fun join(eddsaPart: ByteArray, mldsaPart: ByteArray): ByteArray = eddsaPart + mldsaPart

    companion object {
        /** The composite signature suite for algorithm id 30 or 31, if either. */
        fun forAlgId(algId: Int): CompositeSignSuite? =
            entries.firstOrNull { it.algId == algId }
    }
}
