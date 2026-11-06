// EcCurveOid.kt
// PGPony Android — 4.5.0 (item 17 / Play review): resolve an elliptic-curve
// key's curve from its OID, so ECDSA / ECDH / EdDSA keys label their real curve
// (NIST P-256, brainpoolP384r1, ...) instead of a wrong "RSA 4096" or a blanket
// "Ed25519". BouncyCastle already parses the curve OID onto the BCPG key; this
// maps that OID to a human label. Mirrors the card path's OID table
// (CardAlgorithmAttributes) so both read curves the same way.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.card.CardSigningFormat
import org.bouncycastle.bcpg.ECPublicBCPGKey
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKey

object EcCurveOid {

    /** Dotted curve OID → human label. */
    val LABELS: Map<String, String> = mapOf(
        "1.2.840.10045.3.1.7" to "NIST P-256",
        "1.3.132.0.34" to "NIST P-384",
        "1.3.132.0.35" to "NIST P-521",
        "1.3.132.0.10" to "secp256k1",
        "1.3.36.3.3.2.8.1.1.7" to "brainpoolP256r1",
        "1.3.36.3.3.2.8.1.1.11" to "brainpoolP384r1",
        "1.3.36.3.3.2.8.1.1.13" to "brainpoolP512r1",
        "1.3.6.1.4.1.11591.15.1" to "Ed25519",       // OpenPGP legacy EdDSA OID
        "1.3.6.1.4.1.3029.1.5.1" to "Curve25519",     // OpenPGP legacy ECDH (Cv25519)
        "1.3.101.112" to "Ed25519",                   // RFC 8410
        "1.3.101.110" to "X25519",                    // RFC 8410
        "1.3.101.113" to "Ed448",                     // RFC 8410
        "1.3.101.111" to "X448"                       // RFC 8410
    )

    /** The dotted curve OID for an EC (algo 18/19/22) key, or null if the key is
     *  not curve-based or BouncyCastle did not parse a curve OID. */
    fun oidOf(publicKey: PGPPublicKey): String? =
        (publicKey.publicKeyPacket.key as? ECPublicBCPGKey)?.curveOID?.id

    /** The human curve label for an EC key, or null when the curve is unknown. */
    fun label(publicKey: PGPPublicKey): String? = oidOf(publicKey)?.let { LABELS[it] }

    /**
     * 4.8.0 (4l, #109): a component label for an ECDH key on a Weierstrass
     * curve ("ECDH brainpoolP384r1"), or null for any other key. detectAlgorithm
     * labels such a subkey Unknown, since KeyAlgorithm has no ECDH entries; the
     * choosers that list single keys use this instead.
     */
    fun ecdhLabel(publicKey: PGPPublicKey): String? {
        if (publicKey.algorithm != PublicKeyAlgorithmTags.ECDH) return null
        val curve = label(publicKey) ?: return null
        if (curve == "Curve25519" || curve == "X25519" || curve == "X448") return null
        return "ECDH $curve"
    }

    /**
     * 4.8.0 (4l, #109): the hash a new signature by [publicKey] uses when the
     * caller asks for [requested]. An ECDSA key signs with a hash at least as
     * long as its curve, as gpg does when it signs: SHA-384 for a 384-bit
     * curve, SHA-512 for brainpoolP512r1 and P-521 (the table
     * CardSigningFormat.ecdsaHashFor keeps for card keys). A longer
     * [requested] hash is kept; every other key type gets [requested]
     * unchanged.
     */
    fun signatureHash(publicKey: PGPPublicKey, requested: Int): Int {
        // 4.8.0 (#86): RFC 9580 wants a 512-bit hash for Ed448 signatures.
        if (isEd448(publicKey)) {
            return if (digestBits(requested) >= 512) requested else HashAlgorithmTags.SHA512
        }
        if (publicKey.algorithm != PublicKeyAlgorithmTags.ECDSA) return requested
        val minimum = CardSigningFormat.ecdsaHashFor(oidOf(publicKey))
        return if (digestBits(requested) >= digestBits(minimum)) requested else minimum
    }

    /** 4.8.0 (#86): an Ed448 key, as algorithm 28 or as legacy EdDSA on the Ed448 curve. */
    fun isEd448(publicKey: PGPPublicKey): Boolean =
        publicKey.algorithm == PublicKeyAlgorithmTags.Ed448 ||
            (publicKey.algorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY && oidOf(publicKey) == ED448_OID)

    private const val ED448_OID = "1.3.101.113"

    /** Digest length in bits of an OpenPGP hash id; 0 when unknown here. */
    private fun digestBits(hashAlgorithm: Int): Int = when (hashAlgorithm) {
        HashAlgorithmTags.SHA1, HashAlgorithmTags.RIPEMD160 -> 160
        HashAlgorithmTags.SHA224 -> 224
        HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA3_256 -> 256
        HashAlgorithmTags.SHA384 -> 384
        HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA3_512 -> 512
        else -> 0
    }
}
