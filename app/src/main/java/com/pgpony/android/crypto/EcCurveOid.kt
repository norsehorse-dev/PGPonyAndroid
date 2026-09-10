// EcCurveOid.kt
// PGPony Android — 4.5.0 (item 17 / Play review): resolve an elliptic-curve
// key's curve from its OID, so ECDSA / ECDH / EdDSA keys label their real curve
// (NIST P-256, brainpoolP384r1, ...) instead of a wrong "RSA 4096" or a blanket
// "Ed25519". BouncyCastle already parses the curve OID onto the BCPG key; this
// maps that OID to a human label. Mirrors the card path's OID table
// (CardAlgorithmAttributes) so both read curves the same way.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ECPublicBCPGKey
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
}
