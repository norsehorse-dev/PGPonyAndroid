// CardSigningFormat.kt
// PGPony Android — HW Phase 2b
//
// Pure formatting of the value sent to the card's PSO:COMPUTE DIGITAL
// SIGNATURE, by key algorithm. Kept separate from the BouncyCastle bridge
// so it's unit-testable on the JVM without a card or BC.
//
//   • RSA (algo 1/2/3): the card performs PKCS#1 v1.5 padding + the RSA
//     private operation, so it expects the full DigestInfo (ASN.1 prefix
//     for the hash OID + the raw digest). We prepend the SHA-256
//     DigestInfo prefix.
//   • EdDSA-legacy (algo 22): the card signs the raw hash directly
//     (OpenPGP "prehashed" Ed25519), so we send the digest as-is.
//
// SHA-256 only for now — the prefix below is SHA-256-specific and the
// content signer fixes the hash at SHA-256 to match.

package com.pgpony.android.crypto.card

object CardSigningFormat {

    /** PKCS#1 v1.5 DigestInfo prefix for SHA-256 (RFC 8017 §9.2). */
    val SHA256_DIGESTINFO_PREFIX = byteArrayOf(
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48,
        0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    )

    // OpenPGP public-key algorithm IDs (numeric to avoid BC constant-name
    // drift across versions): RSA = 1/2/3, ECDSA = 19, EdDSA-legacy = 22.
    private val RSA_ALGS = setOf(1, 2, 3)

    /**
     * Prepare the PSO:CDS input for [keyAlgorithm] over the SHA-256
     * [digest]. RSA gets the DigestInfo prefix prepended; everything else
     * (EdDSA) sends the raw digest.
     */
    fun prepareInput(keyAlgorithm: Int, digest: ByteArray): ByteArray =
        if (keyAlgorithm in RSA_ALGS) SHA256_DIGESTINFO_PREFIX + digest else digest

    fun isRsa(keyAlgorithm: Int): Boolean = keyAlgorithm in RSA_ALGS
}
