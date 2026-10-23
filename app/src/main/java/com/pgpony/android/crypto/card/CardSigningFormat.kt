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

    // 4.7.1 (#102): ECDSA (algo 19). The card signs the raw hash and returns
    // r and s as two equal-length big-endian halves. Bouncy Castle's
    // PGPSignatureGenerator reads an ECDSA signature as DER, so it is
    // re-encoded here before BC sees it.

    /** OpenPGP ECDSA public-key algorithm id. */
    const val ECDSA = 19

    /** OpenPGP hash ids (RFC 9580 section 9.5). */
    const val HASH_SHA256 = 8
    const val HASH_SHA384 = 9
    const val HASH_SHA512 = 10

    /**
     * The hash an ECDSA card key signs with: at least as long as the curve, as
     * gpg does. 256-bit curves (P-256, secp256k1, brainpoolP256r1) use
     * SHA-256, 384-bit curves SHA-384, brainpoolP512r1 and P-521 SHA-512. An
     * unknown curve keeps SHA-256.
     */
    fun ecdsaHashFor(curveOid: String?): Int = when (curveOid) {
        "1.3.132.0.34", "1.3.36.3.3.2.8.1.1.11" -> HASH_SHA384
        "1.3.132.0.35", "1.3.36.3.3.2.8.1.1.13" -> HASH_SHA512
        else -> HASH_SHA256
    }

    /** The JCA digest name for an OpenPGP hash id used here. */
    fun digestName(hashId: Int): String = when (hashId) {
        HASH_SHA384 -> "SHA-384"
        HASH_SHA512 -> "SHA-512"
        else -> "SHA-256"
    }

    /**
     * The card's raw ECDSA output (r followed by s, each half the length) as
     * DER: SEQUENCE { INTEGER r, INTEGER s }. Each integer drops leading zero
     * bytes and gets one 0x00 back when its top bit is set, so it stays
     * positive.
     */
    fun rawEcdsaToDer(raw: ByteArray): ByteArray {
        require(raw.isNotEmpty() && raw.size % 2 == 0) { "ECDSA card signature has an odd length" }
        val half = raw.size / 2
        val r = derInteger(raw.copyOfRange(0, half))
        val s = derInteger(raw.copyOfRange(half, raw.size))
        return byteArrayOf(0x30) + derLength(r.size + s.size) + r + s
    }

    private fun derInteger(unsigned: ByteArray): ByteArray {
        var i = 0
        while (i < unsigned.size - 1 && unsigned[i] == 0.toByte()) i++
        var v = unsigned.copyOfRange(i, unsigned.size)
        if (v[0].toInt() and 0x80 != 0) v = byteArrayOf(0) + v
        return byteArrayOf(0x02) + derLength(v.size) + v
    }

    private fun derLength(len: Int): ByteArray = when {
        len < 0x80 -> byteArrayOf(len.toByte())
        len <= 0xFF -> byteArrayOf(0x81.toByte(), len.toByte())
        else -> byteArrayOf(0x82.toByte(), (len shr 8).toByte(), len.toByte())
    }
}
