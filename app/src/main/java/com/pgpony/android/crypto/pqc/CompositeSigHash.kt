// CompositeSigHash.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Builds the v6 "dataDigest" that both composite components sign and verify
// over. BouncyCastle throws on the composite algorithm ids (30/31), so it will
// not compute this hash for us; this reproduces RFC 9580 Section 5.2.4 by
// hand. The result is fed to CompositeSigVerifier (and, later, the signer).
//
// For a v6 document signature the hash context is fed, in order (Section 5.2.4):
//
//   1. the v6 salt (before any other data),
//   2. the document data (binary: as-is; text: caller canonicalizes to
//      CRLF + UTF-8 first),
//   3. the trailer:
//        0x06, signature type, public-key algorithm, hash algorithm,
//        4-octet hashed-subpacket length, hashed-subpacket body,
//        0x06, 0xFF, 4-octet big-endian length of the fields from the
//        version octet through the hashed-subpacket body.
//
// The 4-octet counts are the v6 widths (Section 5.2.3); v4 used 2 octets.

package com.pgpony.android.crypto.pqc

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

object CompositeSigHash {

    /**
     * The v6 dataDigest for a document signature (RFC 9580 Section 5.2.4).
     * [data] is the already-canonicalized document (raw octets for a binary
     * signature). [hashedSubpacketBody] is the exact hashed-subpacket octets
     * from the signature packet, and [salt] its v6 salt.
     */
    fun v6DocumentDigest(
        hashAlgorithm: Int,
        salt: ByteArray,
        data: ByteArray,
        signatureType: Int,
        publicKeyAlgorithm: Int,
        hashedSubpacketBody: ByteArray
    ): ByteArray {
        val md = messageDigestFor(hashAlgorithm)

        // v6: salt first, then the document body.
        md.update(salt)
        md.update(data)

        // The hashed fields from the version octet through the hashed
        // subpacket body, which the trailer length then counts.
        val hashedFields = ByteArrayOutputStream().apply {
            write(0x06)
            write(signatureType and 0xFF)
            write(publicKeyAlgorithm and 0xFF)
            write(hashAlgorithm and 0xFF)
            write(uint32(hashedSubpacketBody.size))
            write(hashedSubpacketBody)
        }.toByteArray()

        md.update(hashedFields)
        md.update(byteArrayOf(0x06, 0xFF.toByte()))
        md.update(uint32(hashedFields.size))
        return md.digest()
    }

    private fun uint32(v: Int): ByteArray = byteArrayOf(
        (v ushr 24).toByte(),
        (v ushr 16).toByte(),
        (v ushr 8).toByte(),
        v.toByte()
    )

    /** Map an OpenPGP hash-algorithm id to its JCA MessageDigest. */
    private fun messageDigestFor(hashAlgorithm: Int): MessageDigest {
        val name = when (hashAlgorithm) {
            8 -> "SHA-256"
            9 -> "SHA-384"
            10 -> "SHA-512"
            12 -> "SHA3-256"
            14 -> "SHA3-512"
            else -> throw IllegalArgumentException(
                "unsupported hash algorithm id $hashAlgorithm for a composite signature"
            )
        }
        return MessageDigest.getInstance(name)
    }
}
