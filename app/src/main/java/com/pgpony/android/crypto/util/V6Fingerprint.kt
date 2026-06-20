// V6Fingerprint.kt
// PGPony Android
//
// RFC 9580 §5.5.4 v6 fingerprint computation.
//
//   v6 fingerprint = SHA-256( 0x9B || 4-byte BE length of body || body )
//
// where `body` is the public-key packet body bytes (version + creation
// time + algorithm + public key material) — the same bytes that appear
// inside the tag-6 public-key packet on the wire.
//
// Two things differ from the v4 scheme (see V4Fingerprint.kt):
//   1. The hash is SHA-256, not SHA-1; the length prefix is 4 bytes
//      (big-endian) instead of 2; and the leading octet is 0x9B, not
//      0x99. The result is 32 bytes, not 20.
//   2. The 8-byte key ID is the LEADING 8 bytes of the fingerprint —
//      NOT the trailing 8 bytes as in v4. This is the single most common
//      v6 footgun: reusing the v4 `takeLast(...)` convention silently
//      yields the wrong key ID for v6 keys.
//
// Added in V6-1 (RFC 9580 plan). On Bouncy Castle 1.84,
// PGPPublicKey.getFingerprint() already returns the correct 32-byte v6
// fingerprint for keys parsed through BC's pipeline, so
// PGPCryptoService.fingerprintHex needs no change. This object is the
// canonical, unit-tested reference for the v6 framing + key-ID rule, and
// the basis for any future raw-packet path (QR import / migration) that
// computes a fingerprint outside BC — mirroring why V4Fingerprint exists.
//
// Unlike v4 (SHA-1), v6 uses SHA-256, so the fingerprint is collision-
// resistant, not merely an identity hash.

package com.pgpony.android.crypto.util

import java.security.MessageDigest

object V6Fingerprint {

    /** Leading octet of the v6 fingerprint hash input (RFC 9580 §5.5.4). */
    private const val V6_PREFIX = 0x9B.toByte()

    /**
     * Compute the 32-byte v6 fingerprint of a public-key packet body.
     * `publicKeyPacketBody` MUST be the body of the tag-6 packet —
     * NOT the framed packet (no CTB, no length prefix).
     */
    fun compute(publicKeyPacketBody: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val len = publicKeyPacketBody.size
        md.update(V6_PREFIX)
        md.update(((len ushr 24) and 0xFF).toByte())
        md.update(((len ushr 16) and 0xFF).toByte())
        md.update(((len ushr 8) and 0xFF).toByte())
        md.update((len and 0xFF).toByte())
        md.update(publicKeyPacketBody)
        return md.digest()
    }

    /** Same as `compute` but returns the uppercase hex string form. */
    fun computeHex(publicKeyPacketBody: ByteArray): String {
        return compute(publicKeyPacketBody).joinToString("") { "%02X".format(it) }
    }

    /**
     * Extract the 8-byte long key ID from a 32-byte v6 fingerprint.
     * Per RFC 9580 §5.5.4 the v6 key ID is the LEADING 8 bytes of the
     * fingerprint (the high-order 64 bits) — the opposite end from v4,
     * where it is the trailing 8 bytes.
     */
    fun longKeyIdFromFingerprint(fingerprint: ByteArray): ByteArray {
        require(fingerprint.size == 32) { "v6 fingerprint must be exactly 32 bytes, got ${fingerprint.size}" }
        return fingerprint.copyOfRange(0, 8)
    }

    /** Format a 32-byte fingerprint as the spaced hex string (groups of 4). */
    fun formatFingerprint(fingerprint: ByteArray): String {
        require(fingerprint.size == 32) { "v6 fingerprint must be exactly 32 bytes, got ${fingerprint.size}" }
        return fingerprint.joinToString("") { "%02X".format(it) }.chunked(4).joinToString(" ")
    }
}
