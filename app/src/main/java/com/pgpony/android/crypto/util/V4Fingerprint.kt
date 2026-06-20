// V4Fingerprint.kt
// PGPony Android
//
// RFC 4880 §12.2 v4 fingerprint computation.
//
//   v4 fingerprint = SHA-1( 0x99 || 2-byte BE length of body || body )
//
// where `body` is the public-key packet body bytes (version + creation
// time + algorithm + algorithm-specific key material) — the same bytes
// that appear inside the tag-6 public-key packet on the wire.
//
// The v4 fingerprint is 20 bytes. The 8-byte long key ID is the last
// 8 bytes of the fingerprint.
//
// Added in Phase A0 (Foundations). Used as a fallback when:
// - Bouncy Castle's PGPPublicKey.fingerprint is unavailable for some
//   reason (e.g. parsing raw packet bytes outside of BC's pipeline)
// - Phase A1 SubkeyMigrationService needs to compute a fingerprint
//   from raw packet bytes during migration
//
// Note: SHA-1 is collision-broken for adversaries who can choose both
// inputs, but the OpenPGP spec still uses it for fingerprint identity
// (and the WKD spec uses it for email-localpart bucketing). We're not
// signing anything here — just identifying keys.

package com.pgpony.android.crypto.util

import java.security.MessageDigest

object V4Fingerprint {

    /**
     * Compute the 20-byte v4 fingerprint of a public-key packet body.
     * `publicKeyPacketBody` MUST be the body of the tag-6 packet —
     * NOT the framed packet (no CTB, no length prefix).
     */
    fun compute(publicKeyPacketBody: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-1")
        val len = publicKeyPacketBody.size
        md.update(0x99.toByte())
        md.update(((len shr 8) and 0xFF).toByte())
        md.update((len and 0xFF).toByte())
        md.update(publicKeyPacketBody)
        return md.digest()
    }

    /** Same as `compute` but returns the uppercase hex string form. */
    fun computeHex(publicKeyPacketBody: ByteArray): String {
        return compute(publicKeyPacketBody).joinToString("") { "%02X".format(it) }
    }

    /**
     * Extract the 8-byte long key ID from a 20-byte v4 fingerprint.
     * The long key ID is the trailing 8 bytes of the fingerprint.
     */
    fun longKeyIdFromFingerprint(fingerprint: ByteArray): ByteArray {
        require(fingerprint.size == 20) { "v4 fingerprint must be exactly 20 bytes, got ${fingerprint.size}" }
        return fingerprint.copyOfRange(12, 20)
    }

    /** Format a 20-byte fingerprint as the spaced 40-char hex string. */
    fun formatFingerprint(fingerprint: ByteArray): String {
        require(fingerprint.size == 20) { "v4 fingerprint must be exactly 20 bytes, got ${fingerprint.size}" }
        return fingerprint.joinToString("") { "%02X".format(it) }.chunked(4).joinToString(" ")
    }
}
