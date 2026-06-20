// EcdhCipherData.kt
// PGPony Android — HW Phase 3a
//
// Builds the Cipher DO passed to PSO:DECIPHER for ECDH. Pure / no card,
// unit-testable.
//
// Structure (OpenPGP card spec v3.4 §7.2.11):
//   A6 <len> { 7F49 <len> { 86 <len> <ephemeral public point> } }
//
// For cv25519 (X25519) the ephemeral point is the 32-byte u-coordinate in
// GnuPG's native format — i.e. prefixed with 0x40, giving 33 bytes. The
// caller supplies whatever point bytes belong in the 86 DO; this builder
// only does the TLV wrapping. All three lengths are short-form (< 128),
// which always holds for X25519 (point ≤ 33 → inner 35 → template 38).

package com.pgpony.android.crypto.card

object EcdhCipherData {

    /**
     * Wrap [point] (the ephemeral public key bytes, e.g. 0x40‖X for
     * cv25519) into A6 { 7F49 { 86 point } }.
     */
    fun cipherDoForPoint(point: ByteArray): ByteArray {
        require(point.size < 0x80) { "ECDH point too large for short-form TLV: ${point.size}" }

        // 86 <len> <point>
        val ecPoint = byteArrayOf(OpenPgpCard.DO_PK_EC_POINT.toByte(), point.size.toByte()) + point
        require(ecPoint.size < 0x80) { "public-key template too large for short-form TLV" }

        // 7F49 <len> <86-DO>
        val template = byteArrayOf(0x7F, 0x49, ecPoint.size.toByte()) + ecPoint
        require(template.size < 0x80) { "cipher DO too large for short-form TLV" }

        // A6 <len> <7F49-DO>
        return byteArrayOf(OpenPgpCard.DO_CIPHER.toByte(), template.size.toByte()) + template
    }
}
