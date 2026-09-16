// EcdhCipherData.kt
// PGPony Android — HW Phase 3a
//
// Builds the Cipher DO passed to PSO:DECIPHER for ECDH. Pure / no card,
// unit-testable.
//
// Structure (OpenPGP card spec v3.4 §7.2.11):
//   A6 <len> { 7F49 <len> { 86 <len> <ephemeral public point> } }
//
// Lengths use BER-TLV definite-length encoding: short form for values below
// 128, long form (0x81 xx, or 0x82 xx xx) above that. For X25519 the point is
// the 32-byte u-coordinate in GnuPG's native format prefixed with 0x40 (33
// bytes), so every length stays short form (point 33 -> inner 35 -> template
// 38). NIST P-521's uncompressed point is 0x04||X||Y = 133 bytes, which pushes
// all three lengths past 127 into long form; the earlier short-form-only
// builder rejected that outright, which is why P-521 cards failed to decrypt.

package com.pgpony.android.crypto.card

object EcdhCipherData {

    /**
     * Wrap [point] (the ephemeral public key bytes, e.g. 0x40‖X for cv25519 or
     * 0x04‖X‖Y for NIST curves) into A6 { 7F49 { 86 point } }.
     */
    fun cipherDoForPoint(point: ByteArray): ByteArray {
        // 86 <len> <point>
        val ecPoint = byteArrayOf(OpenPgpCard.DO_PK_EC_POINT.toByte()) + berLen(point.size) + point

        // 7F49 <len> <86-DO>
        val template = byteArrayOf(0x7F, 0x49) + berLen(ecPoint.size) + ecPoint

        // A6 <len> <7F49-DO>
        return byteArrayOf(OpenPgpCard.DO_CIPHER.toByte()) + berLen(template.size) + template
    }

    /**
     * BER-TLV definite length: short form for values below 128, otherwise long
     * form with a leading count byte (0x81 for one length octet, 0x82 for two).
     * A card Cipher DO never approaches 65535 bytes.
     */
    private fun berLen(len: Int): ByteArray = when {
        len < 0x80 -> byteArrayOf(len.toByte())
        len < 0x100 -> byteArrayOf(0x81.toByte(), len.toByte())
        len < 0x10000 -> byteArrayOf(0x82.toByte(), (len ushr 8).toByte(), len.toByte())
        else -> throw IllegalArgumentException("length too large for BER-TLV: $len")
    }
}
