// SubpacketLength.kt
// PGPony Android
//
// RFC 4880 §5.2.3.1 subpacket length encoding.
// Used both for building hashed/unhashed subpackets in signatures and
// for parsing incoming signature packets that arrive bit-for-bit.
//
//   length < 192      : 1 byte
//   192 <= length < 8384 : 2 bytes  ( ((b1 - 192) << 8) + b2 + 192 )
//   length >= 8384    : 5 bytes  ( 0xFF + 4-byte big-endian length )
//
// New-format packet headers use the SAME length encoding scheme on top of
// the CTB byte, per RFC 4880 §4.2.2.
//
// Added in Phase A0 (Foundations). Used by:
// - Phase A2 SigningService (if hand-rolling v4 signature packet bytes)
// - Phase A7 export-time Cv25519 byte-reverse fallback (if BC export
//   needs a manual fix)

package com.pgpony.android.crypto.util

object SubpacketLength {

    /** Result of decoding one length-prefix from a byte buffer. */
    data class Decoded(
        /** The decoded length value. */
        val length: Int,
        /** Number of bytes consumed from the buffer (1, 2, or 5). */
        val bytesRead: Int
    )

    /**
     * Encode `length` using the shortest valid form per RFC 4880 §5.2.3.1.
     * Throws if `length` is negative.
     */
    fun encode(length: Int): ByteArray {
        require(length >= 0) { "Length must be non-negative, got $length" }
        return when {
            length < 192 -> byteArrayOf(length.toByte())
            length < 8384 -> {
                val adjusted = length - 192
                byteArrayOf(
                    (((adjusted shr 8) and 0xFF) + 192).toByte(),
                    (adjusted and 0xFF).toByte()
                )
            }
            else -> byteArrayOf(
                0xFF.toByte(),
                ((length shr 24) and 0xFF).toByte(),
                ((length shr 16) and 0xFF).toByte(),
                ((length shr 8) and 0xFF).toByte(),
                (length and 0xFF).toByte()
            )
        }
    }

    /**
     * Decode the length prefix at `bytes[offset]`. Returns the decoded
     * length and the number of bytes consumed.
     *
     * Note: this implementation rejects partial-body lengths (b1 in
     * 224..254). Subpacket length prefixes never use partial-body form,
     * but if you point this at a packet-header byte that happens to be
     * partial-body, you'll get an exception. That's the correct
     * behavior for subpacket parsing.
     */
    fun decode(bytes: ByteArray, offset: Int = 0): Decoded {
        require(offset < bytes.size) { "Offset $offset past end of buffer (size ${bytes.size})" }
        val b1 = bytes[offset].toInt() and 0xFF
        return when {
            b1 < 192 -> Decoded(length = b1, bytesRead = 1)
            b1 < 224 -> {
                require(offset + 1 < bytes.size) { "Truncated 2-byte length at offset $offset" }
                val b2 = bytes[offset + 1].toInt() and 0xFF
                Decoded(length = ((b1 - 192) shl 8) + b2 + 192, bytesRead = 2)
            }
            b1 == 255 -> {
                require(offset + 4 < bytes.size) { "Truncated 5-byte length at offset $offset" }
                val length =
                    ((bytes[offset + 1].toInt() and 0xFF) shl 24) or
                    ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
                    ((bytes[offset + 3].toInt() and 0xFF) shl 8) or
                    (bytes[offset + 4].toInt() and 0xFF)
                Decoded(length = length, bytesRead = 5)
            }
            else -> throw IllegalArgumentException(
                "Partial-body length 0x${b1.toString(16)} not valid in subpacket context"
            )
        }
    }
}
