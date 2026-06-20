// ZBase32.kt
// PGPony Android
//
// z-base32 encoding (Phil Zimmermann variant) as required by the OpenPGP
// Web Key Directory spec (draft-koch-openpgp-webkey-service-15).
//
// IMPORTANT: This is NOT RFC 4648 base32. The alphabet is reordered for
// human-friendliness:
//
//   ybndrfg8ejkmcpqxot1uwisza345h769
//   0123456789012345678901234567890
//   0         1111111111222222222233
//
// Do NOT pull in a generic base32 library to satisfy WKD — they all use
// RFC 4648, which produces a different string.
//
// Verified test vector (from the WKD spec):
//   ZBase32.encode(SHA1("joe.doe"))
//     == "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
//
// Output is unpadded. Encoder packs 8-bit input into 5-bit groups
// big-endian; final group is padded with zero bits.
//
// Added in Phase A0 (Foundations). Used by Phase A5 WkdService to hash
// the email localpart before constructing the WKD URL.

package com.pgpony.android.crypto.util

object ZBase32 {

    private const val ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"

    /**
     * Encode `data` as an unpadded z-base32 string using the PGP alphabet.
     */
    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""

        val sb = StringBuilder()
        var buffer = 0
        var bitsInBuffer = 0

        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsInBuffer += 8
            while (bitsInBuffer >= 5) {
                bitsInBuffer -= 5
                val index = (buffer shr bitsInBuffer) and 0x1F
                sb.append(ALPHABET[index])
            }
        }

        // Drain any remaining bits, left-shifted to fill 5 bits with trailing zeros
        if (bitsInBuffer > 0) {
            val index = (buffer shl (5 - bitsInBuffer)) and 0x1F
            sb.append(ALPHABET[index])
        }

        return sb.toString()
    }
}
