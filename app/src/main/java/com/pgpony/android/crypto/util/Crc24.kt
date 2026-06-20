// Crc24.kt
// PGPony Android
//
// RFC 4880 §6.1 CRC-24 for ASCII armor.
// Polynomial 0x1864CFB, initial value 0xB704CE.
//
// Added in Phase A0 (Foundations). Used by:
// - Phase A2 SigningService for clear-sign armor checksum
// - Phase A6 SigningService for revocation certificate armor
// - Any future hand-rolled ASCII armor in the v6.0 backlog
//
// Reference values verified against Python implementation:
//   compute(empty)      == 0xB704CE
//   compute("hello")    == 0x47F58A
//   compute("123456789") == 0x21CF02

package com.pgpony.android.crypto.util

import java.util.Base64

object Crc24 {

    private const val INIT: Int = 0xB704CE
    private const val POLY: Int = 0x1864CFB

    /** Compute the 24-bit CRC of the given bytes, returned as a 24-bit Int. */
    fun compute(data: ByteArray): Int {
        var crc = INIT
        for (b in data) {
            crc = crc xor ((b.toInt() and 0xFF) shl 16)
            repeat(8) {
                crc = crc shl 1
                if ((crc and 0x1000000) != 0) {
                    crc = crc xor POLY
                }
            }
        }
        return crc and 0xFFFFFF
    }

    /** Return the CRC-24 of `data` as 3 raw bytes, big-endian. */
    fun computeBytes(data: ByteArray): ByteArray {
        val crc = compute(data)
        return byteArrayOf(
            ((crc shr 16) and 0xFF).toByte(),
            ((crc shr 8) and 0xFF).toByte(),
            (crc and 0xFF).toByte()
        )
    }

    /**
     * Return the CRC-24 of `data` as the base64-encoded 3-byte form that
     * appears on the `=XXXX` line at the end of ASCII armor blocks.
     */
    fun computeBase64(data: ByteArray): String {
        return Base64.getEncoder().encodeToString(computeBytes(data))
    }
}
