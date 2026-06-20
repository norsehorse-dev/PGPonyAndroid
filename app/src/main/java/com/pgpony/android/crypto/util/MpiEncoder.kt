// MpiEncoder.kt
// PGPony Android
//
// RFC 4880 §3.2 Multi-Precision Integer (MPI) encoding.
//
//   An MPI consists of:
//     - a two-octet scalar that is the length of the MPI in BITS
//       (NOT bytes), big-endian
//     - the actual integer value, big-endian, with all leading zero
//       octets stripped
//
//   The bit length is measured from the most-significant non-zero bit
//   of the value. Examples from the RFC:
//     [0x0F]        -> bit length 4    -> MPI = [0x00, 0x04, 0x0F]
//     [0x01, 0xFF]  -> bit length 9    -> MPI = [0x00, 0x09, 0x01, 0xFF]
//     [0x80, ... 32 bytes] -> bit length 256 -> MPI = [0x01, 0x00, 0x80, ...]
//
// Added in Phase A0 (Foundations). Used by:
// - Phase A2 SigningService for R and S in EdDSA signature output
// - Phase A7 export-time Cv25519 byte-reverse fallback (if BC export
//   needs a manual fix)
//
// Note: Bouncy Castle's PGPSignatureGenerator emits properly-encoded
// MPIs natively — this utility is for the hand-rolled fallback paths.

package com.pgpony.android.crypto.util

object MpiEncoder {

    /**
     * Encode `value` as a big-endian MPI per RFC 4880 §3.2.
     *
     * Leading zero bytes in `value` are stripped before encoding. A
     * value of all zeros (or an empty array) encodes as `[0x00, 0x00]`
     * (a zero-length, zero-valued MPI).
     */
    fun encode(value: ByteArray): ByteArray {
        if (value.isEmpty()) return byteArrayOf(0, 0)

        // Find the first non-zero byte
        var firstNonZero = 0
        while (firstNonZero < value.size && value[firstNonZero].toInt() == 0) {
            firstNonZero++
        }
        if (firstNonZero == value.size) return byteArrayOf(0, 0)

        val stripped = value.copyOfRange(firstNonZero, value.size)
        val highByte = stripped[0].toInt() and 0xFF
        // Integer.numberOfLeadingZeros returns leading zero bits in a 32-bit Int.
        // Our highByte occupies the low 8 bits, so subtract 24 to get the leading
        // zeros within just the byte.
        val leadingZeroBits = Integer.numberOfLeadingZeros(highByte) - 24
        val bitLength = stripped.size * 8 - leadingZeroBits

        val out = ByteArray(2 + stripped.size)
        out[0] = ((bitLength shr 8) and 0xFF).toByte()
        out[1] = (bitLength and 0xFF).toByte()
        System.arraycopy(stripped, 0, out, 2, stripped.size)
        return out
    }

    /**
     * Decode the MPI at `bytes[offset]`, returning the value (with
     * leading-zero padding restored if needed to reach `expectedByteLength`)
     * along with the total number of bytes consumed from the buffer.
     *
     * If `expectedByteLength` is null, the value is returned exactly as
     * the MPI encoded it (i.e. minimum bytes needed). Callers that need
     * a fixed-size value (e.g. 32 bytes for an Ed25519 R/S) should pass
     * the expected length so the result is left-padded with zeros.
     */
    fun decode(bytes: ByteArray, offset: Int = 0, expectedByteLength: Int? = null): Pair<ByteArray, Int> {
        require(offset + 1 < bytes.size) { "Truncated MPI at offset $offset" }
        val bitLength = ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
        val byteLength = (bitLength + 7) ushr 3
        require(offset + 2 + byteLength <= bytes.size) {
            "Truncated MPI body: need $byteLength bytes at offset ${offset + 2}, have ${bytes.size - offset - 2}"
        }
        val raw = bytes.copyOfRange(offset + 2, offset + 2 + byteLength)
        val padded = if (expectedByteLength != null && raw.size < expectedByteLength) {
            ByteArray(expectedByteLength).also { dst ->
                System.arraycopy(raw, 0, dst, expectedByteLength - raw.size, raw.size)
            }
        } else {
            raw
        }
        return padded to (2 + byteLength)
    }
}
