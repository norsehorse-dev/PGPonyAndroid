// CompositePkeskStripper.kt
// PGPony Android — 4.5.0 RC7 (a tester, PGPony Android 4.4.1 feedback)
//
// Remove composite (post-quantum) PKESK packets from a message so BouncyCastle
// can decrypt the classical part of a MIXED multi-recipient message.
//
// The problem: when a message is encrypted to more than one recipient and at
// least one recipient's key is a composite PQC key (algorithm 8 LibrePGP, or
// 35/36 IETF), BouncyCastle's PKESK reader throws on the unknown algorithm and
// cannot reach a classical PKESK later in the same message. The composite
// decryptors handle the composite slots, but a holder of ONLY a classical key
// (whose own slot is classical, while a co-recipient is composite) then can't
// decrypt at all: the composite path finds no held composite key and throws,
// and BC can't parse past the composite packet.
//
// The fix: strip the composite PKESK packets, leaving the classical PKESKs, any
// SKESK, and the encrypted-data body untouched. Every PKESK wraps the SAME
// session key, so BC opens the classical slot and decrypts the body normally.
// Only used as a fallback, after the composite decryptors have declined.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ArmoredInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

object CompositePkeskStripper {

    /** [message] is the input with composite PKESK packets removed.
     *  [removedComposite] is true when at least one was stripped.
     *  [hasOtherEsk] is true when a classical PKESK or an SKESK remains, i.e.
     *  there is something for BouncyCastle to try. */
    class Result(
        val message: ByteArray,
        val removedComposite: Boolean,
        val hasOtherEsk: Boolean
    )

    private const val TAG_PKESK = 1
    private const val TAG_SKESK = 3

    // Composite public-key algorithm ids: 8 = LibrePGP v5 composite,
    // 35 = ML-KEM-768+X25519 (IETF), 36 = ML-KEM-1024+X448 (IETF).
    private val COMPOSITE_ALGOS = setOf(8, 35, 36)

    /** Returns null when the input is not a parseable OpenPGP packet stream or
     *  carries no leading ESK region we recognise. */
    fun strip(input: ByteArray): Result? {
        val data = toBinary(input)
        val out = ByteArrayOutputStream()
        var removedComposite = false
        var hasOtherEsk = false
        var i = 0
        val n = data.size
        while (i < n) {
            val first = data[i].toInt() and 0xFF
            if (first and 0x80 == 0) return null
            val tag = if (first and 0x40 != 0) first and 0x3F else (first shr 2) and 0x0F
            if (tag != TAG_PKESK && tag != TAG_SKESK) {
                // Body region begins here; keep it verbatim (partial lengths
                // and all), like the composite decryptors' split().
                out.write(data, i, n - i)
                return Result(out.toByteArray(), removedComposite, hasOtherEsk)
            }
            val h = header(data, i) ?: return null
            val packetEnd = h.bodyStart + h.bodyLen
            if (h.bodyLen < 0 || packetEnd > n || packetEnd <= i) return null
            if (tag == TAG_PKESK) {
                val algo = pkeskAlgorithm(data, h.bodyStart, h.bodyLen)
                if (algo != null && algo in COMPOSITE_ALGOS) {
                    removedComposite = true // drop this packet
                } else {
                    out.write(data, i, packetEnd - i)
                    hasOtherEsk = true
                }
            } else { // SKESK
                out.write(data, i, packetEnd - i)
                hasOtherEsk = true
            }
            i = packetEnd
        }
        return null // reached the end with no body packet: not our shape
    }

    /** Public-key algorithm octet of a v2/v3 or v6 PKESK body, or null. */
    private fun pkeskAlgorithm(data: ByteArray, bodyStart: Int, bodyLen: Int): Int? {
        if (bodyLen < 1) return null
        return when (data[bodyStart].toInt() and 0xFF) {
            2, 3 -> if (bodyLen >= 10) data[bodyStart + 9].toInt() and 0xFF else null
            6 -> {
                // v6: version(1), count(1), count octets (key version +
                // fingerprint), then the algorithm octet.
                if (bodyLen < 2) return null
                val count = data[bodyStart + 1].toInt() and 0xFF
                val algoOff = 2 + count
                if (bodyLen > algoOff) data[bodyStart + algoOff].toInt() and 0xFF else null
            }
            else -> null
        }
    }

    private class Header(val tag: Int, val bodyStart: Int, val bodyLen: Int)

    private fun header(data: ByteArray, start: Int): Header? {
        var i = start
        val c = data[i++].toInt() and 0xFF
        if (c and 0x80 == 0) return null
        val tag: Int
        val length: Int
        if (c and 0x40 != 0) {
            tag = c and 0x3F
            val l0 = data[i++].toInt() and 0xFF
            length = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (data[i++].toInt() and 0xFF) + 192
                l0 == 255 -> readUInt32(data, i).also { i += 4 }
                else -> return null // partial length on an ESK: not expected
            }
        } else {
            tag = (c shr 2) and 0x0F
            length = when (c and 0x03) {
                0 -> data[i++].toInt() and 0xFF
                1 -> (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> readUInt32(data, i).also { i += 4 }
                else -> data.size - i
            }
        }
        return Header(tag, i, length)
    }

    private fun readUInt32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    private fun toBinary(data: ByteArray): ByteArray {
        val looksArmored = data.isNotEmpty() && data[0].toInt() == '-'.code
        if (!looksArmored) return data
        ArmoredInputStream(ByteArrayInputStream(data)).use { return it.readBytes() }
    }
}
