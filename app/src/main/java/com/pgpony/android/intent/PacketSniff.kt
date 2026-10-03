// PacketSniff.kt
// PGPony Android 4.6.3 (#67, 4.7.0 item 2): route a shared or opened file by
// what its OpenPGP packets actually are, not by its first byte.
//
// IntentHandler decided "detached signature" from the first byte alone: it
// read that byte as a packet header and took tag 2 as a signature. A PNG starts
// with 0x89, which reads as an old-format header with tag 2, so every PNG
// shared into PGPony landed in Verify's signature field with the file field
// empty. Separately, an encrypted message whose recipients BouncyCastle could
// not list (a post-quantum PKESK, for one) fell through to Encrypt.
//
// This walks packet headers only (RFC 9580 section 4.2); it never parses
// packet contents beyond a version octet, and it reads nothing outside the
// array it is given.

package com.pgpony.android.intent

internal object PacketSniff {

    /** Larger than any real detached signature, ML-DSA-87 ones included. */
    const val MAX_SIGNATURE_FILE = 1 shl 20

    private const val TAG_PKESK = 1
    private const val TAG_SIGNATURE = 2
    private const val TAG_SKESK = 3

    private class Header(val tag: Int, val bodyStart: Int, val bodyLen: Int, val partial: Boolean)

    /** Formats that are never OpenPGP and whose first byte can look like a header. */
    fun isKnownNonOpenPgp(b: ByteArray): Boolean {
        fun at(i: Int) = if (i < b.size) b[i].toInt() and 0xFF else -1
        fun ascii(i: Int, s: String) = s.indices.all { at(i + it) == s[it].code }
        return (at(0) == 0x89 && ascii(1, "PNG")) ||
            (at(0) == 0xFF && at(1) == 0xD8 && at(2) == 0xFF) ||
            ascii(0, "GIF8") ||
            (ascii(0, "RIFF") && ascii(8, "WEBP")) ||
            ascii(0, "%PDF") ||
            (ascii(0, "PK") && at(2) == 0x03 && at(3) == 0x04)
    }

    /** The packet header at [pos], or null when it is not a well-formed one. */
    private fun header(b: ByteArray, pos: Int): Header? {
        if (pos >= b.size) return null
        val c = b[pos].toInt() and 0xFF
        if (c and 0x80 == 0) return null
        var i = pos + 1
        fun byte(): Int? = if (i < b.size) (b[i++].toInt() and 0xFF) else null
        if (c and 0x40 != 0) {
            val tag = c and 0x3F
            val l0 = byte() ?: return null
            return when {
                l0 < 192 -> Header(tag, i, l0, false)
                l0 < 224 -> {
                    val l1 = byte() ?: return null
                    Header(tag, i, ((l0 - 192) shl 8) + l1 + 192, false)
                }
                l0 == 255 -> {
                    var len = 0L
                    repeat(4) { len = (len shl 8) or (byte() ?: return null).toLong() }
                    if (len > Int.MAX_VALUE) return null
                    Header(tag, i, len.toInt(), false)
                }
                else -> Header(tag, i, 1 shl (l0 and 0x1F), true)
            }
        }
        val tag = (c shr 2) and 0x0F
        val len = when (c and 0x03) {
            0 -> byte() ?: return null
            1 -> ((byte() ?: return null) shl 8) or (byte() ?: return null)
            2 -> {
                var len = 0L
                repeat(4) { len = (len shl 8) or (byte() ?: return null).toLong() }
                if (len > Int.MAX_VALUE) return null
                len.toInt()
            }
            else -> return Header(tag, i, b.size - i, true) // indeterminate: to the end
        }
        return Header(tag, i, len, false)
    }

    /**
     * True only when [b] is one or more complete signature packets and
     * nothing else: a binary detached signature (gpg -b without --armor).
     */
    fun isDetachedSignature(b: ByteArray): Boolean {
        if (b.isEmpty() || b.size > MAX_SIGNATURE_FILE || isKnownNonOpenPgp(b)) return false
        var pos = 0
        var count = 0
        while (pos < b.size) {
            val h = header(b, pos) ?: return false
            if (h.tag != TAG_SIGNATURE || h.partial || h.bodyLen < 1) return false
            val end = h.bodyStart.toLong() + h.bodyLen
            if (end > b.size) return false
            val version = b[h.bodyStart].toInt() and 0xFF
            if (version !in 3..6) return false
            pos = end.toInt()
            count++
        }
        return count > 0
    }

    /**
     * True when [b] starts the way an encrypted OpenPGP message does: a
     * complete public-key (PKESK v3 or v6) or password (SKESK v4 to v6)
     * session-key packet. Only the head is needed, so a large file can be
     * checked from its first bytes.
     */
    fun looksLikeEncryptedMessage(b: ByteArray): Boolean {
        if (b.isEmpty() || isKnownNonOpenPgp(b)) return false
        val h = header(b, 0) ?: return false
        if (h.partial || h.bodyLen < 2) return false
        if (h.bodyStart.toLong() + h.bodyLen > b.size) return false
        val version = b[h.bodyStart].toInt() and 0xFF
        return when (h.tag) {
            TAG_PKESK -> version == 3 || version == 6
            TAG_SKESK -> version in 4..6
            else -> false
        }
    }
}
