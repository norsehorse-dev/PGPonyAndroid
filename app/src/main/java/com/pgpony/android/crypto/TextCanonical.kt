// TextCanonical.kt
// PGPony Android, 4.8.0 (item 4e): the canonical form of text signature data.
//
// A text signature (type 0x01) is made over text with CR LF line endings (RFC
// 9580 5.2.1.2). GnuPG hashes the literal data of an inline text signature as
// it is stored, so the literal data packet has to carry the text in that form
// already, as gpg --textmode writes it. A lone CR or a lone LF becomes CR LF,
// the same mapping PonySigGen and Bouncy Castle apply while hashing.

package com.pgpony.android.crypto

object TextCanonical {

    fun crlf(data: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream(data.size + data.size / 32 + 16)
        var i = 0
        while (i < data.size) {
            val b = data[i].toInt() and 0xFF
            when (b) {
                0x0D -> {
                    out.write(0x0D); out.write(0x0A)
                    if (i + 1 < data.size && data[i + 1].toInt() == 0x0A) i++
                }
                0x0A -> { out.write(0x0D); out.write(0x0A) }
                else -> out.write(b)
            }
            i++
        }
        return out.toByteArray()
    }
}
