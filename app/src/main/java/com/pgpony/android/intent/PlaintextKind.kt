// PlaintextKind.kt
// PGPony Android 4.7.0 (item 25, #67): tell decrypted text from a decrypted
// file by its content.
//
// The Quick Action decided text or file by whether String(data, UTF_8)
// produced something, and that lenient decode never fails, so a decrypted
// image with no literal filename (the composite ML-DSA inline path) was shown
// as text and offered as "message.txt". This uses a strict UTF-8 decode, NUL
// bytes, and the image and archive magic numbers PacketSniff already knows.

package com.pgpony.android.intent

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

internal object PlaintextKind {

    /** True when [data] reads as text: no known binary magic, no NUL, valid UTF-8. */
    fun isText(data: ByteArray): Boolean {
        if (data.isEmpty()) return true
        if (PacketSniff.isKnownNonOpenPgp(data)) return false
        if (data.any { it == 0.toByte() }) return false
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data))
            true
        } catch (_: CharacterCodingException) {
            false
        }
    }

    /** A file extension for a known binary format, without the dot, or null. */
    fun extensionFor(data: ByteArray): String? {
        fun at(i: Int) = if (i < data.size) data[i].toInt() and 0xFF else -1
        fun ascii(i: Int, s: String) = s.indices.all { at(i + it) == s[it].code }
        return when {
            at(0) == 0x89 && ascii(1, "PNG") -> "png"
            at(0) == 0xFF && at(1) == 0xD8 && at(2) == 0xFF -> "jpg"
            ascii(0, "GIF8") -> "gif"
            ascii(0, "RIFF") && ascii(8, "WEBP") -> "webp"
            ascii(0, "%PDF") -> "pdf"
            ascii(0, "PK") && at(2) == 0x03 && at(3) == 0x04 -> "zip"
            else -> null
        }
    }
}
