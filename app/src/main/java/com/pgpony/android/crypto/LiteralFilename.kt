// LiteralFilename.kt
// PGPony Android, 4.6.0 (item 17.3): the OpenPGP literal-data filename is
// chosen by whoever made the message. It is reduced to a plain base name the
// moment it is read, so no caller ever sees a path: separators (both kinds),
// NUL and other control characters are removed, "." and ".." are refused, and
// the length is capped. Anything that still writes it to disk goes through
// ScratchFiles.safeChild as well.

package com.pgpony.android.crypto

object LiteralFilename {

    private const val MAX_CHARS = 200

    /** A safe base name for [raw], or null when nothing usable remains. */
    fun sanitize(raw: String?): String? {
        if (raw == null) return null
        val base = raw.substringAfterLast('/').substringAfterLast('\\')
        val cleaned = base.filter { it >= ' ' && it != '\u007F' }.trim()
        if (cleaned.isEmpty() || cleaned == "." || cleaned == "..") return null
        return if (cleaned.length > MAX_CHARS) cleaned.take(MAX_CHARS) else cleaned
    }
}
