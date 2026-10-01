// LiteralFilename.kt
// PGPony Android, 4.6.0 (item 17.3): the OpenPGP literal-data filename is
// chosen by whoever made the message. It is reduced to a plain base name the
// moment it is read, so no caller ever sees a path: separators (both kinds),
// NUL and other control characters are removed, "." and ".." are refused, and
// the length is capped. Anything that still writes it to disk goes through
// ScratchFiles.safeChild as well.
//
// The name must also be a plain base name on Windows, whatever platform reads
// it (a file decrypted here may be copied there, and the desktop app runs
// there): a colon (a drive prefix such as "D:x", or an alternate data stream
// such as "a.txt:s") and the other characters Windows refuses in names
// (< > " | ? *) become "_", trailing dots and spaces are dropped (Windows
// drops them itself), and a reserved device name (CON, PRN, AUX, NUL, COM0 to
// COM9, LPT0 to LPT9, CONIN$, CONOUT$, with or without an extension) gets a
// leading "_".

package com.pgpony.android.crypto

object LiteralFilename {

    private const val MAX_CHARS = 200

    /** Characters Windows does not allow in a file name, besides separators. */
    private const val WINDOWS_RESERVED_CHARS = "<>:\"|?*"

    private val DEVICE_NAMES: Set<String> =
        setOf("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$") +
            (0..9).flatMap { listOf("COM$it", "LPT$it") } +
            listOf('¹', '²', '³').flatMap { listOf("COM$it", "LPT$it") }

    /** A safe base name for [raw], or null when nothing usable remains. */
    fun sanitize(raw: String?): String? {
        if (raw == null) return null
        val base = raw.substringAfterLast('/').substringAfterLast('\\')
        val cleaned = base
            .filter { it >= ' ' && it != '\u007F' }
            .map { if (it in WINDOWS_RESERVED_CHARS) '_' else it }
            .joinToString("")
            .trim()
            .trimEnd('.', ' ')
        if (cleaned.isEmpty() || cleaned == "." || cleaned == "..") return null
        val capped = (if (cleaned.length > MAX_CHARS) cleaned.take(MAX_CHARS) else cleaned).trimEnd('.', ' ')
        if (capped.isEmpty()) return null
        return if (isDeviceName(capped)) "_$capped" else capped
    }

    /**
     * [name] is a Windows reserved device name, alone or with an extension
     * ("NUL", "com1.txt", "Aux .tar.gz"): its part before the first dot,
     * without trailing spaces, compared without case.
     */
    fun isDeviceName(name: String): Boolean {
        val stem = name.substringBefore('.').trimEnd(' ')
        return DEVICE_NAMES.any { it.equals(stem, ignoreCase = true) }
    }
}
