// BackupFileSniff.kt
// PGPony Android, 4.8.0 (#67): is a shared file a keyring backup, by its
// content?
//
// A PGPony backup is an armored PGP MESSAGE whose armor carries
// `Comment: PGPony Backup v1` (BackupService.ARMOR_COMMENT). An OpenKeychain
// backup is an armored PGP MESSAGE with a `Passphrase-Format:` header. Both
// open in Settings > Backup > Restore, so both count. The .pgpony extension
// alone is not enough: it counts only on a file that is an armored PGP
// MESSAGE, for a backup written without the comment. Text that merely
// mentions "PGPony Backup" (a note, an email about restoring) is not a
// backup, because only the armor headers are read.
//
// Pure, so it is unit tested (BackupFileSniffTest). Only the head of the
// file is needed: the armor headers sit right after the BEGIN line.

package com.pgpony.android.backup

object BackupFileSniff {

    /** How much of a file the headers are looked for in. The main app's own
     *  open path (IntentHandler.handleFileUri) sniffs the same 1 KB, so a
     *  file this calls a backup is one the main app routes to Restore too. */
    const val HEAD_BYTES = 1024

    private const val BEGIN_MESSAGE = "-----BEGIN PGP MESSAGE-----"

    /** True when [head] (the start of the file, any length) is a keyring
     *  backup that Restore takes. [filename] is the shared display name. */
    fun isKeyringBackup(head: ByteArray, filename: String?): Boolean {
        if (head.isEmpty()) return false
        val text = try {
            String(head, 0, minOf(head.size, HEAD_BYTES), Charsets.UTF_8)
        } catch (_: Exception) {
            return false
        }
        val begin = text.indexOf(BEGIN_MESSAGE)
        // A backup starts with its armor; only whitespace may come first.
        if (begin < 0 || text.substring(0, begin).isNotBlank()) return false
        val headers = text.substring(begin + BEGIN_MESSAGE.length)
            .lineSequence()
            .drop(1) // the rest of the BEGIN line
            .takeWhile { it.isNotBlank() }
            .toList()
        val pgponyComment = headers.any { line ->
            line.startsWith("Comment:", ignoreCase = true) &&
                line.contains("PGPony Backup", ignoreCase = true)
        }
        if (pgponyComment) return true
        val openKeychain = headers.any { it.startsWith("Passphrase-Format:", ignoreCase = true) }
        if (openKeychain) return true
        return filename?.trim()?.endsWith(".${BackupService.FILE_EXTENSION}", ignoreCase = true) == true
    }
}
