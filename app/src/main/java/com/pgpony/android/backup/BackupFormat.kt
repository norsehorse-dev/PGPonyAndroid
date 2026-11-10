// BackupFormat.kt
// PGPony Android, 4.8.0: the constants of the .pgpony backup format that
// more than one file needs (docs/PGPONY_BACKUP_FORMAT.md).
//
// Moved here from BackupService's companion, values unchanged. BackupService
// is app code (KeyRepository, PGPonyApp) and PGPony Desktop does not vendor
// it, so a shared file that named BackupService.FILE_EXTENSION, as
// BackupFileSniff did, could not compile there. Pure JVM, no imports.

package com.pgpony.android.backup

object BackupFormat {
    /** The armor Comment header of a PGPony backup. Readers sniff it. */
    const val ARMOR_COMMENT = "PGPony Backup v1"
    /** formatVersion in pgpony-meta.json. */
    const val FORMAT_VERSION = 1
    /** The file extension, without the dot. */
    const val FILE_EXTENSION = "pgpony"
}
