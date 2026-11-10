// BackupFileSniffTest.kt
// PGPony Android, 4.8.0 (#67): a keyring backup shared to the Quick Action is
// recognized by its content (the armor headers), not by its name alone.

package com.pgpony.android.backup

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class BackupFileSniffTest {

    /** An armored PGP MESSAGE with [headers], as BackupService.armorMessage writes one. */
    private fun armored(vararg headers: Pair<String, String>): ByteArray {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).apply {
            setHeader("Version", null)
            for ((k, v) in headers) setHeader(k, v)
            // A symmetric-key session packet header byte, then filler; only the armor matters here.
            write(byteArrayOf(0xC3.toByte(), 0x04, 0x04, 0x09, 0x03, 0x08) + ByteArray(200) { it.toByte() })
            close()
        }
        return out.toByteArray()
    }

    @Test
    fun `a PGPony backup is recognized by its armor comment, whatever its name`() {
        val backup = armored("Comment" to BackupFormat.ARMOR_COMMENT)
        assertTrue(BackupFileSniff.isKeyringBackup(backup, "pgpony-2026-11-05.pgpony"))
        assertTrue(BackupFileSniff.isKeyringBackup(backup, "renamed.asc"))
        assertTrue(BackupFileSniff.isKeyringBackup(backup, null))
    }

    @Test
    fun `an OpenKeychain backup is recognized by its Passphrase-Format header`() {
        val backup = armored("Passphrase-Format" to "numeric9x4")
        assertTrue(BackupFileSniff.isKeyringBackup(backup, "backup_2026-11-05.sec.pgp"))
    }

    @Test
    fun `CRLF line endings and leading whitespace still read as a backup`() {
        val crlf = String(armored("Comment" to BackupFormat.ARMOR_COMMENT), Charsets.UTF_8)
            .replace("\r\n", "\n").replace("\n", "\r\n")
        assertTrue(BackupFileSniff.isKeyringBackup(("\r\n  " + crlf).toByteArray(Charsets.UTF_8), null))
    }

    @Test
    fun `an ordinary encrypted message is not a backup`() {
        assertFalse(BackupFileSniff.isKeyringBackup(armored(), "message.asc"))
        assertFalse(BackupFileSniff.isKeyringBackup(armored("Comment" to "Made with PGPony"), "message.asc"))
    }

    @Test
    fun `the extension counts only on an armored message`() {
        // A .pgpony that is an armored message but carries no comment.
        assertTrue(BackupFileSniff.isKeyringBackup(armored(), "keys.pgpony"))
        assertTrue(BackupFileSniff.isKeyringBackup(armored(), "KEYS.PGPONY"))
        // A .pgpony that is not a PGP message at all.
        assertFalse(BackupFileSniff.isKeyringBackup("hello".toByteArray(), "keys.pgpony"))
        assertFalse(BackupFileSniff.isKeyringBackup(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47), "photo.pgpony"))
        assertFalse(BackupFileSniff.isKeyringBackup(ByteArray(0), "empty.pgpony"))
    }

    @Test
    fun `text that only mentions a backup is not one`() {
        val note = "How to restore a PGPony Backup v1\nPassphrase-Format: numeric9x4\n"
        assertFalse(BackupFileSniff.isKeyringBackup(note.toByteArray(), "notes.txt"))
        // A backup's armor quoted inside other text is not a backup file either.
        val quoted = "See below:\n\n" + String(armored("Comment" to BackupFormat.ARMOR_COMMENT), Charsets.UTF_8)
        assertFalse(BackupFileSniff.isKeyringBackup(quoted.toByteArray(Charsets.UTF_8), "mail.eml"))
    }

    @Test
    fun `a comment in the message body is not an armor header`() {
        val text = "-----BEGIN PGP MESSAGE-----\n\nComment: PGPony Backup v1\nwy4ECQMI\n-----END PGP MESSAGE-----\n"
        assertFalse(BackupFileSniff.isKeyringBackup(text.toByteArray(), "message.asc"))
    }
}
