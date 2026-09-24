// ZipPackaging.kt
// PGPony Android — 4.3.0 §5.6.3 (#31 zip output)
//
// A thin, streamed .zip packaging layer for encrypt results. The zip is
// transport packaging, NOT encryption: it wraps the already-encrypted
// .gpg/.asc so a store-and-forward channel that mangles those extensions
// still delivers the ciphertext intact. Single entry, streamed both ways
// so a large ciphertext never has to be held in memory (keeps the #32
// class fixed).

package com.pgpony.android.ui.util

import com.pgpony.android.crypto.LiteralFilename
import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.SecurityLimits
import java.io.InputStream
import java.io.OutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

object ZipPackaging {

    /** PGP ciphertext extensions we recognise as the payload inside a zip. */
    private val PGP_EXTENSIONS = listOf(".gpg", ".pgp", ".asc")

    /**
     * Write [body]'s bytes as ONE zip entry named [entryName] into [sink],
     * then close [sink]. Streamed: [body] receives the entry stream and may
     * copy an arbitrary-size source into it. The caller must NOT also close
     * [sink] (this owns it).
     */
    fun writeSingleEntry(sink: OutputStream, entryName: String, body: (OutputStream) -> Unit) {
        ZipOutputStream(sink).use { zip ->
            zip.putNextEntry(ZipEntry(safeEntryName(entryName)))
            body(zip)
            zip.closeEntry()
        }
    }

    /**
     * Like [writeSingleEntry] but finishes the archive WITHOUT closing [sink],
     * for callers that own and close the sink themselves (the bundle export
     * streams). The internal deflater is released by GC.
     */
    fun writeSingleEntryNoClose(sink: OutputStream, entryName: String, body: (OutputStream) -> Unit) {
        val zip = ZipOutputStream(sink)
        zip.putNextEntry(ZipEntry(safeEntryName(entryName)))
        body(zip)
        zip.closeEntry()
        zip.finish()
    }

    /**
     * 4.6.0: the name an entry is written under. A name can come from a picked
     * file's display name, which the providing app controls, so it is reduced
     * to a plain base name: no separators, so whoever unzips it gets one file
     * next to the archive, never a path outside it.
     */
    fun safeEntryName(name: String?): String = LiteralFilename.sanitize(name) ?: "encrypted.gpg"

    /**
     * Copy [input] into [out], refusing past [max] bytes with
     * [PGPCryptoError.ResourceLimitExceeded]. Returns the bytes copied. What
     * was written before the refusal stays in [out]; the caller deletes it.
     */
    fun copyToCapped(input: InputStream, out: OutputStream, max: Long = SecurityLimits.MAX_ZIP_PAYLOAD_BYTES): Long {
        val buf = ByteArray(DEFAULT_BUFFER_SIZE)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) return total
            total += n
            if (total > max) throw PGPCryptoError.ResourceLimitExceeded("zip entry larger than $max bytes")
            out.write(buf, 0, n)
        }
    }

    /** Counts entries as a scan walks an archive, refusing past the cap. */
    class EntryBudget(private val max: Int = SecurityLimits.MAX_ZIP_ENTRIES) {
        private var seen = 0
        fun next() {
            if (++seen > max) throw PGPCryptoError.ResourceLimitExceeded("zip has more than $max entries")
        }
    }

    /** True if the leading bytes are the local-file-header zip magic (PK). */
    fun looksLikeZip(prefix: ByteArray): Boolean =
        prefix.size >= 4 && prefix[0] == 0x50.toByte() && prefix[1] == 0x4B.toByte() &&
            prefix[2] == 0x03.toByte() && prefix[3] == 0x04.toByte()

    /** A ciphertext entry found inside a zip: its name and whether it is the sole one. */
    data class Entry(val name: String)

    /**
     * Scan [zipStream] (streamed, not fully buffered) and return the names of
     * entries that look like PGP ciphertext, by extension. Directory entries
     * and everything else are ignored. Caller decides single vs bundle from
     * the count. Does NOT close [zipStream].
     */
    fun listPgpEntries(zipStream: ZipInputStream): List<Entry> {
        val found = mutableListOf<Entry>()
        val budget = EntryBudget()
        var e: ZipEntry? = zipStream.nextEntry
        while (e != null) {
            budget.next()
            val name = e.name
            if (!e.isDirectory && PGP_EXTENSIONS.any { name.lowercase().endsWith(it) }) {
                found.add(Entry(name))
            }
            zipStream.closeEntry()
            e = zipStream.nextEntry
        }
        return found
    }

    /**
     * Open [source] as a zip and stream the FIRST entry whose name equals
     * [entryName] into [out]. Returns true if written. Streamed; closes
     * neither [source] nor [out]. Bounded: an entry past [max] bytes, or an
     * archive past [SecurityLimits.MAX_ZIP_ENTRIES] entries, is refused with
     * [PGPCryptoError.ResourceLimitExceeded].
     */
    fun extractEntry(
        source: InputStream,
        entryName: String,
        out: OutputStream,
        max: Long = SecurityLimits.MAX_ZIP_PAYLOAD_BYTES
    ): Boolean {
        val zip = ZipInputStream(source)
        val budget = EntryBudget()
        var e: ZipEntry? = zip.nextEntry
        while (e != null) {
            budget.next()
            if (!e.isDirectory && e.name == entryName) {
                copyToCapped(zip, out, max)
                zip.closeEntry()
                return true
            }
            zip.closeEntry()
            e = zip.nextEntry
        }
        return false
    }
}
