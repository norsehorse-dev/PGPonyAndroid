// ScratchFiles.kt
// PGPony Android — 4.0.4
//
// Backing store for the streaming file paths on the Encrypt and
// Decrypt tabs.
//
// Before 4.0.4 both tabs round-tripped whole files through memory: the
// picked file was read into a ByteArray held in UI state, the crypto
// core accumulated its output in a ByteArrayOutputStream (which doubles
// its backing array as it grows, then copies once more on
// toByteArray()), and the result went back into UI state as a second
// ByteArray. For a 13 MB input that peaked around 60 MB of largely
// contiguous allocations, which OOMs on a device with a modest heap.
// Reported as issue #6.
//
// Now the crypto core streams straight from the input content:// URI
// into a file under cacheDir/scratch/, and the result sheets read,
// save and share from that file. Peak memory is the 64 KiB chunk
// buffer regardless of file size.
//
// ── Lifecycle ────────────────────────────────────────────────────────
//
// The trade is that decrypted plaintext now touches disk. cacheDir is
// app-private storage (mode 0700, not world-readable, excluded from
// backup by android:allowBackup="false"), so it is not addressable by
// other apps, but it does outlive the process. So:
//
//   • clearAll() runs on app start (PGPonyApp.onCreate), clearing
//     anything a crash or a kill left behind.
//   • clearAll() runs when a result sheet is dismissed, matching the
//     old behaviour where dismissFileDecryptResult() dropped the
//     decrypted ByteArray.
//   • allocate() clears its own scope first, so each surface holds at
//     most one streamed output at a time.
//
// Deletion is a plain unlink, not a wipe. On the flash storage every
// modern Android device uses, overwriting a file does not reliably
// clear the underlying blocks anyway, and the filesystem is encrypted
// at rest. Callers that must not spill plaintext at all (the clipboard
// path, the inline preview) still work in memory on bounded slices.
//
// ── Sharing ──────────────────────────────────────────────────────────
//
// scratch/ is declared in res/xml/file_paths.xml, so uriFor() hands a
// content:// URI straight to a share target with no intermediate copy.
// The previous code wrote a second full-size copy into cacheDir/exports
// purely to have something to share.

package com.pgpony.android.ui.util

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File

object ScratchFiles {

    private const val DIR_NAME = "scratch"

    // ── Scopes ───────────────────────────────────────────────────────
    //
    // Three surfaces can each hold one streamed output at a time, and
    // they can be live simultaneously (the Quick Action runs in its own
    // activity over the main app). Each gets its own subdirectory so
    // allocating in one never disturbs another.
    const val SCOPE_ENCRYPT = "encrypt"
    const val SCOPE_DECRYPT = "decrypt"
    const val SCOPE_QUICK = "quick"

    /** cacheDir/scratch, created on demand. */
    fun dir(context: Context): File =
        File(context.cacheDir, DIR_NAME).apply { mkdirs() }

    /**
     * Reserve a file to stream an operation's output into.
     *
     * [displayName] is used verbatim as the filename so a share target
     * shows something meaningful, with path separators stripped — the
     * name can originate from an OpenPGP literal-data packet, which is
     * attacker-controlled, and "../" in it would otherwise escape the
     * scratch directory. Each allocation lands in its own numbered
     * subdirectory so two operations with the same output name cannot
     * collide.
     *
     * Clears this [scope]'s previous output first, so each surface holds
     * at most one streamed result at a time. See the SCOPE_ constants.
     */
    fun allocate(context: Context, displayName: String, scope: String): File {
        // Clear only this scope. Wiping the whole directory here would
        // let one surface delete another's output — a Quick Action share
        // dropping the file the Decrypt tab still has open in its result
        // sheet, for instance. Each surface owns exactly one live output.
        clearScope(context, scope)
        val safeName = displayName
            .substringAfterLast('/')
            .substringAfterLast('\\')
            .ifBlank { "output" }
        val slot = File(scopeDir(context, scope), System.nanoTime().toString()).apply { mkdirs() }
        return File(slot, safeName)
    }

    /** cacheDir/scratch/<scope>, created on demand. */
    private fun scopeDir(context: Context, scope: String): File =
        File(dir(context), scope).apply { mkdirs() }

    /** Delete one surface's scratch output, leaving the others alone. */
    fun clearScope(context: Context, scope: String) {
        runCatching {
            val d = File(File(context.cacheDir, DIR_NAME), scope)
            if (d.exists()) d.deleteRecursively()
        }
    }

    /**
     * A content:// URI for [file], suitable for ACTION_SEND. Requires
     * [file] to sit under [dir] — that is what file_paths.xml exposes.
     */
    fun uriFor(context: Context, file: File): Uri =
        FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )

    /**
     * Delete every scratch file. Safe to call when the directory does
     * not exist, and never throws: a failure to clean up must not take
     * down the caller (a result sheet dismissing, or app start).
     */
    fun clearAll(context: Context) {
        runCatching {
            val d = File(context.cacheDir, DIR_NAME)
            if (d.exists()) d.deleteRecursively()
        }
    }

    /**
     * Read at most [maxBytes] from the front of [file] and decode as
     * UTF-8, or null if the head is not valid UTF-8.
     *
     * Used for the result sheets' inline preview, which previously
     * decoded the entire output just to show the first few lines. A
     * truncated read can split a multi-byte sequence at the boundary,
     * so the tail is trimmed back to the last complete character rather
     * than failing the whole decode.
     */
    fun previewText(file: File, maxBytes: Int = 64 * 1024): String? = runCatching {
        val len = minOf(file.length(), maxBytes.toLong()).toInt()
        if (len <= 0) return@runCatching null
        val buf = ByteArray(len)
        val read = file.inputStream().use { it.read(buf) }
        if (read <= 0) return@runCatching null
        var end = read
        // Walk back off a trailing partial UTF-8 sequence (continuation
        // bytes are 10xxxxxx); at most 3 steps for a 4-byte codepoint.
        var steps = 0
        while (end > 0 && steps < 4 && (buf[end - 1].toInt() and 0xC0) == 0x80) {
            end--; steps++
        }
        if (end > 0 && (buf[end - 1].toInt() and 0x80) != 0) end--
        val text = String(buf, 0, end, Charsets.UTF_8)
        // A lossy decode means the bytes were not text at all.
        if (text.contains('�')) null else text
    }.getOrNull()

    /**
     * 4.6.0 (item 17.3): the only way to turn a name that may be untrusted (an
     * OpenPGP literal-data filename, a MIME filename, a User ID) into a file
     * under [parent]. Strips every path component and control character,
     * refuses "." and "..", and checks the canonical path really is a direct
     * child of [parent], so a name can never escape the directory.
     */
    fun safeChild(parent: File, untrustedName: String?, fallback: String = "output"): File {
        val name = com.pgpony.android.crypto.LiteralFilename.sanitize(untrustedName) ?: fallback
        val child = File(parent, name)
        require(child.canonicalFile.parentFile == parent.canonicalFile) { "unsafe output name" }
        return child
    }

    /** cacheDir/exports, the FileProvider-exposed directory share and export
     *  actions write into, created on demand. */
    fun exportsDir(context: Context): File =
        File(context.cacheDir, EXPORTS_DIR_NAME).apply { mkdirs() }

    /**
     * 4.6.0 (item 17.3): delete everything in cacheDir/exports. Buffered
     * plaintext and unprotected key exports used to linger there until the
     * system trimmed the cache. Called at app start and when a result sheet
     * that wrote there is dismissed. Never throws.
     */
    fun clearExports(context: Context) {
        runCatching {
            File(context.cacheDir, EXPORTS_DIR_NAME).listFiles()?.forEach { it.deleteRecursively() }
        }
    }

    private const val EXPORTS_DIR_NAME = "exports"

    /** True when [file] is small enough to hold in memory for clipboard use. */
    fun isClipboardSized(file: File): Boolean = file.length() in 1..(1L * 1024 * 1024)
}
