// DocumentBytes.kt
// PGPony Android — 3.1.0 Phase 8 Fix1
//
// Robust ContentResolver byte reader. Origin: NorseHorse device test —
// importing a public key by file said "No key data" while pasting the
// SAME content worked. openInputStream() returns null or throws for a
// class of documents that are perfectly readable by other means:
//
//   • virtual / cloud-backed documents (Google Drive, OneDrive, some
//     Files providers) that only stream via a typed AssetFileDescriptor
//   • providers that gate the plain stream but serve typed streams
//
// Every file entry point funnels through here now: the Import screen's
// Choose File, open-with routing (handleFileUri), multi-file share-in,
// and share-classify. Read order: plain stream first (the common,
// cheap case), then typed asset descriptors from most-specific to
// wildcard. Returns null only when every route failed — callers
// surface a READ error for that, distinct from "no key data".

package com.pgpony.android.intent

import android.content.ContentResolver
import android.net.Uri

object DocumentBytes {

    /**
     * 3.1.0 Phase 8 Fix3 (origin: on-device diagnostic — a 1197-byte
     * .asc came back as 2 non-printable bytes, i.e. a provider served
     * an effectively-empty typed "conversion" instead of the file).
     * The ladder now (a) queries the provider's DECLARED size and
     * display name first, (b) tries multiple raw routes before any
     * typed route, (c) validates every candidate against the declared
     * size, returning the first exact match, and only otherwise the
     * largest thing any route produced. text/plain was REMOVED from
     * the typed list — it invites lossy text conversion; the typed
     * rung is octet-stream and wildcard only, and runs last.
     */
    data class Detailed(
        val bytes: ByteArray?,
        val declaredSize: Long?,
        val displayName: String?,
        /** 4.6.3: the file is over the caller's maxBytes, so nothing was kept. */
        val tooLarge: Boolean = false
    )

    /** 4.6.3: thrown inside the ladder when a route goes past maxBytes. */
    private class OverLimit : Exception()

    /** Read [input] fully, or throw [OverLimit] once it passes [max]. */
    private fun readBounded(input: java.io.InputStream, max: Long): ByteArray {
        if (max == Long.MAX_VALUE) return input.readBytes()
        val out = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val n = input.read(chunk)
            if (n < 0) break
            total += n
            if (total > max) throw OverLimit()
            out.write(chunk, 0, n)
        }
        return out.toByteArray()
    }

    /**
     * 4.6.3 (4.7.0 item 19 F, Play crash): [maxBytes] bounds every route.
     * Picking a large non-key file to import as a key read it whole, and the
     * key preview then copied it into a String and an armored copy, which ran
     * out of memory. Past [maxBytes] this returns [Detailed.tooLarge] with no
     * bytes; a declared size past it is refused before anything is read.
     */
    fun readDetailed(resolver: ContentResolver, uri: Uri, maxBytes: Long = Long.MAX_VALUE): Detailed {
        var declaredSize: Long? = null
        var displayName: String? = null
        try {
            resolver.query(
                uri,
                arrayOf(
                    android.provider.OpenableColumns.SIZE,
                    android.provider.OpenableColumns.DISPLAY_NAME
                ),
                null, null, null
            )?.use { c ->
                if (c.moveToFirst()) {
                    if (!c.isNull(0)) declaredSize = c.getLong(0)
                    if (!c.isNull(1)) displayName = c.getString(1)
                }
            }
        } catch (_: Exception) {
            // metadata is best-effort
        }

        if (declaredSize?.let { it > maxBytes } == true) {
            return Detailed(null, declaredSize, displayName, tooLarge = true)
        }
        var overLimit = false

        var best: ByteArray? = null
        fun consider(b: ByteArray?): Boolean {
            if (b == null) return false
            if (best == null || b.size > best!!.size) best = b
            return declaredSize?.let { b.size.toLong() == it } ?: b.isNotEmpty()
        }

        try {
            if (consider(resolver.openInputStream(uri)?.use { readBounded(it, maxBytes) })) {
                return Detailed(best, declaredSize, displayName)
            }
        } catch (_: OverLimit) { overLimit = true } catch (_: Throwable) {}
        try {
            if (consider(resolver.openFileDescriptor(uri, "r")?.use { pfd ->
                    readBounded(java.io.FileInputStream(pfd.fileDescriptor), maxBytes)
                })) return Detailed(best, declaredSize, displayName)
        } catch (_: OverLimit) { overLimit = true } catch (_: Throwable) {}
        try {
            if (consider(resolver.openAssetFileDescriptor(uri, "r")?.use { afd ->
                    afd.createInputStream().use { readBounded(it, maxBytes) }
                })) return Detailed(best, declaredSize, displayName)
        } catch (_: OverLimit) { overLimit = true } catch (_: Throwable) {}
        for (mime in arrayOf("application/octet-stream", "*/*")) {
            try {
                if (consider(
                        resolver.openTypedAssetFileDescriptor(uri, mime, null)
                            ?.createInputStream()?.use { readBounded(it, maxBytes) }
                    )) return Detailed(best, declaredSize, displayName)
            } catch (_: OverLimit) { overLimit = true } catch (_: Throwable) {}
        }
        if (overLimit && best == null) return Detailed(null, declaredSize, displayName, tooLarge = true)
        return Detailed(best, declaredSize, displayName)
    }

    fun read(resolver: ContentResolver, uri: Uri): ByteArray? =
        readDetailed(resolver, uri).bytes

    /**
     * 4.0.4 — the provider's declared size, or null when it doesn't
     * report one. Used to decide whether a shared file can be read into
     * memory at all before anything tries to (issue #6).
     */
    fun declaredSize(resolver: ContentResolver, uri: Uri): Long? = try {
        resolver.query(
            uri, arrayOf(android.provider.OpenableColumns.SIZE), null, null, null
        )?.use { c ->
            if (c.moveToFirst() && !c.isNull(0)) c.getLong(0) else null
        }
    } catch (e: Exception) {
        null
    }

    /**
     * 4.0.4 — read at most [maxBytes] from the front of [uri].
     *
     * Deliberately the plain stream only, not the full typed-descriptor
     * ladder above: this is for classifying a file too big to hold in
     * memory, and every marker that classification looks at (armor
     * headers, RFC 3156 boundaries, OpenPGP session-key packets) sits at
     * the very front. A provider that needs the typed ladder is serving
     * a converted document, which is not the large-binary case this
     * exists for. Returns null if the stream can't be opened.
     */
    fun readHead(resolver: ContentResolver, uri: Uri, maxBytes: Int): ByteArray? = try {
        resolver.openInputStream(uri)?.use { input ->
            val buf = ByteArray(maxBytes)
            var total = 0
            while (total < maxBytes) {
                val n = input.read(buf, total, maxBytes - total)
                if (n <= 0) break
                total += n
            }
            buf.copyOf(total)
        }
    } catch (e: Exception) {
        null
    }
}
