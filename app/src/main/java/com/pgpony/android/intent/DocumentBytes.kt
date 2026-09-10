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
        val displayName: String?
    )

    fun readDetailed(resolver: ContentResolver, uri: Uri): Detailed {
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

        var best: ByteArray? = null
        fun consider(b: ByteArray?): Boolean {
            if (b == null) return false
            if (best == null || b.size > best!!.size) best = b
            return declaredSize?.let { b.size.toLong() == it } ?: b.isNotEmpty()
        }

        try {
            if (consider(resolver.openInputStream(uri)?.use { it.readBytes() })) {
                return Detailed(best, declaredSize, displayName)
            }
        } catch (_: Throwable) {}
        try {
            if (consider(resolver.openFileDescriptor(uri, "r")?.use { pfd ->
                    java.io.FileInputStream(pfd.fileDescriptor).readBytes()
                })) return Detailed(best, declaredSize, displayName)
        } catch (_: Throwable) {}
        try {
            if (consider(resolver.openAssetFileDescriptor(uri, "r")?.use { afd ->
                    afd.createInputStream().use { it.readBytes() }
                })) return Detailed(best, declaredSize, displayName)
        } catch (_: Throwable) {}
        for (mime in arrayOf("application/octet-stream", "*/*")) {
            try {
                if (consider(
                        resolver.openTypedAssetFileDescriptor(uri, mime, null)
                            ?.createInputStream()?.use { it.readBytes() }
                    )) return Detailed(best, declaredSize, displayName)
            } catch (_: Throwable) {}
        }
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
