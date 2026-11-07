// CompressionPolicy.kt
// PGPony Android 4.8.0 (#104): one place that decides whether a streamed
// file encrypt compresses with ZLIB.

package com.pgpony.android.ui.encrypt

/**
 * 4.0.4: above this, file encrypt skips ZLIB.
 *
 * Deflate runs single-threaded over every byte and is the slowest stage
 * in the pipeline by a wide margin, well behind AES and the integrity
 * hash. On the files that get this big (video, photos, archives,
 * anything already compressed) it buys close to nothing, so paying
 * minutes for it is a bad trade. PGPCryptoService.encryptStream already
 * took enableCompression as a parameter for the card path, which skips
 * it for the same reason: to keep the card-held time short.
 *
 * Moved here from EncryptDecryptViewModel.kt in 4.8.0 (#104), so the
 * decision below can be tested without the ViewModel.
 *
 * Decrypt is unaffected: it decompresses whatever it is given.
 */
internal const val COMPRESSION_LIMIT: Long = 16L * 1024 * 1024

/**
 * 4.8.0 (#104): the ZLIB decision for a streamed file encrypt.
 *
 * Off by default, the Settings switch "Compress large files" keeps the
 * 4.0.4 rule above. On, it lifts the limit so every file is compressed,
 * still with ZLIB (the method every OpenPGP reader takes; decrypt here reads
 * ZIP, ZLIB and BZip2). A user asked for it for large CSV exports, which
 * do shrink a lot; the Encrypt progress already covers the longer run.
 *
 * The setting is passed in rather than read from prefs here, the same way
 * the Argon2 setting reaches PGPCryptoService, so crypto code never reads
 * Settings and the rule stays a pure function.
 *
 * There is no "skip already compressed formats" rule anywhere in the app,
 * so none is applied here: with the switch on, a video is compressed too.
 */
internal object CompressionPolicy {

    /** SharedPreferences key ("pgpony_prefs") for the Settings switch. */
    const val PREF_COMPRESS_LARGE_FILES = "compress_large_files"

    /**
     * True when a file of [sizeBytes] should be ZLIB-compressed.
     *
     * [sizeBytes] is the plaintext size as the caller knows it; a negative
     * value means unknown, which 4.0.4 already treated as "do not compress"
     * (only the switch turns it on then). [limit] is injectable for tests
     * so they need not push 16 MB through deflate.
     */
    fun shouldCompress(
        sizeBytes: Long,
        compressLargeFiles: Boolean,
        limit: Long = COMPRESSION_LIMIT
    ): Boolean = compressLargeFiles || sizeBytes in 0..limit
}
