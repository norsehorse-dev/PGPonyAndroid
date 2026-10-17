package com.pgpony.android.qr

import android.graphics.Bitmap
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * Text frames and a shared symbol version, with at most three rendered bitmaps.
 * Construction probes capacity without retaining matrices. Render on a worker
 * dispatcher; calls and cache clearing are serialized. Eviction only drops our
 * reference, because Compose may still be displaying the previous bitmap.
 */
class QrFrameStore private constructor(
    private val frames: List<String>,
    val policy: QrEncodingPolicy,
    val layout: QrSymbolLayout,
) {
    val frameCount: Int get() = frames.size
    val version: Int get() = layout.version
    val errorCorrection: ErrorCorrectionLevel get() = policy.errorCorrection
    private val cache = QrFrameCache<Bitmap>()

    /** Returns a bitmap whose physical size is an integer number of modules. */
    @Synchronized
    fun bitmap(index: Int, targetPixels: Int = 800): Bitmap {
        require(index in frames.indices)
        require(targetPixels <= MAX_RENDER_PIXELS) { "QR display exceeds supported pixel size" }
        val size = layout.fit(targetPixels).symbolPixels
        return cache.get(index, size) { QrBitmap.render(frames[index], layout, policy, size) }
    }

    /** Release cached references; displayed bitmaps remain valid until their owner releases them. */
    @Synchronized
    fun clear() = cache.clear()

    companion object {
        // PGPONY2 currently uses at most 160 frames of fewer than 900 characters.
        // These bounds also accommodate the compatible transport and raw symbols.
        private const val MAX_STORED_FRAMES = 256
        private const val MAX_FRAME_CHARS = 4_096
        private const val MAX_STORED_CHARS = 256 * 4_096
        private const val MAX_RENDER_PIXELS = 4_096

        fun create(text: String, policy: QrEncodingPolicy = QrEncodingPolicy.BASELINE): QrFrameStore? =
            QrChunking.split(text, policy)?.let { fromFrames(it, policy) }

        /** Accepts framed text from either transport; it does not interpret the wire protocol. */
        fun fromFrames(frames: List<String>, policy: QrEncodingPolicy = QrEncodingPolicy.BASELINE): QrFrameStore {
            require(frames.isNotEmpty() && frames.size <= MAX_STORED_FRAMES)
            require(frames.all { it.isNotEmpty() && it.length <= MAX_FRAME_CHARS })
            require(frames.sumOf { it.length } <= MAX_STORED_CHARS)
            val snapshot = frames.toList()
            return QrFrameStore(snapshot, policy, QrSymbolLayout.forFrames(snapshot, policy))
        }
    }
}

/** Access-order cache shared by the Android store and JVM ownership tests. */
internal class QrFrameCache<T> {
    private data class Key(val index: Int, val pixels: Int)
    private val entries = LinkedHashMap<Key, T>(4, 0.75f, true)
    val size: Int get() = entries.size

    fun get(index: Int, pixels: Int, load: () -> T): T {
        val key = Key(index, pixels)
        entries[key]?.let { return it }
        val item = load()
        entries[key] = item
        while (entries.size > 3) entries.remove(entries.keys.first())
        return item
    }

    fun clear() = entries.clear()
}
