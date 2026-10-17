package com.pgpony.android.qr

import java.nio.ByteBuffer

/** Rectangle in unrotated analysis-image pixels; right and bottom are exclusive. */
data class PixelCrop(val left: Int, val top: Int, val right: Int, val bottom: Int) {
    val width: Int get() = right - left
    val height: Int get() = bottom - top
}

/** Bytes are borrowed until the next extraction on the same analyzer thread. */
data class LuminanceFrame(val bytes: ByteArray, val width: Int, val height: Int)

/** Copies only selected pixels, including rotation, into one bounded reusable buffer. */
class LuminanceFrameExtractor(private val maxPixels: Int = 4096 * 4096) {
    private var storage = ByteArray(0)

    /** Preserves the source position/limit; null means invalid geometry or missing Y pixels. */
    fun extract(buffer: ByteBuffer, width: Int, height: Int, rowStride: Int, pixelStride: Int,
        crop: PixelCrop = PixelCrop(0, 0, width, height), rotationDegrees: Int = 0): LuminanceFrame? {
        if (width <= 0 || height <= 0 || pixelStride <= 0 || rowStride <= 0 ||
            (rotationDegrees != 0 && rotationDegrees != 90 && rotationDegrees != 180 && rotationDegrees != 270) ||
            crop.left < 0 || crop.top < 0 || crop.right > width || crop.bottom > height ||
            crop.width <= 0 || crop.height <= 0) return null
        val count = crop.width.toLong() * crop.height
        if (count > maxPixels || (width - 1L) * pixelStride + 1 > rowStride) return null
        val base = buffer.position()
        val last = base.toLong() + (crop.bottom - 1L) * rowStride + (crop.right - 1L) * pixelStride
        if (last >= buffer.limit()) return null
        if (storage.size < count) storage = ByteArray(count.toInt())
        val outWidth = if (rotationDegrees % 180 == 0) crop.width else crop.height
        val outHeight = if (rotationDegrees % 180 == 0) crop.height else crop.width
        for (y in 0 until crop.height) {
            val sourceRow = base + (crop.top + y) * rowStride + crop.left * pixelStride
            for (x in 0 until crop.width) {
                val destination = when (rotationDegrees) {
                    90 -> x * crop.height + crop.height - 1 - y
                    180 -> (crop.height - 1 - y) * crop.width + crop.width - 1 - x
                    270 -> (crop.width - 1 - x) * crop.height + y
                    else -> y * crop.width + x
                }
                storage[destination] = buffer.get(sourceRow + x * pixelStride)
            }
        }
        return LuminanceFrame(storage, outWidth, outHeight)
    }
}
