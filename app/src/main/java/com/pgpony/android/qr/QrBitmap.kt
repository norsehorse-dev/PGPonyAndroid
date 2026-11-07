package com.pgpony.android.qr

import android.graphics.Bitmap

/** Android bitmap rendering; protocol and physical module geometry remain independently testable. */
object QrBitmap {
    /** Compatibility API. New display flows should retain [QrFrameStore] and render on demand. */
    fun encodeFrames(text: String): List<Bitmap>? = QrFrameStore.create(text)?.let { sequence ->
        (0 until sequence.frameCount).map { sequence.bitmap(it) }
    }

    /** One symbol with a full four-module quiet zone and nearest-neighbor integer scaling. */
    fun encodeOne(text: String, targetPixels: Int = 800): Bitmap =
        render(text, QrSymbolLayout.forFrames(listOf(text)), QrEncodingPolicy.BASELINE, targetPixels)

    internal fun render(text: String, layout: QrSymbolLayout, policy: QrEncodingPolicy, targetPixels: Int): Bitmap {
        val size = layout.fit(targetPixels).symbolPixels
        val matrix = layout.encode(text, policy)
        val modules = matrix.width
        val colors = IntArray(modules * modules) { i ->
            if (matrix[i % modules, i / modules]) 0xff000000.toInt() else 0xffffffff.toInt()
        }
        val natural = Bitmap.createBitmap(colors, modules, modules, Bitmap.Config.RGB_565)
        if (size == modules) return natural
        val scaled = Bitmap.createScaledBitmap(natural, size, size, false)
        natural.recycle()
        return scaled
    }
}
