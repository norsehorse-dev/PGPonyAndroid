// QrBitmap.kt
// PGPony Android — 4.1.0 Phase 9 (issue #3)
//
// The one place a QR bitmap is produced.
//
// This code existed twice: KeyDetailViewModel.encodeQR and the inline block in
// ExchangeViewModel.generateQR were the same matrix-to-bitmap loop, and
// encodeQR's own comment promised the two were "kept in sync" by hand. Phase 7
// had already shown what that costs, when a one-line fix to the envelope
// unwrap had to be applied to two byte-identical private functions or they
// would silently diverge. Same shape, so the same answer.
//
// Everything Android-specific lives here; the format itself is in QrChunking,
// which is pure Kotlin and unit-tested.

package com.pgpony.android.qr

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter

object QrBitmap {

    private const val TARGET = 800

    /**
     * Encode [text] as one or more QR bitmaps.
     *
     * One bitmap for anything that fits a single symbol, which is every
     * classic key and what 4.0.x always produced. Several for a key that does
     * not, each carrying a `PGPONY1:` frame header.
     *
     * Returns **null** when even chunking cannot hold it, which is the
     * caller's cue to show `R.string.qr_too_large` rather than let a
     * `WriterException` reach the user as "QR generation failed: data too
     * big". That message is what issue #3 was actually reported as.
     */
    fun encodeFrames(text: String): List<Bitmap>? =
        QrChunking.split(text)?.map { encodeOne(it) }

    /** One symbol. Throws ZXing's WriterException if even this will not fit. */
    fun encodeOne(text: String): Bitmap {
        // Encode at the QR's natural module resolution: a 1x1 requested output
        // makes ZXing emit one pixel per module (multiple = 1), so there is no
        // variable centering border, only the 1-module quiet zone. #63: at a
        // fixed large size ZXing centered a dense symbol inside a wide white
        // field and frames sized differently. Scaling the natural matrix up by
        // an integer factor here fills the frame uniformly and keeps the modules
        // crisp regardless of how the ImageView resizes it.
        val hints = mapOf(EncodeHintType.MARGIN to 1)
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 1, 1, hints)
        val modules = matrix.width
        val scale = (TARGET / modules).coerceAtLeast(1)
        val size = modules * scale
        val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
        for (mx in 0 until modules) {
            for (my in 0 until modules) {
                val color = if (matrix.get(mx, my)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
                val ox = mx * scale
                val oy = my * scale
                for (dx in 0 until scale) {
                    for (dy in 0 until scale) {
                        bitmap.setPixel(ox + dx, oy + dy, color)
                    }
                }
            }
        }
        return bitmap
    }
}
