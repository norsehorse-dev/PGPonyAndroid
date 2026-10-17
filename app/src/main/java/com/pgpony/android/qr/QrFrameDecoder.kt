package com.pgpony.android.qr

import java.nio.ByteBuffer
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * Owned by one analyzer executor. The reader and luminance storage never cross threads.
 * Rotated-first search retains the previous ordering until camera replay supports changing it.
 */
class QrFrameDecoder(private val clockNanos: () -> Long = System::nanoTime,
    private val metrics: QrScanMetrics = QrScanMetrics.None, private val sessionId: Long = 0) {
    // QRCodeReader accepts per-attempt hints without rebuilding MultiFormatReader's delegates.
    private val reader = QRCodeReader()
    private val extractor = LuminanceFrameExtractor()
    private val normalHints = emptyMap<DecodeHintType, Any>()
    private val hardHints = mapOf<DecodeHintType, Any>(DecodeHintType.TRY_HARDER to true)
    @Volatile private var lastProgress = clockNanos()
    private var lastFallback = lastProgress

    /** The main thread calls this only for a newly collected part, never for duplicates. */
    fun markProgress() { lastProgress = clockNanos() }

    fun decode(buffer: ByteBuffer,width: Int,height: Int,rowStride: Int,pixelStride: Int,
        crop: PixelCrop = PixelCrop(0,0,width,height),rotationDegrees: Int = 0,
        region: PixelCrop? = null): String? {
        metrics.frame(sessionId,width,height)
        val selected = region?.takeIf {
            it.left >= crop.left && it.top >= crop.top && it.right <= crop.right &&
                it.bottom <= crop.bottom && it.width > 0 && it.height > 0
        } ?: crop
        val primary = extractor.extract(buffer,width,height,rowStride,pixelStride,selected,rotationDegrees)
            ?: return null
        val primaryText = attempt(primary,
            if(selected == crop) DecodeStrategy.FULL_FRAME else DecodeStrategy.REGION,false)
        val now = clockNanos()
        if (now - lastProgress < FALLBACK_NANOS || now - lastFallback < FALLBACK_NANOS) return primaryText
        lastFallback = now
        // Duplicate symbols do not postpone recovery. Collection progress alone resets this budget.
        // One extra search per interval includes ROI/full-frame and rotation fallback together.
        val fallbackRotation = if (selected == crop) 0 else rotationDegrees
        val fallback = extractor.extract(buffer,width,height,rowStride,pixelStride,crop,fallbackRotation)
            ?: return primaryText
        return attempt(fallback,
            if(fallbackRotation != rotationDegrees) DecodeStrategy.HARD_UNROTATED else DecodeStrategy.HARD_FULL_FRAME,true)
            ?: primaryText
    }

    private fun attempt(frame: LuminanceFrame, strategy: DecodeStrategy, hard: Boolean): String? {
        val started = clockNanos()
        var success = false
        try {
            val source = PlanarYUVLuminanceSource(frame.bytes,frame.width,frame.height,
                0,0,frame.width,frame.height,false)
            return reader.decode(BinaryBitmap(HybridBinarizer(source)),if(hard) hardHints else normalHints)
                .text.also { success = true }
        } catch (_: ReaderException) {
            return null
        } finally {
            reader.reset()
            metrics.decode(sessionId,strategy,clockNanos()-started,success)
        }
    }

    private companion object { const val FALLBACK_NANOS = 500_000_000L }
}
