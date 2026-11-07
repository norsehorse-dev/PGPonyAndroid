package com.pgpony.android.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.encoder.Encoder

/** Pure QR geometry, including the complete four-module white quiet zone. */
data class QrSymbolLayout(val version: Int) {
    init { require(version in 1..40) }

    val moduleCount: Int get() = 17 + 4 * version + 2 * QUIET_ZONE_MODULES

    data class Placement(val moduleScale: Int, val symbolPixels: Int, val offsetPixels: Int)

    /** The caller centers this exact pixel size without another image scaling step. */
    fun fit(targetPixels: Int): Placement {
        require(targetPixels >= moduleCount) { "Display is too small for one pixel per QR module" }
        val scale = targetPixels / moduleCount
        val size = moduleCount * scale
        return Placement(scale, size, (targetPixels - size) / 2)
    }

    /** Natural module matrix. Every frame uses this layout's shared QR version. */
    fun encode(text: String, policy: QrEncodingPolicy = QrEncodingPolicy.BASELINE): BitMatrix =
        QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 1, 1, hints(text, policy) + mapOf(
            EncodeHintType.MARGIN to QUIET_ZONE_MODULES,
            EncodeHintType.QR_VERSION to version,
        ))

    companion object {
        const val QUIET_ZONE_MODULES = 4

        /** Probe frames once without retaining matrices or bitmaps. */
        fun forFrames(frames: List<String>, policy: QrEncodingPolicy = QrEncodingPolicy.BASELINE): QrSymbolLayout {
            require(frames.isNotEmpty())
            val version = frames.maxOf {
                Encoder.encode(it, policy.errorCorrection, hints(it, policy)).version.versionNumber
            }
            return QrSymbolLayout(version)
        }

        // 4.8.0 RC6 (#95): ZXing writes a UTF-8 ECI header into every byte-mode code
        // that carries a CHARACTER_SET hint. Key armor, PGPONY frames and pairing
        // invites are ASCII, so they get no hint and stay the codes the iOS and
        // desktop scanners already read. Only text with non-ASCII characters asks for UTF-8.
        private fun hints(text: String, policy: QrEncodingPolicy): Map<EncodeHintType, Any> =
            if (text.any { it.code > 0x7F }) mapOf(
                EncodeHintType.CHARACTER_SET to "UTF-8",
                EncodeHintType.ERROR_CORRECTION to policy.errorCorrection,
            ) else mapOf(EncodeHintType.ERROR_CORRECTION to policy.errorCorrection)
    }
}
