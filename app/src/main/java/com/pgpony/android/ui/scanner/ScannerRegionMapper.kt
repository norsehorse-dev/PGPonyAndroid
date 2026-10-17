package com.pgpony.android.ui.scanner

import com.pgpony.android.qr.PixelCrop
import kotlin.math.ceil
import kotlin.math.floor

data class PreviewRectangle(val left: Float, val top: Float, val right: Float, val bottom: Float)

object ScannerRegionMapper {
    /**
     * Maps PreviewView pixels into unrotated analysis pixels with a CameraX 3x3 matrix.
     * Returns null for unavailable transforms or empty intersections, requiring full-frame search.
     */
    fun map(rectangle: PreviewRectangle, previewToImage: FloatArray?, crop: PixelCrop,
        quietZoneExpansion: Float = 0.12f): PixelCrop? {
        val m = previewToImage ?: return null
        if (m.size != 9 || m.any { !it.isFinite() } || quietZoneExpansion < 0 ||
            !quietZoneExpansion.isFinite() || rectangle.right <= rectangle.left ||
            rectangle.bottom <= rectangle.top) return null
        val determinant = m[0] * (m[4]*m[8]-m[5]*m[7]) -
            m[1] * (m[3]*m[8]-m[5]*m[6]) + m[2] * (m[3]*m[7]-m[4]*m[6])
        if (!determinant.isFinite() || kotlin.math.abs(determinant) < 1e-8f) return null
        var left = Float.POSITIVE_INFINITY
        var top = Float.POSITIVE_INFINITY
        var right = Float.NEGATIVE_INFINITY
        var bottom = Float.NEGATIVE_INFINITY
        for (corner in 0..3) {
            val x = if (corner % 2 == 0) rectangle.left else rectangle.right
            val y = if (corner < 2) rectangle.top else rectangle.bottom
            val w = m[6]*x + m[7]*y + m[8]
            if (w <= 0 || !w.isFinite()) return null
            val mappedX = (m[0]*x + m[1]*y + m[2]) / w
            val mappedY = (m[3]*x + m[4]*y + m[5]) / w
            if (!mappedX.isFinite() || !mappedY.isFinite()) return null
            left = minOf(left, mappedX); right = maxOf(right, mappedX)
            top = minOf(top, mappedY); bottom = maxOf(bottom, mappedY)
        }
        val dx = (right-left) * quietZoneExpansion
        val dy = (bottom-top) * quietZoneExpansion
        val result = PixelCrop(
            maxOf(crop.left, floor(left-dx).toInt()),
            maxOf(crop.top, floor(top-dy).toInt()),
            minOf(crop.right, ceil(right+dx).toInt()),
            minOf(crop.bottom, ceil(bottom+dy).toInt())
        )
        return result.takeIf { it.width > 0 && it.height > 0 }
    }
}
