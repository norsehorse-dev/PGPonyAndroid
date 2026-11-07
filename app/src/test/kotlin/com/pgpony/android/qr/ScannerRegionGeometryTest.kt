package com.pgpony.android.qr

import com.pgpony.android.ui.scanner.PreviewRectangle
import com.pgpony.android.ui.scanner.ScannerRegionMapper
import org.junit.Assert.*
import org.junit.Test

class ScannerRegionGeometryTest {
    private val crop = PixelCrop(20,10,620,470)
    @Test fun mapsFillCenterTranslationAndClipsToSensorCrop() {
        val matrix = floatArrayOf(2f,0f,20f,0f,2f,-50f,0f,0f,1f)
        assertEquals(PixelCrop(20,10,620,470), ScannerRegionMapper.map(
            PreviewRectangle(0f,0f,300f,300f),matrix,crop,0f))
    }
    @Test fun mapsQuarterTurnsAndExpandsQuietZone() {
        val matrix = floatArrayOf(0f,1f,20f,-1f,0f,470f,0f,0f,1f)
        assertEquals(PixelCrop(110,250,230,490).copy(bottom=470), ScannerRegionMapper.map(
            PreviewRectangle(0f,100f,200f,200f),matrix,crop,0.1f))
        val opposite = floatArrayOf(0f,-1f,620f,1f,0f,10f,0f,0f,1f)
        assertEquals(PixelCrop(420,10,520,210), ScannerRegionMapper.map(
            PreviewRectangle(0f,100f,200f,200f),opposite,crop,0f))
    }
    @Test fun rejectsMissingSingularOrNonFiniteTransformAndOffscreenRegion() {
        val rect = PreviewRectangle(0f,0f,10f,10f)
        assertNull(ScannerRegionMapper.map(rect,null,crop))
        assertNull(ScannerRegionMapper.map(rect,FloatArray(9),crop))
        assertNull(ScannerRegionMapper.map(rect,FloatArray(9) { Float.NaN },crop))
        assertNull(ScannerRegionMapper.map(rect,floatArrayOf(1f,0f,900f,0f,1f,900f,0f,0f,1f),crop))
    }
}
