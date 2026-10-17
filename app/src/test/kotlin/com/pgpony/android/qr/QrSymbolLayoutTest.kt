package com.pgpony.android.qr

import com.google.zxing.BinaryBitmap
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import org.junit.Assert.*
import org.junit.Test

class QrSymbolLayoutTest {
    @Test fun physicalPlacementUsesWholeModulesAndCentersRemainder() {
        val layout = QrSymbolLayout(23)
        val fit = layout.fit(947)
        assertEquals(117, layout.moduleCount)
        assertEquals(8, fit.moduleScale)
        assertEquals(936, fit.symbolPixels)
        assertEquals(5, fit.offsetPixels)
        assertTrue(fit.symbolPixels <= 947)
    }

    @Test fun productionMatricesShareVersionHaveFourWhiteModulesAndDecode() {
        val text = javaClass.getResource("/pqc/rfc9980-a3-mldsa65-ed25519-cert.asc")!!.readText()
        for (policy in QrEncodingPolicy.entries) {
            val frames = QrChunking.split(text, policy)!!
            val layout = QrSymbolLayout.forFrames(frames, policy)
            for (frame in listOf(frames.first(), frames[frames.size / 2], frames.last())) {
                val matrix = layout.encode(frame, policy)
                assertEquals(layout.moduleCount, matrix.width)
                assertEquals(matrix.width, matrix.height)
                for (y in 0 until matrix.height) for (x in 0 until matrix.width) {
                    if (x < 4 || y < 4 || x >= matrix.width - 4 || y >= matrix.height - 4) {
                        assertFalse("quiet zone at $x,$y for $policy", matrix[x, y])
                    }
                }
                val scale = 4
                val size = matrix.width * scale
                val pixels = IntArray(size * size) { i ->
                    if (matrix[i % size / scale, i / size / scale]) 0xff000000.toInt() else 0xffffffff.toInt()
                }
                val result = QRCodeReader().decode(BinaryBitmap(HybridBinarizer(RGBLuminanceSource(size, size, pixels))))
                assertEquals(frame, result.text)
            }
        }
    }

    @Test fun utf8TextSurvivesTheProductionMatrix() {
        val text = "Comment: 中文 🦄"
        val layout = QrSymbolLayout.forFrames(listOf(text))
        val matrix = layout.encode(text)
        val size = matrix.width * 4
        val pixels = IntArray(size * size) { i ->
            if (matrix[i % size / 4, i / size / 4]) 0xff000000.toInt() else -1
        }
        assertEquals(text, QRCodeReader().decode(BinaryBitmap(HybridBinarizer(RGBLuminanceSource(size, size, pixels)))).text)
    }
}
