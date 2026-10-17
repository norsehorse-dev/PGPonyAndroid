package com.pgpony.android.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test

class QrFrameReplayUnitTest {
    private fun qr(text: String): ByteBuffer {
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 240, 240)
        return ByteBuffer.wrap(ByteArray(240*240) { if(matrix[it%240,it/240]) 0 else 255.toByte() })
    }
    @Test fun decodesActualSymbolsAcrossRotationAndReuse() {
        val decoder = QrFrameDecoder()
        for(rotation in listOf(0,90,180,270,0)) {
            assertEquals("rotation=$rotation", "PGPony replay", decoder.decode(qr("PGPony replay"),240,240,240,1,
                rotationDegrees=rotation))
        }
    }
    @Test fun regionMissFallsBackToFullFrameAfterBudgetInterval() {
        var time = 0L
        val strategies = mutableListOf<DecodeStrategy>()
        val metrics = object : QrScanMetrics {
            override fun decode(sessionId: Long,strategy: DecodeStrategy,elapsedNanos: Long,success: Boolean) {
                strategies += strategy
            }
        }
        val decoder = QrFrameDecoder(clockNanos={time}, metrics=metrics)
        val image = qr("Full image fallback")
        val region = PixelCrop(0,0,40,40)
        assertNull(decoder.decode(image,240,240,240,1,region=region))
        assertEquals(listOf(DecodeStrategy.REGION),strategies)
        time = 500_000_000L
        assertEquals("Full image fallback",decoder.decode(image,240,240,240,1,region=region))
        assertEquals(DecodeStrategy.HARD_FULL_FRAME,strategies.last())
        strategies.clear()
        assertNull(decoder.decode(image,240,240,240,1,region=region))
        assertEquals(listOf(DecodeStrategy.REGION),strategies)
        time += 500_000_000L
        decoder.markProgress()
        strategies.clear()
        assertNull(decoder.decode(image,240,240,240,1,region=region))
        assertEquals(listOf(DecodeStrategy.REGION),strategies)
    }

    @Test fun repeatedSuccessfulDecodeDoesNotHideRecoveryBudgetWithoutCollectionProgress() {
        var time = 0L
        val strategies = mutableListOf<DecodeStrategy>()
        val metrics = object : QrScanMetrics {
            override fun decode(sessionId: Long,strategy: DecodeStrategy,elapsedNanos: Long,success: Boolean) {
                strategies += strategy
            }
        }
        val decoder = QrFrameDecoder(clockNanos={time},metrics=metrics)
        val image = qr("Duplicate symbol")
        assertEquals("Duplicate symbol",decoder.decode(image,240,240,240,1))
        time = 500_000_000L
        strategies.clear()
        assertEquals("Duplicate symbol",decoder.decode(image,240,240,240,1))
        assertEquals(listOf(DecodeStrategy.FULL_FRAME,DecodeStrategy.HARD_FULL_FRAME),strategies)
    }
}
