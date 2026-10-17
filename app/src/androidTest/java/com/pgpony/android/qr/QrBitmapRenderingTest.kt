package com.pgpony.android.qr

import android.graphics.Bitmap
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.zxing.BinaryBitmap
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Pixel checks run against Android's actual Bitmap scaling implementation. */
@RunWith(AndroidJUnit4::class)
class QrBitmapRenderingTest {
    @Test fun physicalBitmapsHaveCompleteQuietZoneWholeModulesAndDecode() {
        val text = "Comment: key exchange\n" + "abcDEF123".repeat(400)
        for (policy in QrEncodingPolicy.entries) {
            val frames = QrChunking.split(text, policy)!!
            val sequence = QrFrameStore.fromFrames(frames, policy)
            val placement = sequence.layout.fit(947)
            for (index in listOf(0, frames.lastIndex)) {
                val bitmap = sequence.bitmap(index, 947)
                assertEquals(placement.symbolPixels, bitmap.width)
                assertEquals(bitmap.width, bitmap.height)
                val matrix = sequence.layout.encode(frames[index], policy)
                val pixels = IntArray(bitmap.width * bitmap.height)
                bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
                for (y in 0 until bitmap.height) for (x in 0 until bitmap.width) {
                    val mx = x / placement.moduleScale
                    val my = y / placement.moduleScale
                    val expected = if (matrix[mx, my]) 0xff000000.toInt() else 0xffffffff.toInt()
                    assertEquals("pixel $x,$y", expected, pixels[y * bitmap.width + x])
                    if (mx < 4 || my < 4 || mx >= matrix.width - 4 || my >= matrix.height - 4) {
                        assertEquals(0xffffffff.toInt(), pixels[y * bitmap.width + x])
                    }
                }
                assertEquals(frames[index], decode(bitmap))
            }
            sequence.clear()
        }
    }

    @Test fun evictionAndClearPreserveBitmapsStillOwnedByTheDisplay() {
        val frames = QrChunking.split("abc".repeat(2_000))!!
        val sequence = QrFrameStore.fromFrames(frames)
        val displayed = sequence.bitmap(0, 800)
        assertSame(displayed, sequence.bitmap(0, 800))
        for (index in 1..3) sequence.bitmap(index, 800)
        assertFalse(displayed.isRecycled)
        assertEquals(frames[0], decode(displayed))
        assertNotSame(displayed, sequence.bitmap(0, 800))
        sequence.clear()
        assertFalse(displayed.isRecycled)
        assertEquals(frames[0], decode(displayed))
    }

    @Test fun legacyApiStillReturnsDecodableFrames() {
        val text = "Comment: original API\n" + "abc".repeat(1_000)
        val expected = QrChunking.split(text)!!
        val bitmaps = QrBitmap.encodeFrames(text)!!
        assertEquals(expected, bitmaps.map(::decode))
    }

    private fun decode(bitmap: Bitmap): String {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        return QRCodeReader().decode(BinaryBitmap(HybridBinarizer(RGBLuminanceSource(bitmap.width, bitmap.height, pixels)))).text
    }
}
