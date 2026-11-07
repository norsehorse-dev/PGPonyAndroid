package com.pgpony.android.qr

import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test

class LuminanceExtractionTest {
    @Test fun extractsPaddedPixelsFromPositionWithoutReadingMissingLastRowPadding() {
        val buffer = ByteBuffer.wrap(byteArrayOf(99, 98, 1, 9, 2, 9, 3, 8, 8, 4, 9, 5, 9, 6))
        buffer.position(2)
        val frame = LuminanceFrameExtractor().extract(buffer, 3, 2, 7, 2)!!
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6), frame.bytes.copyOf(6))
        assertEquals(2, buffer.position())
    }

    @Test fun cropsBeforeRotatingInEveryRightAngle() {
        val source = ByteBuffer.wrap(byteArrayOf(1,2,3,4,5,6,7,8,9,10,11,12))
        val expected = mapOf(
            0 to byteArrayOf(2,3,6,7,10,11),
            90 to byteArrayOf(10,6,2,11,7,3),
            180 to byteArrayOf(11,10,7,6,3,2),
            270 to byteArrayOf(3,7,11,2,6,10)
        )
        val extractor = LuminanceFrameExtractor()
        for ((rotation, pixels) in expected) {
            val frame = extractor.extract(source, 4, 3, 4, 1, PixelCrop(1,0,3,3), rotation)!!
            assertArrayEquals("rotation=$rotation", pixels, frame.bytes.copyOf(6))
            assertEquals(if (rotation % 180 == 0) 2 else 3, frame.width)
        }
    }

    @Test fun reusesSameSizedStorageAndRejectsTruncatedFrames() {
        val extractor = LuminanceFrameExtractor()
        val first = extractor.extract(ByteBuffer.wrap(ByteArray(12)), 4,3,4,1)!!
        val second = extractor.extract(ByteBuffer.wrap(ByteArray(12) { 7 }), 4,3,4,1)!!
        assertSame(first.bytes, second.bytes)
        assertEquals(7.toByte(), second.bytes[11])
        assertNull(extractor.extract(ByteBuffer.wrap(ByteArray(11)),4,3,4,1))
        assertNull(extractor.extract(ByteBuffer.allocate(12),4,3,4,1, PixelCrop(3,0,5,2)))
        assertNull(extractor.extract(ByteBuffer.allocate(12),4,3,4,1, rotationDegrees = 45))
    }
}
