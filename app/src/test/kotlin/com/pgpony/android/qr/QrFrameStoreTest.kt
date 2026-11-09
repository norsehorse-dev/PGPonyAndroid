package com.pgpony.android.qr

import org.junit.Assert.*
import org.junit.Test

class QrFrameStoreTest {
    @Test fun genericFrameStoreSnapshotsInputAndKeepsOneSharedVersion() {
        val frames = mutableListOf("PGPONY2:SHORT", "PGPONY2:" + "ABC123".repeat(100))
        val expected = QrSymbolLayout.forFrames(frames, QrEncodingPolicy.BALANCED)
        val store = QrFrameStore.fromFrames(frames, QrEncodingPolicy.BALANCED)
        frames.clear()
        assertEquals(2, store.frameCount)
        assertEquals(expected.version, store.version)
        assertEquals(QrEncodingPolicy.BALANCED.errorCorrection, store.errorCorrection)
    }

    @Test fun compatibleFactoryKeepsPublishedSizeCeilings() {
        assertEquals(1, QrFrameStore.create("a".repeat(1_200))!!.frameCount)
        assertEquals(32, QrFrameStore.create("a".repeat(32_000))!!.frameCount)
        assertNull(QrFrameStore.create("a".repeat(32_001)))
    }

    // 4.8.0 RC8 (#100): Long QR codes holds a 512-part sequence; the default stays at 32.
    @Test fun longCodesFactoryHoldsUpTo512Parts() {
        val text = "a".repeat(QrChunking.MAX_TEXT_CHARS_LONG)
        assertNull(QrFrameStore.create(text))
        assertEquals(512, QrFrameStore.create(text, QrEncodingPolicy.BASELINE, QrChunking.MAX_FRAMES_LONG)!!.frameCount)
        assertNull(QrFrameStore.create(text + "a", QrEncodingPolicy.BASELINE, QrChunking.MAX_FRAMES_LONG))
    }

    // 4.8.0 RC6 (#95): Larger dots never makes a single code denser.
    @Test fun singleCodeAlwaysUsesBaselineWhateverThePolicy() {
        val text = "a".repeat(1_200)
        val baseline = QrFrameStore.create(text, QrEncodingPolicy.BASELINE)!!
        val robust = QrFrameStore.create(text, QrEncodingPolicy.ROBUST)!!
        assertEquals(1, robust.frameCount)
        assertEquals(QrEncodingPolicy.BASELINE, robust.policy)
        assertEquals(baseline.version, robust.version)
        val multi = QrFrameStore.create("a".repeat(3_000), QrEncodingPolicy.ROBUST)!!
        assertTrue(multi.frameCount > 1)
        assertEquals(QrEncodingPolicy.ROBUST, multi.policy)
    }

    @Test fun genericFrameBoundsFailBeforeExpensiveEncoding() {
        // 4.8.0 RC8 (#100): the frame ceiling is 512 now (Long QR codes), so 513 is the first rejected count.
        for (frames in listOf(emptyList(), List(513) { "a" }, listOf("a".repeat(4_097)))) {
            try {
                QrFrameStore.fromFrames(frames)
                fail("invalid frame collection must be rejected")
            } catch (_: IllegalArgumentException) { }
        }
    }
}
