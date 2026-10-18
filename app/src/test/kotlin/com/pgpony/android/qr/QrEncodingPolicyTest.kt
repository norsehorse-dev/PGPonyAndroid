package com.pgpony.android.qr

import org.junit.Assert.*
import org.junit.Test

class QrEncodingPolicyTest {
    @Test fun defaultsKeepLegacyBytesAndRawThreshold() {
        val text = "a".repeat(2_001)
        val frames = QrChunking.split(text)!!
        assertEquals(listOf(1_000, 1_000, 1), frames.map { QrChunking.parse(it)!!.payload.length })
        for (policy in QrEncodingPolicy.entries) {
            assertEquals(listOf("a".repeat(1_200)), QrChunking.split("a".repeat(1_200), policy))
        }
    }

    @Test fun sameFrameCountAlwaysUsesIdenticalBoundaries() {
        for (length in listOf(1_201, 1_350, 1_499, 1_501, 1_800, 2_001, 18_554, 31_999, 32_000)) {
            val text = "abcDEF123:\n".repeat(length / 11 + 1).take(length)
            val groups = QrEncodingPolicy.entries.map { QrChunking.split(text, it)!! }.groupBy { it.size }
            for (group in groups.values) group.forEach { assertEquals(group.first(), it) }
        }
    }

    @Test fun optionalProfilesRespectCeilingAndRoundTripOutOfOrder() {
        for (policy in QrEncodingPolicy.entries) {
            for (length in listOf(1_201, 2_001, 18_554, 32_000)) {
                val text = "a".repeat(length)
                val frames = QrChunking.split(text, policy)!!
                assertTrue(frames.size <= 32)
                val collector = QrChunking.Collector()
                assertEquals(QrChunking.Outcome.Complete(text), frames.reversed().map(collector::offer).last())
            }
            assertNull(QrChunking.split("a".repeat(32_001), policy))
        }
        assertEquals(19, QrChunking.split("a".repeat(18_554), QrEncodingPolicy.BASELINE)!!.size)
        assertEquals(25, QrChunking.split("a".repeat(18_554), QrEncodingPolicy.BALANCED)!!.size)
        assertEquals(31, QrChunking.split("a".repeat(18_554), QrEncodingPolicy.ROBUST)!!.size)
    }
}
