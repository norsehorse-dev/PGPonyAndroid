// QrPartLimitTest.kt
// PGPony Android, 4.8.0 RC8 (#100): the Long QR codes limit, the too-large
// message's numbers, and what the scanner shows about missing parts.

package com.pgpony.android.qr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class QrPartLimitTest {

    @Test fun `the setting switches the sender between 32 and 512 parts`() {
        assertEquals(32, QrPartLimit.maxFrames(false))
        assertEquals(512, QrPartLimit.maxFrames(true))
    }

    @Test fun `too large names the parts needed and whether long codes would fit it`() {
        val mid = "a".repeat(40_500)
        assertEquals(QrPartLimit.TooLarge(41, 32, true), QrPartLimit.tooLarge(mid, longCodes = false))
        val huge = "a".repeat(600_000)
        assertEquals(QrPartLimit.TooLarge(600, 32, false), QrPartLimit.tooLarge(huge, longCodes = false))
        assertEquals(QrPartLimit.TooLarge(600, 512, false), QrPartLimit.tooLarge(huge, longCodes = true))
    }

    @Test fun `missing parts are listed only when a few are left`() {
        assertNull(QrMissingParts.toList(emptyList()))
        assertEquals(listOf(31), QrMissingParts.toList(listOf(31)))
        assertEquals(listOf(2, 9, 30), QrMissingParts.toList(listOf(30, 2, 9)))
        assertEquals((1..8).toList(), QrMissingParts.toList((1..8).toList()))
        assertNull(QrMissingParts.toList((1..9).toList()))
    }

    @Test fun `the strip is one row at 32 parts and a short block at 512`() {
        assertEquals(2, QrMissingParts.columns(2))
        assertEquals(1, QrMissingParts.rows(2))
        assertEquals(32, QrMissingParts.columns(32))
        assertEquals(1, QrMissingParts.rows(32))
        assertEquals(32, QrMissingParts.columns(64))
        assertEquals(2, QrMissingParts.rows(64))
        assertEquals(64, QrMissingParts.columns(65))
        assertEquals(2, QrMissingParts.rows(65))
        assertEquals(64, QrMissingParts.columns(512))
        assertEquals(8, QrMissingParts.rows(512))
        assertEquals(0, QrMissingParts.rows(0))
    }

    @Test fun `public key collector reports the missing PGPONY1 parts`() {
        val frames = QrChunking.split("d".repeat(5_000))!!
        assertEquals(5, frames.size)
        val collector = PublicKeyQrCollector()
        val first = collector.offer(frames[1]) as PublicKeyQrResult.Progress
        assertFalse(first.enhanced)
        assertEquals(listOf(1, 3, 4, 5), first.missing)
        val second = collector.offer(frames[4]) as PublicKeyQrResult.Progress
        assertEquals(listOf(1, 3, 4), second.missing)
        assertEquals(PublicKeyQrResult.Duplicate, collector.offer(frames[4]))
        collector.offer(frames[0]); collector.offer(frames[2])
        assertTrue(collector.offer(frames[3]) is PublicKeyQrResult.Complete)
    }
}
