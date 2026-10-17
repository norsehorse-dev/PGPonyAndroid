package com.pgpony.android.qr

import org.junit.Assert.*
import org.junit.Test

class PublicKeyQrCollectorTest {
    @Test fun `pairing scanner can accept the existing invitation URI`() {
        val invite = "pgpony-pair:1?a=192.168.1.20:49152&h=Z8ov_W_p76s9duN8NJkKWg"
        assertEquals(PublicKeyQrResult.Complete(invite), PublicKeyQrCollector(true).offer(invite))
        assertEquals(PublicKeyQrResult.Malformed, PublicKeyQrCollector().offer(invite))
    }
    @Test fun `preview timing is delivered exactly once across recomposition`() {
        val events = mutableListOf<ScanMilestone>()
        val timing = QrPreviewTiming(42, object : QrScanMetrics {
            override fun milestone(sessionId: Long, event: ScanMilestone, monotonicNanos: Long) {
                assertEquals(42L, sessionId)
                events += event
            }
        })
        timing.previewShown()
        timing.previewShown()
        assertEquals(listOf(ScanMilestone.PREVIEW), events)
    }

    @Test fun `unknown transport does not complete or disturb existing parts`() {
        val text = "a".repeat(1500)
        val frames = QrChunking.split(text)!!
        val collector = PublicKeyQrCollector()
        assertTrue(collector.offer(frames[0]) is PublicKeyQrResult.Progress)
        assertEquals(PublicKeyQrResult.Unsupported, collector.offer("PGPONY9:unknown"))
        assertEquals(PublicKeyQrResult.Complete(text), collector.offer(frames[1]))
    }
    @Test fun `duplicates cannot be mistaken for new progress`() {
        val collector = PublicKeyQrCollector()
        val frame = QrChunking.split("b".repeat(1500))!!.first()
        collector.offer(frame)
        assertEquals(PublicKeyQrResult.Duplicate, collector.offer(frame))
    }
    @Test fun `unframed public key retains existing import path`() {
        val armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nbody\n-----END PGP PUBLIC KEY BLOCK-----"
        assertEquals(PublicKeyQrResult.Complete(armor), PublicKeyQrCollector().offer(armor))
        assertEquals(PublicKeyQrResult.Malformed, PublicKeyQrCollector().offer("https://example.org"))
    }
}
