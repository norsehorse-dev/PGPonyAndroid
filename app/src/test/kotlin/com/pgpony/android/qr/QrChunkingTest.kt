// QrChunkingTest.kt
// PGPony Android — 4.1.0 Phase 9 (issue #3)
//
// The multi-QR format, tested without a camera. The reason this is a JVM test
// at all is that QrChunking was written as pure Kotlin outside the ViewModels:
// the alternative would have been a format only reachable by pointing a phone
// at a screen, which is how a splitting bug stays hidden until a user hits it.
//
// The case that matters most is payloadWithColons_survivesRoundTrip. Armored
// key text carries `Comment:` and `Version:` headers, so a naive split(':')
// header parser would corrupt exactly the certs that are large enough to need
// chunking.

package com.pgpony.android.qr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class QrChunkingTest {

    /** Roughly the shape of a real armored cert, including armor headers. */
    private fun armored(bodyChars: Int, comment: String = "PGPony"): String =
        buildString {
            append("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
            append("Comment: ").append(comment).append("\n")
            append("Version: BCPG v1.80\n")
            append("\n")
            var i = 0
            while (i < bodyChars) {
                append("mDMEZ").append(('a' + (i % 26))).append("Kx9h")
                i += 10
            }
            append("\n-----END PGP PUBLIC KEY BLOCK-----\n")
        }

    private fun feed(frames: List<String>): QrChunking.Outcome {
        val c = QrChunking.Collector()
        var last: QrChunking.Outcome = QrChunking.Outcome.NotAFrame
        for (f in frames) last = c.offer(f)
        return last
    }

    // ── single symbol, unchanged from 4.0.x ──────────────────────────────

    @Test
    fun smallKey_staysOneUnheaderedSymbol() {
        val text = armored(400)
        assertTrue("precondition: fits in one symbol", text.length <= QrChunking.SINGLE_MAX)

        val frames = QrChunking.split(text)
        assertNotNull(frames)
        assertEquals("a small key must not gain a header", 1, frames!!.size)
        assertEquals("and must be byte-identical to the input", text, frames[0])
        assertTrue(
            "so any ordinary QR reader still handles it",
            !QrChunking.isFrame(frames[0])
        )
    }

    @Test
    fun exactlyAtTheThreshold_staysSingle() {
        val text = "A".repeat(QrChunking.SINGLE_MAX)
        val frames = QrChunking.split(text)!!
        assertEquals(1, frames.size)
        assertEquals(text, frames[0])
    }

    @Test
    fun oneOverTheThreshold_chunks() {
        val text = "A".repeat(QrChunking.SINGLE_MAX + 1)
        val frames = QrChunking.split(text)!!
        assertTrue("must chunk", frames.size > 1)
        assertTrue("and be framed", frames.all { QrChunking.isFrame(it) })
    }

    // ── round trips ──────────────────────────────────────────────────────

    @Test
    fun largeKey_roundTripsInOrder() {
        val text = armored(6_000)
        assertTrue("precondition: too big for one symbol", text.length > QrChunking.SINGLE_MAX)

        val frames = QrChunking.split(text)!!
        assertTrue("expected several frames, got ${frames.size}", frames.size >= 3)

        val outcome = feed(frames)
        assertTrue("expected Complete, got $outcome", outcome is QrChunking.Outcome.Complete)
        assertEquals(text, (outcome as QrChunking.Outcome.Complete).text)
    }

    @Test
    fun largeKey_roundTripsOutOfOrder() {
        val text = armored(6_000)
        val frames = QrChunking.split(text)!!.reversed()

        val outcome = feed(frames)
        assertTrue(outcome is QrChunking.Outcome.Complete)
        assertEquals(text, (outcome as QrChunking.Outcome.Complete).text)
    }

    /**
     * THE ONE THAT WOULD HAVE BITTEN. Armored certs carry `Comment:` and
     * `Version:` headers, so a header parser that split on ':' would corrupt
     * the payload of exactly the keys big enough to need chunking.
     */
    @Test
    fun payloadWithColons_survivesRoundTrip() {
        val text = armored(6_000, comment = "a:b:c: colons: everywhere:")
        assertTrue("precondition: payload contains colons", text.contains("Comment: a:b:c:"))

        val frames = QrChunking.split(text)!!
        val outcome = feed(frames)
        assertTrue(outcome is QrChunking.Outcome.Complete)
        assertEquals(text, (outcome as QrChunking.Outcome.Complete).text)
    }

    // ── camera reality: the same symbol decodes over and over ────────────

    @Test
    fun repeatedFrames_areDeduplicatedAndStillComplete() {
        val text = armored(6_000)
        val frames = QrChunking.split(text)!!
        val c = QrChunking.Collector()

        // Frame 1 seen many times, as a camera would.
        repeat(5) { c.offer(frames[0]) }
        assertEquals(1, c.have)

        var last: QrChunking.Outcome = QrChunking.Outcome.NotAFrame
        for (f in frames) last = c.offer(f)

        assertTrue(last is QrChunking.Outcome.Complete)
        assertEquals(text, (last as QrChunking.Outcome.Complete).text)
    }

    @Test
    fun duplicateBeforeCompletion_reportsDuplicateNotProgress() {
        val text = armored(6_000)
        val frames = QrChunking.split(text)!!
        val c = QrChunking.Collector()

        assertTrue(c.offer(frames[0]) is QrChunking.Outcome.Progress)
        assertTrue(c.offer(frames[0]) is QrChunking.Outcome.Duplicate)
    }

    // ── the failure mode that would be silent ────────────────────────────

    /**
     * Pointing the camera at a second key mid-scan must discard what is in
     * hand. Splicing half of one certificate onto half of another would
     * produce garbage that looks like a successful scan.
     */
    @Test
    fun framesFromADifferentKey_restartRatherThanSplice() {
        val a = armored(6_000, comment = "key A")
        val b = armored(6_000, comment = "key B")
        val fa = QrChunking.split(a)!!
        val fb = QrChunking.split(b)!!
        assertTrue("precondition: different sequence ids", fa[0] != fb[0])

        val c = QrChunking.Collector()
        c.offer(fa[0])
        c.offer(fa[1])
        assertEquals(2, c.have)

        val outcome = c.offer(fb[0])
        assertTrue("expected Restarted, got $outcome", outcome is QrChunking.Outcome.Restarted)
        assertEquals("key A's parts must be gone", 1, c.have)

        var last: QrChunking.Outcome = outcome
        for (f in fb) last = c.offer(f)
        assertTrue(last is QrChunking.Outcome.Complete)
        assertEquals("must reassemble key B, uncontaminated", b, (last as QrChunking.Outcome.Complete).text)
    }

    @Test
    fun idIsDeterministicAndDiffersBetweenKeys() {
        val a = armored(6_000, comment = "key A")
        val b = armored(6_000, comment = "key B")
        assertEquals(QrChunking.idFor(a), QrChunking.idFor(a))
        assertTrue(QrChunking.idFor(a) != QrChunking.idFor(b))
        assertEquals(8, QrChunking.idFor(a).length)
    }

    // ── what must NOT be treated as a frame ──────────────────────────────

    @Test
    fun bareArmoredBlock_isNotAFrame() {
        val text = armored(400)
        val c = QrChunking.Collector()
        assertTrue(
            "a plain scanned key must fall through to the single-QR path",
            c.offer(text) is QrChunking.Outcome.NotAFrame
        )
    }

    @Test
    fun malformedHeader_isRejectedNotMisparsed() {
        val c = QrChunking.Collector()
        assertTrue(c.offer("PGPONY1:notanumber:3:deadbeef:xx") is QrChunking.Outcome.Malformed)
        assertTrue(c.offer("PGPONY1:5:3:deadbeef:xx") is QrChunking.Outcome.Malformed)
        assertTrue(c.offer("PGPONY1:1:3:NOTHEX00:xx") is QrChunking.Outcome.Malformed)
        assertTrue(c.offer("PGPONY1:1:99:deadbeef:xx") is QrChunking.Outcome.Malformed)
        assertTrue(c.offer("PGPONY1:1:3:deadbeef") is QrChunking.Outcome.Malformed)
    }

    // ── the ceiling, where the actionable message takes over ─────────────

    @Test
    fun beyondMaxFrames_returnsNullSoTheCallerCanExplain() {
        val huge = "A".repeat(QrChunking.PAYLOAD_MAX * QrChunking.MAX_FRAMES + 1)
        assertNull(
            "past the frame ceiling the caller must show the too-large message, " +
                "never a raw encoder exception",
            QrChunking.split(huge)
        )
    }

    @Test
    fun exactlyMaxFrames_stillSplits() {
        val text = "A".repeat(QrChunking.PAYLOAD_MAX * QrChunking.MAX_FRAMES)
        val frames = QrChunking.split(text)!!
        assertEquals(QrChunking.MAX_FRAMES, frames.size)
        val outcome = feed(frames)
        assertTrue(outcome is QrChunking.Outcome.Complete)
        assertEquals(text, (outcome as QrChunking.Outcome.Complete).text)
    }

    @Test
    fun compositeMlDsaSizedKey_chunksInsteadOfOverflowing() {
        // A PQ-only composite ML-DSA cert armors to ~18.5 KB (every self-sig is
        // a ~3.3 KB ML-DSA signature). Under the old 1,000 x 16 = 16 KB ceiling
        // split() returned null and no QR was produced, single or multipart.
        // It must now chunk within the frame cap and reassemble intact.
        val text = armored(18_503)
        val frames = QrChunking.split(text)
        assertNotNull("a composite ML-DSA cert must chunk, not overflow the cap", frames)
        assertTrue(
            "must fit within the frame ceiling",
            frames!!.size <= QrChunking.MAX_FRAMES
        )
        val outcome = feed(frames)
        assertTrue(outcome is QrChunking.Outcome.Complete)
        assertEquals(text, (outcome as QrChunking.Outcome.Complete).text)
    }

    @Test
    fun everyFrameStaysUnderASensibleSymbolSize() {
        val text = armored(12_000)
        val frames = QrChunking.split(text)!!
        for (f in frames) {
            assertTrue(
                "frame of ${f.length} chars is larger than intended",
                f.length <= QrChunking.PAYLOAD_MAX + 40
            )
        }
    }
}
