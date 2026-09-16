// QrChunking.kt
// PGPony Android — 4.1.0 Phase 9 (issue #3)
//
// Splitting a key across several QR codes, and collecting it back.
//
// THE PROBLEM. A single QR code holds roughly 2,953 bytes in byte mode at
// error-correction level L, which is what ZXing defaults to. An ML-KEM v6
// public key armors out to about 2.3 to 3.0 KB, so it sits ON that ceiling:
// a lean cert squeaks under, and adding a comment, a longer UID or an
// expiration subpacket tips it over into "QR generation failed - data too
// big" (issue #3, hulkspec). ML-KEM-1024 in 4.2.0 will not fit under any
// amount of shrinking.
//
// WHY NOT ZXing'S STRUCTURED APPEND. ZXing supports it in the encoder, but
// QRCodeWriter.encode does not expose it, and that is the API both QR call
// sites use. Reaching past QRCodeWriter into the internal encoder to emit
// structured-append headers would be a much larger change for a format that
// still no ordinary scanner reassembles on its own.
//
// SO THIS IS AN APPLICATION-LEVEL FORMAT, AND THAT IS A REAL TRADE-OFF.
// Multi-part transfer is PGPony to PGPony. Say so on issue #3 and in the
// release notes rather than letting someone discover it with a camera. What
// it buys is that the QR path keeps working for exactly the keys that broke
// it, with no new dependency and no reach into ZXing's internals.
//
// COMPATIBILITY IS PRESERVED FOR EVERYTHING THAT WORKS TODAY. Anything at or
// under SINGLE_MAX is emitted as ONE unheadered symbol, byte-identical to what
// 4.0.x produced, so classic v4 keys still scan in any QR reader. Only keys
// that would have failed outright get the chunked form.
//
// Pure Kotlin, no Android imports, so the format is unit-testable rather than
// reachable only through a camera. See PHASE_4.1.0-7_NOTES.md for why that is
// now the default rather than an afterthought.

package com.pgpony.android.qr

import java.security.MessageDigest

object QrChunking {

    /** Frame marker. The digit is the format version, not the frame number. */
    const val PREFIX = "PGPONY1:"

    /**
     * At or under this, emit one unheadered symbol. Kept near the per-frame
     * payload rather than the encoder's ~2,953-byte ceiling: a symbol that
     * dense renders with tiny modules a second phone struggles to scan (#63),
     * so a key past this splits into several roomier frames instead.
     */
    const val SINGLE_MAX = 1_200

    /**
     * Payload characters per frame. Back to 1,000 for 4.5.1 (#63). 4.5.0 raised
     * this to 1,800 to fit a large post-quantum cert, but that packs each frame
     * into a dense ~version-30 symbol whose small modules a second phone
     * struggles to scan. A composite ML-DSA (PQ-only) cert still fits because
     * the capacity now comes from more frames (MAX_FRAMES) rather than denser
     * ones, which is the scannable trade.
     */
    const val PAYLOAD_MAX = 1_000

    /**
     * Ceiling on frames. At 1,000 chars each this is ~32 KB of capacity, which
     * holds a composite ML-DSA PQ-only cert (~18.5 KB, ~19 frames) with headroom
     * for the larger ML-DSA-87 / ML-KEM-1024 shapes to come. Past this the
     * caller falls back to the actionable "use Share or Copy" message rather
     * than emitting a sequence nobody will finish scanning.
     */
    const val MAX_FRAMES = 32

    private const val ID_LEN = 8
    private const val HEX = "0123456789abcdef"

    data class Frame(
        val seq: Int,
        val total: Int,
        val id: String,
        val payload: String,
    )

    sealed interface Outcome {
        /** Every frame is in; [text] is the reassembled original. */
        data class Complete(val text: String) : Outcome

        /** A new frame landed. */
        data class Progress(val have: Int, val total: Int) : Outcome

        /** Already had this one. Common: the camera sees a frame many times. */
        data class Duplicate(val have: Int, val total: Int) : Outcome

        /**
         * A frame from a DIFFERENT sequence arrived. Partial progress was
         * discarded and collection restarted. The caller should say so: the
         * user has pointed the camera at a second key mid-scan, and silently
         * merging halves of two keys would be much worse than starting over.
         */
        data class Restarted(val have: Int, val total: Int) : Outcome

        /** Not one of ours. The caller should treat it as a single QR. */
        data object NotAFrame : Outcome

        /** Carries our prefix but the header is unreadable. */
        data object Malformed : Outcome
    }

    /**
     * Split [text] for QR encoding.
     *
     * Returns a single-element list holding [text] verbatim when it fits in
     * one symbol, a list of framed chunks when it does not, and **null** when
     * even chunking cannot hold it, which is the caller's cue to show the
     * actionable too-large message instead of a raw encoder exception.
     */
    fun split(text: String): List<String>? {
        if (text.length <= SINGLE_MAX) return listOf(text)

        val total = (text.length + PAYLOAD_MAX - 1) / PAYLOAD_MAX
        if (total > MAX_FRAMES) return null

        val id = idFor(text)
        return (0 until total).map { i ->
            val from = i * PAYLOAD_MAX
            val to = minOf(from + PAYLOAD_MAX, text.length)
            PREFIX + (i + 1) + ":" + total + ":" + id + ":" + text.substring(from, to)
        }
    }

    /** True when [raw] carries our marker. Cheap pre-check for the scanner. */
    fun isFrame(raw: String): Boolean = raw.startsWith(PREFIX)

    /**
     * Parse one frame. Returns null when [raw] is not ours or the header does
     * not hold up.
     *
     * Note the payload is taken as everything after the FOURTH colon rather
     * than by splitting on ':'. Armored key text contains colons of its own
     * (`Comment:`, `Version:`), so a naive split would corrupt any cert
     * carrying armor headers, which is precisely the kind of cert that is
     * large enough to need chunking in the first place.
     */
    fun parse(raw: String): Frame? {
        if (!raw.startsWith(PREFIX)) return null
        val rest = raw.substring(PREFIX.length)

        val c1 = rest.indexOf(':')
        if (c1 <= 0) return null
        val c2 = rest.indexOf(':', c1 + 1)
        if (c2 <= c1 + 1) return null
        val c3 = rest.indexOf(':', c2 + 1)
        if (c3 <= c2 + 1) return null

        val seq = rest.substring(0, c1).toIntOrNull() ?: return null
        val total = rest.substring(c1 + 1, c2).toIntOrNull() ?: return null
        val id = rest.substring(c2 + 1, c3)
        val payload = rest.substring(c3 + 1)

        if (seq < 1 || total < 1 || seq > total || total > MAX_FRAMES) return null
        if (id.length != ID_LEN || !id.all { it in HEX }) return null

        return Frame(seq, total, id, payload)
    }

    /**
     * Stateful reassembly for the scanner. Frames may arrive in any order and
     * will arrive repeatedly, since the camera decodes the same symbol on
     * every frame it is held in view.
     *
     * Not thread-safe; drive it from one place.
     */
    class Collector {
        private var id: String? = null
        private var total: Int = 0
        private val parts = mutableMapOf<Int, String>()

        val have: Int get() = parts.size
        val expected: Int get() = total

        fun reset() {
            id = null
            total = 0
            parts.clear()
        }

        fun offer(raw: String): Outcome {
            if (!isFrame(raw)) return Outcome.NotAFrame
            val frame = parse(raw) ?: return Outcome.Malformed

            // A different key, or the same key re-encoded at a different
            // size. Either way the parts in hand cannot be mixed with these.
            val switching = id != null && (frame.id != id || frame.total != total)
            if (switching) reset()

            if (id == null) {
                id = frame.id
                total = frame.total
            }

            val fresh = parts.put(frame.seq, frame.payload) == null

            if (parts.size == total) {
                val text = buildString {
                    for (i in 1..total) append(parts[i])
                }
                return Outcome.Complete(text)
            }
            return when {
                switching -> Outcome.Restarted(parts.size, total)
                fresh -> Outcome.Progress(parts.size, total)
                else -> Outcome.Duplicate(parts.size, total)
            }
        }
    }

    /**
     * Sequence identifier: first four bytes of SHA-256 over the whole text,
     * hex. Deterministic on purpose, so the same key always produces the same
     * frames and a test can assert on them. It is a collision tag, not a
     * checksum: it exists to stop two different keys being spliced together,
     * which is the one failure mode of this format that would be silent.
     */
    fun idFor(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8))
        val sb = StringBuilder(ID_LEN)
        for (i in 0 until ID_LEN / 2) {
            val b = digest[i].toInt() and 0xFF
            sb.append(HEX[b ushr 4]).append(HEX[b and 0x0F])
        }
        return sb.toString()
    }
}
