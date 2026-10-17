package com.pgpony.android.qr

import java.security.MessageDigest

object QrChunking {

    /** Frame marker. The digit is the format version, not the frame number. */
    const val PREFIX = "PGPONY1:"

    /** Raw symbols at or below this threshold preserve the released single-QR format. */
    const val SINGLE_MAX = 1_200

    /** Released default payload width. Optional profiles may use smaller canonical slices. */
    const val PAYLOAD_MAX = 1_000

    /** The compatible transport retains its released ceiling of 32 parts and 32,000 characters. */
    const val MAX_FRAMES = 32

    /** Maximum retained text, including older senders with larger per-frame payloads. */
    const val MAX_TEXT_CHARS = PAYLOAD_MAX * MAX_FRAMES
    private const val MAX_HEADER_CHARS = 64

    private const val ID_LEN = 8
    private const val HEX = "0123456789abcdef"

    data class Frame(
        val seq: Int,
        val total: Int,
        val id: String,
        val payload: String,
    )

    sealed interface Outcome {
        /** Every frame is in and the reassembled [text] matches the content ID. */
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

        /** Invalid framing, conflicting content, resource overflow or a failed content-ID check. */
        data object Malformed : Outcome
    }

    /**
     * Split [text] for QR encoding.
     *
     * Returns a single-element list holding [text] verbatim when it fits in
     * one symbol, a list of framed chunks when it does not, and **null** when
     * even chunking cannot hold it, which is the caller's cue to show the
     * actionable too-large message instead of a raw encoder exception.
     * Profiles retain the same wire grammar and single-symbol threshold. If a
     * preferred width would exceed 32 parts, the width rises to fit that cap.
     */
    fun split(text: String, policy: QrEncodingPolicy = QrEncodingPolicy.BASELINE): List<String>? {
        if (text.length <= SINGLE_MAX) return listOf(text)
        if (text.length > MAX_TEXT_CHARS) return null

        val payload = maxOf(policy.payloadChars, ceilDiv(text.length, MAX_FRAMES))
        val total = ceilDiv(text.length, payload)
        // Old collectors identify a sequence by content ID and count alone.
        // Equal counts must therefore imply equal slices across every profile.
        val width = if (total == ceilDiv(text.length, PAYLOAD_MAX)) {
            PAYLOAD_MAX
        } else {
            ceilDiv(text.length, total)
        }
        val id = idFor(text)
        return (0 until total).map { i ->
            val from = i * width
            val to = minOf(from + width, text.length)
            PREFIX + (i + 1) + ":" + total + ":" + id + ":" + text.substring(from, to)
        }
    }

    private fun ceilDiv(value: Int, divisor: Int): Int = (value + divisor - 1) / divisor

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
        if (!raw.startsWith(PREFIX) || raw.length > MAX_TEXT_CHARS + MAX_HEADER_CHARS) return null
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
        if (payload.length > MAX_TEXT_CHARS) return null

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
        private var retainedChars = 0

        val have: Int get() = parts.size
        val expected: Int get() = total

        fun reset() {
            id = null
            total = 0
            parts.clear()
            retainedChars = 0
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

            val previous = parts[frame.seq]
            if (previous != null && previous != frame.payload) {
                reset()
                return Outcome.Malformed
            }
            val fresh = previous == null
            if (fresh) {
                if (retainedChars + frame.payload.length > MAX_TEXT_CHARS) {
                    reset()
                    return Outcome.Malformed
                }
                parts[frame.seq] = frame.payload
                retainedChars += frame.payload.length
            }

            if (parts.size == total) {
                val text = buildString {
                    for (i in 1..total) append(parts[i])
                }
                if (idFor(text) != id) {
                    reset()
                    return Outcome.Malformed
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
     * hex. Receivers verify this tag after reassembly to detect mixed or
     * corrupted frames. Its 32-bit scope provides limited collision resistance;
     * it does not authenticate a key owner or replace fingerprint verification.
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
