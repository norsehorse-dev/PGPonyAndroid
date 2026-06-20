// ApplicationRelatedData.kt
// PGPony Android — HW Phase 0
//
// Parses the OpenPGP card "Application Related Data" returned by
// GET DATA 0x6E into the fields PGPony cares about: card identity (AID →
// manufacturer + serial), per-slot algorithm attributes, per-slot
// fingerprints, PIN retry counters, and key generation timestamps.
//
// Robust to whether a given card wraps the response in the 0x6E DO or
// returns its content directly, and to whether C1..CD sit directly under
// 0x6E or nested under the Discretionary DO 0x73 — we locate each sub-DO
// with Tlv.findRecursive. No Android dependencies — unit-testable.

package com.pgpony.android.crypto.card

data class ApplicationRelatedData(
    val aidHex: String,
    val manufacturerId: Int,
    val manufacturerName: String,
    val serialHex: String,
    val sigAlgorithm: CardAlgorithmAttributes?,
    val decAlgorithm: CardAlgorithmAttributes?,
    val authAlgorithm: CardAlgorithmAttributes?,
    /** Uppercase hex, or null when the slot's fingerprint is all-zero. */
    val sigFingerprint: String?,
    val decFingerprint: String?,
    val authFingerprint: String?,
    val pw1TriesRemaining: Int,
    val pw3TriesRemaining: Int,
    /** Epoch milliseconds, or null when the slot has no generation time. */
    val sigGenTimeMs: Long?,
    val decGenTimeMs: Long?,
    val authGenTimeMs: Long?
) {
    companion object {
        private const val FINGERPRINT_LEN = 20
        private val HEX = "0123456789ABCDEF".toCharArray()

        fun parse(raw: ByteArray): ApplicationRelatedData {
            // ── AID (DO 0x4F) → manufacturer + serial ──
            val aid = Tlv.findRecursive(raw, OpenPgpCard.DO_AID)?.value
                ?: throw OpenPgpCardException.Malformed("Application Related Data missing AID (0x4F)")
            if (aid.size < OpenPgpCard.AID_LENGTH) {
                throw OpenPgpCardException.Malformed("AID too short: ${aid.size} bytes")
            }
            val manufacturerId =
                ((aid[OpenPgpCard.AID_OFFSET_MANUFACTURER].toInt() and 0xFF) shl 8) or
                    (aid[OpenPgpCard.AID_OFFSET_MANUFACTURER + 1].toInt() and 0xFF)
            val serialBytes = aid.copyOfRange(
                OpenPgpCard.AID_OFFSET_SERIAL,
                OpenPgpCard.AID_OFFSET_SERIAL + 4
            )

            // ── Algorithm attributes (C1 / C2 / C3) ──
            val sigAlgo = Tlv.findRecursive(raw, OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_SIG)
                ?.let { CardAlgorithmAttributes.parse(it.value) }
            val decAlgo = Tlv.findRecursive(raw, OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_DEC)
                ?.let { CardAlgorithmAttributes.parse(it.value) }
            val authAlgo = Tlv.findRecursive(raw, OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_AUTH)
                ?.let { CardAlgorithmAttributes.parse(it.value) }

            // ── Fingerprints (C5): 3 × 20 bytes (sig | dec | auth) ──
            val fps = Tlv.findRecursive(raw, OpenPgpCard.DO_FINGERPRINTS)?.value
            val sigFp = fingerprintAt(fps, 0)
            val decFp = fingerprintAt(fps, 1)
            val authFp = fingerprintAt(fps, 2)

            // ── PW status (C4): byte[4]=PW1 tries, byte[6]=PW3 tries ──
            val pw = Tlv.findRecursive(raw, OpenPgpCard.DO_PW_STATUS_BYTES)?.value
            val pw1Tries = pw?.getOrNull(4)?.toInt()?.and(0xFF) ?: -1
            val pw3Tries = pw?.getOrNull(6)?.toInt()?.and(0xFF) ?: -1

            // ── Generation times (CD): 3 × 4-byte big-endian unix seconds ──
            val gen = Tlv.findRecursive(raw, OpenPgpCard.DO_GENERATION_TIMES)?.value
            val sigGen = genTimeAt(gen, 0)
            val decGen = genTimeAt(gen, 1)
            val authGen = genTimeAt(gen, 2)

            return ApplicationRelatedData(
                aidHex = toHex(aid),
                manufacturerId = manufacturerId,
                manufacturerName = OpenPgpCard.manufacturerName(manufacturerId),
                serialHex = toHex(serialBytes),
                sigAlgorithm = sigAlgo,
                decAlgorithm = decAlgo,
                authAlgorithm = authAlgo,
                sigFingerprint = sigFp,
                decFingerprint = decFp,
                authFingerprint = authFp,
                pw1TriesRemaining = pw1Tries,
                pw3TriesRemaining = pw3Tries,
                sigGenTimeMs = sigGen,
                decGenTimeMs = decGen,
                authGenTimeMs = authGen
            )
        }

        private fun fingerprintAt(all: ByteArray?, index: Int): String? {
            if (all == null) return null
            val start = index * FINGERPRINT_LEN
            if (start + FINGERPRINT_LEN > all.size) return null
            val slice = all.copyOfRange(start, start + FINGERPRINT_LEN)
            if (slice.all { it.toInt() == 0 }) return null   // empty slot
            return toHex(slice)
        }

        private fun genTimeAt(all: ByteArray?, index: Int): Long? {
            if (all == null) return null
            val start = index * 4
            if (start + 4 > all.size) return null
            var secs = 0L
            for (i in 0 until 4) {
                secs = (secs shl 8) or (all[start + i].toLong() and 0xFF)
            }
            if (secs == 0L) return null
            return secs * 1000L
        }

        private fun toHex(bytes: ByteArray): String {
            val sb = StringBuilder(bytes.size * 2)
            for (b in bytes) {
                val v = b.toInt() and 0xFF
                sb.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
            }
            return sb.toString()
        }
    }
}
