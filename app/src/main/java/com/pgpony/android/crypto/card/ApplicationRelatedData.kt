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
    val authGenTimeMs: Long?,
    /** 4.8.0 (#108): OpenPGP card spec version from AID octets 6 and 7,
     *  0x0304 for 3.4. */
    val specVersion: Int = 0,
    /** 4.8.0 (#108): the card supports MANAGE SECURITY ENVIRONMENT for the
     *  decryption and authentication keys, so PSO:DECIPHER can be pointed at
     *  the authentication key. See [mseSupportedBy]. */
    val mseSupported: Boolean = false
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
            val specVersion =
                ((aid[AID_OFFSET_VERSION].toInt() and 0xFF) shl 8) or (aid[AID_OFFSET_VERSION + 1].toInt() and 0xFF)

            // ── 4.8.0 (#108): Extended Capabilities (C0) → MSE support ──
            val extCaps = Tlv.findRecursive(raw, OpenPgpCard.DO_EXTENDED_CAPABILITIES)?.value

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
                authGenTimeMs = authGen,
                specVersion = specVersion,
                mseSupported = mseSupportedBy(specVersion, extCaps)
            )
        }

        /** AID octets 6 and 7: the spec version, BCD-like (03 04 = 3.4). */
        private const val AID_OFFSET_VERSION = 6

        /**
         * 4.8.0 (#108): does a card of [specVersion] with Extended
         * Capabilities [extCaps] (DO C0) support MANAGE SECURITY ENVIRONMENT
         * for key numbers 2 (DEC) and 3 (AUT)? OpenPGP card 3.4, 4.4.3.7: in
         * the ten-octet C0 of a 3.3 or later card, the ninth octet is the PIN
         * block 2 format flag and the tenth is MSE, 00 (not supported) or 01
         * (supported). On a 2.x card the same octet is the low byte of the
         * maximum response length, so the version is checked first and an
         * older card never counts.
         */
        internal fun mseSupportedBy(specVersion: Int, extCaps: ByteArray?): Boolean {
            if (specVersion < OpenPgpCard.SPEC_VERSION_MSE) return false
            if (extCaps == null || extCaps.size < 10) return false
            return (extCaps[9].toInt() and 0x01) != 0
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
