// Ccid.kt
// PGPony Android — USB Phase 0
//
// CCID (USB Chip/Smart Card Interface Device, class 0x0B) message framing.
// This is the layer IsoDep provides for free over NFC and that Android's
// framework does not provide at all over USB: the host has to build and parse
// the bulk-transfer envelopes itself.
//
// Deliberately the same shape as CommandApdu / ResponseApdu / Tlv: pure
// Kotlin, no Android imports, unit-testable without a device. HW Phase 0 built
// the APDU layer this way before IsoDepCardTransport existed in Phase 1; this
// is the same split for USB.
//
// SCOPE. This is a dumb pipe for APDUs. It does NOT implement APDU-level
// chaining — OpenPgpCardSession already handles 0x61xx (GET RESPONSE) and
// 0x6Cxx (wrong Le) above the transport, exactly as it does over NFC, and
// duplicating that here would give two implementations of one rule.
//
// Every multi-byte field in CCID is LITTLE-endian, which is the opposite of
// every other length in this codebase (ISO 7816, OpenPGP, and the card's own
// TLVs are all big-endian). That reversal is the single easiest thing to get
// wrong in this file.

package com.pgpony.android.crypto.card

/** CCID message types and the fixed header size, per CCID 1.1 §4–5. */
object Ccid {
    // ── PC → Reader ────────────────────────────────────────────────────
    const val PC_TO_RDR_ICC_POWER_ON = 0x62
    const val PC_TO_RDR_ICC_POWER_OFF = 0x63
    const val PC_TO_RDR_GET_SLOT_STATUS = 0x65
    const val PC_TO_RDR_XFR_BLOCK = 0x6F

    // ── Reader → PC ────────────────────────────────────────────────────
    const val RDR_TO_PC_DATA_BLOCK = 0x80
    const val RDR_TO_PC_SLOT_STATUS = 0x81

    /** Every CCID message begins with a 10-byte header. */
    const val HEADER_LEN = 10

    // ── bStatus, bits 6–7: bmCommandStatus ─────────────────────────────
    const val CMD_STATUS_SUCCESS = 0
    const val CMD_STATUS_FAILED = 1
    /** The reader needs longer; read another response from bulk-IN. */
    const val CMD_STATUS_TIME_EXTENSION = 2

    // ── bChainParameter on RDR_to_PC_DataBlock ─────────────────────────
    /** The whole response is in this block. */
    const val CHAIN_BEGINS_AND_ENDS = 0x00
    /** First block of a chained response; more follow. */
    const val CHAIN_BEGINS = 0x01
    /** Last block of a chained response. */
    const val CHAIN_ENDS = 0x02
    /** A middle block of a chained response; more follow. */
    const val CHAIN_CONTINUES = 0x03

    /**
     * wLevelParameter on an empty PC_to_RDR_XfrBlock: the host asking the
     * reader for the next block of a chained response. The reader waits for
     * this before sending each block after the first.
     */
    const val LEVEL_EXPECTING_MORE = 0x10

    // ── bStatus, bits 0–1: bmICCStatus ─────────────────────────────────
    const val ICC_PRESENT_ACTIVE = 0
    const val ICC_PRESENT_INACTIVE = 1
    const val ICC_ABSENT = 2

    /**
     * bError values worth naming. The rest are reported by number — a card
     * that answers with something exotic should say so rather than be
     * flattened into "unknown error".
     */
    fun errorText(bError: Int): String = when (bError and 0xFF) {
        0x00 -> "command not supported by this reader"
        0xE0 -> "slot busy"
        0xEF -> "PIN entry cancelled"
        0xF0 -> "PIN entry timed out"
        0xF2 -> "reader busy with an automatic sequence"
        0xF3 -> "protocol deactivated"
        0xF4 -> "procedure byte conflict"
        0xF5 -> "card class not supported"
        0xF6 -> "card protocol not supported"
        0xF7 -> "bad ATR checksum"
        0xF8 -> "bad ATR TS"
        0xFB -> "reader hardware error"
        0xFC -> "transfer overrun"
        0xFD -> "transfer parity error"
        0xFE -> "card is mute — it did not answer"
        0xFF -> "command aborted"
        else -> "reader error 0x%02X".format(bError and 0xFF)
    }
}

/**
 * A PC_to_RDR message. [param0]–[param2] are the three message-specific
 * header bytes at offsets 7–9, which mean different things per message type;
 * the companion builders name them so call sites do not have to remember.
 *
 * [sequence] is echoed back by the reader in its response and is the only way
 * to tell a stale reply from the current one, so the transport must increment
 * it per exchange and check it.
 */
data class CcidCommand(
    val messageType: Int,
    val sequence: Int,
    val slot: Int = 0,
    val param0: Int = 0,
    val param1: Int = 0,
    val param2: Int = 0,
    val data: ByteArray = ByteArray(0)
) {
    fun toBytes(): ByteArray {
        val out = ByteArray(Ccid.HEADER_LEN + data.size)
        out[0] = (messageType and 0xFF).toByte()
        // dwLength — LITTLE-endian, and it counts abData only, not the header.
        val n = data.size
        out[1] = (n and 0xFF).toByte()
        out[2] = ((n ushr 8) and 0xFF).toByte()
        out[3] = ((n ushr 16) and 0xFF).toByte()
        out[4] = ((n ushr 24) and 0xFF).toByte()
        out[5] = (slot and 0xFF).toByte()
        out[6] = (sequence and 0xFF).toByte()
        out[7] = (param0 and 0xFF).toByte()
        out[8] = (param1 and 0xFF).toByte()
        out[9] = (param2 and 0xFF).toByte()
        data.copyInto(out, Ccid.HEADER_LEN)
        return out
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CcidCommand) return false
        return messageType == other.messageType && sequence == other.sequence &&
            slot == other.slot && param0 == other.param0 &&
            param1 == other.param1 && param2 == other.param2 &&
            data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var r = messageType
        r = 31 * r + sequence
        r = 31 * r + slot
        r = 31 * r + param0
        r = 31 * r + param1
        r = 31 * r + param2
        r = 31 * r + data.contentHashCode()
        return r
    }

    companion object {
        /**
         * Power the card up and read its ATR. [powerSelect] 0x00 means
         * "automatic voltage selection", which is what any modern token wants.
         */
        fun powerOn(sequence: Int, slot: Int = 0, powerSelect: Int = 0x00) =
            CcidCommand(Ccid.PC_TO_RDR_ICC_POWER_ON, sequence, slot, param0 = powerSelect)

        fun powerOff(sequence: Int, slot: Int = 0) =
            CcidCommand(Ccid.PC_TO_RDR_ICC_POWER_OFF, sequence, slot)

        fun getSlotStatus(sequence: Int, slot: Int = 0) =
            CcidCommand(Ccid.PC_TO_RDR_GET_SLOT_STATUS, sequence, slot)

        /**
         * Carry one APDU to the card.
         *
         * [bwi] is the block waiting time multiplier — how long the reader is
         * told to wait before giving up on the card. 0 means "use the default
         * from the descriptor". On-card RSA-4096 and touch-confirm (UIF) can
         * take seconds, so a caller that knows it is about to ask for one
         * should raise this rather than rely on time extensions alone.
         *
         * [levelParameter] is wLevelParameter, used only for CCID-level
         * chaining on extended-APDU readers; 0 for the ordinary case.
         */
        fun xfrBlock(
            sequence: Int,
            apdu: ByteArray,
            slot: Int = 0,
            bwi: Int = 0,
            levelParameter: Int = 0
        ) = CcidCommand(
            messageType = Ccid.PC_TO_RDR_XFR_BLOCK,
            sequence = sequence,
            slot = slot,
            param0 = bwi,
            // wLevelParameter is little-endian across offsets 8 and 9.
            param1 = levelParameter and 0xFF,
            param2 = (levelParameter ushr 8) and 0xFF,
            data = apdu
        )
    }
}

/**
 * An RDR_to_PC message. Both response types share the 10-byte header shape;
 * offset 9 is bChainParameter on a DataBlock and bClockStatus on a
 * SlotStatus, so it is kept raw and interpreted by the caller.
 */
data class CcidResponse(
    val messageType: Int,
    val sequence: Int,
    val slot: Int,
    val status: Int,
    val error: Int,
    val chainParameter: Int,
    val data: ByteArray
) {
    /** bmCommandStatus — bits 6–7 of bStatus. */
    val commandStatus: Int get() = (status shr 6) and 0x03

    /** bmICCStatus — bits 0–1 of bStatus. */
    val iccStatus: Int get() = status and 0x03

    val isSuccess: Boolean get() = commandStatus == Ccid.CMD_STATUS_SUCCESS
    val isFailed: Boolean get() = commandStatus == Ccid.CMD_STATUS_FAILED

    /**
     * The reader is still working and is asking for more time. NOT an error:
     * the correct response is to read the next message from bulk-IN and keep
     * doing so until the status changes. A card doing RSA-4096 or waiting on
     * a touch will produce a run of these.
     */
    val isTimeExtensionRequest: Boolean
        get() = commandStatus == Ccid.CMD_STATUS_TIME_EXTENSION

    val cardPresent: Boolean get() = iccStatus != Ccid.ICC_ABSENT

    /**
     * True when this DataBlock is the first or a middle block of a chained
     * response and the reader is holding more for the host to request.
     */
    val moreBlocksFollow: Boolean
        get() = messageType == Ccid.RDR_TO_PC_DATA_BLOCK &&
            (chainParameter == Ccid.CHAIN_BEGINS || chainParameter == Ccid.CHAIN_CONTINUES)

    /** Human-readable reason, meaningful only when [isFailed]. */
    fun errorText(): String = Ccid.errorText(error)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CcidResponse) return false
        return messageType == other.messageType && sequence == other.sequence &&
            slot == other.slot && status == other.status && error == other.error &&
            chainParameter == other.chainParameter && data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var r = messageType
        r = 31 * r + sequence
        r = 31 * r + slot
        r = 31 * r + status
        r = 31 * r + error
        r = 31 * r + chainParameter
        r = 31 * r + data.contentHashCode()
        return r
    }

    companion object {
        /**
         * Parse one RDR_to_PC message.
         *
         * [raw] may be longer than the message — a bulk read returns whatever
         * the endpoint had buffered — so dwLength decides where abData ends,
         * not the array size. A message that claims more data than arrived is
         * a short read and is reported as such rather than silently truncated.
         */
        fun parse(raw: ByteArray): CcidResponse {
            if (raw.size < Ccid.HEADER_LEN) {
                throw OpenPgpCardException.Communication(
                    "CCID response too short (${raw.size} bytes) — expected at least " +
                        "${Ccid.HEADER_LEN} for the header"
                )
            }
            // dwLength is little-endian. Read as Long so a hostile or corrupt
            // length cannot wrap into a negative Int and slip past the check.
            val declared =
                (raw[1].toLong() and 0xFF) or
                    ((raw[2].toLong() and 0xFF) shl 8) or
                    ((raw[3].toLong() and 0xFF) shl 16) or
                    ((raw[4].toLong() and 0xFF) shl 24)
            val available = (raw.size - Ccid.HEADER_LEN).toLong()
            if (declared > available) {
                throw OpenPgpCardException.Communication(
                    "CCID response declared $declared bytes of data but only $available arrived"
                )
            }
            val end = Ccid.HEADER_LEN + declared.toInt()
            return CcidResponse(
                messageType = raw[0].toInt() and 0xFF,
                sequence = raw[6].toInt() and 0xFF,
                slot = raw[5].toInt() and 0xFF,
                status = raw[7].toInt() and 0xFF,
                error = raw[8].toInt() and 0xFF,
                chainParameter = raw[9].toInt() and 0xFF,
                data = raw.copyOfRange(Ccid.HEADER_LEN, end)
            )
        }
    }
}
