// CcidExchange.kt
// PGPony Android — USB Phase 1
//
// The CCID conversation, one layer above framing and one below USB.
//
// WHY THIS IS A SEPARATE FILE FROM THE TRANSPORT. Everything hard about CCID
// is in the exchange, not in the bytes: the reader can ask for more time an
// unbounded number of times, it echoes a sequence number that is the only way
// to tell a stale reply from the current one, and a bulk read returns whatever
// the endpoint happened to have buffered rather than exactly one message. All
// three are testable with a fake pipe and none of them are testable through
// android.hardware.usb.
//
// This is the same split Ccid.kt and CcidDescriptor.kt already made, and the
// same one MimeEnvelope and QrChunking arrived at the hard way earlier in this
// release: put the logic where a test can reach it, and leave the platform
// class as thin plumbing.
//
// SCOPE. Response chaining is handled: a reader at extended-APDU level may
// split one card response across several DataBlocks (bChainParameter) and
// wait for the host to ask for each one after the first. The Nitrokey 3 does
// this for anything longer than one USB packet. Command chaining is not
// handled: an APDU larger than the reader's dwMaxCCIDMessageLength is
// reported with the actual limit rather than truncated or hung on. See
// transceiveApdu.

package com.pgpony.android.crypto.card

/**
 * A bidirectional byte pipe to the reader. Implemented over USB bulk
 * endpoints by UsbCcidCardTransport; implemented by a fake in tests.
 *
 * Both calls return the byte count, or a negative number on failure, matching
 * android.hardware.usb.UsbDeviceConnection.bulkTransfer so the real
 * implementation is a direct pass-through with nothing to get wrong.
 */
interface CcidPipe {
    fun write(bytes: ByteArray, timeoutMs: Int): Int
    fun read(buffer: ByteArray, timeoutMs: Int): Int

    /** Largest single read to attempt. Sized from the reader's descriptor. */
    val readBufferSize: Int
}

class CcidExchange(
    private val pipe: CcidPipe,
    private val descriptor: CcidDescriptor,
    private val slot: Int = 0,
) {

    /**
     * bSeq. Wraps at 8 bits because the field is one byte; the reader echoes
     * it and a mismatch means the reply belongs to an earlier command.
     */
    private var sequence: Int = 0

    private fun nextSequence(): Int {
        sequence = (sequence + 1) and 0xFF
        return sequence
    }

    /** Power the card up and return its ATR. */
    fun powerOn(timeoutMs: Int = DEFAULT_TIMEOUT_MS): ByteArray =
        exchange(CcidCommand.powerOn(nextSequence(), slot), timeoutMs).data

    /** Best-effort power down. Failures here are not worth propagating. */
    fun powerOff(timeoutMs: Int = SHORT_TIMEOUT_MS) {
        runCatching { exchange(CcidCommand.powerOff(nextSequence(), slot), timeoutMs) }
    }

    fun slotStatus(timeoutMs: Int = SHORT_TIMEOUT_MS): CcidResponse =
        exchange(CcidCommand.getSlotStatus(nextSequence(), slot), timeoutMs)

    /**
     * Send one APDU and return the card's response, status word included.
     *
     * [bwi] raises the reader's block waiting time. On-card RSA-4096 and
     * touch-confirm can take seconds; a caller that knows it is about to ask
     * for one should raise this rather than lean on time extensions alone.
     */
    fun transceiveApdu(
        apdu: ByteArray,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        bwi: Int = 0,
    ): ByteArray {
        if (!descriptor.fitsInOneTransfer(apdu.size)) {
            // Deliberately explicit rather than a truncation or a hang. The
            // case that reaches here is an extended-length APDU (RSA-4096
            // PSO:DECIPHER sends 1 + 512 bytes) against a reader with a small
            // dwMaxCCIDMessageLength. CCID-level chaining is the fix and it is
            // not in Phase 1.
            throw OpenPgpCardException.Communication(
                "This reader accepts at most ${descriptor.maxApduLength} bytes per " +
                    "transfer and this operation needs ${apdu.size}. PGPony does not " +
                    "yet split APDUs across CCID transfers, so use NFC for this key " +
                    "or a smaller key size."
            )
        }
        var response = exchange(
            CcidCommand.xfrBlock(nextSequence(), apdu, slot, bwi = bwi),
            timeoutMs,
        )
        if (!response.moreBlocksFollow) return response.data

        // Chained response. Reading only the first block and treating its
        // last two bytes as the status word turns a large response into a
        // nonsense status (seen as 0x0A3F on a Nitrokey 3), so collect every
        // block before handing anything up.
        val assembled = java.io.ByteArrayOutputStream()
        assembled.write(response.data)
        var blocks = 1
        while (response.moreBlocksFollow) {
            if (++blocks > MAX_CHAINED_BLOCKS) {
                throw OpenPgpCardException.Communication(
                    "Reader kept chaining past $MAX_CHAINED_BLOCKS blocks without ending the response"
                )
            }
            response = exchange(
                CcidCommand.xfrBlock(
                    nextSequence(),
                    ByteArray(0),
                    slot,
                    bwi = bwi,
                    levelParameter = Ccid.LEVEL_EXPECTING_MORE,
                ),
                timeoutMs,
            )
            assembled.write(response.data)
        }
        return assembled.toByteArray()
    }

    /**
     * Write one command and read its reply.
     *
     * Handles the three things that make this more than a write-then-read:
     * time extensions, stale replies, and messages split across bulk reads.
     */
    fun exchange(command: CcidCommand, timeoutMs: Int = DEFAULT_TIMEOUT_MS): CcidResponse {
        val out = command.toBytes()
        val written = pipe.write(out, timeoutMs)
        if (written < 0) {
            // A write that fails on a link that was working means the device
            // went away. TagLost is the card-is-gone signal the session layer
            // already understands from NFC, so USB reuses it rather than
            // inventing a second vocabulary for the same event — but NOT its
            // default message, which says "Card moved away — hold it still",
            // and nothing moved anywhere. It was unplugged.
            throw OpenPgpCardException.TagLost(DISCONNECTED)
        }
        if (written != out.size) {
            throw OpenPgpCardException.Communication(
                "Short write to reader: sent $written of ${out.size} bytes"
            )
        }

        var timeExtensions = 0
        var staleReplies = 0

        while (true) {
            val response = readOneMessage(timeoutMs)

            if (response.sequence != command.sequence) {
                // A reply to something we already gave up on. Discard and read
                // again rather than handing the caller another command's data,
                // which would be a wrong answer rather than an error.
                staleReplies++
                if (staleReplies > MAX_STALE_REPLIES) {
                    throw OpenPgpCardException.Communication(
                        "Reader kept answering with sequence ${response.sequence} " +
                            "while ${command.sequence} was outstanding"
                    )
                }
                continue
            }

            if (response.isTimeExtensionRequest) {
                // NOT an error. The card is busy (RSA-4096, or waiting on a
                // touch) and the reader is asking us to keep listening. There
                // is no defined limit on how many of these arrive, so the cap
                // exists only to stop an infinite loop on a broken reader.
                timeExtensions++
                if (timeExtensions > MAX_TIME_EXTENSIONS) {
                    throw OpenPgpCardException.Communication(
                        "Reader asked for more time $timeExtensions times without " +
                            "answering. The card may be waiting for a touch."
                    )
                }
                continue
            }

            if (response.isFailed) {
                if (!response.cardPresent) throw OpenPgpCardException.TagLost(CARD_GONE)
                throw OpenPgpCardException.Communication(
                    "Reader rejected the command: ${response.errorText()}"
                )
            }

            return response
        }
    }

    /**
     * Read exactly one CCID message.
     *
     * A bulk read returns whatever the endpoint had buffered, which may be
     * less than a whole message. dwLength in the header decides how much is
     * expected, so this reads until it has that much rather than trusting the
     * first read to be complete.
     */
    private fun readOneMessage(timeoutMs: Int): CcidResponse {
        val buffer = ByteArray(pipe.readBufferSize)
        var total = pipe.read(buffer, timeoutMs)
        if (total < 0) throw OpenPgpCardException.TagLost(DISCONNECTED)
        if (total == 0) {
            throw OpenPgpCardException.Communication("Reader returned an empty response")
        }
        if (total < Ccid.HEADER_LEN) {
            throw OpenPgpCardException.Communication(
                "CCID response too short ($total bytes) — expected at least " +
                    "${Ccid.HEADER_LEN} for the header"
            )
        }

        val declared = declaredLength(buffer)
        val needed = Ccid.HEADER_LEN + declared
        if (needed > buffer.size) {
            throw OpenPgpCardException.Communication(
                "Reader announced a $declared-byte message, larger than the " +
                    "${buffer.size}-byte read buffer this descriptor allows"
            )
        }

        var reads = 0
        while (total < needed) {
            if (++reads > MAX_CONTINUATION_READS) {
                throw OpenPgpCardException.Communication(
                    "Reader stopped ${needed - total} bytes short of the " +
                        "$declared bytes it announced"
                )
            }
            val chunk = ByteArray(needed - total)
            val n = pipe.read(chunk, timeoutMs)
            if (n < 0) throw OpenPgpCardException.TagLost(DISCONNECTED)
            if (n == 0) continue
            chunk.copyInto(buffer, total, 0, n)
            total += n
        }

        return CcidResponse.parse(buffer.copyOfRange(0, total))
    }

    /** dwLength, little-endian, read as Long so a corrupt value cannot wrap. */
    private fun declaredLength(b: ByteArray): Int {
        val v = (b[1].toLong() and 0xFF) or
            ((b[2].toLong() and 0xFF) shl 8) or
            ((b[3].toLong() and 0xFF) shl 16) or
            ((b[4].toLong() and 0xFF) shl 24)
        if (v < 0 || v > Int.MAX_VALUE) {
            throw OpenPgpCardException.Communication("CCID message declared $v bytes")
        }
        return v.toInt()
    }

    companion object {
        /**
         * OpenPgpCardException.TagLost defaults to NFC copy ("Card moved away
         * — hold it still and try again"), which is wrong on a wired link.
         * Same exception type, because the session layer already knows how to
         * handle it; different words, because the user did something else.
         */
        const val DISCONNECTED =
            "The security key was disconnected. Plug it back in and try again."

        /** The reader is still there; the card in it is not. */
        const val CARD_GONE = "The reader reports no card in the slot."

        /** Generous: on-card RSA-4096 and touch-confirm both run for seconds. */
        const val DEFAULT_TIMEOUT_MS = 20_000

        /** Status and power-down, where a hang is worse than a failure. */
        const val SHORT_TIMEOUT_MS = 2_000

        /**
         * No spec limit on time extensions; this only stops a broken reader
         * from spinning forever. At the default timeout per read this is far
         * longer than any real card operation.
         */
        const val MAX_TIME_EXTENSIONS = 60

        const val MAX_STALE_REPLIES = 8
        const val MAX_CONTINUATION_READS = 64

        /**
         * A 64 KiB response in 54-byte blocks is about 1,200 blocks; this
         * only stops a reader that never sends the last one.
         */
        const val MAX_CHAINED_BLOCKS = 2048
    }
}
