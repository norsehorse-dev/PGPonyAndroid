// CcidExchangeTest.kt
// PGPony Android — USB Phase 1
//
// The CCID conversation, driven by a fake pipe. None of this is reachable
// through android.hardware.usb, and all of it is the part that will actually
// go wrong against a real reader:
//
//   • the reader asking for more time, repeatedly, while the card does
//     RSA-4096 or waits for a touch
//   • a stale reply arriving with an earlier sequence number
//   • a message split across bulk reads, because a bulk read returns whatever
//     the endpoint had buffered rather than exactly one message
//   • the device being unplugged mid-operation
//
// Every one of those is a wrong-answer bug rather than a crash if it is
// handled carelessly, which is why they are tested before the USB layer
// exists rather than after it misbehaves in someone's hand.

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CcidExchangeTest {

    /** APDU exchange level, 512-byte messages. Typical of a real token. */
    private fun descriptor(maxMessageLength: Long = 512L) = CcidDescriptor(
        maxSlotIndex = 0,
        features = 0x00040000L,
        maxMessageLength = maxMessageLength,
    )

    /**
     * Fake pipe. [replies] are handed out one bulk read at a time, so a reply
     * split into two entries models a message arriving across two reads.
     */
    private class FakePipe(
        private val replies: MutableList<ByteArray>,
        override val readBufferSize: Int = 1024,
        var failWriteAfter: Int = Int.MAX_VALUE,
        var failReadAfter: Int = Int.MAX_VALUE,
    ) : CcidPipe {
        val written = mutableListOf<ByteArray>()
        private var writes = 0
        private var reads = 0

        override fun write(bytes: ByteArray, timeoutMs: Int): Int {
            if (writes++ >= failWriteAfter) return -1
            written += bytes.copyOf()
            return bytes.size
        }

        override fun read(buffer: ByteArray, timeoutMs: Int): Int {
            if (reads++ >= failReadAfter) return -1
            if (replies.isEmpty()) return 0
            val next = replies.removeAt(0)
            val n = minOf(next.size, buffer.size)
            next.copyInto(buffer, 0, 0, n)
            return n
        }
    }

    private fun dataBlock(
        sequence: Int,
        data: ByteArray = ByteArray(0),
        status: Int = 0,
        error: Int = 0,
        chain: Int = 0,
    ): ByteArray {
        val out = ByteArray(Ccid.HEADER_LEN + data.size)
        out[9] = chain.toByte()
        out[0] = Ccid.RDR_TO_PC_DATA_BLOCK.toByte()
        out[1] = (data.size and 0xFF).toByte()
        out[2] = ((data.size ushr 8) and 0xFF).toByte()
        out[6] = sequence.toByte()
        out[7] = status.toByte()
        out[8] = error.toByte()
        data.copyInto(out, Ccid.HEADER_LEN)
        return out
    }

    /** bmCommandStatus lives in bits 6-7 of bStatus. */
    private fun statusByte(commandStatus: Int, iccStatus: Int = Ccid.ICC_PRESENT_ACTIVE) =
        ((commandStatus and 0x03) shl 6) or (iccStatus and 0x03)

    private val sw9000 = byteArrayOf(0x90.toByte(), 0x00)

    // ── the ordinary case ────────────────────────────────────────────────

    @Test
    fun apduRoundTrip_returnsCardDataIncludingStatusWord() {
        val pipe = FakePipe(mutableListOf(dataBlock(1, byteArrayOf(0x01, 0x02) + sw9000)))
        val ex = CcidExchange(pipe, descriptor())

        val out = ex.transceiveApdu(byteArrayOf(0x00, 0xCA.toByte(), 0x5F, 0x52, 0x00))

        assertArrayEquals(byteArrayOf(0x01, 0x02) + sw9000, out)
        assertEquals("one command written", 1, pipe.written.size)
        assertEquals(
            "must be an XfrBlock",
            Ccid.PC_TO_RDR_XFR_BLOCK,
            pipe.written[0][0].toInt() and 0xFF
        )
    }

    @Test
    fun sequenceIncrementsPerCommand() {
        val pipe = FakePipe(mutableListOf(dataBlock(1), dataBlock(2), dataBlock(3)))
        val ex = CcidExchange(pipe, descriptor())

        ex.transceiveApdu(byteArrayOf(0x00))
        ex.transceiveApdu(byteArrayOf(0x00))
        ex.transceiveApdu(byteArrayOf(0x00))

        assertEquals(listOf(1, 2, 3), pipe.written.map { it[6].toInt() and 0xFF })
    }

    @Test
    fun powerOn_returnsTheAtr() {
        val atr = byteArrayOf(0x3B, 0xDA.toByte(), 0x18, 0xFF.toByte())
        val pipe = FakePipe(mutableListOf(dataBlock(1, atr)))
        val ex = CcidExchange(pipe, descriptor())

        assertArrayEquals(atr, ex.powerOn())
        assertEquals(
            Ccid.PC_TO_RDR_ICC_POWER_ON,
            pipe.written[0][0].toInt() and 0xFF
        )
    }

    // ── the reader asking for more time ──────────────────────────────────

    /**
     * A card doing RSA-4096, or waiting for the user to touch the key, makes
     * the reader emit a run of time extensions. Treating any of them as the
     * answer would return an empty response as if the card had replied.
     */
    @Test
    fun timeExtensions_areWaitedThroughNotMistakenForAnAnswer() {
        val te = statusByte(Ccid.CMD_STATUS_TIME_EXTENSION)
        val pipe = FakePipe(
            mutableListOf(
                dataBlock(1, status = te),
                dataBlock(1, status = te),
                dataBlock(1, status = te),
                dataBlock(1, data = sw9000),
            )
        )
        val ex = CcidExchange(pipe, descriptor())

        assertArrayEquals(sw9000, ex.transceiveApdu(byteArrayOf(0x00)))
        assertEquals("must not have re-sent the command", 1, pipe.written.size)
    }

    @Test
    fun endlessTimeExtensions_giveUpWithAnExplanation() {
        val te = statusByte(Ccid.CMD_STATUS_TIME_EXTENSION)
        val replies = MutableList(CcidExchange.MAX_TIME_EXTENSIONS + 5) {
            dataBlock(1, status = te)
        }
        val ex = CcidExchange(FakePipe(replies), descriptor())

        val e = runCatching { ex.transceiveApdu(byteArrayOf(0x00)) }.exceptionOrNull()
        assertTrue("expected a Communication failure, got $e",
            e is OpenPgpCardException.Communication)
        assertTrue(
            "the message should point at the touch case: ${e?.message}",
            e?.message?.contains("touch") == true
        )
    }

    // ── stale replies ────────────────────────────────────────────────────

    /**
     * The sequence byte is the ONLY way to tell a reply to the current command
     * from a leftover. Accepting a stale one hands the caller another
     * command's data, which is a wrong answer rather than an error, and on a
     * card that is the worst possible outcome.
     */
    @Test
    fun staleReply_isDiscardedAndTheRealOneUsed() {
        val pipe = FakePipe(
            mutableListOf(
                dataBlock(sequence = 0, data = byteArrayOf(0xDE.toByte())),
                dataBlock(sequence = 1, data = sw9000),
            )
        )
        val ex = CcidExchange(pipe, descriptor())

        assertArrayEquals(sw9000, ex.transceiveApdu(byteArrayOf(0x00)))
    }

    @Test
    fun onlyStaleReplies_failsRatherThanReturningTheWrongData() {
        val replies = MutableList(CcidExchange.MAX_STALE_REPLIES + 3) {
            dataBlock(sequence = 99, data = byteArrayOf(0xDE.toByte()))
        }
        val ex = CcidExchange(FakePipe(replies), descriptor())

        val e = runCatching { ex.transceiveApdu(byteArrayOf(0x00)) }.exceptionOrNull()
        assertTrue(e is OpenPgpCardException.Communication)
    }

    // ── messages split across bulk reads ─────────────────────────────────

    /**
     * A bulk read returns whatever the endpoint had buffered. Parsing the
     * first read as a whole message would truncate the card's response, and a
     * truncated APDU response is not detectably wrong to the layer above.
     */
    @Test
    fun messageSplitAcrossTwoReads_isReassembled() {
        val payload = ByteArray(40) { it.toByte() } + sw9000
        val whole = dataBlock(1, payload)
        val first = whole.copyOfRange(0, 15)
        val second = whole.copyOfRange(15, whole.size)

        val pipe = FakePipe(mutableListOf(first, second))
        val ex = CcidExchange(pipe, descriptor())

        assertArrayEquals(payload, ex.transceiveApdu(byteArrayOf(0x00)))
    }

    @Test
    fun headerShorterThanTenBytes_isReportedNotParsed() {
        val pipe = FakePipe(mutableListOf(byteArrayOf(0x80.toByte(), 0x00, 0x00)))
        val ex = CcidExchange(pipe, descriptor())

        val e = runCatching { ex.transceiveApdu(byteArrayOf(0x00)) }.exceptionOrNull()
        assertTrue(e is OpenPgpCardException.Communication)
    }

    // ── the device going away ────────────────────────────────────────────

    /**
     * Unplugging mid-operation must surface as TagLost, the same signal the
     * session layer already handles from NFC, rather than as a generic I/O
     * failure it has no plan for.
     */
    @Test
    fun writeFailure_surfacesAsTagLost() {
        val pipe = FakePipe(mutableListOf(), failWriteAfter = 0)
        val ex = CcidExchange(pipe, descriptor())

        val e = runCatching { ex.transceiveApdu(byteArrayOf(0x00)) }.exceptionOrNull()
        assertTrue("expected TagLost, got $e", e is OpenPgpCardException.TagLost)
    }

    @Test
    fun readFailure_surfacesAsTagLost() {
        val pipe = FakePipe(mutableListOf(), failReadAfter = 0)
        val ex = CcidExchange(pipe, descriptor())

        val e = runCatching { ex.transceiveApdu(byteArrayOf(0x00)) }.exceptionOrNull()
        assertTrue("expected TagLost, got $e", e is OpenPgpCardException.TagLost)
    }

    @Test
    fun cardRemovedReportedByTheReader_surfacesAsTagLost() {
        val pipe = FakePipe(
            mutableListOf(
                dataBlock(
                    1,
                    status = statusByte(Ccid.CMD_STATUS_FAILED, Ccid.ICC_ABSENT),
                    error = 0xFE,
                )
            )
        )
        val ex = CcidExchange(pipe, descriptor())

        val e = runCatching { ex.transceiveApdu(byteArrayOf(0x00)) }.exceptionOrNull()
        assertTrue("expected TagLost, got $e", e is OpenPgpCardException.TagLost)
    }

    @Test
    fun readerErrorWithCardStillPresent_reportsTheReaderText() {
        val pipe = FakePipe(
            mutableListOf(
                dataBlock(
                    1,
                    status = statusByte(Ccid.CMD_STATUS_FAILED),
                    error = 0xFE,
                )
            )
        )
        val ex = CcidExchange(pipe, descriptor())

        val e = runCatching { ex.transceiveApdu(byteArrayOf(0x00)) }.exceptionOrNull()
        assertTrue(e is OpenPgpCardException.Communication)
        assertTrue(
            "should name the reader's own reason: ${e?.message}",
            e?.message?.contains("mute") == true
        )
    }

    // ── the limit we do not implement ────────────────────────────────────

    /**
     * RSA-4096 PSO:DECIPHER sends 1 + 512 bytes. Against a reader with a small
     * dwMaxCCIDMessageLength that needs CCID-level chaining, which Phase 1
     * does not do. It must say so with the real number rather than truncate,
     * hang, or fail obscurely.
     */
    @Test
    fun apduLargerThanTheReaderAllows_saysSoWithTheActualLimit() {
        val ex = CcidExchange(FakePipe(mutableListOf()), descriptor(maxMessageLength = 64L))

        val e = runCatching { ex.transceiveApdu(ByteArray(300)) }.exceptionOrNull()
        assertTrue(e is OpenPgpCardException.Communication)
        val msg = e?.message ?: ""
        assertTrue("should state the reader's limit: $msg", msg.contains("54"))
        assertTrue("should state what was needed: $msg", msg.contains("300"))
        assertTrue("should suggest a way forward: $msg", msg.contains("NFC"))
    }

    @Test
    fun apduExactlyAtTheLimit_isSent() {
        val size = 54
        val pipe = FakePipe(mutableListOf(dataBlock(1, sw9000)))
        val ex = CcidExchange(pipe, descriptor(maxMessageLength = 64L))

        assertArrayEquals(sw9000, ex.transceiveApdu(ByteArray(size)))
    }

    // ── response chaining ────────────────────────────────────────────────

    /**
     * The Nitrokey 3 splits any response longer than one USB packet into
     * chained DataBlocks and waits for the host to request each one. Reading
     * only the first block produced a status word from the middle of the
     * data (0x0A3F in a user report).
     */
    @Test
    fun chainedResponse_isRequestedBlockByBlockAndReassembled() {
        val part1 = ByteArray(54) { it.toByte() }
        val part2 = ByteArray(54) { (100 + it).toByte() }
        val part3 = byteArrayOf(0x11, 0x22, 0x90.toByte(), 0x00)
        val pipe = FakePipe(
            mutableListOf(
                dataBlock(1, part1, chain = Ccid.CHAIN_BEGINS),
                dataBlock(2, part2, chain = Ccid.CHAIN_CONTINUES),
                dataBlock(3, part3, chain = Ccid.CHAIN_ENDS),
            )
        )
        val ex = CcidExchange(pipe, descriptor())

        val out = ex.transceiveApdu(byteArrayOf(0x00, 0xCA.toByte(), 0x00, 0x6E, 0x00))

        assertArrayEquals(part1 + part2 + part3, out)
        assertEquals(3, pipe.written.size)
        for (i in 1..2) {
            val req = pipe.written[i]
            assertEquals(Ccid.HEADER_LEN, req.size)
            assertEquals(Ccid.PC_TO_RDR_XFR_BLOCK, req[0].toInt() and 0xFF)
            assertEquals(i + 1, req[6].toInt() and 0xFF)
            val level = (req[8].toInt() and 0xFF) or ((req[9].toInt() and 0xFF) shl 8)
            assertEquals(Ccid.LEVEL_EXPECTING_MORE, level)
        }
    }

    @Test
    fun unchainedResponse_sendsNoExtraRequest() {
        val pipe = FakePipe(mutableListOf(dataBlock(1, sw9000, chain = Ccid.CHAIN_BEGINS_AND_ENDS)))
        val ex = CcidExchange(pipe, descriptor())

        assertArrayEquals(sw9000, ex.transceiveApdu(byteArrayOf(0x00)))
        assertEquals(1, pipe.written.size)
    }

    @Test
    fun chainThatNeverEnds_failsInsteadOfLooping() {
        val replies = MutableList(CcidExchange.MAX_CHAINED_BLOCKS + 1) { i ->
            dataBlock(i + 1, byteArrayOf(0x01), chain = if (i == 0) Ccid.CHAIN_BEGINS else Ccid.CHAIN_CONTINUES)
        }
        val ex = CcidExchange(FakePipe(replies), descriptor())

        val e = runCatching { ex.transceiveApdu(byteArrayOf(0x00)) }.exceptionOrNull()
        assertTrue(e is OpenPgpCardException.Communication)
    }
}
