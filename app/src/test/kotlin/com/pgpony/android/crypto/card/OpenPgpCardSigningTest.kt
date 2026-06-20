// OpenPgpCardSigningTest.kt
// PGPony Android — HW Phase 2a tests
//
// Exercises the PIN-verify, sign-digest, and change-reference-data
// primitives against a scripted in-memory transport that records the
// command bytes, so we can assert both the responses are handled and the
// correct APDUs are emitted — no device needed.

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class OpenPgpCardSigningTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    private fun sw(hi: Int, lo: Int) = byteArrayOf(hi.toByte(), lo.toByte())

    /** Returns a programmed response per INS byte and records every command sent. */
    private class ScriptedTransport(private val responses: Map<Int, ByteArray>) : CardTransport {
        val sent = mutableListOf<ByteArray>()
        override fun transceive(commandApdu: ByteArray): ByteArray {
            sent.add(commandApdu)
            val ins = commandApdu[1].toInt() and 0xFF
            return responses[ins] ?: byteArrayOf(0x6D.toByte(), 0x00)
        }
    }

    private val PIN_123456 = bytes(0x31, 0x32, 0x33, 0x34, 0x35, 0x36)
    private val PIN_654321 = bytes(0x36, 0x35, 0x34, 0x33, 0x32, 0x31)

    @Test
    fun verifySendsCorrectApduOnSuccess() {
        val t = ScriptedTransport(mapOf(OpenPgpCard.INS_VERIFY to sw(0x90, 0x00)))
        OpenPgpCardSession(t).verify(OpenPgpCard.PW1_SIGN, PIN_123456)
        // 00 20 00 81 06 31 32 33 34 35 36
        assertArrayEquals(
            bytes(0x00, 0x20, 0x00, 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36),
            t.sent[0]
        )
    }

    @Test
    fun verifyWrongPinReportsTriesRemaining() {
        val t = ScriptedTransport(mapOf(OpenPgpCard.INS_VERIFY to sw(0x63, 0xC2)))
        try {
            OpenPgpCardSession(t).verify(OpenPgpCard.PW1_SIGN, PIN_123456)
            fail("expected WrongPin")
        } catch (e: OpenPgpCardException.WrongPin) {
            assertEquals(2, e.triesRemaining)
        }
    }

    @Test
    fun verifyBlockedThrowsCardStatus() {
        val t = ScriptedTransport(mapOf(OpenPgpCard.INS_VERIFY to sw(0x69, 0x83)))
        try {
            OpenPgpCardSession(t).verify(OpenPgpCard.PW1_SIGN, PIN_123456)
            fail("expected CardStatus")
        } catch (e: OpenPgpCardException.CardStatus) {
            assertEquals(0x6983, e.sw)
        }
    }

    @Test
    fun signDigestReturnsSignatureBytes() {
        val signature = ByteArray(64) { 0xAB.toByte() }
        val t = ScriptedTransport(
            mapOf(OpenPgpCard.INS_PERFORM_SECURITY_OPERATION to (signature + sw(0x90, 0x00)))
        )
        val digest = ByteArray(32) { 0x11 }
        val out = OpenPgpCardSession(t).signDigest(digest)
        assertArrayEquals(signature, out)
        // 00 2A 9E 9A <Lc=32> <digest> <Le=00>
        val cmd = t.sent[0]
        assertEquals(0x2A, cmd[1].toInt() and 0xFF)
        assertEquals(0x9E, cmd[2].toInt() and 0xFF)
        assertEquals(0x9A, cmd[3].toInt() and 0xFF)
    }

    @Test
    fun changeReferenceDataConcatenatesOldThenNew() {
        val t = ScriptedTransport(mapOf(OpenPgpCard.INS_CHANGE_REFERENCE_DATA to sw(0x90, 0x00)))
        OpenPgpCardSession(t).changeReferenceData(OpenPgpCard.CRD_PW1, PIN_123456, PIN_654321)
        // 00 24 00 81 0C <old(6)><new(6)>
        val cmd = t.sent[0]
        assertEquals(0x24, cmd[1].toInt() and 0xFF)
        assertEquals(0x81, cmd[3].toInt() and 0xFF)
        assertEquals(0x0C, cmd[4].toInt() and 0xFF)
        assertArrayEquals(PIN_123456 + PIN_654321, cmd.copyOfRange(5, 5 + 12))
    }

    @Test
    fun changeUserPinSelectsThenChanges() {
        val t = ScriptedTransport(
            mapOf(
                OpenPgpCard.INS_SELECT to sw(0x90, 0x00),
                OpenPgpCard.INS_CHANGE_REFERENCE_DATA to sw(0x90, 0x00)
            )
        )
        OpenPgpCardSession(t).changeUserPin("123456", "654321")
        assertEquals(2, t.sent.size)
        assertEquals(0xA4, t.sent[0][1].toInt() and 0xFF) // SELECT first
        assertEquals(0x24, t.sent[1][1].toInt() and 0xFF) // then CHANGE REFERENCE DATA
        assertArrayEquals(PIN_123456 + PIN_654321, t.sent[1].copyOfRange(5, 5 + 12))
    }

    @Test
    fun wrongPinZeroTriesReportsBlocked() {
        val e = OpenPgpCardException.CardStatus.of(0x63C0)
        // 0x63C0 → WrongPin(0)
        if (e is OpenPgpCardException.WrongPin) {
            assertEquals(0, e.triesRemaining)
        } else {
            fail("expected WrongPin for 0x63C0")
        }
    }
}
