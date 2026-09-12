// TruncatedMessageTest.kt
// PGPony Android — 4.5.0 (item 23 / #55): a truncated message reads as
// "incomplete", not a raw range error.
//
// Grigori Perelman hit "Decryption failed: toIndex (3370) is greater than size
// (2784)" after pasting only part of an encrypted message. A cut-off message
// leaves a packet length pointing past the end of the buffer, which surfaces as a
// range / end-of-stream error deep in the parser. looksIncomplete classifies
// those so decrypt maps them to PGPCryptoError.MessageIncomplete and the UI shows
// a clear "incomplete message" instead of the raw exception text.

package com.pgpony.android.crypto

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.EOFException

class TruncatedMessageTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `range and end-of-stream errors are classified as incomplete`() {
        assertTrue(
            "the exact reported error",
            svc.looksIncomplete(IndexOutOfBoundsException("toIndex (3370) is greater than size (2784)."))
        )
        assertTrue("any IndexOutOfBounds", svc.looksIncomplete(ArrayIndexOutOfBoundsException("length=10; index=42")))
        assertTrue("EOF by type", svc.looksIncomplete(EOFException()))
        assertTrue("EOF nested in a cause", svc.looksIncomplete(RuntimeException("read failed", EOFException())))
        assertTrue("premature end message", svc.looksIncomplete(RuntimeException("premature end of stream in packet")))
    }

    @Test
    fun `genuine crypto failures are not classified as incomplete`() {
        assertFalse("a wrong key is not truncation", svc.looksIncomplete(PGPCryptoError.NoMatchingKey()))
        assertFalse("a tamper is not truncation", svc.looksIncomplete(RuntimeException("data integrity check failed")))
        assertFalse("a bad passphrase is not truncation", svc.looksIncomplete(RuntimeException("checksum mismatch")))
    }
}
