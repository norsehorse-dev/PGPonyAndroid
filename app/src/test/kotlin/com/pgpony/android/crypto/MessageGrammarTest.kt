// MessageGrammarTest.kt
// PGPony Android, 3.0.0 checkpoint 5d-2: the OpenPGP message grammar
// (RFC 9580 10.3) and the strict packet reader, on hand-built packets.

package com.pgpony.android.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.Deflater

class MessageGrammarTest {

    private fun pkt(tag: Int, body: ByteArray) = CertificateBindings.frame(tag, body)

    private fun literal(text: String = "hello", name: String = "") =
        pkt(11, byteArrayOf('b'.code.toByte(), name.length.toByte()) + name.toByteArray() + ByteArray(4) + text.toByteArray())

    /** A v3 one-pass signature for public-key algorithm [algo]; [last] = the nested flag. */
    private fun ops(version: Int = 3, algo: Int = 22, last: Boolean = true) =
        pkt(4, byteArrayOf(version.toByte(), 0, 8, algo.toByte()) + ByteArray(8) { 0x11 } + byteArrayOf(if (last) 1 else 0))

    /** A v4 signature packet shell (the grammar reads only its header). */
    private fun sig(version: Int = 4, algo: Int = 22) =
        pkt(2, byteArrayOf(version.toByte(), 0, algo.toByte(), 8, 0, 0, 0, 0, 0x12, 0x34, 0, 8, 0x7F))

    private fun zlib(inner: ByteArray, cut: Int = 0, junk: Int = 0): ByteArray {
        val d = Deflater()
        d.setInput(inner); d.finish()
        val buf = ByteArray(inner.size + 64)
        val n = d.deflate(buf)
        d.end()
        return pkt(8, byteArrayOf(2) + buf.copyOf(n - cut) + ByteArray(junk) { 0x55 })
    }

    private fun cat(vararg parts: ByteArray): ByteArray = ByteArrayOutputStream().apply { parts.forEach { write(it) } }.toByteArray()

    private fun malformed(bytes: ByteArray) =
        assertThrows(MessageGrammar.Malformed::class.java) { MessageGrammar.normalizePlaintext(bytes) }

    @Test
    fun `a literal message, a compressed one and signed ones are well formed and pass through unchanged`() {
        for (m in listOf(
            literal(),
            zlib(literal()),
            cat(ops(), literal(), sig()),
            cat(sig(), literal()),
            cat(ops(last = false), ops(), literal(), sig(), sig()),
            zlib(cat(ops(), literal(), sig()))
        )) {
            assertSame(m, MessageGrammar.normalizePlaintext(m))
        }
    }

    @Test
    fun `malformed structures are rejected`() {
        malformed(cat(literal(), literal()))
        malformed(cat(zlib(literal()), literal()))
        malformed(cat(literal(), zlib(literal())))
        malformed(cat(ops(), literal()))
        malformed(cat(literal(), sig()))
        malformed(cat(literal(), pkt(6, byteArrayOf(4, 0, 0, 0, 0, 22))))
        malformed(cat(literal(), pkt(19, ByteArray(20))))
        malformed(ByteArray(0))
        malformed(zlib(ByteArray(0)))
        malformed(cat(pkt(1, byteArrayOf(3) + ByteArray(8) + byteArrayOf(1)), literal()))
    }

    @Test
    fun `unknown packets are skipped when non-critical and rejected when critical`() {
        for (tag in listOf(40, 60, 63)) {
            assertTrue(MessageGrammar.normalizePlaintext(cat(pkt(tag, byteArrayOf(1)), literal())).isNotEmpty())
        }
        for (tag in listOf(0, 15, 16, 39)) {
            malformed(cat(pkt(tag, byteArrayOf(1)), literal()))
            malformed(cat(literal(), pkt(tag, byteArrayOf(1))))
        }
        assertTrue(MessageGrammar.normalizePlaintext(cat(pkt(10, "PGP".toByteArray()), literal())).isNotEmpty())
    }

    @Test
    fun `a literal filename that runs past its packet is rejected`() {
        val bad = pkt(11, byteArrayOf('b'.code.toByte(), 40) + "short".toByteArray())
        malformed(bad)
    }

    @Test
    fun `compressed data must end inside its packet, and trailing octets are ignored`() {
        malformed(zlib(literal(), cut = 1))
        assertTrue(MessageGrammar.normalizePlaintext(zlib(literal(), junk = 100)).isNotEmpty())
    }

    @Test
    fun `nesting is bounded`() {
        var m = literal()
        repeat(4) { m = zlib(m) }
        MessageGrammar.normalizePlaintext(m)
        repeat(28) { m = zlib(m) }
        malformed(m)
    }

    @Test
    fun `a first partial chunk under 512 octets is rejected`() {
        fun partial(first: Int, total: Int): ByteArray {
            val body = byteArrayOf('b'.code.toByte(), 0) + ByteArray(4) + ByteArray(total - 6) { 0x41 }
            val exp = Integer.numberOfTrailingZeros(first)
            val rest = body.size - first
            return cat(byteArrayOf((0xC0 or 11).toByte(), (224 + exp).toByte()), body.copyOf(first),
                byteArrayOf(rest.toByte()), body.copyOfRange(first, body.size))
        }
        MessageGrammar.normalizePlaintext(partial(512, 600))
        malformed(partial(256, 300))
        assertThrows(MessageGrammar.Malformed::class.java) {
            MessageGrammar.normalizePlaintext(cat(byteArrayOf((0xC0 or 2).toByte(), (224 + 9).toByte()), ByteArray(600)))
        }
    }

    @Test
    fun `a truncated packet is reported as truncated`() {
        val m = literal("hello world")
        assertThrows(MessageGrammar.Truncated::class.java) { MessageGrammar.normalizePlaintext(m.copyOf(m.size - 3)) }
    }

    @Test
    fun `signatures of an unknown version or algorithm are dropped with their one-pass partner`() {
        val m = cat(ops(version = 23), ops(), literal("kept"), sig(), sig(version = 23))
        val out = MessageGrammar.normalizePlaintext(m)
        assertArrayEquals(cat(ops(), literal("kept"), sig()), out)
        val m2 = cat(ops(algo = 99), literal("kept"), sig(algo = 99))
        assertArrayEquals(literal("kept"), MessageGrammar.normalizePlaintext(m2))
        val m3 = zlib(cat(ops(version = 23), literal("kept"), sig(version = 23)))
        assertArrayEquals(literal("kept"), MessageGrammar.normalizePlaintext(m3))
    }

    // ── Outer message ────────────────────────────────────────────────────

    private fun pkesk3(algo: Int) = pkt(1, byteArrayOf(3) + ByteArray(8) { 0x22 } + byteArrayOf(algo.toByte(), 0, 8, 0x7F))
    private fun pkesk6(algo: Int = 25) = pkt(1, byteArrayOf(6, 0, algo.toByte()) + ByteArray(33))
    private fun skesk(version: Int) = pkt(3, byteArrayOf(version.toByte(), 9, 3, 8) + ByteArray(9))
    private fun seipd(version: Int) = pkt(18, byteArrayOf(version.toByte()) + ByteArray(64))

    @Test
    fun `an ordinary encrypted message passes through unchanged`() {
        val m = cat(pkesk3(18), skesk(4), seipd(1))
        assertSame(m, MessageGrammar.normalizeOuter(m))
        val v2 = cat(pkesk6(), skesk(6), seipd(2))
        assertSame(v2, MessageGrammar.normalizeOuter(v2))
    }

    @Test
    fun `session keys of an unknown algorithm or version are skipped`() {
        val out = MessageGrammar.normalizeOuter(cat(pkesk3(99), pkesk3(18), pkt(1, byteArrayOf(23, 1, 2, 3)), seipd(1)))
        assertArrayEquals(cat(pkesk3(18), seipd(1)), out)
    }

    @Test
    fun `session keys must match the encrypted data version`() {
        assertThrows(MessageGrammar.Malformed::class.java) { MessageGrammar.normalizeOuter(cat(pkesk6(), seipd(1))) }
        // PGPony's own mixed messages (a v4 recipient beside a composite one) pair these.
        val mixed = cat(pkesk6(35), pkesk3(18), seipd(2))
        assertSame(mixed, MessageGrammar.normalizeOuter(mixed))
        assertThrows(MessageGrammar.Malformed::class.java) { MessageGrammar.normalizeOuter(cat(skesk(4), seipd(2))) }
        assertThrows(MessageGrammar.Malformed::class.java) { MessageGrammar.normalizeOuter(cat(skesk(6), seipd(1))) }
        assertArrayEquals(cat(pkesk3(18), seipd(1)), MessageGrammar.normalizeOuter(cat(pkesk6(), pkesk3(18), seipd(1))))
    }

    @Test
    fun `an encrypted message ends with its encrypted data`() {
        assertThrows(MessageGrammar.Malformed::class.java) {
            MessageGrammar.normalizeOuter(cat(pkesk3(18), seipd(1), pkesk3(18), seipd(1)))
        }
        assertThrows(MessageGrammar.Malformed::class.java) { MessageGrammar.normalizeOuter(cat(pkesk3(18), seipd(1), literal())) }
        assertThrows(MessageGrammar.Malformed::class.java) { MessageGrammar.normalizeOuter(cat(pkesk3(18), literal())) }
    }

    @Test
    fun `marker packets around an encrypted message are dropped`() {
        val marker = pkt(10, "PGP".toByteArray())
        assertArrayEquals(cat(pkesk3(18), seipd(1)), MessageGrammar.normalizeOuter(cat(marker, pkesk3(18), seipd(1))))
        assertEquals(1, MessageGrammar.firstSignificantTag(cat(marker, pkesk3(18), seipd(1))))
        assertFalse(MessageGrammar.firstSignificantTag(marker) == 10)
    }
}
