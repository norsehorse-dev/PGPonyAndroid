// PairHardeningTest.kt
// The pairing protocol's guard rails (docs/PAIRING_PROTOCOL.md): strict invite addresses, the host
// key hash length, the typed code on the host, whole-frame deadlines, the offer rules of section 5,
// items that go out unbroken, and ending a session whose peer stopped reading.

package com.pgpony.android.pair

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.random.Random

class PairHardeningTest {

    private val threads = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }

    private fun <T> async(block: () -> T): CompletableFuture<T> = CompletableFuture.supplyAsync(block, threads)

    private fun attempts(): Pair<PairAttempt, PairAttempt> {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val host = async {
                val s = server.accept()
                PairProtocol.host(s.getInputStream(), s.getOutputStream(), { s.soTimeout = it }, { s.close() })
            }
            val s = Socket(InetAddress.getLoopbackAddress(), server.localPort)
            val joiner = PairProtocol.join(s.getInputStream(), s.getOutputStream(), { s.soTimeout = it }, { s.close() })
            return host.get(10, TimeUnit.SECONDS) to joiner
        }
    }

    private fun sessions(): Pair<PairSession, PairSession> {
        val (h, j) = attempts()
        val hs = async { h.confirm() }
        val js = j.confirm()
        return hs.get(10, TimeUnit.SECONDS) to js
    }

    // ── PAIRING-PROTOCOL-2 / PAIRING-IMPL-4: invite addresses ─────────────

    @Test
    fun ipv6LiteralsAreParsedStrictly() {
        val good = mapOf(
            "::1" to "00000000000000000000000000000001",
            "1:2:3:4:5:6:7:8" to "00010002000300040005000600070008",
            "1:2:3:4:5:6:7::" to "00010002000300040005000600070000",
            "::ffff:1.2.3.4" to "00000000000000000000ffff01020304",
            "FD00::ABCD" to "fd00000000000000000000000000abcd",
            "::" to "00000000000000000000000000000000"
        )
        for ((text, bytes) in good) assertEquals(text, bytes, hex(PairInvite.hostBytes(text)!!))
        val bad = listOf(
            ":::1", "1:2", ".:1", "..:", "1::2::3", "1.2.3.4:5", ":1", "1:", "12345::1", "::1.2.3.04",
            "1.2.3.4::", "fe80::1%en0", "fe80::1%25en0", "g::1", "1:2:3:4:5:6:7:8:9", "1::2:3:4:5:6:7:8",
            "::1.2.3", " ::1", "::1 ", "[::1]", "localhost", "pgpony.local", "\u0661::1"
        )
        for (text in bad) assertNull(text, PairInvite.hostBytes(text))
    }

    @Test
    fun aMalformedIPv6InviteIsRefusedNotThrown() {
        val h = "A".repeat(21) + "A"
        for (inner in listOf(":::1", "1:2", ".:1", "..:", "1::2::3", "1.2.3.4:5", "....::")) {
            assertNull(inner, PairInvite.parse("pgpony-pair:1?a=[$inner]:5&h=$h"))
            assertNull(inner, PairInvite.parseAddress("[$inner]:5"))
        }
    }

    @Test
    fun noPastedTextMakesTheParserThrow() {
        val alphabet = "pgony-air:1?a=h&,[]:.0123456789abcdefABCDEF%_- \n\u0131\u0130\u00e9"
        val rnd = Random(20261001)
        repeat(20_000) {
            val prefix = if (rnd.nextBoolean()) "pgpony-pair:1?" else ""
            val text = prefix + String(CharArray(rnd.nextInt(0, 80)) { alphabet[rnd.nextInt(alphabet.length)] })
            val invite = PairInvite.parse(text)
            invite?.addresses?.forEach { it.socketAddress() }
            PairInvite.parseAddress(text)
        }
    }

    @Test
    fun inviteAddressesConnectWithoutALookup() {
        val a = PairInvite.parseAddress("[::ffff:192.168.1.5]:9")!!
        assertEquals("192.168.1.5", a.socketAddress().address.hostAddress)
        assertFalse(a.socketAddress().isUnresolved)
        val b = PairInvite.parseAddress("[fd00::1]:9")!!
        assertArrayEquals(PairInvite.hostBytes("fd00::1"), b.socketAddress().address.address)
    }

    // ── PAIRING-PROTOCOL-7: the expected host key hash ────────────────────

    @Test
    fun anExpectedHostKeyHashMustBeSixteenBytes() {
        for (size in listOf(0, 8, 15, 17, 32)) {
            var closed = false
            assertThrows(IllegalArgumentException::class.java) {
                PairProtocol.join(ByteArrayInputStream(ByteArray(0)), ByteArrayOutputStream(), {}, { closed = true }, ByteArray(size))
            }
            assertTrue("the connection is closed", closed)
        }
    }

    // ── PAIRING-PROTOCOL-1: the host types the code ───────────────────────

    @Test
    fun theHostChecksTheCodeItsUserTyped() {
        val (host, joiner) = attempts()
        val digits = joiner.code.replace(" ", "")
        assertTrue(host.matchesTypedCode(joiner.code))
        assertTrue(host.matchesTypedCode(digits))
        assertTrue(host.matchesTypedCode(" ${digits.substring(0, 3)}-${digits.substring(3)} "))
        val wrong = ((digits.toInt() + 1) % 1_000_000).toString().padStart(6, '0')
        assertFalse(host.matchesTypedCode(wrong))
        assertFalse(host.matchesTypedCode(digits.substring(0, 5)))
        assertFalse(host.matchesTypedCode(digits + "0"))
        assertFalse(host.matchesTypedCode(""))
        assertFalse(host.matchesTypedCode("\u0661" + digits.substring(1)))
        assertFalse(host.matchesTypedCode("$digits.x"))
        host.reject()
        assertEquals(PairFailure.REFUSED, joiner.peerRefused.get(10, TimeUnit.SECONDS))
    }

    // ── PAIRING-PROTOCOL-5: whole-frame deadlines ─────────────────────────

    /** Hands out one byte per [everyMs], for ever (until closed). */
    private class Drip(private val bytes: ByteArray, private val everyMs: Long) : InputStream() {
        private var i = 0
        @Volatile var closed = false
        override fun read(): Int {
            Thread.sleep(everyMs)
            if (closed) throw java.io.IOException("closed")
            return if (i < bytes.size) bytes[i++].toInt() and 0xFF else 0x41
        }
    }

    @Test
    fun aFrameThatDripsInEndsAtItsDeadline() {
        // Each read returns in time, but the frame never completes: the deadline closes it.
        val drip = Drip(byteArrayOf(0x41, 0, 0, 0, 33), everyMs = 50)
        val wire = PairWire(drip, ByteArrayOutputStream()) { drip.closed = true }
        val started = System.nanoTime()
        val e = assertThrows(PairException::class.java) { wire.withDeadline(400) { wire.readFrame(33) } }
        assertEquals(PairFailure.TIMEOUT, e.failure)
        assertTrue(drip.closed)
        assertTrue((System.nanoTime() - started) / 1_000_000 < 5_000)
    }

    @Test
    fun aDeclaredLengthIsCheckedBeforeAnythingIsRead() {
        val header = byteArrayOf(0x41, 0x00, 0x11, 0x00, 0x00) // JOIN claiming 1,114,112 bytes
        val wire = PairWire(ByteArrayInputStream(header), ByteArrayOutputStream()) {}
        val e = assertThrows(PairException::class.java) { wire.readFrame(33) }
        assertEquals(PairFailure.PROTOCOL, e.failure)
        // The host refuses such a JOIN at once instead of waiting for a megabyte.
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val host = async {
                val s = server.accept()
                PairProtocol.host(s.getInputStream(), s.getOutputStream(), { s.soTimeout = it }, { s.close() })
            }
            Socket(InetAddress.getLoopbackAddress(), server.localPort).use { s ->
                s.getOutputStream().write(PairProtocol.MAGIC + header)
                val failure = assertThrows(ExecutionException::class.java) { host.get(10, TimeUnit.SECONDS) }
                assertEquals(PairFailure.PROTOCOL, (failure.cause as PairException).failure)
            }
        }
    }

    // ── PAIRING-PROTOCOL-3: the version is in T ───────────────────────────

    @Test
    fun theTranscriptCoversTheVersion() {
        val pk = PairCrypto.randomBytes(32)
        val n = PairCrypto.randomBytes(32)
        val v1 = PairCrypto.transcript(pk, pk, n, n)
        assertArrayEquals(v1, PairCrypto.transcript(pk, pk, n, n, 1))
        assertFalse(v1.contentEquals(PairCrypto.transcript(pk, pk, n, n, 2)))
        assertArrayEquals(v1, PairCrypto.sha256("pgpony/pair/transcript/v1".toByteArray(), "PGPP".toByteArray(), byteArrayOf(1), pk, pk, n, n))
    }

    // ── PAIRING-PROTOCOL-4: one offer at a time ───────────────────────────

    private val certSize = 10L

    @Test
    fun aSecondOfferBeforeTheAnswerEndsTheSession() {
        val (host, joiner) = sessions()
        host.sendOffer(PairOffer(listOf(PairItem(1, PairItem.PUBLIC_KEY, "first", "AB".repeat(20), certSize))))
        assertTrue(joiner.receive() is PairMessage.Offer)
        // A well-behaved sender cannot even send it.
        assertThrows(IllegalStateException::class.java) {
            host.sendOffer(PairOffer(listOf(PairItem(2, PairItem.PUBLIC_KEY, "second", "CD".repeat(20), certSize))))
        }
        // One that skips the check is cut off by the receiver.
        sendRaw(host, PairSession.OFFER, """{"items":[{"id":2,"kind":"public-key","name":"x","fingerprint":null,"size":1}]}""")
        val e = assertThrows(PairException::class.java) { joiner.receive() }
        assertEquals(PairFailure.PROTOCOL, e.failure)
        host.close()
    }

    @Test
    fun anOfferBeforeTheResultsOfTheLastEndsTheSession() {
        val (host, joiner) = sessions()
        val bytes = "0123456789".toByteArray()
        host.sendOffer(PairOffer(listOf(PairItem(1, PairItem.PUBLIC_KEY, "first", "AB".repeat(20), bytes.size.toLong()))))
        assertTrue(joiner.receive() is PairMessage.Offer)
        joiner.sendAnswer(PairAnswer(listOf(1)))
        assertTrue(host.receive() is PairMessage.Answer)
        host.sendItem(1, bytes)
        assertTrue(joiner.receive(mapOf(1 to bytes.size.toLong())) is PairMessage.Item)
        assertThrows(IllegalStateException::class.java) {
            host.sendOffer(PairOffer(listOf(PairItem(2, PairItem.PUBLIC_KEY, "next", "CD".repeat(20), 1))))
        }
        sendRaw(host, PairSession.OFFER, """{"items":[{"id":2,"kind":"public-key","name":"x","fingerprint":null,"size":1}]}""")
        assertEquals(PairFailure.PROTOCOL, assertThrows(PairException::class.java) { joiner.receive() }.failure)
        host.close()
    }

    @Test
    fun theNextOfferFollowsTheResults() {
        val (host, joiner) = sessions()
        val bytes = "0123456789".toByteArray()
        host.sendOffer(PairOffer(listOf(PairItem(1, PairItem.PUBLIC_KEY, "first", "AB".repeat(20), bytes.size.toLong()))))
        assertTrue(joiner.receive() is PairMessage.Offer)
        // An answer may only name ids the offer listed, and only once.
        assertThrows(IllegalArgumentException::class.java) { joiner.sendAnswer(PairAnswer(listOf(9))) }
        joiner.sendAnswer(PairAnswer(listOf(1)))
        assertThrows(IllegalStateException::class.java) { joiner.sendAnswer(PairAnswer(listOf(1))) }
        assertTrue(host.receive() is PairMessage.Answer)
        host.sendItem(1, bytes)
        assertTrue(joiner.receive(mapOf(1 to bytes.size.toLong())) is PairMessage.Item)
        assertThrows(IllegalStateException::class.java) { joiner.sendResult(PairResult(5, true)) }
        joiner.sendResult(PairResult(1, true))
        assertTrue(host.receive() is PairMessage.Result)
        host.sendOffer(PairOffer(listOf(PairItem(2, PairItem.PUBLIC_KEY, "next", "CD".repeat(20), 1))))
        assertTrue(joiner.receive() is PairMessage.Offer)
        joiner.sendAnswer(PairAnswer(emptyList()))
        assertEquals(PairAnswer(emptyList()), (host.receive() as PairMessage.Answer).answer)
        // A declined offer leaves nothing open.
        host.sendOffer(PairOffer(listOf(PairItem(3, PairItem.PUBLIC_KEY, "third", "EF".repeat(20), 1))))
        assertTrue(joiner.receive() is PairMessage.Offer)
        host.close()
    }

    @Test
    fun anAcceptedItemComesOnceAndAnAnswerNamesEachIdOnce() {
        val (host, joiner) = sessions()
        val bytes = "0123456789".toByteArray()
        host.sendOffer(PairOffer(listOf(PairItem(1, PairItem.PUBLIC_KEY, "first", "AB".repeat(20), bytes.size.toLong()))))
        assertTrue(joiner.receive() is PairMessage.Offer)
        assertThrows(IllegalArgumentException::class.java) { joiner.sendAnswer(PairAnswer(listOf(1, 1))) }
        joiner.sendAnswer(PairAnswer(listOf(1)))
        assertTrue(host.receive() is PairMessage.Answer)
        host.sendItem(1, bytes)
        assertTrue(joiner.receive(mapOf(1 to bytes.size.toLong())) is PairMessage.Item)
        // The same item again, even with the caller still expecting it, ends the session.
        host.sendItem(1, bytes)
        assertEquals(PairFailure.PROTOCOL, assertThrows(PairException::class.java) { joiner.receive(mapOf(1 to bytes.size.toLong())) }.failure)
        host.close()
    }

    @Test
    fun anAnswerOrResultThatFitsNoOfferEndsTheSession() {
        for (case in 0..2) {
            val (host, joiner) = sessions()
            when (case) {
                0 -> sendRaw(joiner, PairSession.ANSWER, """{"accept":[1]}""")
                1 -> {
                    host.sendOffer(PairOffer(listOf(PairItem(1, PairItem.PUBLIC_KEY, "a", "AB".repeat(20), 1))))
                    assertTrue(joiner.receive() is PairMessage.Offer)
                    sendRaw(joiner, PairSession.ANSWER, """{"accept":[1,2]}""")
                }
                else -> sendRaw(joiner, PairSession.RESULT, """{"id":1,"ok":true,"error":null}""")
            }
            assertEquals("case $case", PairFailure.PROTOCOL, assertThrows(PairException::class.java) { host.receive() }.failure)
            joiner.close()
        }
    }

    // ── PAIRING-PROTOCOL-6: an item goes out unbroken ─────────────────────

    @Test
    fun aMessageSentDuringAnItemWaitsUntilTheItemEnds() {
        val (host, joiner) = sessions()
        val big = PairCrypto.randomBytes(2_500_000)
        host.sendOffer(PairOffer(listOf(PairItem(1, PairItem.KEY_PAIR, "big", "AB".repeat(20), big.size.toLong()))))
        assertTrue(joiner.receive() is PairMessage.Offer)
        joiner.sendAnswer(PairAnswer(listOf(1)))
        joiner.sendOffer(PairOffer(listOf(PairItem(9, PairItem.PUBLIC_KEY, "small", "CD".repeat(20), 3))))
        assertTrue(host.receive() is PairMessage.Answer)
        assertTrue(host.receive() is PairMessage.Offer)

        // While the item streams, another thread answers the joiner's offer.
        val answered = CountDownLatch(1)
        val sending = async {
            var once = true
            host.sendItem(1, big) {
                if (once) {
                    once = false
                    async { host.sendAnswer(PairAnswer(listOf(9))); answered.countDown() }
                    Thread.sleep(300)
                }
            }
        }
        val item = joiner.receive(mapOf(1 to big.size.toLong())) as PairMessage.Item
        assertArrayEquals(big, item.bytes)
        assertEquals(PairAnswer(listOf(9)), (joiner.receive() as PairMessage.Answer).answer)
        sending.get(10, TimeUnit.SECONDS)
        assertTrue(answered.await(10, TimeUnit.SECONDS))
        host.close()
        joiner.close()
    }

    // ── PAIRING-IMPL-5: ending never blocks ───────────────────────────────

    @Test
    fun endingASessionWhosePeerStoppedReadingNeverBlocks() {
        val (host, joiner) = sessions()
        val huge = ByteArray(40 * 1024 * 1024)
        host.sendOffer(PairOffer(listOf(PairItem(1, PairItem.BACKUP, "backup", null, huge.size.toLong()))))
        assertTrue(joiner.receive() is PairMessage.Offer)
        joiner.sendAnswer(PairAnswer(listOf(1)))
        assertTrue(host.receive() is PairMessage.Answer)
        // The joiner never reads the item: the host's writes fill the socket buffers and block.
        val sending = async { runCatching { host.sendItem(1, huge) } }
        Thread.sleep(500)
        assertFalse("the send is stuck, as with a peer that stopped reading", sending.isDone)
        val started = System.nanoTime()
        host.endAsync(graceMs = 300)
        assertTrue("endAsync returns at once", (System.nanoTime() - started) / 1_000_000 < 200)
        // The connection is closed after the grace period, which ends the stuck write.
        assertTrue(sending.get(10, TimeUnit.SECONDS).isFailure)
        assertThrows(PairException::class.java) { host.sendInfo(PairInfo("x", "y")) }
        joiner.close()
    }

    // ── PairPeer ──────────────────────────────────────────────────────────

    @Test
    fun aHostLetsOnlyLocalSourcesThrough() {
        val subnets = listOf(PairPeer.Subnet(PairInvite.hostBytes("203.0.113.10")!!, 24))
        assertTrue(PairPeer.isAllowed(InetAddress.getLoopbackAddress(), subnets))
        assertTrue(PairPeer.isAllowed(PairInvite.hostBytes("203.0.113.99")!!, subnets))
        assertFalse(PairPeer.isAllowed(PairInvite.hostBytes("203.0.112.99")!!, subnets))
        assertFalse(PairPeer.isAllowed(PairInvite.hostBytes("100.100.1.1")!!, subnets))
        assertFalse(PairPeer.isAllowed(ByteArray(5), subnets))
        assertThrows(IllegalArgumentException::class.java) { PairPeer.Subnet(ByteArray(4), 33) }
        assertNotNull(PairPeer.Subnet(ByteArray(16), 128))
    }

    /** Sends a sealed message with no checks, as a peer that ignores the rules would. */
    private fun sendRaw(session: PairSession, type: Byte, json: String) {
        val m = PairSession::class.java.getDeclaredMethod("send", Byte::class.javaPrimitiveType, ByteArray::class.java)
        m.isAccessible = true
        m.invoke(session, type, json.toByteArray())
    }
}
