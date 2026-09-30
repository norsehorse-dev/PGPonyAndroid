// PairProtocolTest.kt
// The pairing protocol (docs/PAIRING_PROTOCOL.md) end to end over loopback sockets: a transfer
// both ways, refusals, someone in the middle, and the checks that end a session.

package com.pgpony.android.pair

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class PairProtocolTest {

    // Dedicated threads: the blocking reads must not wait on a small common pool.
    private val threads = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }

    private fun <T> async(block: () -> T): CompletableFuture<T> = CompletableFuture.supplyAsync(block, threads)

    private fun hostOn(server: ServerSocket): CompletableFuture<PairAttempt> = async {
        val s = server.accept()
        PairProtocol.host(s.getInputStream(), s.getOutputStream(), { s.soTimeout = it }, { s.close() })
    }

    private fun joinTo(port: Int, hostKeyHash: ByteArray? = null): PairAttempt {
        val s = Socket(InetAddress.getLoopbackAddress(), port)
        return PairProtocol.join(s.getInputStream(), s.getOutputStream(), { s.soTimeout = it }, { s.close() }, hostKeyHash)
    }

    private fun pair(): Pair<PairSession, PairSession> {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val host = hostOn(server)
            val joiner = joinTo(server.localPort)
            val h = host.get(10, TimeUnit.SECONDS)
            assertEquals(h.code, joiner.code)
            assertTrue(Regex("^\\d{3} \\d{3}$").matches(h.code))
            val hs = async { h.confirm() }
            val js = joiner.confirm()
            return hs.get(10, TimeUnit.SECONDS) to js
        }
    }

    @Test
    fun pairsAndMovesItemsBothWays() {
        val (host, joiner) = pair()
        host.sendInfo(PairInfo("Office Mac", "PGPony Desktop 3.0.0"))
        joiner.sendInfo(PairInfo("Pixel", "PGPony Android 4.7.0", setOf(PairItem.PUBLIC_KEY, PairItem.KEY_PAIR)))
        val joinerInfo = (host.receive() as PairMessage.Info).info
        assertEquals("Pixel", joinerInfo.name)
        assertTrue(joinerInfo.takes(PairItem.KEY_PAIR))
        assertTrue(!joinerInfo.takes(PairItem.BACKUP))
        val hostInfo = (joiner.receive() as PairMessage.Info).info
        assertEquals("Office Mac", hostInfo.name)
        assertTrue(hostInfo.takes(PairItem.BACKUP)) // no accepts member: all three

        // Host offers two items; the joiner takes one of them. The big one spans three ITEM_DATA.
        val big = PairCrypto.randomBytes(2_500_000)
        val cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n".toByteArray()
        host.sendOffer(PairOffer(listOf(
            PairItem(1, PairItem.KEY_PAIR, "Alice", "AB".repeat(20), big.size.toLong()),
            PairItem(2, PairItem.PUBLIC_KEY, "Bob", "CD".repeat(20), cert.size.toLong())
        )))
        val offer = (joiner.receive() as PairMessage.Offer).offer
        assertEquals(2, offer.items.size)
        joiner.sendAnswer(PairAnswer(listOf(1)))
        assertEquals(listOf(1), (host.receive() as PairMessage.Answer).answer.accept)

        val sent = async { host.sendItem(1, big) }
        var lastProgress = 0L
        val item = joiner.receive(mapOf(1 to big.size.toLong())) { _, n -> lastProgress = n } as PairMessage.Item
        sent.get(10, TimeUnit.SECONDS)
        assertEquals(1, item.id)
        assertArrayEquals(big, item.bytes)
        assertEquals(big.size.toLong(), lastProgress)
        joiner.sendResult(PairResult(1, true))
        assertEquals(PairResult(1, true), (host.receive() as PairMessage.Result).result)

        // The other direction, in the same session.
        joiner.sendOffer(PairOffer(listOf(PairItem(7, PairItem.PUBLIC_KEY, "Carol", null, cert.size.toLong()))))
        assertTrue(host.receive() is PairMessage.Offer)
        host.sendAnswer(PairAnswer(listOf(7)))
        assertTrue(joiner.receive() is PairMessage.Answer)
        joiner.sendItem(7, cert)
        assertArrayEquals(cert, (host.receive(mapOf(7 to cert.size.toLong())) as PairMessage.Item).bytes)

        joiner.sendBye()
        assertEquals(PairMessage.Bye, host.receive())
        joiner.close()
    }

    @Test
    fun anItemThatWasNotAcceptedEndsTheSession() {
        val (host, joiner) = pair()
        host.sendItem(3, "unasked".toByteArray())
        val e = assertThrows(PairException::class.java) { joiner.receive(emptyMap()) }
        assertEquals(PairFailure.PROTOCOL, e.failure)
        host.close()
    }

    @Test
    fun aRefusalOnEitherSideEndsTheAttempt() {
        for (refuser in PairRole.entries) {
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
                val hostF = hostOn(server)
                val joiner = joinTo(server.localPort)
                val host = hostF.get(10, TimeUnit.SECONDS)
                val (no, yes) = if (refuser == PairRole.HOST) host to joiner else joiner to host
                no.reject()
                assertEquals(PairFailure.REFUSED, yes.peerRefused.get(10, TimeUnit.SECONDS))
                val e = assertThrows(PairException::class.java) { yes.confirm() }
                assertEquals("$refuser refused", PairFailure.REFUSED, e.failure)
            }
        }
    }

    @Test
    fun someoneInTheMiddleGetsTwoDifferentCodes() {
        // A relays between the joiner and the host, running its own exchange with each.
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { realHost ->
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { fakeHost ->
                val host = hostOn(realHost)
                val middleAsHost = hostOn(fakeHost)
                val middleAsJoiner = async { joinTo(realHost.localPort) }
                val joiner = joinTo(fakeHost.localPort)
                val codeOnJoiner = joiner.code
                val codeOnHost = host.get(10, TimeUnit.SECONDS).code
                assertEquals(codeOnJoiner, middleAsHost.get(10, TimeUnit.SECONDS).code)
                assertEquals(codeOnHost, middleAsJoiner.get(10, TimeUnit.SECONDS).code)
                assertNotEquals(codeOnJoiner, codeOnHost)
            }
        }
    }

    @Test
    fun theInviteHashPinsTheHostKey() {
        val hostKey = PairCrypto.keyPair()
        val pinned = PairInvite.forHostKey(hostKey.public, listOf(PairInvite.Address("127.0.0.1", 1))).hostKeyHash
        val other = PairInvite.forHostKey(PairCrypto.keyPair().public, listOf(PairInvite.Address("127.0.0.1", 1))).hostKeyHash
        for ((hash, matches) in listOf(pinned to true, other to false)) {
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
                val host = async {
                    val s = server.accept()
                    PairProtocol.host(s.getInputStream(), s.getOutputStream(), { s.soTimeout = it }, { s.close() }, hostKey)
                }
                if (matches) {
                    val joiner = joinTo(server.localPort, hash)
                    assertEquals(host.get(10, TimeUnit.SECONDS).code, joiner.code)
                    joiner.reject()
                } else {
                    val e = assertThrows(PairException::class.java) { joinTo(server.localPort, hash) }
                    assertEquals(PairFailure.HANDSHAKE, e.failure)
                    val h = assertThrows(ExecutionException::class.java) { host.get(10, TimeUnit.SECONDS) }
                    assertEquals(PairFailure.HANDSHAKE, (h.cause as PairException).failure)
                }
            }
        }
    }

    @Test
    fun aHostThatChangesItsNonceIsCaught() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val fake = async {
                server.accept().use { s ->
                    val wire = PairWire(s.getInputStream(), s.getOutputStream()) { s.close() }
                    wire.readExact(4)
                    wire.writeRaw(PairProtocol.MAGIC)
                    val join = wire.readFrame().second
                    val pk = PairCrypto.keyPair().public
                    wire.writeFrame(PairProtocol.ACCEPT, pk + PairCrypto.commit(ByteArray(32), pk, join.copyOfRange(1, 33)))
                    wire.readFrame()
                    wire.writeFrame(PairProtocol.NONCE_H, ByteArray(32) { 1 })
                    runCatching { wire.readFrame() }
                }
            }
            val e = assertThrows(PairException::class.java) { joinTo(server.localPort) }
            assertEquals(PairFailure.HANDSHAKE, e.failure)
            fake.get(10, TimeUnit.SECONDS)
        }
    }

    @Test
    fun aJoinerThatDoesNotSpeakPairingIsTurnedAway() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val host = hostOn(server)
            Socket(InetAddress.getLoopbackAddress(), server.localPort).use {
                it.getOutputStream().write("GET / HTTP/1.1\r\n\r\n".toByteArray())
            }
            val e = assertThrows(ExecutionException::class.java) { host.get(10, TimeUnit.SECONDS) }
            assertEquals(PairFailure.PROTOCOL, (e.cause as PairException).failure)
        }
    }

    @Test
    fun sealedMessagesMustArriveInOrder() {
        val key = PairCrypto.randomBytes(32)
        val m0 = PairCrypto.seal(key, 0, byteArrayOf(1, 2, 3))
        val m1 = PairCrypto.seal(key, 1, byteArrayOf(4))
        assertArrayEquals(byteArrayOf(1, 2, 3), PairCrypto.open(key, 0, m0))
        assertThrows(PairException::class.java) { PairCrypto.open(key, 0, m1) }
        assertThrows(PairException::class.java) { PairCrypto.open(key, 1, m0) }
        m1[m1.size - 1] = (m1[m1.size - 1].toInt() xor 1).toByte()
        assertThrows(PairException::class.java) { PairCrypto.open(key, 1, m1) }
    }
}
