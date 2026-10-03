// PairVectorsTest.kt
// The published pairing vectors (test resources, pairing/): every other implementation of
// docs/PAIRING_PROTOCOL.md, the Swift one included, reproduces the same files.
//
//   v1-vectors.json  the derivations of one attempt
//   v1-session.json  every byte of one whole session, both directions, with fixed randomness
//   v1-invites.json  QR invites that must parse, with their fields, and ones that must not
//   v1-peers.json    connection sources a host lets through to phase 1, and ones it closes

package com.pgpony.android.pair

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class PairVectorsTest {

    private fun resource(name: String): JsonObject =
        Json.parseToJsonElement(javaClass.getResourceAsStream("/pairing/$name")!!.readBytes().toString(Charsets.UTF_8)).jsonObject

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.bytes(key: String) = unhex(str(key))

    @Test
    fun derivationsReproduce() {
        val v = resource("v1-vectors.json")
        val j = PairCrypto.keyPair(v.bytes("sk_J"))
        val h = PairCrypto.keyPair(v.bytes("sk_H"))
        assertEquals(v.str("pk_J"), hex(j.public))
        assertEquals(v.str("pk_H"), hex(h.public))
        val nJ = v.bytes("n_J")
        val nH = v.bytes("n_H")
        assertEquals(v.str("commit"), hex(PairCrypto.commit(nH, h.public, j.public)))
        val version = v.bytes("version").single()
        assertEquals(PairProtocol.VERSION, version)
        val t = PairCrypto.transcript(j.public, h.public, nJ, nH, version)
        assertEquals(v.str("T"), hex(t))
        // The version is part of T: another version gives another code.
        assertNotEquals(hex(t), hex(PairCrypto.transcript(j.public, h.public, nJ, nH, 2)))
        val z = PairCrypto.agree(v.bytes("sk_H"), j.public)!!
        assertEquals(v.str("Z"), hex(z))
        assertEquals(v.str("Z"), hex(PairCrypto.agree(v.bytes("sk_J"), h.public)!!))
        val keys = PairCrypto.derive(z, t)
        assertEquals(v.str("K"), hex(keys.pairKey))
        assertEquals(v.str("k_HJ"), hex(keys.hostToJoiner))
        assertEquals(v.str("k_JH"), hex(keys.joinerToHost))
        assertEquals(v.str("code"), PairCrypto.code(t))
        assertEquals(v.str("host_msg_0_sealed"), hex(PairCrypto.seal(keys.hostToJoiner, 0, v.bytes("host_msg_0_plaintext"))))
        assertEquals(v.str("joiner_msg_0_sealed"), hex(PairCrypto.seal(keys.joinerToHost, 0, v.bytes("joiner_msg_0_plaintext"))))
    }

    @Test
    fun aLowOrderPeerKeyIsRefused() {
        assertNull(PairCrypto.agree(PairCrypto.randomBytes(32), ByteArray(32)))
    }

    @Test
    fun theWholeSessionReproducesByteForByte() {
        val v = resource("v1-session.json")
        val run = SessionScript.run(SessionScript.Inputs.from(v))
        assertEquals(v.str("code"), run.code)
        assertEquals(v.str("host_to_joiner"), hex(run.hostToJoiner))
        assertEquals(v.str("joiner_to_host"), hex(run.joinerToHost))
        val item = v.getValue("items").jsonObject.getValue("1").jsonPrimitive.content
        assertEquals(item, hex(run.received))
    }

    @Test
    fun eachSessionMessageSealsAndReadsAsListed() {
        val v = resource("v1-session.json")
        val keys = PairCrypto.derive(
            PairCrypto.agree(v.bytes("sk_H"), PairCrypto.keyPair(v.bytes("sk_J")).public)!!,
            PairCrypto.transcript(PairCrypto.keyPair(v.bytes("sk_J")).public, PairCrypto.keyPair(v.bytes("sk_H")).public, v.bytes("n_J"), v.bytes("n_H"))
        )
        for (m in v.getValue("messages").jsonArray.map { it.jsonObject }) {
            val key = if (m.str("from") == "host") keys.hostToJoiner else keys.joinerToHost
            val seq = m.getValue("seq").jsonPrimitive.int.toLong()
            val plaintext = m.bytes("plaintext")
            assertEquals(m.getValue("type").jsonPrimitive.int, plaintext[0].toInt() and 0xFF)
            val frame = PairFrames.frame(PairFrames.ENVELOPE, PairCrypto.seal(key, seq, plaintext))
            assertEquals(m.str("frame"), hex(frame))
            assertArrayEquals(plaintext, PairCrypto.open(key, seq, frame.copyOfRange(5, frame.size)))
            val json: JsonElement? = m["json"]
            if (json != null) {
                val body = plaintext.copyOfRange(1, plaintext.size).toString(Charsets.UTF_8)
                assertEquals(json, Json.parseToJsonElement(body))
            }
        }
    }

    @Test
    fun invitesParseAsListed() {
        val v = resource("v1-invites.json")
        for (c in v.getValue("valid").jsonArray.map { it.jsonObject }) {
            val invite = PairInvite.parse(c.str("uri"))
            assertNotNull(c.str("uri"), invite)
            assertEquals(c.getValue("addresses").jsonArray.map { it.jsonPrimitive.content }, invite!!.addresses.map { it.toString() })
            assertEquals(c.str("h"), hex(invite.hostKeyHash))
            c["canonical"]?.let { assertEquals(it.jsonPrimitive.content, invite.toUri()) }
            c["pk_H"]?.let {
                assertEquals(invite, PairInvite.forHostKey(unhex(it.jsonPrimitive.content), invite.addresses))
            }
            c["address_bytes"]?.let { list ->
                assertEquals(list.jsonArray.map { it.jsonPrimitive.content }, invite.addresses.map { hex(it.bytes()) })
                // The socket address is built from those bytes, with no lookup. (The JDK turns an
                // IPv4-mapped IPv6 address into the IPv4 address it carries: its last 4 bytes.)
                invite.addresses.forEach {
                    val built = it.socketAddress().address.address
                    assertEquals(hex(it.bytes()).takeLast(2 * built.size), hex(built))
                }
            }
            invite.addresses.forEach { it.socketAddress() }
        }
        for (bad in v.getValue("invalid").jsonArray.map { it.jsonObject }) {
            assertNull(bad.str("why"), PairInvite.parse(bad.str("uri")))
        }
    }

    @Test
    fun peersClassifyAsListed() {
        val v = resource("v1-peers.json")
        val subnets = v.getValue("subnets").jsonArray.map { it.jsonObject }.map {
            PairPeer.Subnet(PairInvite.hostBytes(it.str("address"))!!, it.getValue("prefix").jsonPrimitive.int)
        }
        for ((key, expected) in listOf("allowed" to true, "refused" to false)) {
            for (c in v.getValue(key).jsonArray.map { it.jsonObject }) {
                val bytes = PairInvite.hostBytes(c.str("address"))
                assertNotNull(c.str("address"), bytes)
                assertEquals(c.str("address") + ": " + c.str("why"), expected, PairPeer.isAllowed(bytes!!, subnets))
            }
        }
        // Without the subnets only the always-local ranges pass.
        assertTrue(PairPeer.isAllowed(PairInvite.hostBytes("192.168.1.5")!!))
        assertTrue(!PairPeer.isAllowed(PairInvite.hostBytes("203.0.113.200")!!))
    }

    @Test
    fun anInviteWritesWhatItReads() {
        val invite = PairInvite.forHostKey(
            PairCrypto.keyPair().public,
            listOf(PairInvite.Address("192.168.1.20", 49152), PairInvite.Address("fd00::1", 49152))
        )
        assertTrue(invite.toUri().startsWith("pgpony-pair:1?a=192.168.1.20:49152,[fd00::1]:49152&h="))
        assertEquals(invite, PairInvite.parse(invite.toUri()))
    }
}

/**
 * The scripted session behind v1-session.json, run over loopback sockets with fixed
 * randomness. The byte streams depend only on the script and the inputs, not on timing: each
 * direction is written by one side in script order.
 */
internal object SessionScript {

    class Inputs(
        val skH: ByteArray, val skJ: ByteArray, val nH: ByteArray, val nJ: ByteArray,
        val helloNonce: ByteArray, val ackNonce: ByteArray
    ) {
        companion object {
            fun from(v: JsonObject): Inputs {
                fun b(k: String) = unhex(v.getValue(k).jsonPrimitive.content)
                return Inputs(b("sk_H"), b("sk_J"), b("n_H"), b("n_J"), b("hello_nonce"), b("ack_nonce"))
            }
        }
    }

    class Run(val code: String, val hostToJoiner: ByteArray, val joinerToHost: ByteArray, val received: ByteArray)

    val HOST_INFO = PairInfo("Office Mac", "PGPony Desktop 3.0.0", PairItem.KINDS)
    val JOINER_INFO = PairInfo("Pixel", "PGPony Android 4.7.0", setOf(PairItem.PUBLIC_KEY, PairItem.KEY_PAIR))
    val ITEM_1: ByteArray = (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nPGPony pairing test item: not a key.\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n"
        ).toByteArray(Charsets.UTF_8)
    const val FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
    val OFFER = PairOffer(listOf(
        PairItem(1, PairItem.PUBLIC_KEY, "Alice <alice@example.org>", FINGERPRINT, ITEM_1.size.toLong()),
        PairItem(2, PairItem.KEY_PAIR, "Alice <alice@example.org>", FINGERPRINT, 1234)
    ))

    /** Hands out the listed values in order; the protocol asking for anything else fails. */
    private class FixedRandom(values: List<ByteArray>) : PairRandom {
        private val queue = ArrayDeque(values)
        @Synchronized
        override fun bytes(n: Int): ByteArray {
            val next = queue.removeFirstOrNull() ?: error("no fixed random bytes left")
            check(next.size == n) { "asked for $n random bytes, fixed value has ${next.size}" }
            return next.copyOf()
        }
    }

    private class Tee(private val out: OutputStream, private val copy: ByteArrayOutputStream) : OutputStream() {
        override fun write(b: Int) { synchronized(copy) { copy.write(b) }; out.write(b) }
        override fun write(b: ByteArray, off: Int, len: Int) { synchronized(copy) { copy.write(b, off, len) }; out.write(b, off, len) }
        override fun flush() = out.flush()
        override fun close() = out.close()
    }

    fun run(inputs: Inputs): Run {
        val threads = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }
        try {
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
                val hostBytes = ByteArrayOutputStream()
                val joinerBytes = ByteArrayOutputStream()
                val hostF = CompletableFuture.supplyAsync({
                    val s = server.accept()
                    PairProtocol.hostWith(
                        s.getInputStream(), Tee(s.getOutputStream(), hostBytes), { s.soTimeout = it }, { s.close() },
                        PairCrypto.keyPair(inputs.skH), FixedRandom(listOf(inputs.nH, inputs.ackNonce))
                    )
                }, threads)
                val s = Socket(InetAddress.getLoopbackAddress(), server.localPort)
                val joinerAttempt = PairProtocol.joinWith(
                    s.getInputStream(), Tee(s.getOutputStream(), joinerBytes), { s.soTimeout = it }, { s.close() },
                    null, FixedRandom(listOf(inputs.skJ, inputs.nJ, inputs.helloNonce))
                )
                val hostAttempt = hostF.get(10, TimeUnit.SECONDS)
                check(hostAttempt.code == joinerAttempt.code)
                val hostSessionF = CompletableFuture.supplyAsync({ hostAttempt.confirm() }, threads)
                val joiner = joinerAttempt.confirm()
                val host = hostSessionF.get(10, TimeUnit.SECONDS)

                host.sendInfo(HOST_INFO)
                joiner.sendInfo(JOINER_INFO)
                check((host.receive() as PairMessage.Info).info == JOINER_INFO)
                check((joiner.receive() as PairMessage.Info).info == HOST_INFO)
                host.sendOffer(OFFER)
                check((joiner.receive() as PairMessage.Offer).offer == OFFER)
                joiner.sendAnswer(PairAnswer(listOf(1)))
                check((host.receive() as PairMessage.Answer).answer == PairAnswer(listOf(1)))
                host.sendItem(1, ITEM_1)
                val item = joiner.receive(mapOf(1 to ITEM_1.size.toLong())) as PairMessage.Item
                joiner.sendResult(PairResult(1, true))
                check((host.receive() as PairMessage.Result).result == PairResult(1, true))
                host.sendBye()
                check(joiner.receive() == PairMessage.Bye)
                host.close()
                joiner.close()
                return Run(joinerAttempt.code, hostBytes.toByteArray(), joinerBytes.toByteArray(), item.bytes)
            }
        } finally {
            threads.shutdownNow()
        }
    }
}

internal fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

internal fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
