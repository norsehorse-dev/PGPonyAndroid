// PairProtocol.kt
// The pairing handshake and key confirmation (docs/PAIRING_PROTOCOL.md, sections 3 and 4) over
// one blocking stream pair.
//
// Usage, on each side: PairProtocol.host(...) or PairProtocol.join(...) runs phase 1 and returns
// a PairAttempt holding the comparison code. The joiner shows the code and asks whether the other
// screen shows the same; the host asks its user to type the code the joiner shows and checks it
// with matchesTypedCode (section 4). The user's answer is confirm() (phase 2, returns the
// session) or reject(). Meanwhile the attempt already watches for the other side's answer, so a
// refusal over there reaches peerRefused without waiting for this user. Every call blocks: run
// them off the main thread (Dispatchers.IO on Android).

package com.pgpony.android.pair

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

enum class PairFailure(val abortReason: Int) {
    BUSY(1), VERSION(2), HANDSHAKE(3), REFUSED(4), TIMEOUT(5), PROTOCOL(0), CLOSED(0);

    companion object {
        fun ofReason(r: Int): PairFailure = entries.firstOrNull { it.abortReason == r && r != 0 } ?: PROTOCOL
    }
}

class PairException(val failure: PairFailure, message: String) : IOException(message)

enum class PairRole { HOST, JOINER }

object PairProtocol {

    val MAGIC: ByteArray = "PGPP".toByteArray(Charsets.US_ASCII)
    const val VERSION: Byte = 1

    const val JOIN: Byte = 0x41
    const val ACCEPT: Byte = 0x42
    const val NONCE_J: Byte = 0x43
    const val NONCE_H: Byte = 0x44
    const val ABORT: Byte = 0x4F

    /**
     * Phase 1 frame deadline and the time the users get to compare the code (section 3). Each is
     * a wall-clock limit on a whole frame, not only on each read.
     */
    const val FRAME_TIMEOUT_MS = 30_000
    const val CONFIRM_TIMEOUT_MS = 300_000

    /** The longest phase 2 frame: HELLO, HELLO_ACK and NO_MATCH are 48 bytes. */
    internal const val PHASE2_MAX_FRAME = 48L

    /**
     * Runs phase 1 as the host. [setTimeout] sets the read timeout of the underlying socket;
     * [close] closes it. [keyPair] is the host key fixed when the window opened (the QR shows
     * its hash).
     */
    fun host(
        input: InputStream, output: OutputStream, setTimeout: (Int) -> Unit, close: () -> Unit,
        keyPair: PairCrypto.KeyPair = PairCrypto.keyPair()
    ): PairAttempt = hostWith(input, output, setTimeout, close, keyPair, PairRandom.SECURE)

    /** [host] with its randomness supplied: the published session transcript only. */
    internal fun hostWith(
        input: InputStream, output: OutputStream, setTimeout: (Int) -> Unit, close: () -> Unit,
        keyPair: PairCrypto.KeyPair, random: PairRandom
    ): PairAttempt {
        val wire = PairWire(input, output, close)
        try {
            setTimeout(FRAME_TIMEOUT_MS)
            val magic = wire.withDeadline(FRAME_TIMEOUT_MS.toLong()) { wire.readExact(4) }
            if (!magic.contentEquals(MAGIC)) throw PairException(PairFailure.PROTOCOL, "not a PGPony pairing connection")
            wire.writeRaw(MAGIC)
            val join = expect(wire, JOIN, 33)
            if (join[0] != VERSION) {
                abort(wire, PairFailure.VERSION)
                throw PairException(PairFailure.VERSION, "the other side speaks pairing version ${join[0]}")
            }
            val pkJ = join.copyOfRange(1, 33)
            val nH = random.bytes(32)
            wire.writeFrame(ACCEPT, keyPair.public + PairCrypto.commit(nH, keyPair.public, pkJ))
            val nJ = expect(wire, NONCE_J, 32)
            wire.writeFrame(NONCE_H, nH)
            return finish(PairRole.HOST, wire, keyPair, pkJ, keyPair.public, nJ, nH, setTimeout, random)
        } catch (e: Exception) {
            keyPair.wipe()
            wire.close()
            throw wrap(e)
        }
    }

    /** Runs phase 1 as the joiner. [expectedHostKeyHash] is the QR's `h` when there is one. */
    fun join(
        input: InputStream, output: OutputStream, setTimeout: (Int) -> Unit, close: () -> Unit,
        expectedHostKeyHash: ByteArray? = null
    ): PairAttempt = joinWith(input, output, setTimeout, close, expectedHostKeyHash, PairRandom.SECURE)

    /** [join] with its randomness supplied: the published session transcript only. */
    internal fun joinWith(
        input: InputStream, output: OutputStream, setTimeout: (Int) -> Unit, close: () -> Unit,
        expectedHostKeyHash: ByteArray?, random: PairRandom
    ): PairAttempt {
        // An empty hash would match any host key and a longer one none: only the invite's 16 bytes.
        if (expectedHostKeyHash != null && expectedHostKeyHash.size != PairInvite.HASH_BYTES) {
            runCatching { close() }
            throw IllegalArgumentException("the expected host key hash is ${PairInvite.HASH_BYTES} bytes")
        }
        val wire = PairWire(input, output, close)
        val keyPair = PairCrypto.keyPair(random.bytes(32))
        try {
            setTimeout(FRAME_TIMEOUT_MS)
            wire.writeRaw(MAGIC)
            val magic = wire.withDeadline(FRAME_TIMEOUT_MS.toLong()) { wire.readExact(4) }
            if (!magic.contentEquals(MAGIC)) throw PairException(PairFailure.PROTOCOL, "not a PGPony pairing host")
            wire.writeFrame(JOIN, byteArrayOf(VERSION) + keyPair.public)
            val accept = expect(wire, ACCEPT, 64)
            val pkH = accept.copyOfRange(0, 32)
            val commit = accept.copyOfRange(32, 64)
            if (expectedHostKeyHash != null &&
                !PairFrames.constantTimeEquals(PairCrypto.sha256(pkH).copyOf(expectedHostKeyHash.size), expectedHostKeyHash)
            ) {
                abort(wire, PairFailure.HANDSHAKE)
                throw PairException(PairFailure.HANDSHAKE, "the host key does not match the QR code")
            }
            val nJ = random.bytes(32)
            wire.writeFrame(NONCE_J, nJ)
            val nH = expect(wire, NONCE_H, 32)
            if (!PairFrames.constantTimeEquals(PairCrypto.commit(nH, pkH, keyPair.public), commit)) {
                abort(wire, PairFailure.HANDSHAKE)
                throw PairException(PairFailure.HANDSHAKE, "the host changed its nonce")
            }
            return finish(PairRole.JOINER, wire, keyPair, keyPair.public, pkH, nJ, nH, setTimeout, random)
        } catch (e: Exception) {
            keyPair.wipe()
            wire.close()
            throw wrap(e)
        }
    }

    private fun finish(
        role: PairRole, wire: PairWire, own: PairCrypto.KeyPair, pkJ: ByteArray, pkH: ByteArray,
        nJ: ByteArray, nH: ByteArray, setTimeout: (Int) -> Unit, random: PairRandom
    ): PairAttempt {
        val peer = if (role == PairRole.HOST) pkJ else pkH
        val z = PairCrypto.agree(own.secret, peer)
        own.wipe()
        if (z == null) {
            abort(wire, PairFailure.HANDSHAKE)
            throw PairException(PairFailure.HANDSHAKE, "the other side sent an invalid key")
        }
        val t = PairCrypto.transcript(pkJ, pkH, nJ, nH, VERSION)
        val keys = PairCrypto.derive(z, t)
        z.fill(0)
        setTimeout(CONFIRM_TIMEOUT_MS)
        return PairAttempt(role, wire, keys, PairCrypto.code(t), random)
    }

    private fun expect(wire: PairWire, type: Byte, size: Int): ByteArray {
        val (t, payload) = wire.withDeadline(FRAME_TIMEOUT_MS.toLong()) { wire.readFrame(maxOf(size, 1).toLong()) }
        if (t == ABORT && payload.size == 1) {
            val f = PairFailure.ofReason(payload[0].toInt())
            throw PairException(f, "the other side ended the pairing (${f.name.lowercase()})")
        }
        if (t != type || payload.size != size) throw PairException(PairFailure.PROTOCOL, "unexpected pairing message")
        return payload
    }

    internal fun abort(wire: PairWire, failure: PairFailure) {
        runCatching { wire.writeFrame(ABORT, byteArrayOf(failure.abortReason.toByte())) }
    }

    internal fun wrap(e: Throwable): PairException = when (e) {
        is PairException -> e
        is java.net.SocketTimeoutException -> PairException(PairFailure.TIMEOUT, "the other side stopped answering")
        is ExecutionException -> wrap(e.cause ?: e)
        is TimeoutException -> PairException(PairFailure.TIMEOUT, "the other side stopped answering")
        else -> PairException(PairFailure.CLOSED, e.message ?: "connection lost")
    }
}

/**
 * Phase 1 is done and both screens can show [code]. Exactly one of [confirm] or [reject] must
 * follow; [peerRefused] completes early if the other user refuses first.
 */
class PairAttempt internal constructor(
    val role: PairRole,
    private val wire: PairWire,
    private val keys: PairCrypto.Keys,
    val code: String,
    private val random: PairRandom
) {
    /** The other side's answer: its phase 2 frame, read as soon as it arrives. */
    private val peerAnswer: CompletableFuture<Pair<Byte, ByteArray>> = CompletableFuture.supplyAsync({
        wire.withDeadline(PairProtocol.CONFIRM_TIMEOUT_MS.toLong()) {
            val first = wire.readExact(1)[0]
            if (first == 'P'.code.toByte()) {
                if (!wire.readExact(3).contentEquals("DR1".toByteArray(Charsets.US_ASCII))) {
                    throw PairException(PairFailure.PROTOCOL, "unexpected data")
                }
                wire.readFrame(PairProtocol.PHASE2_MAX_FRAME)
            } else {
                wire.readFrameAfterType(first, PairProtocol.PHASE2_MAX_FRAME)
            }
        }
    }, { r -> Thread(r, "pgpony-pair-read").apply { isDaemon = true }.start() })

    /** Completes with the failure when the other user refuses before this one answers. */
    val peerRefused: CompletableFuture<PairFailure> = peerAnswer.handle { frame, error ->
        when {
            error != null -> PairProtocol.wrap(error).failure
            frame.first == PairProtocol.ABORT -> PairFailure.ofReason(frame.second.firstOrNull()?.toInt() ?: 0)
            else -> null
        }
    }.thenCompose { f -> if (f == null) CompletableFuture<PairFailure>() else CompletableFuture.completedFuture(f) }

    private fun peerFrame(): Pair<Byte, ByteArray> = try {
        peerAnswer.get(PairProtocol.CONFIRM_TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS)
    } catch (e: Exception) {
        throw PairProtocol.wrap(e)
    }

    private fun refusedBy(frame: Pair<Byte, ByteArray>): PairException? =
        if (frame.first == PairProtocol.ABORT) {
            val f = PairFailure.ofReason(frame.second.firstOrNull()?.toInt() ?: 0)
            PairException(f, if (f == PairFailure.REFUSED) "the other side said the codes do not match" else "the other side ended the pairing")
        } else null

    private fun refusalSoFar(waitMs: Long = 0): PairException? {
        val frame = try {
            if (waitMs == 0L) peerAnswer.getNow(null) else peerAnswer.get(waitMs, TimeUnit.MILLISECONDS)
        } catch (e: Exception) {
            null
        } ?: return null
        return refusedBy(frame)
    }

    /**
     * Whether [typed], the code this user typed from the other screen, is this attempt's code.
     * Spaces and hyphens between the digits are ignored; anything else makes it a mismatch.
     * Compared in constant time. The host asks for the code this way instead of a "same code"
     * button, so its user cannot confirm without reading the other screen (section 4).
     */
    fun matchesTypedCode(typed: String): Boolean {
        val t = typed.trim()
        if (t.any { !(it in '0'..'9' || it == ' ' || it == '-') }) return false
        val digits = t.filter { it in '0'..'9' }
        if (digits.length != 6) return false
        val own = code.filter { it in '0'..'9' }
        return PairFrames.constantTimeEquals(digits.toByteArray(Charsets.US_ASCII), own.toByteArray(Charsets.US_ASCII))
    }

    /** This user says the codes match: phase 2. Returns the session or throws. */
    fun confirm(): PairSession {
        try {
            if (role == PairRole.JOINER) {
                // A refusal may already be here; it explains a failed write better than the write.
                refusalSoFar()?.let { throw it }
                val dialerNonce = random.bytes(16)
                try {
                    wire.writeRaw(PairFrames.PDR1)
                    wire.writeFrame(PairFrames.HELLO, dialerNonce + PairFrames.identifyTag(keys.pairKey, dialerNonce))
                } catch (e: IOException) {
                    throw refusalSoFar(waitMs = 2_000) ?: e
                }
                val frame = peerFrame()
                refusedBy(frame)?.let { throw it }
                if (frame.first != PairFrames.HELLO_ACK || frame.second.size != 48) {
                    throw PairException(PairFailure.HANDSHAKE, "the codes did not match")
                }
                val listenerNonce = frame.second.copyOfRange(0, 16)
                val expected = PairFrames.identifyAckTag(keys.pairKey, dialerNonce, listenerNonce)
                if (!PairFrames.constantTimeEquals(expected, frame.second.copyOfRange(16, 48))) {
                    throw PairException(PairFailure.HANDSHAKE, "the codes did not match")
                }
            } else {
                val frame = peerFrame()
                refusedBy(frame)?.let { throw it }
                val ok = frame.first == PairFrames.HELLO && frame.second.size == 48 &&
                    PairFrames.constantTimeEquals(
                        PairFrames.identifyTag(keys.pairKey, frame.second.copyOfRange(0, 16)),
                        frame.second.copyOfRange(16, 48)
                    )
                wire.writeRaw(PairFrames.PDR1)
                if (!ok) {
                    wire.writeFrame(PairFrames.NO_MATCH, random.bytes(48))
                    throw PairException(PairFailure.HANDSHAKE, "the codes did not match")
                }
                val listenerNonce = random.bytes(16)
                wire.writeFrame(
                    PairFrames.HELLO_ACK,
                    listenerNonce + PairFrames.identifyAckTag(keys.pairKey, frame.second.copyOfRange(0, 16), listenerNonce)
                )
            }
            val send = if (role == PairRole.HOST) keys.hostToJoiner else keys.joinerToHost
            val receive = if (role == PairRole.HOST) keys.joinerToHost else keys.hostToJoiner
            val session = PairSession(role, wire, send.copyOf(), receive.copyOf())
            keys.wipe()
            return session
        } catch (e: Exception) {
            keys.wipe()
            wire.close()
            throw PairProtocol.wrap(e)
        }
    }

    /** This user says the codes differ, or cancels. */
    fun reject() {
        PairProtocol.abort(wire, PairFailure.REFUSED)
        keys.wipe()
        wire.close()
    }
}
