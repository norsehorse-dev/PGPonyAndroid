// PairWire.kt
// The pairing protocol (docs/PAIRING_PROTOCOL.md): framing, the PonyDirect pieces phase 2 and 3
// reuse, the random source, and the blocking stream both phases run over.
//
// Shared by Android and desktop (desktop vendors this package). Pure Kotlin on the JDK: no
// Android API, so a unit test and the desktop build run it unchanged.

package com.pgpony.android.pair

import java.io.DataInputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/**
 * The PonyDirect LAN identify handshake and ENVELOPE frame, byte for byte as PonyDirect's
 * WIRE-PROTOCOL.md defines them. Copied here, not linked, so the pairing code has no
 * dependency beyond the JDK and Bouncy Castle; the test vectors pin every byte.
 */
object PairFrames {
    /** Prefixes phase 2 in each direction. */
    val PDR1: ByteArray = "PDR1".toByteArray(Charsets.US_ASCII)

    const val HELLO: Byte = 0x01
    const val HELLO_ACK: Byte = 0x02
    const val NO_MATCH: Byte = 0x03
    const val ENVELOPE: Byte = 0x04

    private val LABEL_IDENTIFY = "ponydirect/id/v1".toByteArray(Charsets.US_ASCII)
    private val LABEL_IDENTIFY_ACK = "ponydirect/id-ack/v1".toByteArray(Charsets.US_ASCII)

    /** `type(1) | length(4, big-endian) | payload`. */
    fun frame(type: Byte, payload: ByteArray): ByteArray {
        val n = payload.size
        val out = ByteArray(5 + n)
        out[0] = type
        out[1] = (n ushr 24).toByte()
        out[2] = (n ushr 16).toByte()
        out[3] = (n ushr 8).toByte()
        out[4] = n.toByte()
        System.arraycopy(payload, 0, out, 5, n)
        return out
    }

    /** HELLO tag: HMAC-SHA256(K, "ponydirect/id/v1" || dialer nonce). */
    fun identifyTag(pairKey: ByteArray, dialerNonce: ByteArray): ByteArray =
        PairCrypto.hmac(pairKey, LABEL_IDENTIFY, dialerNonce)

    /** HELLO_ACK tag: HMAC-SHA256(K, "ponydirect/id-ack/v1" || dialer nonce || listener nonce). */
    fun identifyAckTag(pairKey: ByteArray, dialerNonce: ByteArray, listenerNonce: ByteArray): ByteArray =
        PairCrypto.hmac(pairKey, LABEL_IDENTIFY_ACK, dialerNonce, listenerNonce)

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}

/**
 * Where the protocol's random bytes come from. Always [SECURE] in the app; the published
 * session transcript (test resources, pairing/v1-session.json) replays a fixed one.
 */
fun interface PairRandom {
    fun bytes(n: Int): ByteArray

    companion object {
        val SECURE = PairRandom { PairCrypto.randomBytes(it) }
    }
}

/** The framed byte stream both phases run over. */
internal class PairWire(input: InputStream, private val output: OutputStream, private val onClose: () -> Unit) {
    private val input = DataInputStream(input)

    fun writeRaw(bytes: ByteArray) {
        output.write(bytes)
        output.flush()
    }

    fun writeFrame(type: Byte, payload: ByteArray) = writeRaw(PairFrames.frame(type, payload))

    fun readExact(n: Int): ByteArray = try {
        ByteArray(n).also { input.readFully(it) }
    } catch (e: EOFException) {
        throw PairException(PairFailure.CLOSED, "the other side closed the connection")
    }

    /** One frame whose type byte was already read. */
    fun readFrameAfterType(type: Byte): Pair<Byte, ByteArray> {
        val len = readExact(4).fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
        if (len > MAX_FRAME) throw PairException(PairFailure.PROTOCOL, "frame too long")
        return type to readExact(len.toInt())
    }

    fun readFrame(): Pair<Byte, ByteArray> = readFrameAfterType(readExact(1)[0])

    fun close() {
        runCatching { onClose() }
    }

    companion object {
        const val MAX_FRAME = 1_048_576L + 65_536L
    }
}
