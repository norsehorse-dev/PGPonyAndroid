// PairSession.kt
// Phase 3 of the pairing protocol (docs/PAIRING_PROTOCOL.md, section 5): sealed messages inside
// ENVELOPE frames, and the offer and item messages that move keys and backups. The session keys
// live only here and are wiped on close.

package com.pgpony.android.pair

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import java.io.Closeable

// JSON bodies are built and read by hand (kotlinx.serialization.json elements, no compiler
// plugin) so the member names are exactly the ones in the protocol document.

/** One item on offer (section 5, `ITEM`). */
data class PairItem(
    val id: Int,
    val kind: String,
    val name: String,
    val fingerprint: String? = null,
    val size: Long
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("id", id); put("kind", kind); put("name", name)
        put("fingerprint", fingerprint?.let { JsonPrimitive(it) } ?: JsonNull)
        put("size", size)
    }

    companion object {
        const val PUBLIC_KEY = "public-key"
        const val KEY_PAIR = "key-pair"
        const val BACKUP = "backup"
        val KINDS = setOf(PUBLIC_KEY, KEY_PAIR, BACKUP)

        fun fromJson(o: JsonObject) = PairItem(
            id = o["id"]!!.jsonPrimitive.int,
            kind = o["kind"]!!.jsonPrimitive.content,
            name = o["name"]?.jsonPrimitive?.contentOrNull ?: "",
            fingerprint = o["fingerprint"]?.jsonPrimitive?.contentOrNull,
            size = o["size"]!!.jsonPrimitive.long
        )
    }
}

/**
 * The INFO message (section 5). [accepts] lists the item kinds this side can import; null
 * (the member left out) means all three. A sender offers nothing the receiver does not accept.
 */
data class PairInfo(val name: String, val app: String, val accepts: Set<String>? = null) {
    fun toJson() = buildJsonObject {
        put("name", name); put("app", app)
        if (accepts != null) {
            val ordered = PairItem.KINDS.filter { it in accepts } + accepts.filter { it !in PairItem.KINDS }.sorted()
            put("accepts", JsonArray(ordered.map { JsonPrimitive(it) }))
        }
    }

    /** Whether the side that sent this INFO can import items of [kind]. */
    fun takes(kind: String): Boolean = accepts?.contains(kind) ?: (kind in PairItem.KINDS)

    companion object {
        fun fromJson(o: JsonObject) = PairInfo(
            o["name"]?.jsonPrimitive?.contentOrNull ?: "", o["app"]?.jsonPrimitive?.contentOrNull ?: "",
            (o["accepts"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }?.toSet()
        )
    }
}

data class PairOffer(val items: List<PairItem>) {
    fun toJson() = JsonObject(mapOf("items" to JsonArray(items.map { it.toJson() })))

    companion object {
        fun fromJson(o: JsonObject) = PairOffer(o["items"]!!.jsonArray.map { PairItem.fromJson(it.jsonObject) })
    }
}

data class PairAnswer(val accept: List<Int>) {
    fun toJson() = JsonObject(mapOf("accept" to JsonArray(accept.map { JsonPrimitive(it) })))

    companion object {
        fun fromJson(o: JsonObject) = PairAnswer(o["accept"]!!.jsonArray.map { it.jsonPrimitive.int })
    }
}

data class PairResult(val id: Int, val ok: Boolean, val error: String? = null) {
    fun toJson() = buildJsonObject {
        put("id", id); put("ok", ok); put("error", error?.let { JsonPrimitive(it) } ?: JsonNull)
    }

    companion object {
        fun fromJson(o: JsonObject) = PairResult(
            o["id"]!!.jsonPrimitive.int, o["ok"]?.jsonPrimitive?.booleanOrNull ?: false,
            o["error"]?.jsonPrimitive?.contentOrNull
        )
    }
}

/** A message received in the session. */
sealed class PairMessage {
    data class Info(val info: PairInfo) : PairMessage()
    data class Offer(val offer: PairOffer) : PairMessage()
    data class Answer(val answer: PairAnswer) : PairMessage()
    /** A whole item, reassembled and checked against its size and hash. */
    class Item(val id: Int, val bytes: ByteArray) : PairMessage()
    data class Result(val result: PairResult) : PairMessage()
    object Bye : PairMessage()
}

class PairSession internal constructor(
    val role: PairRole,
    private val wire: PairWire,
    private val sendKey: ByteArray,
    private val receiveKey: ByteArray
) : Closeable {

    private var sendSeq = 0L
    private var receiveSeq = 0L
    @Volatile private var closed = false


    companion object {
        const val INFO: Byte = 0x01
        const val OFFER: Byte = 0x10
        const val ANSWER: Byte = 0x11
        const val ITEM_BEGIN: Byte = 0x20
        const val ITEM_DATA: Byte = 0x21
        const val ITEM_END: Byte = 0x22
        const val RESULT: Byte = 0x30
        const val BYE: Byte = 0x3F

        const val MAX_PLAINTEXT = 1_048_576
        const val MAX_ITEM_BYTES = 64L * 1024 * 1024
        const val MAX_OFFER_ITEMS = 1000
        private const val CHUNK = MAX_PLAINTEXT - 16
    }

    // ── Sealed messages ────────────────────────────────────────────────

    @Synchronized
    private fun send(type: Byte, body: ByteArray) {
        if (closed) throw PairException(PairFailure.CLOSED, "the session is closed")
        val plaintext = byteArrayOf(type) + body
        require(plaintext.size <= MAX_PLAINTEXT)
        try {
            wire.writeFrame(PairFrames.ENVELOPE, PairCrypto.seal(sendKey, sendSeq++, plaintext))
        } catch (e: Exception) {
            close()
            throw PairProtocol.wrap(e)
        }
    }

    private fun receiveRaw(): Pair<Byte, ByteArray> {
        try {
            val (type, payload) = wire.readFrame()
            if (type != PairFrames.ENVELOPE) throw PairException(PairFailure.PROTOCOL, "unexpected frame")
            val plaintext = PairCrypto.open(receiveKey, receiveSeq++, payload)
            if (plaintext.isEmpty() || plaintext.size > MAX_PLAINTEXT) throw PairException(PairFailure.PROTOCOL, "bad message")
            return plaintext[0] to plaintext.copyOfRange(1, plaintext.size)
        } catch (e: Exception) {
            close()
            throw PairProtocol.wrap(e)
        }
    }

    private fun encode(o: JsonObject): ByteArray = o.toString().toByteArray(Charsets.UTF_8)

    private fun <T> decode(body: ByteArray, read: (JsonObject) -> T): T = try {
        read(Json.parseToJsonElement(String(body, Charsets.UTF_8)).jsonObject)
    } catch (e: Exception) {
        protocolError("malformed message")
    }

    // ── Sending ────────────────────────────────────────────────────────

    fun sendInfo(info: PairInfo) = send(INFO, encode(info.toJson()))

    fun sendOffer(offer: PairOffer) {
        require(offer.items.size in 1..MAX_OFFER_ITEMS)
        require(offer.items.all { it.kind in PairItem.KINDS && it.size in 0..MAX_ITEM_BYTES })
        send(OFFER, encode(offer.toJson()))
    }

    fun sendAnswer(answer: PairAnswer) = send(ANSWER, encode(answer.toJson()))

    fun sendResult(result: PairResult) = send(RESULT, encode(result.toJson()))

    /** One accepted item: ITEM_BEGIN, ITEM_DATA pieces, ITEM_END. [progress] gets bytes sent. */
    fun sendItem(id: Int, bytes: ByteArray, progress: (Long) -> Unit = {}) {
        require(bytes.size <= MAX_ITEM_BYTES)
        val idb = intBytes(id)
        send(ITEM_BEGIN, idb + PairCrypto.seqBytes(bytes.size.toLong()))
        var off = 0
        while (off < bytes.size) {
            val n = minOf(CHUNK - 4, bytes.size - off)
            send(ITEM_DATA, idb + bytes.copyOfRange(off, off + n))
            off += n
            progress(off.toLong())
        }
        send(ITEM_END, idb + PairCrypto.sha256(bytes))
    }

    fun sendBye() = runCatching { send(BYE, ByteArray(0)) }.let { }

    // ── Receiving ──────────────────────────────────────────────────────

    /**
     * The next message. Item pieces are gathered here and handed over as one [PairMessage.Item]
     * once ITEM_END checks out; [itemProgress] gets (id, bytes so far) while one arrives.
     * [expectedItems] are the ids this side accepted and their announced sizes; an item outside
     * it ends the session.
     */
    fun receive(expectedItems: Map<Int, Long> = emptyMap(), itemProgress: (Int, Long) -> Unit = { _, _ -> }): PairMessage {
        while (true) {
            val (type, body) = receiveRaw()
            when (type) {
                INFO -> return PairMessage.Info(decode(body, PairInfo::fromJson))
                OFFER -> {
                    val offer = decode(body, PairOffer::fromJson)
                    if (offer.items.isEmpty() || offer.items.size > MAX_OFFER_ITEMS ||
                        offer.items.any { it.size !in 0..MAX_ITEM_BYTES } ||
                        offer.items.map { it.id }.toSet().size != offer.items.size
                    ) protocolError("bad offer")
                    return PairMessage.Offer(offer)
                }
                ANSWER -> return PairMessage.Answer(decode(body, PairAnswer::fromJson))
                RESULT -> return PairMessage.Result(decode(body, PairResult::fromJson))
                BYE -> {
                    close()
                    return PairMessage.Bye
                }
                ITEM_BEGIN -> {
                    if (body.size != 12) protocolError("bad item header")
                    val id = readInt(body, 0)
                    val size = body.copyOfRange(4, 12).fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
                    val announced = expectedItems[id] ?: protocolError("an item that was not accepted")
                    if (size != announced || size > MAX_ITEM_BYTES) protocolError("item size does not match the offer")
                    return PairMessage.Item(id, receiveItemBody(id, size.toInt(), itemProgress))
                }
                else -> protocolError("unknown message")
            }
        }
    }

    private fun receiveItemBody(id: Int, size: Int, progress: (Int, Long) -> Unit): ByteArray {
        val buf = java.io.ByteArrayOutputStream(size)
        while (true) {
            val (type, body) = receiveRaw()
            if (body.size < 4 || readInt(body, 0) != id) protocolError("item pieces out of order")
            when (type) {
                ITEM_DATA -> {
                    if (buf.size() + body.size - 4 > size) protocolError("item longer than announced")
                    buf.write(body, 4, body.size - 4)
                    progress(id, buf.size().toLong())
                }
                ITEM_END -> {
                    val bytes = buf.toByteArray()
                    if (bytes.size != size || body.size != 36 ||
                        !PairFrames.constantTimeEquals(PairCrypto.sha256(bytes), body.copyOfRange(4, 36))
                    ) protocolError("item damaged in transit")
                    return bytes
                }
                else -> protocolError("item pieces out of order")
            }
        }
    }

    private fun protocolError(msg: String): Nothing {
        close()
        throw PairException(PairFailure.PROTOCOL, msg)
    }

    private fun intBytes(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun readInt(b: ByteArray, off: Int) =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    /** Ends the session and wipes its keys. Safe to call more than once. */
    override fun close() {
        if (closed) return
        closed = true
        sendKey.fill(0)
        receiveKey.fill(0)
        wire.close()
    }
}
