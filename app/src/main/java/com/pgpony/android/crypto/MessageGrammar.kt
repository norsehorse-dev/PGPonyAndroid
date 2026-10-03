// MessageGrammar.kt
// PGPony Android, 3.0.0 checkpoint 5d-2: what a well-formed OpenPGP message
// is, checked on the packet sequence before and after decryption.
//
// Bouncy Castle reads the packets it expects and quietly steps over most of
// what it does not, so a message with two literal packets, a literal packet
// with a stray key or signature after it, a one-pass signature without its
// signature, or an unknown critical packet used to decrypt or verify as if
// nothing were wrong. The OpenPGP interoperability test suite probes exactly
// these. This object applies RFC 9580 section 10.3:
//
//   OpenPGP Message   :- Encrypted | Signed | Compressed | Literal Message
//   Encrypted Message :- [ESK Sequence] Encrypted Data   (content: a Message)
//   Signed Message    :- Signature, Message | OPS, Message, Signature
//   Compressed Message:- Compressed Data                 (content: a Message)
//
// Marker, padding and trust packets, and unknown packets of a non-critical
// type (40 and up), may appear anywhere and are skipped. An unknown packet of
// a critical type (below 40) makes the message malformed (RFC 9580 4.3).
//
// Two entry points:
//
//   * normalizeOuter(): the undecrypted message. An encrypted message must be
//     ESKs followed by exactly one encrypted data packet and nothing after it.
//     ESKs of an unknown version or public-key algorithm are dropped (RFC 9580
//     asks for them to be skipped, Bouncy Castle stops on them), and so are
//     ESKs whose version does not match the encrypted data packet (a v4 SKESK
//     goes with SEIPDv1, a v6 PKESK or SKESK with SEIPDv2, RFC 9580 5.1 and
//     5.3). One exception: a v3 PKESK before SEIPDv2 is kept, because PGPony
//     4.5 and later write that pairing for v4 recipients of mixed messages.
//     A message that is not encrypted gets the full grammar check.
//   * normalizePlaintext(): the decrypted content, with compressed packets
//     opened (bounded in depth and size). One-pass signatures and signatures
//     of an unknown version or algorithm are dropped with their partner, so
//     the rest of the message still reads.
//
// Both return the input itself when nothing had to change, so ordinary
// messages reach Bouncy Castle byte for byte as before. The packet reader is
// strict: a truncated packet, a partial length on a packet type that may not
// use one, or a first partial chunk under 512 octets (RFC 9580 4.2.1.4) is
// malformed.

package com.pgpony.android.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.DataFormatException
import java.util.zip.Inflater

object MessageGrammar {

    /** The message is not well formed. */
    class Malformed(msg: String) : Exception(msg)

    /** A packet was cut short: the input ends inside it. */
    class Truncated : Exception("truncated packet")

    private const val TAG_PKESK = 1
    private const val TAG_SIGNATURE = 2
    private const val TAG_SKESK = 3
    private const val TAG_OPS = 4
    private const val TAG_COMPRESSED = 8
    private const val TAG_SED = 9
    private const val TAG_MARKER = 10
    private const val TAG_LITERAL = 11
    private const val TAG_TRUST = 12
    private const val TAG_SEIPD = 18
    private const val TAG_PADDING = 21
    private const val TAG_OCB = 20

    /** Packet types RFC 9580 defines (4.3). */
    private val KNOWN_TAGS = (1..14).toSet() + (17..21)

    /** Types that may be sent with partial lengths (RFC 9580 4.2.1.4). */
    private val PARTIAL_OK = setOf(TAG_COMPRESSED, TAG_SED, TAG_LITERAL, TAG_SEIPD, TAG_OCB)

    private val ENCRYPTED_DATA = setOf(TAG_SED, TAG_SEIPD, TAG_OCB)

    /** Public-key algorithms a PKESK may name here: RSA, Elgamal, ECDH,
     *  X25519, X448, and the composite ML-KEM suites (LibrePGP 8, IETF 35/36). */
    private val PKESK_ALGORITHMS = setOf(1, 2, 16, 18, 25, 26, 8, 35, 36)

    /** Public-key algorithms a signature or one-pass signature may name here. */
    private val SIGNATURE_ALGORITHMS: Set<Int> by lazy {
        setOf(1, 3, 17, 19, 22, 27, 28) +
            com.pgpony.android.crypto.pqc.CompositeSignSuite.entries.map { it.algId }
    }

    /** Nested containers (compressed or encrypted data) allowed. */
    private const val MAX_DEPTH = 16

    /** Nested signature layers allowed (one-pass and prefixed signatures). */
    private const val MAX_SIGNATURE_NESTING = 256

    // ── Packet reader ───────────────────────────────────────────────────

    /** One packet: its type, where its header starts and its body ends in the
     *  input, and the body ranges (several for a partial-length packet). */
    internal class Pkt(val tag: Int, val rawStart: Int, val rawEnd: Int, val ranges: List<IntRange>, private val src: ByteArray) {
        val bodySize: Int get() = ranges.sumOf { it.last - it.first + 1 }
        fun body(): ByteArray {
            if (ranges.size == 1) return src.copyOfRange(ranges[0].first, ranges[0].last + 1)
            val out = ByteArrayOutputStream(bodySize)
            for (r in ranges) out.write(src, r.first, r.last - r.first + 1)
            return out.toByteArray()
        }
        /** The first [n] body octets (fewer if the body is shorter). */
        fun head(n: Int): ByteArray {
            val out = ByteArrayOutputStream(n)
            var left = n
            for (r in ranges) {
                if (left <= 0) break
                val take = minOf(left, r.last - r.first + 1)
                out.write(src, r.first, take)
                left -= take
            }
            return out.toByteArray()
        }
        fun raw(): ByteArray = src.copyOfRange(rawStart, rawEnd)
    }

    internal fun packets(data: ByteArray): List<Pkt> {
        val out = ArrayList<Pkt>()
        var i = 0
        fun u8(): Int {
            if (i >= data.size) throw Truncated()
            return data[i++].toInt() and 0xFF
        }
        fun be(n: Int): Int {
            var v = 0L
            repeat(n) { v = (v shl 8) or u8().toLong() }
            if (v > Int.MAX_VALUE) throw Malformed("packet length too large")
            return v.toInt()
        }
        while (i < data.size) {
            val start = i
            val c = u8()
            if (c and 0x80 == 0) throw Malformed("not a packet header")
            val ranges = ArrayList<IntRange>()
            val tag: Int
            if (c and 0x40 != 0) {
                tag = c and 0x3F
                var first = true
                while (true) {
                    val l0 = u8()
                    val len: Int
                    var partial = false
                    when {
                        l0 < 192 -> len = l0
                        l0 < 224 -> len = ((l0 - 192) shl 8) + u8() + 192
                        l0 == 255 -> len = be(4)
                        else -> { len = 1 shl (l0 and 0x1F); partial = true }
                    }
                    if (partial) {
                        if (tag !in PARTIAL_OK) throw Malformed("partial length on packet type $tag")
                        if (first && len < 512) throw Malformed("first partial chunk shorter than 512 octets")
                    }
                    if (len > data.size - i) throw Truncated()
                    if (len > 0) ranges.add(i until i + len)
                    i += len
                    first = false
                    if (!partial) break
                }
            } else {
                tag = (c shr 2) and 0x0F
                val len = when (c and 0x03) {
                    0 -> be(1)
                    1 -> be(2)
                    2 -> be(4)
                    else -> data.size - i // indeterminate: to the end of the input
                }
                if (len > data.size - i) throw Truncated()
                if (len > 0) ranges.add(i until i + len)
                i += len
            }
            out.add(Pkt(tag, start, i, ranges, data))
        }
        return out
    }

    private fun ignorable(tag: Int) = tag == TAG_MARKER || tag == TAG_PADDING || tag == TAG_TRUST || tag >= 40

    private fun criticalUnknown(tag: Int) = tag < 40 && tag !in KNOWN_TAGS

    // ── Outer message ───────────────────────────────────────────────────

    /**
     * The undecrypted message [binary] (not armored), checked. Returns the
     * input when it is fine as it stands, or a rewritten copy without the
     * ESKs that must be skipped. Throws [Malformed] or [Truncated].
     */
    fun normalizeOuter(binary: ByteArray): ByteArray {
        val all = packets(binary)
        all.firstOrNull { criticalUnknown(it.tag) }?.let { throw Malformed("unknown critical packet type ${it.tag}") }
        val pkts = all.filterNot { ignorable(it.tag) }
        val first = pkts.firstOrNull() ?: throw Malformed("no OpenPGP message")
        if (first.tag != TAG_PKESK && first.tag != TAG_SKESK && first.tag !in ENCRYPTED_DATA) {
            walk(pkts, 0, Budget(), 0, null).let { end ->
                if (end != pkts.size) throw Malformed("packets after the end of the message")
            }
            return binary
        }
        val esks = pkts.takeWhile { it.tag == TAG_PKESK || it.tag == TAG_SKESK }
        val data = pkts.getOrNull(esks.size) ?: throw Malformed("session keys without encrypted data")
        if (data.tag !in ENCRYPTED_DATA) throw Malformed("session keys followed by packet type ${data.tag}")
        if (pkts.size > esks.size + 1) throw Malformed("packets after the encrypted data")
        val dataVersion = if (data.tag == TAG_SEIPD) data.head(1).firstOrNull()?.toInt()?.and(0xFF) else null
        val keep = esks.filter { usableEsk(it, data.tag, dataVersion) }
        if (esks.isNotEmpty() && keep.isEmpty()) {
            throw Malformed("no session key packet fits the encrypted data")
        }
        if (keep.size == esks.size && all.size == pkts.size) return binary
        val out = ByteArrayOutputStream(binary.size)
        keep.forEach { out.write(it.raw()) }
        out.write(binary, data.rawStart, data.rawEnd - data.rawStart)
        return out.toByteArray()
    }

    /** Should [esk] be offered for encrypted data of type [dataTag] and [dataVersion]? */
    private fun usableEsk(esk: Pkt, dataTag: Int, dataVersion: Int?): Boolean {
        val h = esk.head(64)
        if (h.isEmpty()) return false
        val v = h[0].toInt() and 0xFF
        if (esk.tag == TAG_PKESK) {
            val algo = when (v) {
                3 -> h.getOrNull(9)?.toInt()?.and(0xFF)
                6 -> h.getOrNull(1)?.toInt()?.and(0xFF)?.let { count -> h.getOrNull(2 + count)?.toInt()?.and(0xFF) }
                else -> return false
            } ?: return false
            if (algo !in PKESK_ALGORITHMS) return false
            // A v6 PKESK never goes with SEIPDv1. A v3 PKESK in front of
            // SEIPDv2 is out of spec too, but PGPony 4.5 and later write
            // exactly that for a v4 recipient of a message that also goes to
            // a composite key, so it stays readable.
            return !(dataTag == TAG_SEIPD && dataVersion == 1 && v == 6)
        }
        if (v !in setOf(4, 5, 6)) return false
        return when {
            dataTag == TAG_SEIPD && dataVersion == 1 -> v == 4
            dataTag == TAG_SEIPD && dataVersion == 2 -> v == 6
            else -> true
        }
    }

    // ── Decrypted content ───────────────────────────────────────────────

    /**
     * The decrypted content [plain], checked against the message grammar with
     * compressed packets opened. Returns [plain] when nothing had to change,
     * or the message flattened (compression removed) without one-pass
     * signatures and signatures of an unknown version or algorithm. Throws
     * [Malformed] or [Truncated].
     */
    fun normalizePlaintext(plain: ByteArray): ByteArray {
        val flat = ArrayList<ByteArray>()
        val budget = Budget()
        checkMessageBytes(plain, 0, budget, flat)
        if (!budget.dropped) return plain
        val out = ByteArrayOutputStream()
        flat.forEach { out.write(it) }
        return out.toByteArray()
    }

    /** Output size left for decompression, and whether anything was dropped. */
    private class Budget(var bytesLeft: Long = SecurityLimits.MAX_MESSAGE_PLAINTEXT_BYTES, var dropped: Boolean = false)

    /** [bytes] must hold exactly one message; its flattened packets go to [flat]. */
    private fun checkMessageBytes(bytes: ByteArray, depth: Int, budget: Budget, flat: MutableList<ByteArray>?) {
        val all = packets(bytes)
        all.firstOrNull { criticalUnknown(it.tag) }?.let { throw Malformed("unknown critical packet type ${it.tag}") }
        val pkts = all.filterNot { ignorable(it.tag) }
        val end = walk(pkts, 0, budget, depth, flat)
        if (end != pkts.size) throw Malformed("packets after the end of the message")
    }

    /**
     * Walk one OpenPGP Message starting at [i]; returns the index after it.
     * Packets that are kept are appended (raw) to [flat] when it is given.
     */
    private fun walk(pkts: List<Pkt>, start: Int, budget: Budget, depth: Int, flat: MutableList<ByteArray>?, nesting: Int = 0): Int {
        if (nesting > MAX_SIGNATURE_NESTING) throw Malformed("signatures nested too deeply")
        var i = start
        val p = pkts.getOrNull(i) ?: throw Malformed("message ends where a message was expected")
        when (p.tag) {
            TAG_LITERAL -> {
                val h = p.head(2)
                if (h.size < 2) throw Malformed("literal data packet too short")
                val nameLen = h[1].toInt() and 0xFF
                if (p.bodySize < 2 + nameLen + 4) throw Malformed("literal data filename runs past the packet")
                flat?.add(p.raw())
                return i + 1
            }
            TAG_COMPRESSED -> {
                if (depth + 1 > MAX_DEPTH) throw Malformed("containers nested too deeply")
                val inner = decompress(p.body(), budget)
                val innerFlat = if (flat != null) ArrayList<ByteArray>() else null
                checkMessageBytes(inner, depth + 1, budget, innerFlat)
                if (flat != null) flat.addAll(innerFlat!!)
                return i + 1
            }
            TAG_PKESK, TAG_SKESK -> {
                while (pkts.getOrNull(i)?.tag.let { it == TAG_PKESK || it == TAG_SKESK }) {
                    flat?.add(pkts[i].raw()); i++
                }
                val d = pkts.getOrNull(i) ?: throw Malformed("session keys without encrypted data")
                if (d.tag !in ENCRYPTED_DATA) throw Malformed("session keys followed by packet type ${d.tag}")
                if (depth + 1 > MAX_DEPTH) throw Malformed("containers nested too deeply")
                flat?.add(d.raw())
                return i + 1
            }
            TAG_SED, TAG_SEIPD, TAG_OCB -> {
                if (depth + 1 > MAX_DEPTH) throw Malformed("containers nested too deeply")
                flat?.add(p.raw())
                return i + 1
            }
            TAG_OPS -> {
                val known = knownOps(p)
                val mark = flat?.size
                if (known) flat?.add(p.raw())
                val after = walk(pkts, i + 1, budget, depth, flat, nesting + 1)
                val sig = pkts.getOrNull(after) ?: throw Malformed("one-pass signature without its signature")
                if (sig.tag != TAG_SIGNATURE) throw Malformed("one-pass signature without its signature")
                if (known && knownSignature(sig)) {
                    flat?.add(sig.raw())
                } else {
                    budget.dropped = true
                    if (known && flat != null && mark != null) flat.removeAt(mark)
                }
                return after + 1
            }
            TAG_SIGNATURE -> {
                if (knownSignature(p)) flat?.add(p.raw()) else budget.dropped = true
                return walk(pkts, i + 1, budget, depth, flat, nesting + 1)
            }
            else -> throw Malformed("packet type ${p.tag} where a message was expected")
        }
    }

    /** A one-pass signature this app can pair with its signature. */
    private fun knownOps(p: Pkt): Boolean {
        val h = p.head(4)
        if (h.size < 4) return false
        val v = h[0].toInt() and 0xFF
        return (v == 3 || v == 6) && (h[3].toInt() and 0xFF) in SIGNATURE_ALGORITHMS
    }

    /** A signature packet of a version and public-key algorithm this app reads. */
    private fun knownSignature(p: Pkt): Boolean {
        val h = p.head(16)
        if (h.isEmpty()) return false
        val algo = when (h[0].toInt() and 0xFF) {
            3 -> h.getOrNull(15)
            4, 5, 6 -> h.getOrNull(2)
            else -> return false
        }?.toInt()?.and(0xFF) ?: return false
        return algo in SIGNATURE_ALGORITHMS
    }

    /**
     * The content of a compressed data packet [body]. The compressed stream
     * must end inside the packet (RFC 9580 5.6); octets after its end are
     * ignored. Throws [Malformed] on an unknown algorithm or a stream that
     * does not end, and when the output would exceed [budget].
     */
    private fun decompress(body: ByteArray, budget: Budget): ByteArray {
        if (body.isEmpty()) throw Malformed("empty compressed data packet")
        val algo = body[0].toInt() and 0xFF
        val out = ByteArrayOutputStream()
        fun take(n: Int) {
            budget.bytesLeft -= n
            if (budget.bytesLeft < 0) throw PGPCryptoError.ResourceLimitExceeded("decrypted message exceeds size cap")
        }
        when (algo) {
            0 -> { take(body.size - 1); out.write(body, 1, body.size - 1) }
            1, 2 -> {
                val inf = Inflater(algo == 1)
                try {
                    inf.setInput(body, 1, body.size - 1)
                    val buf = ByteArray(64 * 1024)
                    while (!inf.finished()) {
                        val n = try { inf.inflate(buf) } catch (e: DataFormatException) {
                            throw Malformed("bad compressed data")
                        }
                        if (n > 0) { take(n); out.write(buf, 0, n); continue }
                        if (inf.needsInput()) throw Malformed("compressed data extends beyond packet")
                        if (inf.needsDictionary()) throw Malformed("bad compressed data")
                    }
                } finally {
                    inf.end()
                }
            }
            3 -> {
                val input = ByteArrayInputStream(body, 1, body.size - 1)
                val bz = try { org.bouncycastle.apache.bzip2.CBZip2InputStream(input) } catch (e: Exception) {
                    throw Malformed("bad compressed data")
                }
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = try { bz.read(buf) } catch (e: Exception) { throw Malformed("bad compressed data") }
                    if (n < 0) break
                    take(n); out.write(buf, 0, n)
                }
            }
            else -> throw Malformed("unknown compression algorithm $algo")
        }
        return out.toByteArray()
    }

    /** Type of the first packet of [binary] that is not marker, padding, trust
     *  or an unknown non-critical type; -1 when there is none or it cannot be read. */
    fun firstSignificantTag(binary: ByteArray): Int = runCatching {
        packets(binary).firstOrNull { !ignorable(it.tag) }?.tag ?: -1
    }.getOrElse {
        // Unreadable further on (truncated, say): the first header still tells.
        val c = binary.firstOrNull()?.toInt()?.and(0xFF) ?: return -1
        when {
            c and 0x80 == 0 -> -1
            c and 0x40 != 0 -> c and 0x3F
            else -> (c shr 2) and 0x0F
        }
    }
}
