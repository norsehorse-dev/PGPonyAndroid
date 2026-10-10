// CompositeInlineStreamReader.kt
// PGPony Android 4.7.0 (item 23, #73): read a composite ML-DSA inline signed
// message as it streams.
//
// The streaming decrypt used to buffer the whole decrypted content of a
// composite inline message (One-Pass Signature, Literal Data, Signature) to
// hand it to CompositeSignerGate, capped at MAX_MESSAGE_PLAINTEXT_BYTES, so a
// large file signed with an ML-DSA key could be neither made nor opened. A
// composite signature is over a SHA-256 digest like any OpenPGP signature, so
// this reads the packets one at a time: the one-pass packets first, then the
// literal content written straight to the sink while every matching one-pass
// packet's v6 hash is updated, then the signature packets. The caller grades
// the result with CompositeSignerGate.verifyStreamed.
//
// Grammar, as MessageGrammar applies it to buffered content: at most one
// compressed packet around the rest, one-pass packets, exactly one literal,
// signature packets, nothing else (marker and padding packets are skipped). A
// text signature (type 0x01) is hashed over CRLF-canonicalized content, the
// byte-level twin of CompositeSigPacket.canonicalizeText.

package com.pgpony.android.crypto.pqc

import java.io.InputStream

object CompositeInlineStreamReader {

    private const val TAG_SIGNATURE = 2
    private const val TAG_OPS = 4
    private const val TAG_COMPRESSED = 8
    private const val TAG_MARKER = 10
    private const val TAG_LITERAL = 11
    private const val TAG_PADDING = 21

    /** Larger than any composite signature or one-pass packet (ML-DSA-87 included). */
    private const val MAX_SMALL_PACKET = 1 shl 20
    private const val MAX_SIGNATURE_PACKETS = 32
    private const val MAX_ONE_PASS_PACKETS = 32
    /** Every octet outside the literal content (one-pass, signature, marker
     *  and padding packets) counts against this, so a crafted compressed
     *  packet cannot spin on padding or pile up one-pass hashers. */
    private const val MAX_NON_LITERAL_BYTES = 4L shl 20

    /** The message does not have the shape of a composite inline message. */
    class Malformed(msg: String) : Exception(msg)

    /** One signature packet and, when a one-pass packet before the literal
     *  announced it, the v6 digest of the content under that packet's salt. */
    class SignedPart(val signatureBody: ByteArray, val digest: ByteArray?)

    class Result(
        val filename: String?,
        val bytesWritten: Long,
        val onePass: List<ByteArray>,
        val signatures: List<SignedPart>,
        /** Issuer fingerprint (hex uppercase) the last composite signature claims. */
        val claimedSignerFp: String?
    )

    /**
     * Read the decrypted content [input], writing the literal content through
     * [sink]. Throws [Malformed] when the packets are not a composite inline
     * message. Does not close [input].
     */
    fun read(input: InputStream, sink: (ByteArray, Int, Int) -> Unit): Result {
        var first = Header.read(input) ?: throw Malformed("empty message")
        val packets: InputStream
        var compressedBody: BodyStream? = null
        if (first.tag == TAG_COMPRESSED) {
            val body = BodyStream(input, first)
            compressedBody = body
            val algo = body.read()
            packets = when (algo) {
                0 -> body
                1 -> ZipInflaterStream(body)
                2 -> java.util.zip.InflaterInputStream(body, java.util.zip.Inflater(false), 1 shl 16)
                3 -> org.bouncycastle.apache.bzip2.CBZip2InputStream(body)
                else -> throw Malformed("unknown compression algorithm $algo")
            }
            first = Header.read(packets) ?: throw Malformed("empty compressed packet")
        } else {
            packets = input
        }

        var nonLiteral = 0L
        fun charge(n: Long) {
            nonLiteral += n
            if (nonLiteral > MAX_NON_LITERAL_BYTES) throw Malformed("too much data outside the literal")
        }
        val onePass = ArrayList<ByteArray>()
        val hashers = ArrayList<Pair<ByteArray, ContentHasher>>()
        var header: Header? = first
        // One-pass packets, until the literal.
        while (header != null && header.tag != TAG_LITERAL) {
            when (header.tag) {
                TAG_OPS -> {
                    if (onePass.size >= MAX_ONE_PASS_PACKETS) throw Malformed("too many one-pass signatures")
                    val body = BodyStream(packets, header).readAllCapped(MAX_SMALL_PACKET)
                    charge(body.size.toLong())
                    onePass.add(body)
                    hasherFor(body)?.let { hashers.add(body to it) }
                }
                TAG_MARKER, TAG_PADDING -> charge(BodyStream(packets, header).skipAll())
                else -> throw Malformed("unexpected packet ${header.tag} before the literal")
            }
            header = Header.read(packets)
        }
        if (header == null) throw Malformed("no literal data")
        if (onePass.isEmpty()) throw Malformed("no one-pass signature")

        // The literal: format, name, date, then the content.
        val lit = BodyStream(packets, header)
        lit.read().takeIf { it >= 0 } ?: throw Malformed("truncated literal")
        val nameLen = lit.read().takeIf { it >= 0 } ?: throw Malformed("truncated literal")
        val name = ByteArray(nameLen).also { lit.readFully(it) }
        lit.readFully(ByteArray(4))
        val buf = ByteArray(1 shl 16)
        var written = 0L
        while (true) {
            val n = lit.read(buf, 0, buf.size)
            if (n < 0) break
            if (n == 0) continue
            for ((_, h) in hashers) h.update(buf, 0, n)
            sink(buf, 0, n)
            written += n
        }

        // Signatures, then the end of the content.
        val sigs = ArrayList<ByteArray>()
        while (true) {
            val h = Header.read(packets) ?: break
            when (h.tag) {
                TAG_SIGNATURE -> {
                    if (sigs.size >= MAX_SIGNATURE_PACKETS) throw Malformed("too many signatures")
                    val body = BodyStream(packets, h).readAllCapped(MAX_SMALL_PACKET)
                    charge(body.size.toLong())
                    sigs.add(body)
                }
                TAG_MARKER, TAG_PADDING -> charge(BodyStream(packets, h).skipAll())
                else -> throw Malformed("unexpected packet ${h.tag} after the literal")
            }
        }
        if (sigs.isEmpty()) throw Malformed("no signature after the literal")
        if (compressedBody != null) {
            // Nothing may follow the compressed packet.
            if (compressedBody.skipAll() > MAX_NON_LITERAL_BYTES) throw Malformed("data after the compressed content")
            if (Header.read(input) != null) throw Malformed("data after the compressed packet")
        }

        val parts = sigs.map { sig ->
            val digest = runCatching {
                val parsed = CompositeSigPacket.parse(sig)
                hashers.firstOrNull { (ops, _) -> opsMatches(ops, parsed) }?.second
                    ?.finish(parsed.sigType, parsed.pubAlgo, parsed.hashed)
            }.getOrNull()
            SignedPart(sig, digest)
        }
        val claimed = sigs.lastOrNull { it.size > 2 && CompositeSignSuite.forAlgId(it[2].toInt() and 0xFF) != null }
            ?.let { s ->
                runCatching {
                    CompositeSigPacket.issuerFingerprintOf(CompositeSigPacket.parse(s))
                        ?.joinToString("") { "%02X".format(it) }
                }.getOrNull()
            }
        return Result(
            filename = com.pgpony.android.crypto.LiteralFilename.sanitize(String(name, Charsets.UTF_8)),
            bytesWritten = written,
            onePass = onePass,
            signatures = parts,
            claimedSignerFp = claimed
        )
    }

    /** True when [head] (a sniffed prefix of decrypted content) opens with a
     *  composite one-pass packet, compressed or not. */
    fun looksComposite(head: ByteArray): Boolean = runCatching {
        CompositeDocumentVerifier.isCompositeSignature(CompositeDocumentVerifier.decompress(head))
    }.getOrDefault(false)

    // ── one-pass packets ────────────────────────────────────────────

    /** A v6 one-pass packet of a composite algorithm and a supported hash: its hasher. */
    private fun hasherFor(ops: ByteArray): ContentHasher? = runCatching {
        if ((ops[0].toInt() and 0xFF) != 6) return null
        val type = ops[1].toInt() and 0xFF
        val hash = ops[2].toInt() and 0xFF
        val alg = ops[3].toInt() and 0xFF
        if (CompositeSignSuite.forAlgId(alg) == null) return null
        if (type != CompositeSigPacket.TYPE_BINARY && type != CompositeSigPacket.TYPE_TEXT) return null
        val saltLen = ops[4].toInt() and 0xFF
        val salt = ops.copyOfRange(5, 5 + saltLen)
        ContentHasher(CompositeSigHash.V6DocumentHasher(hash, salt), text = type == CompositeSigPacket.TYPE_TEXT)
    }.getOrNull()

    private fun opsMatches(ops: ByteArray, sig: CompositeSigPacket.Parsed): Boolean = runCatching {
        val saltLen = ops[4].toInt() and 0xFF
        (ops[0].toInt() and 0xFF) == 6 &&
            (ops[1].toInt() and 0xFF) == sig.sigType &&
            (ops[2].toInt() and 0xFF) == sig.hashAlgo &&
            (ops[3].toInt() and 0xFF) == sig.pubAlgo &&
            ops.copyOfRange(5, 5 + saltLen).contentEquals(sig.salt)
    }.getOrDefault(false)

    /** The v6 hash of the content; a text signature hashes CR, LF and CRLF all
     *  as CRLF. Also used by CompositeSignerGate.verifyDetachedStream. */
    internal class ContentHasher(private val inner: CompositeSigHash.V6DocumentHasher, private val text: Boolean) {
        private var pendingCr = false
        private val crlf = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte())

        fun update(buf: ByteArray, off: Int, len: Int) {
            if (!text) { inner.update(buf, off, len); return }
            var runStart = off
            for (i in off until off + len) {
                val b = buf[i]
                if (pendingCr) {
                    pendingCr = false
                    if (b == '\n'.code.toByte()) { runStart = i + 1; continue }
                }
                if (b == '\r'.code.toByte() || b == '\n'.code.toByte()) {
                    if (i > runStart) inner.update(buf, runStart, i - runStart)
                    inner.update(crlf, 0, 2)
                    pendingCr = b == '\r'.code.toByte()
                    runStart = i + 1
                }
            }
            if (off + len > runStart) inner.update(buf, runStart, off + len - runStart)
        }

        fun finish(type: Int, alg: Int, hashed: ByteArray): ByteArray = inner.finish(type, alg, hashed)
    }

    // ── packet framing ──────────────────────────────────────────────

    /** A packet header: its tag and the first length (or partial chunk). */
    private class Header(val tag: Int, val newFormat: Boolean, val length: Long, val partial: Boolean, val indeterminate: Boolean) {
        companion object {
            fun read(input: InputStream): Header? {
                val c = input.read()
                if (c < 0) return null
                if (c and 0x80 == 0) throw Malformed("not a packet header")
                if (c and 0x40 != 0) {
                    val tag = c and 0x3F
                    val (len, partial) = newLength(input)
                    if (partial && tag != TAG_LITERAL && tag != TAG_COMPRESSED) throw Malformed("partial length on packet $tag")
                    if (partial && len < 512) throw Malformed("first partial chunk under 512 octets")
                    return Header(tag, true, len, partial, false)
                }
                val tag = (c shr 2) and 0x0F
                return when (c and 0x03) {
                    0 -> Header(tag, false, u8(input).toLong(), false, false)
                    1 -> Header(tag, false, ((u8(input) shl 8) or u8(input)).toLong(), false, false)
                    2 -> Header(tag, false, be32(input), false, false)
                    else -> {
                        if (tag != TAG_LITERAL && tag != TAG_COMPRESSED) throw Malformed("indeterminate length on packet $tag")
                        Header(tag, false, -1, false, true)
                    }
                }
            }

            /** A new-format length: (length, isPartial). */
            fun newLength(input: InputStream): Pair<Long, Boolean> {
                val l0 = u8(input)
                return when {
                    l0 < 192 -> l0.toLong() to false
                    l0 < 224 -> (((l0 - 192) shl 8) + u8(input) + 192).toLong() to false
                    l0 == 255 -> be32(input) to false
                    else -> (1L shl (l0 and 0x1F)) to true
                }
            }

            private fun u8(input: InputStream): Int {
                val b = input.read()
                if (b < 0) throw Malformed("truncated packet header")
                return b
            }

            private fun be32(input: InputStream): Long {
                var v = 0L
                repeat(4) { v = (v shl 8) or u8(input).toLong() }
                return v
            }
        }
    }

    /**
     * ZIP (raw DEFLATE) with the one dummy octet at the end of input that
     * java.util.zip.Inflater needs in nowrap mode, as Bouncy Castle's
     * PGPCompressedData supplies; without it a valid stream can end in EOFException.
     */
    private class ZipInflaterStream(input: InputStream) :
        java.util.zip.InflaterInputStream(input, java.util.zip.Inflater(true), 1 shl 16) {
        private var eof = false
        override fun fill() {
            if (eof) throw java.io.EOFException("Unexpected end of ZIP input stream")
            len = `in`.read(buf, 0, buf.size)
            if (len == -1) {
                buf[0] = 0
                len = 1
                eof = true
            }
            inf.setInput(buf, 0, len)
        }
    }

    /** A packet body, partial chunks included, as a stream. */
    private class BodyStream(private val input: InputStream, header: Header) : InputStream() {
        private var remaining = header.length
        private var partial = header.partial
        private val indeterminate = header.indeterminate
        private var done = false

        private fun nextChunk(): Boolean {
            while (remaining == 0L) {
                if (indeterminate || !partial) { done = true; return false }
                val (len, more) = Header.newLength(input)
                remaining = len
                partial = more
            }
            return true
        }

        override fun read(): Int {
            if (done) return -1
            if (!indeterminate && !nextChunk()) return -1
            val b = input.read()
            if (b < 0) {
                if (indeterminate) { done = true; return -1 }
                throw Malformed("truncated packet")
            }
            if (!indeterminate) remaining--
            return b
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            if (done) return -1
            if (indeterminate) {
                val n = input.read(b, off, len)
                if (n < 0) done = true
                return n
            }
            if (!nextChunk()) return -1
            val want = minOf(len.toLong(), remaining).toInt()
            val n = input.read(b, off, want)
            if (n < 0) throw Malformed("truncated packet")
            remaining -= n
            return n
        }

        fun readFully(out: ByteArray) {
            var got = 0
            while (got < out.size) {
                val n = read(out, got, out.size - got)
                if (n < 0) throw Malformed("truncated packet")
                got += n
            }
        }

        fun readAllCapped(cap: Int): ByteArray {
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (true) {
                val n = read(buf, 0, buf.size)
                if (n < 0) break
                out.write(buf, 0, n)
                if (out.size() > cap) throw Malformed("packet too large")
            }
            return out.toByteArray()
        }

        /** Skip to the end of the body, at most [MAX_NON_LITERAL_BYTES] + 1
         *  octets; returns how many were skipped. */
        fun skipAll(): Long {
            val buf = ByteArray(8192)
            var total = 0L
            while (total <= MAX_NON_LITERAL_BYTES) {
                val n = read(buf, 0, buf.size)
                if (n < 0) break
                total += n
            }
            return total
        }
    }
}
