// CompositeDocumentVerifier.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Verify composite ML-DSA + EdDSA document signatures in all three OpenPGP
// forms (detached, cleartext, inline one-pass). BouncyCastle throws on any
// algo-30 signature packet, so VerifyService must detect composite signatures
// with [isCompositeSignature] BEFORE handing bytes to BouncyCastle and route
// them here instead. This covers composite signatures made by a composite
// primary AND by a composite signing subkey; both are algo-30 packets.

package com.pgpony.android.crypto.pqc

object CompositeDocumentVerifier {

    private const val TAG_ONE_PASS = 4
    private const val TAG_LITERAL = 11
    private const val TAG_SIGNATURE = 2

    data class Result(
        val valid: Boolean,
        val content: ByteArray? = null,
        val signerFingerprint: ByteArray? = null
    )

    /** True if the first signature or one-pass packet in [raw] is composite (algo 30/31). */
    fun isCompositeSignature(raw: ByteArray): Boolean {
        for (pkt in walk(raw)) {
            when (pkt.tag) {
                TAG_SIGNATURE -> return CompositeSignSuite.forAlgId(pkt.body[2].toInt() and 0xFF) != null
                TAG_ONE_PASS -> return CompositeSignSuite.forAlgId(pkt.body[3].toInt() and 0xFF) != null
            }
        }
        return false
    }

    /** Verify a detached (binary) composite signature over [data]. */
    fun verifyDetached(compositePublic: ByteArray, sigPacket: ByteArray, data: ByteArray): Result {
        val (_, body) = CompositeSigPacket.firstPacket(sigPacket)
        return verifyParsed(compositePublic, CompositeSigPacket.parse(body), data)
    }

    /** Verify a detached composite signature supplied as ASCII armor. */
    fun verifyDetachedArmored(compositePublic: ByteArray, armoredSig: String, data: ByteArray): Result =
        verifyDetached(compositePublic, CompositeSigPacket.dearmor(armoredSig), data)

    /**
     * If [message] begins with a Compressed Data packet (tag 8), decompress it
     * to the inner packet stream; otherwise return it unchanged. sequoia and
     * GnuPG compress inline signed messages by default (ZIP/ZLIB).
     */
    fun decompress(message: ByteArray): ByteArray {
        val compressed = walk(message).firstOrNull { it.tag == 8 } ?: return message
        if (compressed.body.isEmpty()) return message
        val algo = compressed.body[0].toInt() and 0xFF
        val data = compressed.body.copyOfRange(1, compressed.body.size)
        return when (algo) {
            0 -> data
            1 -> inflate(data, nowrap = true)   // ZIP (raw DEFLATE)
            2 -> inflate(data, nowrap = false)  // ZLIB
            else -> message                     // BZip2/unknown: leave as-is
        }
    }

    private fun inflate(data: ByteArray, nowrap: Boolean): ByteArray {
        val inflater = java.util.zip.Inflater(nowrap)
        inflater.setInput(data)
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        try {
            while (!inflater.finished()) {
                val n = inflater.inflate(buf)
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) break
                out.write(buf, 0, n)
            }
        } catch (_: Exception) {
        } finally {
            inflater.end()
        }
        return out.toByteArray()
    }

    /** True if [message] is an inline one-pass message carrying a composite signature. */
    fun isCompositeInline(message: ByteArray): Boolean {
        val packets = walk(decompress(message))
        val hasLiteral = packets.any { it.tag == TAG_LITERAL }
        val hasComposite = packets.any {
            it.tag == TAG_SIGNATURE && it.body.size > 2 &&
                CompositeSignSuite.forAlgId(it.body[2].toInt() and 0xFF) != null
        }
        return hasLiteral && hasComposite
    }

    /** The literal content of an inline message, without verifying. */
    fun inlineContent(message: ByteArray): ByteArray? {
        val literal = walk(decompress(message)).firstOrNull { it.tag == TAG_LITERAL } ?: return null
        return literalData(literal.body)
    }

    /** The claimed signer fingerprint (uppercase hex) of an inline message. */
    fun claimedSignerOfInline(message: ByteArray): String? = try {
        val sig = walk(decompress(message)).lastOrNull { it.tag == TAG_SIGNATURE } ?: return null
        CompositeSigPacket.issuerFingerprintOf(CompositeSigPacket.parse(sig.body))
            ?.joinToString("") { "%02X".format(it) }
    } catch (_: Exception) {
        null
    }

    /** Verify an inline one-pass composite message, returning the literal content. */
    fun verifyInline(compositePublic: ByteArray, message: ByteArray): Result {
        val packets = walk(decompress(message))
        val literal = packets.firstOrNull { it.tag == TAG_LITERAL }
            ?: return Result(false)
        val sig = packets.lastOrNull { it.tag == TAG_SIGNATURE }
            ?: return Result(false)
        val data = literalData(literal.body)
        val parsed = CompositeSigPacket.parse(sig.body)
        return verifyParsed(compositePublic, parsed, data).copy(content = data)
    }

    /** Verify a cleartext signed message, returning the recovered text bytes. */
    fun verifyCleartext(compositePublic: ByteArray, message: String): Result {
        val normalized = message.replace("\r\n", "\n").replace("\r", "\n")
        val lines = normalized.split("\n")

        val beginIdx = lines.indexOfFirst { it.trim() == "-----BEGIN PGP SIGNED MESSAGE-----" }
        if (beginIdx < 0) return Result(false)
        // Skip armor headers up to the first blank line.
        var i = beginIdx + 1
        while (i < lines.size && lines[i].isNotEmpty()) i++
        i++ // the blank line itself is not part of the text
        val textLines = ArrayList<String>()
        while (i < lines.size && lines[i].trim() != "-----BEGIN PGP SIGNATURE-----") {
            textLines.add(lines[i]); i++
        }
        if (i >= lines.size) return Result(false)
        val sigBlock = lines.subList(i, lines.size).joinToString("\n")

        // Reverse dash-escaping, then canonicalize the same way the signer did.
        val recovered = textLines.joinToString("\n") { line ->
            if (line.startsWith("- ")) line.substring(2) else line
        }
        val documentData = CompositeSigPacket.canonicalizeCleartext(recovered)
        val sigPacket = CompositeSigPacket.dearmor(sigBlock)
        val (_, body) = CompositeSigPacket.firstPacket(sigPacket)
        val parsed = CompositeSigPacket.parse(body)
        return verifyParsed(compositePublic, parsed, documentData)
            .copy(content = recovered.toByteArray(Charsets.UTF_8))
    }

    /** True if the signature block of a cleartext message is composite (algo 30/31). */
    fun isCompositeCleartext(message: String): Boolean {
        val sig = extractCleartextSignature(message) ?: return false
        return try {
            isCompositeSignature(CompositeSigPacket.dearmor(sig))
        } catch (_: Exception) {
            false
        }
    }

    /** The claimed signer fingerprint (uppercase hex) of a cleartext composite message. */
    fun claimedSignerOfCleartext(message: String): String? {
        val sig = extractCleartextSignature(message) ?: return null
        return try {
            val (_, body) = CompositeSigPacket.firstPacket(CompositeSigPacket.dearmor(sig))
            CompositeSigPacket.issuerFingerprintOf(CompositeSigPacket.parse(body))
                ?.joinToString("") { "%02X".format(it) }
        } catch (_: Exception) {
            null
        }
    }

    /** The recovered cleartext body (dash-unescaped), without verifying. */
    fun cleartextContent(message: String): String? {
        val normalized = message.replace("\r\n", "\n").replace("\r", "\n")
        val lines = normalized.split("\n")
        val beginIdx = lines.indexOfFirst { it.trim() == "-----BEGIN PGP SIGNED MESSAGE-----" }
        if (beginIdx < 0) return null
        var i = beginIdx + 1
        while (i < lines.size && lines[i].isNotEmpty()) i++
        i++
        val textLines = ArrayList<String>()
        while (i < lines.size && lines[i].trim() != "-----BEGIN PGP SIGNATURE-----") {
            textLines.add(lines[i]); i++
        }
        return textLines.joinToString("\n") { if (it.startsWith("- ")) it.substring(2) else it }
    }

    private fun extractCleartextSignature(message: String): String? {
        val i = message.indexOf("-----BEGIN PGP SIGNATURE-----")
        return if (i < 0) null else message.substring(i)
    }

    /** Normalize a detached signature (armored or binary) to raw packet bytes. */
    fun rawSignaturePacket(sig: ByteArray): ByteArray {
        val asText = try { String(sig, Charsets.US_ASCII) } catch (_: Exception) { "" }
        return if (asText.contains("-----BEGIN PGP SIGNATURE-----")) {
            CompositeSigPacket.dearmor(asText)
        } else {
            sig
        }
    }

    /** The claimed signer fingerprint (uppercase hex) of a detached composite signature. */
    fun claimedSignerOfDetached(sig: ByteArray): String? = try {
        val (_, body) = CompositeSigPacket.firstPacket(rawSignaturePacket(sig))
        CompositeSigPacket.issuerFingerprintOf(CompositeSigPacket.parse(body))
            ?.joinToString("") { "%02X".format(it) }
    } catch (_: Exception) {
        null
    }

    private fun verifyParsed(
        compositePublic: ByteArray,
        parsed: CompositeSigPacket.Parsed,
        rawData: ByteArray
    ): Result {
        val suite = CompositeSignSuite.forAlgId(parsed.pubAlgo) ?: return Result(false)
        // A text signature hashes the CRLF-canonicalized document.
        val data = if (parsed.sigType == CompositeSigPacket.TYPE_TEXT) {
            CompositeSigPacket.canonicalizeText(String(rawData, Charsets.UTF_8))
        } else {
            rawData
        }
        val ok = CompositeSigPacket.verifyDocumentSignature(suite, compositePublic, parsed, data)
        return Result(ok, signerFingerprint = CompositeSigPacket.issuerFingerprintOf(parsed))
    }

    /** Literal Data packet body -> the raw literal content. */
    private fun literalData(body: ByteArray): ByteArray {
        var q = 1 // format octet
        val nameLen = body[q++].toInt() and 0xFF
        q += nameLen
        q += 4 // date
        return body.copyOfRange(q, body.size)
    }

    private data class Pkt(val tag: Int, val body: ByteArray)

    private fun walk(raw: ByteArray): List<Pkt> {
        val out = ArrayList<Pkt>()
        var i = 0
        while (i < raw.size) {
            val c = raw[i++].toInt() and 0xFF
            if (c and 0x80 == 0) break
            if (c and 0x40 != 0) {
                // New-format header, possibly with partial (streamed) body lengths.
                val tag = c and 0x3F
                val body = java.io.ByteArrayOutputStream()
                var more = true
                var ok = true
                while (more) {
                    if (i >= raw.size) { ok = false; break }
                    val l0 = raw[i++].toInt() and 0xFF
                    val len: Int
                    when {
                        l0 < 192 -> { len = l0; more = false }
                        l0 < 224 -> { len = ((l0 - 192) shl 8) + (raw[i++].toInt() and 0xFF) + 192; more = false }
                        l0 == 255 -> { len = CompositeSigPacket.beInt(raw, i); i += 4; more = false }
                        else -> { len = 1 shl (l0 and 0x1F); more = true } // partial chunk
                    }
                    if (i + len > raw.size) { ok = false; break }
                    body.write(raw, i, len); i += len
                }
                if (!ok) break
                out.add(Pkt(tag, body.toByteArray()))
            } else {
                // Old-format header.
                val tag = (c shr 2) and 0x0F
                val lt = c and 0x03
                if (lt == 3) { // indeterminate length: to end of stream
                    out.add(Pkt(tag, raw.copyOfRange(i, raw.size))); break
                }
                val len = when (lt) {
                    0 -> raw[i++].toInt() and 0xFF
                    1 -> (((raw[i].toInt() and 0xFF) shl 8) or (raw[i + 1].toInt() and 0xFF)).also { i += 2 }
                    else -> CompositeSigPacket.beInt(raw, i).also { i += 4 }
                }
                if (i + len > raw.size) break
                out.add(Pkt(tag, raw.copyOfRange(i, i + len)))
                i += len
            }
        }
        return out
    }
}
