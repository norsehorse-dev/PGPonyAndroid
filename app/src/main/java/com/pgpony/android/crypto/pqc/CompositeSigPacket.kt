// CompositeSigPacket.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Shared building blocks for composite DOCUMENT signatures (detached,
// cleartext, and inline one-pass), used by CompositeDocumentSigner and
// CompositeDocumentVerifier. BouncyCastle throws "unknown signature key
// algorithm: 30" on any top-level composite signature, so the whole document
// sign/verify path is hand-built around CompositeSigner / CompositeSigVerifier
// and never hands an algo-30 signature to BouncyCastle.
//
// This object owns the v6 signature packet body (build + parse), the text
// canonicalizations (RFC 9580 Section 5.2.4 for text signatures; Section 7 for
// the cleartext framework), and a minimal ASCII armor with the RFC 4880
// CRC-24, so the signer and verifier share exactly one framing implementation.

package com.pgpony.android.crypto.pqc

import java.io.ByteArrayOutputStream
import java.security.SecureRandom

object CompositeSigPacket {

    const val TYPE_BINARY = 0x00
    const val TYPE_TEXT = 0x01
    const val HASH_SHA256 = 8
    const val SALT_SHA256 = 16

    private const val TAG_SIGNATURE = 2
    private const val SUBPKT_CREATION_TIME = 2
    private const val SUBPKT_ISSUER_FP = 33

    /** A parsed v6 signature packet body. */
    data class Parsed(
        val sigType: Int,
        val pubAlgo: Int,
        val hashAlgo: Int,
        val hashed: ByteArray,
        val salt: ByteArray,
        val signature: ByteArray
    )

    /**
     * Build a full composite document signature PACKET (tag 2). [documentData]
     * is the exact octets to hash as the document (already canonicalized by the
     * caller). [signerFingerprint] is the v6 fingerprint of the signing key,
     * written as an Issuer Fingerprint subpacket.
     */
    fun buildDocumentSignature(
        suite: CompositeSignSuite,
        compositeSecret: ByteArray,
        sigType: Int,
        documentData: ByteArray,
        signerFingerprint: ByteArray,
        creationTimeSeconds: Int,
        random: SecureRandom = SecureRandom()
    ): ByteArray {
        val hashed = ByteArrayOutputStream().apply {
            write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32(creationTimeSeconds)))
            write(issuerFingerprintSubpacket(signerFingerprint))
        }.toByteArray()
        val salt = ByteArray(SALT_SHA256).also { random.nextBytes(it) }
        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = HASH_SHA256,
            salt = salt,
            data = documentData,
            signatureType = sigType,
            publicKeyAlgorithm = suite.algId,
            hashedSubpacketBody = hashed
        )
        val signature = CompositeSigner.sign(suite, compositeSecret, digest, random)
        val body = ByteArrayOutputStream().apply {
            write(6)
            write(sigType)
            write(suite.algId)
            write(HASH_SHA256)
            write(uint32(hashed.size))
            write(hashed)
            write(uint32(0)) // no unhashed subpackets
            write(digest[0].toInt() and 0xFF)
            write(digest[1].toInt() and 0xFF)
            write(salt.size)
            write(salt)
            write(signature)
        }.toByteArray()
        return packet(TAG_SIGNATURE, body)
    }

    /** Verify a parsed composite document signature over [documentData]. */
    fun verifyDocumentSignature(
        suite: CompositeSignSuite,
        compositePublic: ByteArray,
        parsed: Parsed,
        documentData: ByteArray
    ): Boolean {
        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = parsed.hashAlgo,
            salt = parsed.salt,
            data = documentData,
            signatureType = parsed.sigType,
            publicKeyAlgorithm = parsed.pubAlgo,
            hashedSubpacketBody = parsed.hashed
        )
        return CompositeSigVerifier.verify(suite, compositePublic, parsed.signature, digest)
    }

    /** Parse a v6 signature packet body (no packet header). */
    fun parse(body: ByteArray): Parsed {
        var q = 1 // version
        val sigType = body[q++].toInt() and 0xFF
        val pubAlgo = body[q++].toInt() and 0xFF
        val hashAlgo = body[q++].toInt() and 0xFF
        val hLen = beInt(body, q); q += 4
        val hashed = body.copyOfRange(q, q + hLen); q += hLen
        val uLen = beInt(body, q); q += 4; q += uLen
        q += 2 // left 16 bits
        val saltSize = body[q++].toInt() and 0xFF
        val salt = body.copyOfRange(q, q + saltSize); q += saltSize
        return Parsed(sigType, pubAlgo, hashAlgo, hashed, salt, body.copyOfRange(q, body.size))
    }

    /** The signer fingerprint from a parsed signature's Issuer Fingerprint subpacket, if present. */
    fun issuerFingerprintOf(parsed: Parsed): ByteArray? {
        var i = 0
        val h = parsed.hashed
        while (i < h.size) {
            val l0 = h[i++].toInt() and 0xFF
            val len = when {
                l0 < 192 -> l0
                l0 < 255 -> ((l0 - 192) shl 8) + (h[i++].toInt() and 0xFF) + 192
                else -> beInt(h, i).also { i += 4 }
            }
            val type = h[i].toInt() and 0x7F
            if (type == SUBPKT_ISSUER_FP) {
                // body: version octet + fingerprint
                return h.copyOfRange(i + 2, i + len)
            }
            i += len
        }
        return null
    }

    // -- text canonicalization ---------------------------------------

    /** RFC 9580 Section 5.2.4 text signature: line endings to CRLF, UTF-8. */
    fun canonicalizeText(text: String): ByteArray {
        val sb = StringBuilder()
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when (c) {
                '\r' -> {
                    sb.append("\r\n")
                    if (i + 1 < text.length && text[i + 1] == '\n') i++
                }
                '\n' -> sb.append("\r\n")
                else -> sb.append(c)
            }
            i++
        }
        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * RFC 9580 Section 7 cleartext canonicalization: strip trailing spaces and
     * tabs from each line, join with CRLF, and exclude the final line ending.
     */
    fun canonicalizeCleartext(text: String): ByteArray {
        val lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        // A trailing newline yields a final empty element that is not signed.
        val effective = if (lines.isNotEmpty() && lines.last().isEmpty()) lines.dropLast(1) else lines
        val trimmed = effective.map { it.trimEnd(' ', '\t') }
        return trimmed.joinToString("\r\n").toByteArray(Charsets.UTF_8)
    }

    // -- framing helpers ---------------------------------------------

    fun packet(tag: Int, body: ByteArray): ByteArray {
        val hdr = when {
            body.size < 192 -> byteArrayOf((0xC0 or tag).toByte(), body.size.toByte())
            body.size < 8384 -> {
                val l = body.size - 192
                byteArrayOf((0xC0 or tag).toByte(), (0xC0 or (l shr 8)).toByte(), (l and 0xFF).toByte())
            }
            else -> byteArrayOf((0xC0 or tag).toByte(), 0xFF.toByte()) + uint32(body.size)
        }
        return hdr + body
    }

    fun uint32(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    fun beInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    private fun subpacket(type: Int, body: ByteArray): ByteArray {
        val len = body.size + 1
        val header = when {
            len < 192 -> byteArrayOf(len.toByte())
            len < 8384 -> {
                val l = len - 192
                byteArrayOf((0xC0 or (l shr 8)).toByte(), (l and 0xFF).toByte())
            }
            else -> byteArrayOf(0xFF.toByte()) + uint32(len)
        }
        return header + byteArrayOf(type.toByte()) + body
    }

    private fun issuerFingerprintSubpacket(fingerprint: ByteArray): ByteArray =
        subpacket(SUBPKT_ISSUER_FP, byteArrayOf(6) + fingerprint)

    /**
     * Read the body of the first packet in [raw], returning (tag, body). Handles
     * both new- and old-format headers.
     */
    fun firstPacket(raw: ByteArray): Pair<Int, ByteArray> {
        var i = 0
        val c = raw[i++].toInt() and 0xFF
        val tag: Int
        val len: Int
        if (c and 0x40 != 0) {
            tag = c and 0x3F
            val l0 = raw[i++].toInt() and 0xFF
            len = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (raw[i++].toInt() and 0xFF) + 192
                l0 == 255 -> beInt(raw, i).also { i += 4 }
                else -> throw IllegalStateException("partial length unsupported")
            }
        } else {
            tag = (c shr 2) and 0x0F
            len = when (c and 0x03) {
                0 -> raw[i++].toInt() and 0xFF
                1 -> (((raw[i].toInt() and 0xFF) shl 8) or (raw[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> beInt(raw, i).also { i += 4 }
                else -> throw IllegalStateException("indeterminate length unsupported")
            }
        }
        return tag to raw.copyOfRange(i, i + len)
    }

    // -- ASCII armor (RFC 4880 Section 6) -----------------------------

    fun armor(headerLine: String, tailLine: String, data: ByteArray): String {
        val b64 = java.util.Base64.getEncoder().encodeToString(data)
        val wrapped = b64.chunked(64).joinToString("\n")
        val crc = crc24(data)
        val crcBytes = byteArrayOf((crc ushr 16).toByte(), (crc ushr 8).toByte(), crc.toByte())
        val crcB64 = java.util.Base64.getEncoder().encodeToString(crcBytes)
        return buildString {
            append(headerLine).append('\n').append('\n')
            append(wrapped).append('\n')
            append('=').append(crcB64).append('\n')
            append(tailLine).append('\n')
        }
    }

    /** Decode the payload of a single ASCII-armored block (ignores the CRC). */
    fun dearmor(armored: String): ByteArray {
        val lines = armored.replace("\r\n", "\n").split("\n")
        val out = StringBuilder()
        var started = false
        for (raw in lines) {
            val line = raw.trim()
            if (!started) {
                if (line.startsWith("-----BEGIN")) started = true
                continue
            }
            if (line.startsWith("-----END")) break
            if (line.startsWith("=")) break // CRC line
            if (line.isEmpty()) continue // armor header separator or blank
            if (line.contains(":")) continue // armor header (e.g. Hash:)
            out.append(line)
        }
        return java.util.Base64.getDecoder().decode(out.toString())
    }

    private fun crc24(data: ByteArray): Int {
        var crc = 0xB704CE
        for (b in data) {
            crc = crc xor ((b.toInt() and 0xFF) shl 16)
            for (j in 0 until 8) {
                crc = crc shl 1
                if (crc and 0x1000000 != 0) crc = crc xor 0x1864CFB
            }
        }
        return crc and 0xFFFFFF
    }
}
