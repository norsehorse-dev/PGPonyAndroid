package com.pgpony.android.qr.v2

import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator

/**
 * Structural public-certificate validation, never signature authentication or sanitization.
 * BC 1.85 cannot read RFC 9980 composite signatures or v4 ML-KEM subkeys supported by
 * this app, and treats LibrePGP v5 algorithm-8 material as opaque. Those known packet
 * shapes receive bounded structural checks; all other
 * packets go through BC. No parsed representation is ever used to rewrite the input.
 */
internal object PublicCertificate {
    fun validate(bytes: ByteArray) {
        require(bytes.size in 1..EnhancedQrEncoder.MAX_CERTIFICATE_BYTES) { "Public certificate length out of bounds" }
        try {
            var offset = 0
            var primaryCount = 0
            var composite = false
            while (offset < bytes.size) {
                val packet = packet(bytes, offset)
                require(packet.tag in setOf(2, 6, 10, 12, 13, 14, 17, 21)) { "Non-public-certificate packet" }
                if (offset == 0) require(packet.tag == 6) { "A public certificate must start with a primary public key" }
                if (packet.tag == 6) primaryCount++
                require(primaryCount == 1) { "Exactly one primary public key is required" }
                val body = bytes.copyOfRange(packet.bodyStart, packet.end)
                if (knownComposite(packet.tag, body)) {
                    composite = true
                } else {
                    BCPGInputStream(bytes.copyOfRange(offset, packet.end).inputStream()).use {
                        require(it.readPacket() != null && it.nextPacketTag() == -1) { "Invalid certificate packet" }
                    }
                }
                offset = packet.end
            }
            // Full BC ring parsing also checks the ordinary certificate packet arrangement.
            // Composite rings are checked by the existing import pipeline after transport.
            if (!composite) PGPPublicKeyRing(bytes, BcKeyFingerprintCalculator())
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid public certificate", e)
        }
    }

    private data class Packet(val tag: Int, val bodyStart: Int, val end: Int)

    /** Definite packet lengths only; no allocations depend on unvalidated claimed lengths. */
    private fun packet(bytes: ByteArray, offset: Int): Packet {
        var cursor = offset
        fun octet(): Int {
            require(cursor < bytes.size) { "Truncated packet header" }
            return bytes[cursor++].toInt() and 255
        }
        fun uint32(): Long {
            var value = 0L
            repeat(4) { value = (value shl 8) or octet().toLong() }
            return value
        }
        val first = octet()
        require(first and 128 != 0) { "Invalid packet header" }
        val tag: Int
        val length: Long
        if (first and 64 != 0) {
            tag = first and 63
            val initial = octet()
            length = when {
                initial < 192 -> initial.toLong()
                initial < 224 -> ((initial - 192) * 256 + octet() + 192).toLong()
                initial == 255 -> uint32()
                else -> throw IllegalArgumentException("Partial certificate packet lengths are unsupported")
            }
        } else {
            tag = (first shr 2) and 15
            length = when (first and 3) {
                0 -> octet().toLong()
                1 -> (octet() * 256 + octet()).toLong()
                2 -> uint32()
                else -> throw IllegalArgumentException("Indeterminate certificate packet lengths are unsupported")
            }
        }
        require(length <= bytes.size - cursor) { "Truncated certificate packet" }
        return Packet(tag, cursor, cursor + length.toInt())
    }

    /** Known opaque composite forms are length checked without claiming signature validity. */
    private fun knownComposite(tag: Int, body: ByteArray): Boolean {
        fun octet(i: Int): Int {
            require(i in body.indices) { "Truncated composite packet" }
            return body[i].toInt() and 255
        }
        fun length(i: Int): Int {
            var value = 0L
            repeat(4) { value = (value shl 8) or octet(i + it).toLong() }
            require(value <= body.size) { "Composite length out of bounds" }
            return value.toInt()
        }
        if (tag == 6 || tag == 14) {
            val algorithm = octet(5)
            if (algorithm == 8) {
                require(octet(0) == 5) { "LibrePGP composite keys require version 5" }
                validateLibrePgp(body)
                return true
            }
            val materialLength = when (algorithm) { 30 -> 1984; 31 -> 2649; 35 -> 1216; 36 -> 1624; else -> return false }
            when (octet(0)) {
                6 -> require(length(6) == materialLength && body.size == 10 + materialLength)
                4 -> require(algorithm == 35 && body.size == 6 + materialLength)
                else -> throw IllegalArgumentException("Unsupported composite public key version")
            }
            return true
        }
        if (tag == 2) {
            val algorithm = if (octet(0) == 6) octet(2) else return false
            val signatureLength = when (algorithm) { 30 -> 3373; 31 -> 4741; else -> return false }
            val hashedEnd = 8 + length(4)
            val unhashedEnd = hashedEnd + 4 + length(hashedEnd)
            val saltOffset = unhashedEnd + 2
            val saltLength = octet(saltOffset)
            val expectedSalt = when (octet(3)) { 8, 12 -> 16; 9 -> 24; 10, 14 -> 32; 11 -> 28; else -> 0 }
            require(expectedSalt != 0 && saltLength == expectedSalt)
            require(body.size == saltOffset + 1 + saltLength + signatureLength)
            return true
        }
        return false
    }

    /**
     * LibrePGP v5 algorithm 8 shares one code point for four suites. The curve OID
     * fixes point and Kyber widths. Accept minimal native-point MPIs and the app's
     * historical 0x40-prefixed form without normalizing or rewriting either form.
     */
    private fun validateLibrePgp(body: ByteArray) {
        var cursor = 6
        fun octet(): Int {
            require(cursor < body.size) { "Truncated LibrePGP composite material" }
            return body[cursor++].toInt() and 255
        }
        fun length(): Int {
            var value = 0L
            repeat(4) { value = (value shl 8) or octet().toLong() }
            require(value <= body.size) { "LibrePGP length out of bounds" }
            return value.toInt()
        }
        require(length() == body.size - 10) { "LibrePGP material length mismatch" }
        val oidLength = octet()
        require(oidLength in 1..9 && oidLength <= body.size - cursor)
        val oid = body.copyOfRange(cursor, cursor + oidLength)
            .joinToString("") { "%02X".format(java.util.Locale.ROOT, it.toInt() and 255) }
        cursor += oidLength
        val suite = when (oid) {
            "2B656E" -> Triple(32, 1184, true) // X25519 + ML-KEM-768.
            "2B656F" -> Triple(56, 1568, true) // X448 + ML-KEM-1024.
            "2B2403030208010107" -> Triple(65, 1184, false) // brainpoolP256r1.
            "2B240303020801010B" -> Triple(97, 1568, false) // brainpoolP384r1.
            else -> throw IllegalArgumentException("Unknown LibrePGP composite curve OID")
        }
        val bits = octet() * 256 + octet()
        val pointLength = (bits + 7) / 8
        val (pointWidth, kyberWidth, native) = suite
        require(pointLength in 1..(pointWidth + if (native) 1 else 0))
        require(pointLength + 4 <= body.size - cursor)
        val first = body[cursor].toInt() and 255
        require(first != 0 && bits == (pointLength - 1) * 8 + 32 - Integer.numberOfLeadingZeros(first)) {
            "Noncanonical LibrePGP point MPI"
        }
        if (native) {
            require(pointLength <= pointWidth || first == 0x40) { "Invalid legacy native point prefix" }
        } else {
            require(pointLength == pointWidth && first == 4) { "Uncompressed brainpool point required" }
        }
        cursor += pointLength
        require(length() == kyberWidth && body.size - cursor == kyberWidth) { "LibrePGP Kyber length mismatch" }
    }

}
