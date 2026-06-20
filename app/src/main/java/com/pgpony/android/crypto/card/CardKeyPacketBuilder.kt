// Phase B1 — byte-exact OpenPGP packet construction for on-card key generation.
//
// This is a faithful port of the iOS Ed25519KeyGenerator packet builders
// (Services/Ed25519KeyGenerator.swift), which are verified against gpg and
// Sequoia: keys assembled this way import with valid certification + binding
// signatures and fingerprints that match gpg byte-for-byte. The byte layout is
// intentionally identical to the Swift so the Android-generated fingerprint
// equals what gpg computes — porting verbatim avoids re-deriving the encoding
// (OID bytes, the 0x40 point prefix, the cv25519 KDF params, MPI bit-lengths)
// from the RFC and risking a one-byte fingerprint divergence.
//
// All functions are pure (no card I/O). The card-signed certification/binding
// signatures are assembled here from the card's 64-byte r||s via
// assembleEdDSASignaturePacket; the orchestration lives in CardKeygenService.

package com.pgpony.android.crypto.card

import com.pgpony.android.crypto.util.V4Fingerprint

object CardKeyPacketBuilder {

    // Ed25519 curve OID 1.3.6.1.4.1.11591.15.1
    val ED25519_OID = byteArrayOf(0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA.toByte(), 0x47, 0x0F, 0x01)
    // Cv25519 curve OID 1.3.6.1.4.1.3029.1.5.1
    val CV25519_OID = byteArrayOf(0x2B, 0x06, 0x01, 0x04, 0x01, 0x97.toByte(), 0x55, 0x01, 0x05, 0x01)

    const val EDDSA_ALGO = 22   // EdDSA
    const val ECDH_ALGO = 18    // ECDH
    const val HASH_SHA256 = 8

    // ── byte helpers ───────────────────────────────────────────────────

    private fun u16be(v: Int): ByteArray =
        byteArrayOf(((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun u32be(v: Long): ByteArray = byteArrayOf(
        ((v shr 24) and 0xFF).toByte(),
        ((v shr 16) and 0xFF).toByte(),
        ((v shr 8) and 0xFF).toByte(),
        (v and 0xFF).toByte()
    )

    /** Leading zero BITS across the array (port of iOS countLeadingZeroBits). */
    private fun countLeadingZeroBits(bytes: ByteArray): Int {
        for (i in bytes.indices) {
            val b = bytes[i].toInt() and 0xFF
            if (b != 0) return i * 8 + (Integer.numberOfLeadingZeros(b) - 24)
        }
        return bytes.size * 8
    }

    /** OpenPGP MPI: 2-byte big-endian bit length, then the (minimal) bytes. */
    private fun mpi(bytes: ByteArray): ByteArray {
        val bits = bytes.size * 8 - countLeadingZeroBits(bytes)
        return u16be(bits) + bytes
    }

    // ── public-key packet bodies (tag 6 / 14) ──────────────────────────

    /**
     * EdDSA (Ed25519) public-key packet body. [publicKey] is the raw 32-byte
     * point (the card's leading 0x40 native-format prefix already stripped).
     */
    fun buildEdDSAPublicKeyBody(creationTime: Long, publicKey: ByteArray): ByteArray {
        val q = byteArrayOf(0x40) + publicKey          // 0x40 prefix + 32 bytes
        return byteArrayOf(4) + u32be(creationTime) + byteArrayOf(EDDSA_ALGO.toByte()) +
            byteArrayOf(ED25519_OID.size.toByte()) + ED25519_OID + mpi(q)
    }

    /**
     * ECDH (Cv25519) public-key packet body. [publicKey] is the raw 32-byte
     * point. Appends the KDF parameter block (len 3, reserved 1, SHA-256 8,
     * AES-128 7) — these bytes are part of the body, so they feed the subkey
     * fingerprint.
     */
    fun buildECDHPublicKeyBody(creationTime: Long, publicKey: ByteArray): ByteArray {
        val q = byteArrayOf(0x40) + publicKey
        return byteArrayOf(4) + u32be(creationTime) + byteArrayOf(ECDH_ALGO.toByte()) +
            byteArrayOf(CV25519_OID.size.toByte()) + CV25519_OID + mpi(q) +
            byteArrayOf(3, 0x01, HASH_SHA256.toByte(), 7)
    }

    /** v4 fingerprint of a tag-6/14 body: SHA-1(0x99 || 2-byte len || body). */
    fun fingerprint(keyBody: ByteArray): ByteArray = V4Fingerprint.compute(keyBody)

    /** Long key ID = last 8 bytes of the fingerprint. */
    fun keyId(fingerprint: ByteArray): ByteArray = fingerprint.copyOfRange(fingerprint.size - 8, fingerprint.size)

    // ── subpackets / packets ───────────────────────────────────────────

    /** Signature subpacket: length(of type+data) || type || data. */
    fun buildSubpacket(type: Int, data: ByteArray): ByteArray {
        val total = data.size + 1
        val len = when {
            total < 192 -> byteArrayOf(total.toByte())
            total < 16576 -> {
                val a = total - 192
                byteArrayOf((((a shr 8) + 192) and 0xFF).toByte(), (a and 0xFF).toByte())
            }
            else -> byteArrayOf(
                0xFF.toByte(),
                ((total shr 24) and 0xFF).toByte(), ((total shr 16) and 0xFF).toByte(),
                ((total shr 8) and 0xFF).toByte(), (total and 0xFF).toByte()
            )
        }
        return len + byteArrayOf(type.toByte()) + data
    }

    /** New-format packet: CTB (0xC0|tag) || length || body (RFC 4880 §4.2.2). */
    fun buildPacket(tag: Int, body: ByteArray): ByteArray {
        val len = body.size
        val lenBytes = when {
            len < 192 -> byteArrayOf(len.toByte())
            len < 8384 -> {
                val a = len - 192
                byteArrayOf((((a shr 8) + 192) and 0xFF).toByte(), (a and 0xFF).toByte())
            }
            else -> byteArrayOf(
                0xFF.toByte(),
                ((len shr 24) and 0xFF).toByte(), ((len shr 16) and 0xFF).toByte(),
                ((len shr 8) and 0xFF).toByte(), (len and 0xFF).toByte()
            )
        }
        return byteArrayOf((0xC0 or tag).toByte()) + lenBytes + body
    }

    // ── signature hash data + trailer ──────────────────────────────────

    private fun buildSignatureTrailer(signatureType: Int, hashedSubpackets: ByteArray): ByteArray {
        val totalHashedLen = 6 + hashedSubpackets.size
        return byteArrayOf(4, signatureType.toByte(), EDDSA_ALGO.toByte(), HASH_SHA256.toByte()) +
            u16be(hashedSubpackets.size) + hashedSubpackets +
            byteArrayOf(4, 0xFF.toByte()) + u32be(totalHashedLen.toLong())
    }

    /** Hash data for a certification sig (0x13): primary(0x99) || uid(0xB4) || trailer. */
    fun buildCertificationHashData(
        primaryKeyBody: ByteArray,
        userIDBytes: ByteArray,
        signatureType: Int,
        hashedSubpackets: ByteArray
    ): ByteArray {
        return byteArrayOf(0x99.toByte()) + u16be(primaryKeyBody.size) + primaryKeyBody +
            byteArrayOf(0xB4.toByte()) + u32be(userIDBytes.size.toLong()) + userIDBytes +
            buildSignatureTrailer(signatureType, hashedSubpackets)
    }

    /** Hash data for a subkey binding sig (0x18): primary(0x99) || subkey(0x99) || trailer. */
    fun buildSubkeyBindingHashData(
        primaryKeyBody: ByteArray,
        subkeyBody: ByteArray,
        signatureType: Int,
        hashedSubpackets: ByteArray
    ): ByteArray {
        return byteArrayOf(0x99.toByte()) + u16be(primaryKeyBody.size) + primaryKeyBody +
            byteArrayOf(0x99.toByte()) + u16be(subkeyBody.size) + subkeyBody +
            buildSignatureTrailer(signatureType, hashedSubpackets)
    }

    // ── hashed/unhashed subpacket sets (match iOS order exactly) ────────

    /** Certification (0x13) hashed subpackets, in iOS order. */
    fun certificationHashedSubpackets(creationTime: Long, expirationSeconds: Long?): ByteArray {
        var out = buildSubpacket(2, u32be(creationTime))                 // creation time
        out += buildSubpacket(27, byteArrayOf(0x03))                     // key flags: certify+sign
        out += buildSubpacket(11, byteArrayOf(9, 8, 7))                  // pref sym: AES256/192/128
        out += buildSubpacket(21, byteArrayOf(10, 9, 8))                 // pref hash: SHA512/384/256
        out += buildSubpacket(22, byteArrayOf(2, 3, 1))                  // pref compression
        out += buildSubpacket(30, byteArrayOf(0x01))                     // features: MDC
        if (expirationSeconds != null) {
            out += buildSubpacket(9, u32be(expirationSeconds))           // key expiration
        }
        return out
    }

    /** Subkey binding (0x18) hashed subpackets. */
    fun bindingHashedSubpackets(creationTime: Long): ByteArray {
        var out = buildSubpacket(2, u32be(creationTime))                 // creation time
        out += buildSubpacket(27, byteArrayOf(0x0C))                     // key flags: encrypt comms+storage
        return out
    }

    /** Unhashed area: issuer key ID (type 16). */
    fun issuerUnhashedSubpackets(keyId: ByteArray): ByteArray = buildSubpacket(16, keyId)

    /**
     * Assemble a v4 EdDSA signature packet body from the card-produced 64-byte
     * r||s. Mirrors the packet tail of the iOS builders exactly.
     */
    fun assembleEdDSASignaturePacket(
        signatureType: Int,
        hashedSubpackets: ByteArray,
        unhashedSubpackets: ByteArray,
        digestPrefix: ByteArray,
        sigBytes: ByteArray
    ): ByteArray {
        require(sigBytes.size == 64) { "EdDSA signature must be 64 bytes (r||s)" }
        require(digestPrefix.size == 2) { "digest prefix must be 2 bytes" }
        val r = sigBytes.copyOfRange(0, 32)
        val s = sigBytes.copyOfRange(32, 64)
        return byteArrayOf(4, signatureType.toByte(), EDDSA_ALGO.toByte(), HASH_SHA256.toByte()) +
            u16be(hashedSubpackets.size) + hashedSubpackets +
            u16be(unhashedSubpackets.size) + unhashedSubpackets +
            digestPrefix +
            mpi(r) + mpi(s)
    }

    /** Strip the OpenPGP native-format 0x40 prefix from a card EC point, if present. */
    fun stripPointPrefix(point: ByteArray): ByteArray =
        if (point.size == 33 && (point[0].toInt() and 0xFF) == 0x40) point.copyOfRange(1, 33) else point
}
