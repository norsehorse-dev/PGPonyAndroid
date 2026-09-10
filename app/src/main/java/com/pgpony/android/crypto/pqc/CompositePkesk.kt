// CompositePkesk.kt
// PGPony Android — 4.0.0 Phase 2b
//
// Encode/parse the v6 Public-Key Encrypted Session Key packet for the
// IETF composite (algorithm 35, ML-KEM-768 + X25519). BouncyCastle can't
// build this (no algo-35 support), so we emit/parse the packet BODY by
// hand; slice 4 wraps the encoded body in a ContainedPacket for BC's
// message generator and detects it on the decrypt side.
//
// v6 PKESK body layout (RFC 9580 §5.1 + draft-ietf-openpgp-pqc §4.3.1):
//   version(1)=6 | keyInfoCount(1) | [keyVersion(1)=6 | fingerprint(32)] |
//   pubkeyAlgo(1)=35 |
//   X25519 ephemeral(32) | ML-KEM ciphertext(1088) |
//   wrappedKeyLen(1) | RFC-3394 wrapped session key
//
// For v6 (used with SEIPD v2) the session key is wrapped bare — NO
// symmetric-algorithm octet is prepended (that's a v3-PKESK-only field).

package com.pgpony.android.crypto.pqc

import java.io.ByteArrayOutputStream

object CompositePkesk {

    const val PKESK_TAG = 1 // Public-Key Encrypted Session Key packet tag
    const val VERSION_6 = 6
    const val VERSION_3 = 3

    data class Parsed(
        /** Recipient v6 fingerprint (empty when anonymous/wildcard or v3). */
        val recipientFingerprint: ByteArray,
        val ephemeralX25519: ByteArray,
        val mlkemCiphertext: ByteArray,
        val wrappedSessionKey: ByteArray,
        /** Which IETF suite (algo 35 or 36) the packet declared. */
        val suite: CompositeSuite = CompositeSuite.IETF_768,
        /** item 14 (#56): v3 PKESK 8-octet recipient key ID (empty for v6/anon). */
        val recipientKeyId: ByteArray = ByteArray(0),
        /** item 14 (#56): symmetric-algorithm ID carried by a v3 PKESK (SEIPDv1);
         *  0 for a v6 PKESK, where the algorithm lives in the SEIPDv2 packet. */
        val symAlgId: Int = 0
    )

    /**
     * The algorithm-specific fields of a v6 algo-35 PKESK — everything
     * after the public-key-algorithm octet:
     *   X25519 ephemeral (32) || ML-KEM ct (1088) || len (1) || wrapped key.
     * This is the `data` blob BC's PublicKeyEncSessionPacket writes verbatim,
     * and also the tail of [encodeBody]. Shared so both paths agree.
     */
    fun encodeAlgoFields(
        ephemeralX25519: ByteArray,
        mlkemCiphertext: ByteArray,
        wrappedSessionKey: ByteArray,
        suite: CompositeSuite = CompositeSuite.IETF_768
    ): ByteArray {
        require(ephemeralX25519.size == suite.curve.keyLen) { "bad ECC ephemeral length" }
        require(mlkemCiphertext.size == suite.mlkem.ctLen) { "bad ML-KEM ciphertext length" }
        require(wrappedSessionKey.size in 1..255) { "wrapped session key length out of range" }

        val out = ByteArrayOutputStream()
        out.write(ephemeralX25519)
        out.write(mlkemCiphertext)
        out.write(wrappedSessionKey.size)    // one-octet length
        out.write(wrappedSessionKey)
        return out.toByteArray()
    }

    /** Encode the v6 algo-35 PKESK packet BODY (no outer tag/length). */
    fun encodeBody(
        recipientFpV6: ByteArray,
        ephemeralX25519: ByteArray,
        mlkemCiphertext: ByteArray,
        wrappedSessionKey: ByteArray,
        suite: CompositeSuite = CompositeSuite.IETF_768
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(VERSION_6)
        if (recipientFpV6.isEmpty()) {
            out.write(0) // anonymous recipient
        } else {
            // item 14 (#56): the PKESK stays v6 (SEIPDv2 pairing), but the
            // TARGET key version octet and fingerprint length follow the
            // recipient's own key version — 6 with a 32-octet fingerprint, or
            // 4 with a 20-octet SHA-1 fingerprint for a v4 algo-35 subkey
            // (RFC 9580 5.1). parseBody reads the length from the count octet,
            // so both round-trip.
            require(recipientFpV6.size == 20 || recipientFpV6.size == 32) {
                "fingerprint must be 20 (v4) or 32 (v6) bytes"
            }
            val keyVersion = if (recipientFpV6.size == 32) 6 else 4
            out.write(1 + recipientFpV6.size) // count = keyVersion(1) + fingerprint
            out.write(keyVersion)             // recipient key version
            out.write(recipientFpV6)
        }
        out.write(suite.ietfAlgId) // 35 or 36
        out.write(encodeAlgoFields(ephemeralX25519, mlkemCiphertext, wrappedSessionKey, suite))
        return out.toByteArray()
    }

    /**
     * Parse a v6 algo-35 PKESK packet BODY. Returns null if the bytes
     * aren't a v6 composite PKESK (wrong version/algo, or truncated).
     */
    fun parseBody(body: ByteArray): Parsed? {
        try {
            return when (body[0].toInt() and 0xFF) {
                VERSION_6 -> parseV6(body)
                VERSION_3 -> parseV3(body)
                else -> null
            }
        } catch (e: Exception) {
            return null
        }
    }

    private fun parseV6(body: ByteArray): Parsed? {
        var i = 1 // version already checked
        val count = body[i++].toInt() and 0xFF
        val fp: ByteArray
        if (count == 0) {
            fp = ByteArray(0)
        } else {
            i++ // key version octet (4 or 6)
            val fpLen = count - 1
            fp = body.copyOfRange(i, i + fpLen); i += fpLen
        }
        // 4.2.0 §1.1: dispatch on the algorithm octet (35 or 36) rather than
        // requiring 35, so an inbound ML-KEM-1024 PKESK parses correctly.
        val suite = CompositeSuite.ietfFor(body[i++].toInt() and 0xFF) ?: return null
        val eph = body.copyOfRange(i, i + suite.curve.keyLen); i += suite.curve.keyLen
        val ct = body.copyOfRange(i, i + suite.mlkem.ctLen); i += suite.mlkem.ctLen
        val skLen = body[i++].toInt() and 0xFF
        val wrapped = body.copyOfRange(i, i + skLen)
        return Parsed(fp, eph, ct, wrapped, suite)
    }

    /**
     * item 14 (#56): a v3 PKESK for an ML-KEM composite (RFC 9980 4.3.1). Layout:
     *   version(1)=3 | keyId(8) | pubAlgo(1) | ecdhCt(curveLen) | mlkemCt |
     *   len(1) | symAlgId(1) | C, where len = length of (symAlgId + C) and C is
     *   the wrapped session key. The recipient is identified by the 8-octet key
     *   ID; the symmetric algorithm is carried here (not encrypted) because the
     *   paired SEIPDv1 packet has no algorithm field.
     */
    private fun parseV3(body: ByteArray): Parsed? {
        var i = 1 // version
        val keyId = body.copyOfRange(i, i + 8); i += 8
        val suite = CompositeSuite.ietfFor(body[i++].toInt() and 0xFF) ?: return null
        val eph = body.copyOfRange(i, i + suite.curve.keyLen); i += suite.curve.keyLen
        val ct = body.copyOfRange(i, i + suite.mlkem.ctLen); i += suite.mlkem.ctLen
        val len = body[i++].toInt() and 0xFF          // length of symAlgId + C
        val symAlgId = body[i++].toInt() and 0xFF
        val cLen = len - 1
        val wrapped = body.copyOfRange(i, i + cLen)
        return Parsed(ByteArray(0), eph, ct, wrapped, suite, recipientKeyId = keyId, symAlgId = symAlgId)
    }
}
