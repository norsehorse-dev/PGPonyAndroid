// Rfc6637.kt
// PGPony Android — HW Phase 3a
//
// Host-side ECDH session-key recovery per RFC 6637. The OpenPGP card does
// only the raw ECDH step (PSO:DECIPHER → shared secret); everything here
// runs on the host:
//
//   1. KDF: KEK = Hash( 00 00 00 01 ‖ sharedSecret ‖ Param ), truncated to
//      the KEK key length. Param encodes the curve OID, the ECDH algo ID,
//      the KDF hash + KEK symmetric algo, the literal "Anonymous Sender"
//      string, and the RECIPIENT (card) encryption-key fingerprint.
//   2. AES Key Wrap (RFC 3394) unwrap of the PKESK's wrapped key with the
//      KEK → the padded "m".
//   3. Strip the PKCS#5-style pad, then parse symAlgoID ‖ sessionKey ‖
//      2-byte checksum and verify the checksum.
//
// Pure JVM (BouncyCastle bcprov only) — unit-testable without a card. The
// KDF hash and KEK algo IDs come from the recipient public key's ECDH KDF
// parameters (read in Phase 3b); they're parameters here, not hardcoded.

package com.pgpony.android.crypto.card

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.RFC3394WrapEngine
import org.bouncycastle.crypto.params.KeyParameter
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

object Rfc6637 {

    /** Literal 20-byte sender string from RFC 6637 §8. */
    val ANONYMOUS_SENDER: ByteArray = "Anonymous Sender    ".toByteArray(Charsets.US_ASCII)

    /** Curve25519 OID 1.3.6.1.4.1.3029.1.5.1 (as it appears in the param). */
    val CURVE25519_OID: ByteArray = byteArrayOf(
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x97.toByte(), 0x55, 0x01, 0x05, 0x01
    )

    /** OpenPGP public-key algorithm ID for ECDH. */
    private const val ALGO_ECDH = 18

    /**
     * Build the RFC 6637 §8 KDF Param:
     *   curveOIDlen ‖ curveOID ‖ 18 ‖ 03 ‖ 01 ‖ kdfHashId ‖ kekAlgoId ‖
     *   "Anonymous Sender    " ‖ recipientFingerprint(20)
     */
    fun kdfParam(
        curveOid: ByteArray,
        kdfHashId: Int,
        kekAlgoId: Int,
        recipientFingerprint: ByteArray
    ): ByteArray {
        require(recipientFingerprint.size == 20) { "v4 fingerprint must be 20 bytes" }
        val out = ByteArrayOutputStream()
        out.write(curveOid.size)
        out.write(curveOid)
        out.write(ALGO_ECDH)
        out.write(0x03)
        out.write(0x01)
        out.write(kdfHashId)
        out.write(kekAlgoId)
        out.write(ANONYMOUS_SENDER)
        out.write(recipientFingerprint)
        return out.toByteArray()
    }

    /** KDF input = 00 00 00 01 ‖ sharedSecret ‖ param. */
    fun kdfInput(sharedSecret: ByteArray, param: ByteArray): ByteArray =
        byteArrayOf(0, 0, 0, 1) + sharedSecret + param

    /**
     * Derive the KEK: Hash(kdfInput) truncated to the KEK key length for
     * [kekAlgoId].
     */
    fun deriveKek(
        sharedSecret: ByteArray,
        param: ByteArray,
        kdfHashId: Int,
        kekAlgoId: Int
    ): ByteArray {
        val md = MessageDigest.getInstance(hashName(kdfHashId))
        val digest = md.digest(kdfInput(sharedSecret, param))
        return digest.copyOf(kekKeyLength(kekAlgoId))
    }

    /** RFC 3394 AES Key Wrap unwrap of [wrapped] under [kek]. */
    fun aesKeyUnwrap(kek: ByteArray, wrapped: ByteArray): ByteArray {
        val engine = RFC3394WrapEngine(AESEngine.newInstance())
        engine.init(false, KeyParameter(kek))
        return engine.unwrap(wrapped, 0, wrapped.size)
    }

    /**
     * Strip the OpenPGP ECDH PKCS#5-style pad (each pad byte equals the pad
     * length, 1..8). Returns symAlgoID ‖ sessionKey ‖ checksum.
     */
    fun stripPad(padded: ByteArray): ByteArray {
        require(padded.isNotEmpty()) { "empty unwrapped key" }
        val n = padded.last().toInt() and 0xFF
        require(n in 1..8 && n <= padded.size) { "bad ECDH pad length: $n" }
        return padded.copyOf(padded.size - n)
    }

    /** Recovered session key: the symmetric algorithm ID + the raw key. */
    data class SessionKey(val symAlgoId: Int, val key: ByteArray)

    /**
     * Parse symAlgoID(1) ‖ key ‖ checksum(2) and verify the 16-bit
     * additive checksum over the key bytes.
     */
    fun parseSessionKey(m: ByteArray): SessionKey {
        require(m.size >= 4) { "session key block too short" }
        val symAlgoId = m[0].toInt() and 0xFF
        val key = m.copyOfRange(1, m.size - 2)
        val expected = ((m[m.size - 2].toInt() and 0xFF) shl 8) or (m[m.size - 1].toInt() and 0xFF)
        var sum = 0
        for (b in key) sum = (sum + (b.toInt() and 0xFF)) and 0xFFFF
        require(sum == expected) { "session key checksum mismatch" }
        return SessionKey(symAlgoId, key)
    }

    /** Full host-side recovery from the card's shared secret. */
    fun recoverSessionKey(
        sharedSecret: ByteArray,
        wrappedKey: ByteArray,
        curveOid: ByteArray,
        kdfHashId: Int,
        kekAlgoId: Int,
        recipientFingerprint: ByteArray
    ): SessionKey {
        val param = kdfParam(curveOid, kdfHashId, kekAlgoId, recipientFingerprint)
        val kek = deriveKek(sharedSecret, param, kdfHashId, kekAlgoId)
        val padded = aesKeyUnwrap(kek, wrappedKey)
        return parseSessionKey(stripPad(padded))
    }

    /** Map an OpenPGP hash algorithm ID to a JCA MessageDigest name. */
    fun hashName(hashId: Int): String = when (hashId) {
        2 -> "SHA-1"
        8 -> "SHA-256"
        9 -> "SHA-384"
        10 -> "SHA-512"
        else -> "SHA-256"
    }

    /** Map an OpenPGP symmetric algorithm ID to the AES key length. */
    fun kekKeyLength(kekAlgoId: Int): Int = when (kekAlgoId) {
        7 -> 16   // AES-128
        8 -> 24   // AES-192
        9 -> 32   // AES-256
        else -> 16
    }
}
