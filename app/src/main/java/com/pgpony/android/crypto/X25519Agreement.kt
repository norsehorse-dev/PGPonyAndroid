// X25519Agreement.kt
// PGPony Android 4.8.2 (item 1): raw X25519 key agreement with the user's own
// Curve25519 encryption subkeys, for the provider's X25519_AGREE action.
//
// StegPony reveals by asking a key for one X25519 agreement per slot it tries
// (its core's KeyDevice.agree: a 32-byte point in, the 32-byte shared secret
// out; on a card that is PSO:DECIPHER). This object holds the parts that do
// not touch Android: which keys qualify, request checks, the software
// agreement, and reading a card's answer. Kept free of Android types for the
// unit tests.
//
// Keys: v4 (and LibrePGP v5) ECDH on Curve25519Legacy, algorithm 18 with the
// 1.3.6.1.4.1.3029.1.5.1 OID (or 1.3.101.110, which some tools wrote), point
// 0x40 || u; and X25519, algorithm 25, a bare 32-byte u. The u-coordinate is
// the RFC 7748 encoding in both, so a client builds an age recipient from it
// directly.
//
// Safety: points are exactly 32 bytes; the small-order u-coordinates (and the
// non-canonical forms of 0 and 1) are refused before any key is touched; an
// all-zero shared secret fails the whole call; the scalar and every secret
// PGPony holds are wiped after use. Nothing here logs.

package com.pgpony.android.crypto

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter
import java.security.MessageDigest

object X25519Agreement {

    const val POINT_LEN = 32

    /** At most this many points per call. */
    const val MAX_POINTS = 32

    const val ALG_ECDH = 18
    const val ALG_X25519 = 25

    /** 1.3.6.1.4.1.3029.1.5.1, Curve25519Legacy (RFC 9580 9.2). */
    private val OID_CURVE25519_LEGACY = byteArrayOf(
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x97.toByte(), 0x55, 0x01, 0x05, 0x01
    )

    /** 1.3.101.110 (id-X25519), seen on algorithm 18 keys from some tools. */
    private val OID_X25519 = byteArrayOf(0x2B, 0x65, 0x6E)

    /**
     * The u-coordinates of small order, and the non-canonical forms of 0 and
     * 1 (p and p + 1), as libsodium lists them. Compared with bit 255
     * cleared, since X25519 ignores it.
     */
    private val LOW_ORDER: List<ByteArray> = listOf(
        ByteArray(32),
        ByteArray(32).also { it[0] = 1 },
        hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    )

    /** Why a request or an agreement was refused. [code] is the stable reason
     *  the provider hands the client (EXTRA_ERROR_REASON). */
    enum class Refusal(val code: String) {
        INVALID_REQUEST("invalid_request"),
        TOO_MANY_POINTS("too_many_points"),
        LOW_ORDER_POINT("low_order_point"),
        UNKNOWN_KEY("unknown_key"),
        UNSUPPORTED_KEY("unsupported_key"),
        KEY_UNAVAILABLE("key_unavailable"),
        AGREEMENT_FAILED("agreement_failed")
    }

    class RefusedException(val refusal: Refusal, message: String) : Exception(message)

    /** True for a point X25519 must not be run on. */
    fun isLowOrder(u: ByteArray): Boolean {
        if (u.size != POINT_LEN) return false
        return LOW_ORDER.any { bad ->
            var diff = 0
            for (i in 0 until 31) diff = diff or (bad[i].toInt() xor u[i].toInt())
            diff = diff or ((bad[31].toInt() xor u[31].toInt()) and 0x7F)
            diff == 0
        }
    }

    /**
     * Split [points] (1 to [MAX_POINTS] points of 32 bytes, concatenated)
     * into separate points, refusing a malformed batch or any low-order
     * point. Throws [RefusedException].
     */
    fun splitPoints(points: ByteArray?): List<ByteArray> {
        if (points == null || points.isEmpty() || points.size % POINT_LEN != 0) {
            throw RefusedException(Refusal.INVALID_REQUEST, "Points must be 32 bytes each, at least one")
        }
        val n = points.size / POINT_LEN
        if (n > MAX_POINTS) {
            throw RefusedException(Refusal.TOO_MANY_POINTS, "At most $MAX_POINTS points per call, got $n")
        }
        val out = (0 until n).map { points.copyOfRange(it * POINT_LEN, (it + 1) * POINT_LEN) }
        if (out.any { isLowOrder(it) }) {
            throw RefusedException(Refusal.LOW_ORDER_POINT, "A point has small order")
        }
        return out
    }

    /**
     * A key fingerprint as the client sent it, normalized: hex, upper case,
     * spaces and colons dropped, 40 (v4) or 64 (v5, v6) digits. Null when
     * it is not one.
     */
    fun normalizeFingerprint(fp: String?): String? {
        val s = fp?.filterNot { it == ' ' || it == ':' }?.uppercase() ?: return null
        if (s.length != 40 && s.length != 64) return null
        if (!s.all { it in '0'..'9' || it in 'A'..'F' }) return null
        return s
    }

    /**
     * The 32-byte u-coordinate of a Curve25519 encryption key, from its
     * public key packet body (version, creation time, algorithm, material);
     * null for any other key.
     */
    fun curve25519Point(publicBody: ByteArray): ByteArray? = runCatching {
        val version = publicBody[0].toInt() and 0xFF
        val alg = publicBody[5].toInt() and 0xFF
        val start = when (version) {
            4 -> 6
            5, 6 -> 10
            else -> return null
        }
        when (alg) {
            ALG_X25519 -> {
                if (publicBody.size < start + POINT_LEN) return null
                publicBody.copyOfRange(start, start + POINT_LEN)
            }
            ALG_ECDH -> {
                var i = start
                val oidLen = publicBody[i++].toInt() and 0xFF
                val oid = publicBody.copyOfRange(i, i + oidLen); i += oidLen
                if (!oid.contentEquals(OID_CURVE25519_LEGACY) && !oid.contentEquals(OID_X25519)) return null
                val bits = ((publicBody[i].toInt() and 0xFF) shl 8) or (publicBody[i + 1].toInt() and 0xFF)
                i += 2
                val len = (bits + 7) / 8
                if (len != POINT_LEN + 1 || (publicBody[i].toInt() and 0xFF) != 0x40) return null
                publicBody.copyOfRange(i + 1, i + 1 + POINT_LEN)
            }
            else -> null
        }
    }.getOrNull()

    /**
     * X25519 of [scalar] (32 bytes, RFC 7748 encoding) with each of [points],
     * the secrets concatenated in order. An all-zero secret anywhere fails
     * the whole call with [Refusal.AGREEMENT_FAILED] and nothing is returned.
     * [scalar] is left as the caller passed it.
     */
    fun agree(scalar: ByteArray, points: List<ByteArray>): ByteArray {
        require(scalar.size == POINT_LEN)
        val out = ByteArray(points.size * POINT_LEN)
        for ((n, u) in points.withIndex()) {
            require(u.size == POINT_LEN)
            if (!X25519.calculateAgreement(scalar, 0, u, 0, out, n * POINT_LEN)) {
                out.fill(0)
                throw RefusedException(Refusal.AGREEMENT_FAILED, "The shared secret was all zero")
            }
        }
        return out
    }

    /**
     * [agree] with an unlocked OpenPGP private key: a v4 Curve25519Legacy
     * ECDH key (Bouncy Castle's converter undoes its reversed scalar) or a
     * v6 X25519 key. The scalar copy is wiped before returning.
     */
    fun agree(privateKey: PGPPrivateKey, points: List<ByteArray>): ByteArray {
        val params = BcPGPKeyConverter().getPrivateKey(privateKey) as? X25519PrivateKeyParameters
            ?: throw RefusedException(Refusal.UNSUPPORTED_KEY, "Not an X25519 key")
        val scalar = ByteArray(POINT_LEN)
        params.encode(scalar, 0)
        return try {
            agree(scalar, points)
        } finally {
            scalar.fill(0)
        }
    }

    /**
     * The shared secret in a card's PSO:DECIPHER answer: 32 bytes, or
     * 0x40 || 32 bytes from cards that answer in the native point format.
     * Null for anything else.
     */
    fun cardSecret(answer: ByteArray): ByteArray? = when {
        answer.size == POINT_LEN -> answer.copyOf()
        answer.size == POINT_LEN + 1 && (answer[0].toInt() and 0xFF) == 0x40 -> answer.copyOfRange(1, answer.size)
        else -> null
    }

    /** True when every byte of [secret] is zero, checked in constant time. */
    fun isAllZero(secret: ByteArray): Boolean {
        var acc = 0
        for (b in secret) acc = acc or b.toInt()
        return acc == 0
    }

    /**
     * Identifies one request across the interaction round trip: the action,
     * the calling package, the subkey and the points. A re-call by another
     * app, or with other points, never matches a stored result.
     */
    fun opKey(action: String, callingPackage: String, subkeyFingerprint: String, points: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        for (part in listOf(action, callingPackage, subkeyFingerprint.uppercase())) {
            md.update(part.toByteArray(Charsets.UTF_8))
            md.update(0)
        }
        md.update(points)
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((Character.digit(s[2 * it], 16) shl 4) or Character.digit(s[2 * it + 1], 16)).toByte() }
}
