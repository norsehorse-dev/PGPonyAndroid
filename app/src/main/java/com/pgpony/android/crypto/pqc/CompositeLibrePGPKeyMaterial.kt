// CompositeLibrePGPKeyMaterial.kt
// PGPony Android — 4.0.0 Phase 2b (LibrePGP composite, algorithm 8)
//
// Parse a v5 LibrePGP composite (algo 8, Kyber/ML-KEM-768 + X25519) secret
// subkey packet: recover the raw secret material and compute the v5
// fingerprint. BouncyCastle can't interpret algo-8 key material, so we
// hand-parse the packet; the S2K + CFB decryption of a protected key reuses
// BC's tested PBESecretKeyDecryptor.
//
// v5 secret subkey packet (verified against GnuPG 2.5.21 output):
//   ver(1)=5 | ctime(4) | algo(1)=8 | pkMatLen(4)=1227 | pubMat(1227) |
//   s2kUsage(1) | [protection] | secMatLen(4) | secretMaterial
// where for usage 254 (SHA-1 CFB) the protection is
//   paramCount(1) | sym(1) | S2K | IV        (paramCount = sym+S2K+IV length)
// and the decrypted secret material is
//   X25519 secret (32) || Kyber-768 seed (64) [ || SHA-1 checksum (20) ].
//
// v5 fingerprint = SHA-256( 0x9A || 4-octet packet-length || packet body ).

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.S2K
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import java.security.MessageDigest
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import java.io.ByteArrayInputStream

object CompositeLibrePGPKeyMaterial {

    const val ALGORITHM_ID = CompositeKemLibrePGP.ALGORITHM_ID // 8
    const val KYBER768_SEED_LEN = 64
    const val X25519_LEN = 32

    private const val USAGE_NONE = 0
    private const val USAGE_SHA1 = 254
    private const val USAGE_CHECKSUM = 255

    data class Material(val x25519Secret: ByteArray, val kyberSeed: ByteArray)

    class ProtectedKeyException(message: String) : Exception(message)

    /** v5 fingerprint over the public-key portion of [packet]. */
    fun v5Fingerprint(packet: ByteArray): ByteArray {
        val body = tagAndBody(packet).second
        val pkMatLen = readUInt32(body, 6)
        val pub = body.copyOfRange(0, 10 + pkMatLen)
        val md = MessageDigest.getInstance("SHA-256")
        md.update(0x9A.toByte())
        md.update(uint32be(pub.size))
        md.update(pub)
        return md.digest()
    }

    /** v5 key ID = the leading 8 octets of the v5 fingerprint. */
    fun v5KeyId(packet: ByteArray): ByteArray = v5Fingerprint(packet).copyOfRange(0, 8)

    /**
     * (X25519 public 32, Kyber-768 public 1184) from a v5 algo-8 key packet.
     * Public material = OID | X25519 point MPI (0x40 || 32) | kyberLen(4) | kyber.
     */
    /**
     * The composite suite (768/X25519 or 1024/X448) of a v5 algo-8 key,
     * read from its curve OID. Algorithm 8 is a shared code point, so the
     * OID (X25519 1.3.101.110 vs X448 1.3.101.111) is what tells the two
     * parameter sets apart.
     */
    fun suiteOf(packet: ByteArray): CompositeSuite {
        val body = tagAndBody(packet).second
        val pkMatLen = readUInt32(body, 6)
        val pub = body.copyOfRange(10, 10 + pkMatLen)
        val oidLen = pub[0].toInt() and 0xFF
        val curve = EccCurve.fromOidTail(pub.copyOfRange(1, 1 + oidLen))
            ?: throw IllegalArgumentException("unknown LibrePGP composite curve OID")
        return CompositeSuite.librePgpFor(curve)
    }

    fun publicMaterial(packet: ByteArray): Pair<ByteArray, ByteArray> {
        val body = tagAndBody(packet).second
        val pkMatLen = readUInt32(body, 6)
        val pub = body.copyOfRange(10, 10 + pkMatLen)
        var p = 0
        val oidLen = pub[p++].toInt() and 0xFF
        val curve = EccCurve.fromOidTail(pub.copyOfRange(1, 1 + oidLen))
            ?: throw IllegalArgumentException("unknown LibrePGP composite curve OID")
        p += oidLen
        val bits = ((pub[p].toInt() and 0xFF) shl 8) or (pub[p + 1].toInt() and 0xFF); p += 2
        val pointLen = (bits + 7) / 8
        val rawPoint = pub.copyOfRange(p, p + pointLen)
        // Montgomery curves normalize the minimal MPI back to the fixed curve
        // length; a Weierstrass curve keeps its uncompressed 0x04 || X || Y point.
        val ecc = if (curve.weierstrass) rawPoint else curve.normalizePoint(rawPoint)
        p += pointLen
        val kyberLen = readUInt32(pub, p); p += 4
        val kyber = pub.copyOfRange(p, p + kyberLen)
        return ecc to kyber
    }

    /**
     * 4.2.0 RC2 workstream F. Before the three gpg wire fixes (d6f8d0d,
     * db59eb4, ee22242) PGPony's own LibrePGP composite generator wrote the
     * ECC point as a 0x40-prefixed, fixed-[EccCurve.keyLen]-plus-one-octet
     * "native point" MPI. gpg 2.5.x itself writes (and expects) a raw point
     * as a MINIMAL MPI (leading zero octets stripped, no 0x40 prefix) — see
     * CompositeKeyGen.v5Bodies's canonicalMpi call. [publicMaterial] already
     * copes with either shape on read (EccCurve.normalizePoint trims a
     * longer point down to keyLen), which is why decrypt still works for a
     * key generated before the fix. The problem is encrypt: gpg parses the
     * 0x40-prefixed MPI as a keyLen-plus-one-octet value, disagrees with
     * PGPony about the point, and produces a session key PGPony can't
     * recover, so `gpg --encrypt` to one of these old keys fails on gpg's
     * side (or round-trips to garbage) even though the key itself imports
     * fine.
     *
     * This inspects the RAW point as stored, before normalization, and
     * reports true only for the specific broken shape: exactly
     * curve.keyLen + 1 octets with a leading 0x40. A key already using the
     * minimal encoding (keyLen octets, or shorter with high zero octets
     * stripped) returns false.
     */
    fun usesLegacyPointEncoding(packet: ByteArray): Boolean {
        val body = tagAndBody(packet).second
        val pkMatLen = readUInt32(body, 6)
        val pub = body.copyOfRange(10, 10 + pkMatLen)
        var p = 0
        val oidLen = pub[p++].toInt() and 0xFF
        val curve = EccCurve.fromOidTail(pub.copyOfRange(1, 1 + oidLen)) ?: return false
        p += oidLen
        val bits = ((pub[p].toInt() and 0xFF) shl 8) or (pub[p + 1].toInt() and 0xFF); p += 2
        val pointLen = (bits + 7) / 8
        if (pointLen != curve.keyLen + 1) return false
        val rawPoint = pub.copyOfRange(p, p + pointLen)
        return rawPoint[0] == 0x40.toByte()
    }

    /**
     * Recover (X25519 secret, Kyber-768 seed) from a v5 algo-8 secret subkey
     * [packet], decrypting with [passphrase] if protected.
     */
    fun extractFromPacket(packet: ByteArray, passphrase: CharArray?): Material {
        val body = tagAndBody(packet).second
        var i = 0
        require((body[i++].toInt() and 0xFF) == 5) { "LibrePGP composite subkey must be v5" }
        i += 4 // creation time
        require((body[i++].toInt() and 0xFF) == ALGORITHM_ID) { "expected algo $ALGORITHM_ID" }
        val pkMatLen = readUInt32(body, i); i += 4
        i += pkMatLen // skip public material

        // algo 8 is shared 768/1024; the curve OID fixes the ECC secret length.
        val eccLen = suiteOf(packet).curve.keyLen
        val usage = body[i++].toInt() and 0xFF
        val material: ByteArray = when (usage) {
            USAGE_NONE -> {
                i++ // v5 conditional-parameter length octet (0 when unprotected)
                val secMatLen = readUInt32(body, i); i += 4
                require(secMatLen >= eccLen + KYBER768_SEED_LEN) { "secret material too short" }
                body.copyOfRange(i, i + eccLen + KYBER768_SEED_LEN)
            }

            USAGE_SHA1, USAGE_CHECKSUM -> {
                if (passphrase == null) {
                    throw ProtectedKeyException("LibrePGP composite secret key is passphrase-protected")
                }
                val paramCount = body[i++].toInt() and 0xFF
                val paramStart = i
                val sym = body[i++].toInt() and 0xFF
                val s2kLen = s2kSpecifierLength(body[i].toInt() and 0xFF)
                val s2kBytes = body.copyOfRange(i, i + s2kLen); i += s2kLen
                val ivLen = paramCount - (i - paramStart)
                val iv = body.copyOfRange(i, i + ivLen); i += ivLen
                val secMatLen = readUInt32(body, i); i += 4
                val enc = body.copyOfRange(i, i + secMatLen)

                val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(passphrase)
                val s2k = buildS2K(s2kBytes)
                // 4.6.0 (item 17.5): bound an Argon2 S2K before running the KDF, as the classical unlock sites do.
                com.pgpony.android.crypto.enforceArgon2Policy(s2k)
                val key = decryptor.makeKeyFromPassPhrase(sym, s2k)
                val plain = decryptor.recoverKeyData(sym, key, iv, enc, 0, enc.size)
                require(plain.size >= eccLen + KYBER768_SEED_LEN) { "recovered material too short" }
                plain.copyOfRange(0, eccLen + KYBER768_SEED_LEN)
            }

            else -> throw ProtectedKeyException("unsupported v5 S2K usage $usage")
        }

        return Material(
            material.copyOfRange(0, eccLen),
            material.copyOfRange(eccLen, eccLen + KYBER768_SEED_LEN)
        )
    }

    // ── helpers ──────────────────────────────────────────────────────

    private fun s2kSpecifierLength(type: Int): Int = when (type) {
        S2K.SIMPLE -> 2                 // type + hash
        S2K.SALTED -> 10                // type + hash + salt(8)
        S2K.SALTED_AND_ITERATED -> 11   // type + hash + salt(8) + count
        S2K.ARGON_2 -> 20               // type + salt(16) + t + p + m
        else -> throw ProtectedKeyException("unsupported S2K type $type")
    }

    private fun buildS2K(b: ByteArray): S2K = when (val type = b[0].toInt() and 0xFF) {
        S2K.SIMPLE -> S2K.simpleS2K(b[1].toInt() and 0xFF)
        S2K.SALTED -> S2K.saltedS2K(b[1].toInt() and 0xFF, b.copyOfRange(2, 10))
        S2K.SALTED_AND_ITERATED -> S2K.saltedAndIteratedS2K(
            b[1].toInt() and 0xFF, b.copyOfRange(2, 10), b[10].toInt() and 0xFF
        )
        S2K.ARGON_2 -> S2K.argon2S2K(
            S2K.Argon2Params(b.copyOfRange(1, 17), b[17].toInt() and 0xFF, b[18].toInt() and 0xFF, b[19].toInt() and 0xFF)
        )
        else -> throw ProtectedKeyException("unsupported S2K type $type")
    }

    private fun uint32be(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun readUInt32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    /**
     * 4.2.0 RC2 workstream F. True if [armoredPublicKey] holds a v5 algo-8
     * LibrePGP composite subkey generated before the wire fixes, i.e. one
     * [usesLegacyPointEncoding] flags. Used to surface a one-time
     * "regenerate this key" hint in the keyring; a key that fails to parse
     * (not armored, not a public key, etc.) is treated as not affected
     * rather than throwing, since this only ever runs as an advisory check
     * over keys the app already imported successfully.
     */
    fun keyNeedsRegeneration(armoredPublicKey: String): Boolean {
        return try {
            val decoder = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(
                ByteArrayInputStream(armoredPublicKey.toByteArray(Charsets.UTF_8))
            )
            val ring = PGPPublicKeyRing(decoder, JcaKeyFingerprintCalculator())
            ring.publicKeys.asSequence().any { key ->
                key.version == 5 && key.algorithm == ALGORITHM_ID && usesLegacyPointEncoding(key.encoded)
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun tagAndBody(packet: ByteArray): Pair<Int, ByteArray> {
        var i = 0
        val c = packet[i++].toInt() and 0xFF
        require(c and 0x80 != 0) { "not a packet header" }
        val tag: Int
        val length: Int
        if (c and 0x40 != 0) {
            tag = c and 0x3F
            val l0 = packet[i++].toInt() and 0xFF
            length = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (packet[i++].toInt() and 0xFF) + 192
                l0 == 255 -> readUInt32(packet, i).also { i += 4 }
                else -> throw IllegalArgumentException("partial length in key packet")
            }
        } else {
            tag = (c shr 2) and 0x0F
            length = when (c and 0x03) {
                0 -> packet[i++].toInt() and 0xFF
                1 -> (((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> readUInt32(packet, i).also { i += 4 }
                else -> packet.size - i
            }
        }
        return tag to packet.copyOfRange(i, i + length)
    }
}
