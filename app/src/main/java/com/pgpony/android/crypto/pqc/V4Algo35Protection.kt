// V4Algo35Protection.kt
// PGPony Android — 4.5.0 (item 14 / #56): passphrase protection for a v4
// algo-35 (ML-KEM-768 + X25519) encryption subkey's secret material.
//
// A v4 key packet carries NO 4-octet material-length field, so BouncyCastle
// cannot parse an algo-35 subkey and CompositeSecretProtection (which is built
// for the v6-framed composite primary) does not fit it. This object protects /
// unlocks JUST the v4 secret region, in the classic v4 form gpg emits for a
// passphrase-set key: S2K usage 254 (SHA-1 integrity), AES-256 in OpenPGP CFB.
//
//   secret region := usage(254) | symAlg(1) | S2K specifier | IV(16) |
//                    CFB( material(96) || SHA-1(material)(20) )
//
// It hand-rolls no cipher: the S2K derivation and the CFB encrypt/decrypt are
// BouncyCastle's own (the same PBESecretKey encryptor/decryptor the classical
// and composite-primary paths use), so the protect side pairs exactly with the
// recoverKeyData CFB the composite decrypt already round-trips. usage 254 + CFB
// is what gpg 2.5.x writes and reads for a v4 secret key, so the export copy
// interops.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import java.security.MessageDigest
import java.security.SecureRandom

object V4Algo35Protection {

    private const val USAGE_NONE = 0
    private const val USAGE_AEAD = 253
    private const val USAGE_SHA1 = 254
    private const val USAGE_CHECKSUM = 255

    /** version(1) + ctime(4) + algo(1) + X25519(32) + ML-KEM-768(1184). */
    private const val PUB_END = 1 + 4 + 1 + 1216

    /** X25519 secret(32) + ML-KEM seed(64). */
    const val MATERIAL_LEN = 96

    class ProtectedKeyException(message: String) : Exception(message)

    /** True if the v4 algo-35 subkey body carries a passphrase-protected secret
     *  (s2k-usage octet non-zero). False for public-only or usage-0 bodies. */
    fun isProtected(subkeyBody: ByteArray): Boolean {
        if (subkeyBody.size <= PUB_END) return false
        return (subkeyBody[PUB_END].toInt() and 0xFF) != USAGE_NONE
    }

    /**
     * Protect [material] (96 octets: X25519 secret || ML-KEM seed) under
     * [passphrase], returning the v4 secret REGION to append after the public
     * body: usage(254) | symAlg | S2K | IV | CFB(material || SHA-1(material)).
     */
    fun protect(
        material: ByteArray,
        passphrase: CharArray,
        random: SecureRandom = SecureRandom()
    ): ByteArray {
        require(material.size == MATERIAL_LEN) { "v4 algo-35 material must be $MATERIAL_LEN octets" }
        require(passphrase.isNotEmpty()) { "protect requires a non-empty passphrase" }

        val s2kDigest = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256)
        // 4.6.0 (item 17.6): calibrated iteration count (s2kDigest is SHA-256 as before).
        val encryptor = com.pgpony.android.crypto.S2kPolicy.v4EncryptorBuilder()
            .setSecureRandom(random)
            .build(passphrase)

        // usage 254: the 20-octet SHA-1 of the material is appended, then the
        // whole thing is CFB-encrypted (BC's own PBE CFB, no resync).
        val sha1 = MessageDigest.getInstance("SHA-1").digest(material)
        val plain = material + sha1 // 116
        val ct = encryptor.encryptKeyData(plain, 0, plain.size)

        val out = java.io.ByteArrayOutputStream()
        out.write(USAGE_SHA1)
        out.write(SymmetricKeyAlgorithmTags.AES_256)
        out.write(encryptor.s2K.encoded)   // type | hash | salt(8) | count
        out.write(encryptor.cipherIV)      // 16 (AES block)
        out.write(ct)
        return out.toByteArray()
    }

    /**
     * Recover the 96-octet secret material from a v4 algo-35 secret subkey body,
     * decrypting with [passphrase] when protected. Returns null for a
     * public-only body; throws [ProtectedKeyException] when the body is
     * protected and no passphrase is given, or when the SHA-1 integrity check
     * fails.
     */
    fun unlock(subkeyBody: ByteArray, passphrase: CharArray?): ByteArray? {
        if (subkeyBody.size <= PUB_END) return null
        var i = PUB_END
        val usage = subkeyBody[i++].toInt() and 0xFF
        if (usage == USAGE_NONE) {
            if (subkeyBody.size < i + MATERIAL_LEN) return null
            return subkeyBody.copyOfRange(i, i + MATERIAL_LEN)
        }
        if (usage != USAGE_SHA1 && usage != USAGE_CHECKSUM && usage != USAGE_AEAD) {
            throw ProtectedKeyException("unsupported v4 S2K usage $usage")
        }
        if (passphrase == null) {
            throw ProtectedKeyException("v4 algo-35 subkey is passphrase-protected")
        }

        val symAlg = subkeyBody[i++].toInt() and 0xFF
        val s2kLen = s2kLength(subkeyBody, i)
        val s2kBytes = subkeyBody.copyOfRange(i, i + s2kLen); i += s2kLen
        val iv = subkeyBody.copyOfRange(i, i + AES_BLOCK); i += AES_BLOCK
        val encData = subkeyBody.copyOfRange(i, subkeyBody.size)

        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(passphrase)
        val s2k = buildS2K(s2kBytes)
        // 4.6.0 (item 17.5): bound an Argon2 S2K before running the KDF, as the classical unlock sites do.
        com.pgpony.android.crypto.enforceArgon2Policy(s2k)
        val s2kKey = decryptor.makeKeyFromPassPhrase(symAlg, s2k)
        val plain = decryptor.recoverKeyData(symAlg, s2kKey, iv, encData, 0, encData.size)
        if (plain.size < MATERIAL_LEN) {
            throw ProtectedKeyException("recovered v4 algo-35 material too short")
        }
        val material = plain.copyOfRange(0, MATERIAL_LEN)
        if (usage == USAGE_SHA1) {
            val expected = MessageDigest.getInstance("SHA-1").digest(material)
            val actual = plain.copyOfRange(MATERIAL_LEN, minOf(plain.size, MATERIAL_LEN + 20))
            if (!expected.contentEquals(actual)) {
                throw ProtectedKeyException("v4 algo-35 subkey SHA-1 integrity check failed (wrong passphrase?)")
            }
        }
        return material
    }

    private const val AES_BLOCK = 16

    /** The on-wire length of a v4 S2K specifier starting at [off]. */
    private fun s2kLength(b: ByteArray, off: Int): Int = when (val type = b[off].toInt() and 0xFF) {
        S2K.SIMPLE -> 2                       // type | hash
        S2K.SALTED -> 10                      // type | hash | salt(8)
        S2K.SALTED_AND_ITERATED -> 11         // type | hash | salt(8) | count
        S2K.ARGON_2 -> 20                     // type | salt(16) | t | p | m
        else -> throw ProtectedKeyException("unsupported S2K type $type")
    }

    private fun buildS2K(b: ByteArray): S2K = when (val type = b[0].toInt() and 0xFF) {
        S2K.SIMPLE -> S2K.simpleS2K(b[1].toInt() and 0xFF)
        S2K.SALTED -> S2K.saltedS2K(b[1].toInt() and 0xFF, b.copyOfRange(2, 10))
        S2K.SALTED_AND_ITERATED -> S2K.saltedAndIteratedS2K(
            b[1].toInt() and 0xFF, b.copyOfRange(2, 10), b[10].toInt() and 0xFF
        )
        S2K.ARGON_2 -> S2K.argon2S2K(
            S2K.Argon2Params(
                b.copyOfRange(1, 17),
                b[17].toInt() and 0xFF,
                b[18].toInt() and 0xFF,
                b[19].toInt() and 0xFF
            )
        )
        else -> throw ProtectedKeyException("unsupported S2K type $type")
    }
}
