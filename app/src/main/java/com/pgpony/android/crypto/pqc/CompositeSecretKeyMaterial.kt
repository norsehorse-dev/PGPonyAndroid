// CompositeSecretKeyMaterial.kt
// PGPony Android — 4.0.0 Phase 2b (slice 4b + protected keys)
//
// Extract the raw secret material from an IETF composite (algo 35) secret
// subkey. BouncyCastle parses the packet fine (v6 key-material length lets
// the public part land in an UnknownBCPGKey and the secret bytes are stored
// verbatim), but BC can't interpret algo-35 secret material, so we read it
// out of the encoded packet by hand.
//
// v6 secret (sub)key packet:
//   ver(1)=6 | ctime(4) | algo(1)=35 | pkMatLen(4)=1216 | pubMat(1216) |
//   s2kUsage(1) | [ v6 conditional S2K params ] | secretMaterial
// and for algo 35 the (decrypted) secretMaterial is exactly
//   X25519 secret (32) || ML-KEM-768 seed (64)   = 96 octets.
//
// Three protection forms are handled:
//   • usage 0        cleartext secret material
//   • usage 253      AEAD (RFC 9580 v6): sym | aead | S2K-len | S2K | nonce
//   • usage 254/255  CFB: sym | S2K-len | S2K | IV   (SHA-1 / 2-octet check)
//
// The S2K derivation and the AEAD/CFB decryption are done by BouncyCastle's
// own (tested, RFC 9580) PBESecretKeyDecryptor.recoverKeyData — we only
// hand-parse the packet fields and hand them over, because BC's high-level
// extractPrivateKey would then try (and fail) to parse the algo-35 result.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.S2K
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider

object CompositeSecretKeyMaterial {

    const val ALGORITHM_ID = CompositeKem.ALGORITHM_ID // 35

    /** ML-KEM-768 FIPS-203 seed length (d || z). */
    const val MLKEM768_SEED_LEN = 64

    private const val USAGE_NONE = 0
    private const val USAGE_AEAD = 253
    private const val USAGE_SHA1 = 254
    private const val USAGE_CHECKSUM = 255

    /** X25519 secret (32) + ML-KEM-768 seed (64), both raw. */
    data class Material(val x25519Secret: ByteArray, val mlkemSeed: ByteArray)

    class ProtectedKeyException(message: String) : Exception(message)

    /**
     * Raw composite secret material for an algo-35 [secKey], decrypting the
     * secret region with [passphrase] if the key is S2K-protected. Returns
     * null if the key isn't a composite. Throws [ProtectedKeyException] when
     * the key is protected but no passphrase was supplied.
     */
    fun extract(secKey: PGPSecretKey, passphrase: CharArray? = null): Material? {
        if (CompositeSuite.ietfFor(secKey.publicKey.algorithm) == null) return null
        return extractFromPacket(secKey.encoded, passphrase)
    }

    /**
     * Same as [extract] but operates directly on a single encoded secret
     * (sub)key packet — used to reach composite keys whose ring BC can't
     * parse (e.g. ML-DSA-signed keys) and for unit tests over raw fixtures.
     */
    fun extractFromPacket(packet: ByteArray, passphrase: CharArray?): Material {
        val (tag, body) = tagAndBody(packet)

        var i = 0
        val version = body[i++].toInt() and 0xFF
        require(version == 6) { "composite secret key must be v6, got v$version" }
        i += 4 // creation time
        val algo = body[i++].toInt() and 0xFF
        val suite = CompositeSuite.ietfFor(algo)
            ?: throw IllegalArgumentException("expected composite algo 35 or 36, got $algo")
        val pkMatLen = readUInt32(body, i); i += 4
        require(pkMatLen == suite.compositePubLen) {
            "composite public material must be ${suite.compositePubLen}, got $pkMatLen"
        }
        // AEAD AAD = the public-key packet contents (ver..pubMat), i.e. exactly
        // what BC's PublicKeyPacket.getEncodedContents() returns for v6.
        val pubkeyContents = body.copyOfRange(0, i + pkMatLen)
        i += pkMatLen

        val s2kUsage = body[i++].toInt() and 0xFF
        val secretMaterial: ByteArray = when (s2kUsage) {
            USAGE_NONE -> {
                val need = suite.curve.keyLen + suite.mlkem.seedLen
                require(body.size - i >= need) { "composite secret material truncated" }
                body.copyOfRange(i, i + need)
            }

            USAGE_AEAD, USAGE_SHA1, USAGE_CHECKSUM -> {
                if (passphrase == null) {
                    throw ProtectedKeyException("composite secret key is passphrase-protected")
                }
                decryptProtected(tag, version, s2kUsage, body, i, pubkeyContents, passphrase, suite)
            }

            else -> throw ProtectedKeyException("unsupported S2K usage $s2kUsage")
        }

        val x = secretMaterial.copyOfRange(0, suite.curve.keyLen)
        val seed = secretMaterial.copyOfRange(
            suite.curve.keyLen,
            suite.curve.keyLen + suite.mlkem.seedLen
        )
        return Material(x, seed)
    }

    // ── protected-key decryption ─────────────────────────────────────

    private fun decryptProtected(
        packetTag: Int,
        keyVersion: Int,
        s2kUsage: Int,
        body: ByteArray,
        offset: Int,
        pubkeyContents: ByteArray,
        passphrase: CharArray,
        suite: CompositeSuite
    ): ByteArray {
        var i = offset
        // v6: a one-octet count of all following conditional params (up to IV).
        val condLen = body[i++].toInt() and 0xFF
        val condStart = i

        val symAlg = body[i++].toInt() and 0xFF
        val aeadAlg = if (s2kUsage == USAGE_AEAD) body[i++].toInt() and 0xFF else 0
        val s2kLen = body[i++].toInt() and 0xFF
        val s2kBytes = body.copyOfRange(i, i + s2kLen); i += s2kLen
        val ivLen = condLen - (i - condStart)
        val iv = body.copyOfRange(i, i + ivLen); i += ivLen
        val encData = body.copyOfRange(i, body.size)

        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(passphrase)
        val s2k = buildS2K(s2kBytes)
        // 4.6.0 (item 17.5): bound an Argon2 S2K before running the KDF, as the classical unlock sites do.
        com.pgpony.android.crypto.enforceArgon2Policy(s2k)
        val s2kKey = decryptor.makeKeyFromPassPhrase(symAlg, s2k)

        return if (s2kUsage == USAGE_AEAD) {
            // AEAD strips its own 16-octet tag, leaving the 96 secret octets.
            decryptor.recoverKeyData(
                symAlg, aeadAlg, s2kKey, iv, packetTag, keyVersion, encData, pubkeyContents
            )
        } else {
            // CFB: recovered data is secret material followed by a checksum
            // (20-octet SHA-1 for usage 254, 2-octet sum for 255). We only
            // need the leading composite material; a wrong passphrase is
            // caught downstream when the recovered key fails to decrypt.
            val plain = decryptor.recoverKeyData(symAlg, s2kKey, iv, encData, 0, encData.size)
            val need = suite.curve.keyLen + suite.mlkem.seedLen
            require(plain.size >= need) { "recovered composite secret material too short" }
            plain.copyOfRange(0, need)
        }
    }

    /**
     * Rebuild an [S2K] from its raw specifier bytes. BC's S2K(InputStream)
     * parser is package-private, so we dispatch on the type octet to the
     * public factories instead.
     */
    private fun buildS2K(b: ByteArray): S2K = when (val type = b[0].toInt() and 0xFF) {
        S2K.SIMPLE -> S2K.simpleS2K(b[1].toInt() and 0xFF)
        S2K.SALTED -> S2K.saltedS2K(b[1].toInt() and 0xFF, b.copyOfRange(2, 10))
        S2K.SALTED_AND_ITERATED -> S2K.saltedAndIteratedS2K(
            b[1].toInt() and 0xFF, b.copyOfRange(2, 10), b[10].toInt() and 0xFF
        )
        S2K.ARGON_2 -> S2K.argon2S2K(
            S2K.Argon2Params(
                b.copyOfRange(1, 17),      // 16-octet salt
                b[17].toInt() and 0xFF,    // passes (t)
                b[18].toInt() and 0xFF,    // parallelism (p)
                b[19].toInt() and 0xFF     // memory-size exponent (m)
            )
        )
        else -> throw ProtectedKeyException("unsupported S2K type $type")
    }

    // ── packet / int helpers ─────────────────────────────────────────

    private fun readUInt32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or
            ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or
            (b[off + 3].toInt() and 0xFF)

    /** Return (packetTag, body) for a single encoded packet (new/old format). */
    private fun tagAndBody(packet: ByteArray): Pair<Int, ByteArray> {
        var i = 0
        val c = packet[i++].toInt() and 0xFF
        require(c and 0x80 != 0) { "not an OpenPGP packet header: ${c.toString(16)}" }
        val tag: Int
        val length: Int
        if (c and 0x40 != 0) { // new format
            tag = c and 0x3F
            val l0 = packet[i++].toInt() and 0xFF
            length = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (packet[i++].toInt() and 0xFF) + 192
                l0 == 255 -> readUInt32(packet, i).also { i += 4 }
                else -> throw IllegalArgumentException("partial length in key packet")
            }
        } else { // old format
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
