// CompositeSecretProtection.kt
// PGPony Android, 4.4.0 RC4 (#26 for composite ML-DSA signing keys)
//
// Passphrase protection for the raw composite ML-DSA + EdDSA secret material of
// a composite PRIMARY key. Those keys are stored as raw OpenPGP octets because
// BouncyCastle rejects their algo-30/31 signatures, so the whole ring cannot be
// re-protected the way a classical or composite-subkey ring is (see
// PGPCryptoService.changePassphrase). This object protects/unlocks just the
// secret region of the composite primary's key packet.
//
// It does NOT hand-roll any cipher. To protect, the composite material is wrapped
// as a v6 SECRET SUBKEY under a throwaway classical v6 primary — a ring BC parses
// fine (the algo-30 key rides in an UnknownBCPGKey, exactly as CompositeSignSubkeyGen
// relies on) — and BC's own AEAD (OCB + Argon2id, RFC 9580 S2K usage 253) protects
// it via PGPSecretKey.copyWithNewPassword. The protected secret region is then
// spliced back into the real primary packet by the caller.
//
// AEAD tag consistency: BC binds the packet tag into the AEAD associated data.
// The material is protected as a subkey (tag 7), so [unlock] MUST present tag 7
// to BC's recoverKeyData too, even though the material lives on the wire inside a
// primary (tag 5) packet. PGPony is the only reader/writer of this secret, so the
// tag only has to be self-consistent, not match the enclosing packet. See
// [AAD_PACKET_TAG]. The public-key contents used as the rest of the AAD are the
// composite key's own public body, identical on both sides.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.AEADAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import java.io.ByteArrayInputStream
import java.util.Date
import java.security.SecureRandom

object CompositeSecretProtection {

    /** The material is protected as a v6 secret SUBKEY, so both sides use tag 7. */
    private const val AAD_PACKET_TAG = 7

    private const val USAGE_NONE = 0
    private const val USAGE_AEAD = 253
    private const val USAGE_SHA1 = 254
    private const val USAGE_CHECKSUM = 255

    class ProtectedKeyException(message: String) : Exception(message)

    /**
     * True if [secretKeyPacketBody] (a tag-5/6/7/14 key packet BODY, i.e. the
     * bytes after the packet header) carries a passphrase-protected secret,
     * i.e. its s2k-usage octet is non-zero.
     */
    fun isProtected(secretKeyPacketBody: ByteArray): Boolean {
        val usageOffset = publicBodyLen(secretKeyPacketBody)
        if (usageOffset >= secretKeyPacketBody.size) return false
        return (secretKeyPacketBody[usageOffset].toInt() and 0xFF) != USAGE_NONE
    }

    /**
     * Protect [secretMaterial] (the raw composite secret, EdDSA secret || ML-DSA
     * seed) under [passphrase], returning the SECRET REGION to store in place of
     * the "usage 0 || plaintext" tail of the composite primary's key packet:
     * the s2k-usage octet, the v6 conditional params, and the AEAD ciphertext.
     *
     * [compositePublicBody] is the composite key's public body
     * (version .. public material), used verbatim as the subkey's public part so
     * the AEAD associated data matches on [unlock].
     */
    fun protect(
        compositePublicBody: ByteArray,
        secretMaterial: ByteArray,
        passphrase: CharArray,
        random: SecureRandom = SecureRandom()
    ): ByteArray {
        require(passphrase.isNotEmpty()) { "protect requires a non-empty passphrase" }
        val compositeAlgo = compositePublicBody[1 + 4].toInt() and 0xFF

        // Throwaway v6 Ed25519 primary — only needed so BC will parse a ring that
        // carries the composite key as a subkey. Never stored.
        val impl = org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation()
        val gen = org.bouncycastle.openpgp.api.OpenPGPKeyGenerator(
            impl, PublicKeyPacket.VERSION_6, false, Date()
        )
        val throwaway = gen
            .withPrimaryKey(
                org.bouncycastle.openpgp.api.KeyPairGeneratorCallback { g -> g.generateEd25519KeyPair() }
            )
            .addUserId("composite-protect-temp")
            .build()
        val throwawayRing = throwaway.getPGPSecretKeyRing()

        // Composite key as an UNPROTECTED v6 secret subkey packet (tag 7):
        //   public body || s2k-usage 0 || secret material.
        val subSecBody = compositePublicBody + byteArrayOf(0) + secretMaterial
        val assembled = throwawayRing.encoded + packet(7, subSecBody)
        val ring = PGPSecretKeyRing(ByteArrayInputStream(assembled), JcaKeyFingerprintCalculator())
        val compositeSub = ring.secretKeys.asSequence()
            .firstOrNull { it.publicKey.algorithm == compositeAlgo }
            ?: throw ProtectedKeyException("BouncyCastle did not retain the composite subkey for protection")

        // BC's own AEAD + Argon2id protection (RFC 9580 usage 253), the same path
        // changePassphrase and CompositeKeyGen use for v6 keys.
        val encryptor = BcAEADSecretKeyEncryptorBuilder(
            AEADAlgorithmTags.OCB,
            SymmetricKeyAlgorithmTags.AES_256,
            S2K.Argon2Params.memoryConstrainedParameters()
        ).setSecureRandom(random)
            .build(passphrase, compositeSub.publicKey.publicKeyPacket)
        val protectedSub = PGPSecretKey.copyWithNewPassword(compositeSub, null, encryptor)

        // Return everything after the public body: usage octet, params, ciphertext.
        val body = packetBody(protectedSub.encoded)
        return body.copyOfRange(publicBodyLen(body), body.size)
    }

    /**
     * Recover the raw composite secret material ([expectedLen] octets) from a
     * composite primary's key packet BODY, decrypting with [passphrase] when the
     * key is protected. [passphrase] may be null for an unprotected key; a
     * protected key with no passphrase throws [ProtectedKeyException].
     */
    fun unlock(
        secretKeyPacketBody: ByteArray,
        passphrase: CharArray?,
        expectedLen: Int
    ): ByteArray {
        val body = secretKeyPacketBody
        var i = 1 + 4 + 1
        val matLen = readUInt32(body, i); i += 4
        val pubkeyContents = body.copyOfRange(0, i + matLen)
        i += matLen
        val usage = body[i++].toInt() and 0xFF

        return when (usage) {
            USAGE_NONE -> {
                require(body.size - i >= expectedLen) { "composite secret material truncated" }
                body.copyOfRange(i, i + expectedLen)
            }

            USAGE_AEAD, USAGE_SHA1, USAGE_CHECKSUM -> {
                if (passphrase == null) {
                    throw ProtectedKeyException("composite secret key is passphrase-protected")
                }
                decryptProtected(usage, body, i, pubkeyContents, passphrase, expectedLen)
            }

            else -> throw ProtectedKeyException("unsupported S2K usage $usage")
        }
    }

    // -- protected-key decryption (mirrors CompositeSecretKeyMaterial) --

    private fun decryptProtected(
        s2kUsage: Int,
        body: ByteArray,
        offset: Int,
        pubkeyContents: ByteArray,
        passphrase: CharArray,
        expectedLen: Int
    ): ByteArray {
        var i = offset
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
        val s2kKey = decryptor.makeKeyFromPassPhrase(symAlg, s2k)

        return if (s2kUsage == USAGE_AEAD) {
            decryptor.recoverKeyData(
                symAlg, aeadAlg, s2kKey, iv, AAD_PACKET_TAG, 6, encData, pubkeyContents
            )
        } else {
            val plain = decryptor.recoverKeyData(symAlg, s2kKey, iv, encData, 0, encData.size)
            require(plain.size >= expectedLen) { "recovered composite secret material too short" }
            plain.copyOfRange(0, expectedLen)
        }
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

    // -- packet / int helpers --

    /** Length of the public-key body prefix (version .. public material). */
    private fun publicBodyLen(keyPacketBody: ByteArray): Int {
        var q = 1 + 4 + 1
        val matLen = readUInt32(keyPacketBody, q); q += 4
        return q + matLen
    }

    private fun readUInt32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    private fun uint32(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun packet(tag: Int, body: ByteArray): ByteArray {
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

    /** The body of the first packet in [encoded] (new/old format header). */
    private fun packetBody(encoded: ByteArray): ByteArray {
        var i = 1
        val c = encoded[0].toInt() and 0xFF
        val len: Int
        if (c and 0x40 != 0) {
            val l0 = encoded[i++].toInt() and 0xFF
            len = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (encoded[i++].toInt() and 0xFF) + 192
                l0 == 255 -> readUInt32(encoded, i).also { i += 4 }
                else -> encoded.size - i
            }
        } else {
            len = when (c and 0x03) {
                0 -> encoded[i++].toInt() and 0xFF
                1 -> (((encoded[i].toInt() and 0xFF) shl 8) or (encoded[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> readUInt32(encoded, i).also { i += 4 }
                else -> encoded.size - i
            }
        }
        return encoded.copyOfRange(i, i + len)
    }
}
