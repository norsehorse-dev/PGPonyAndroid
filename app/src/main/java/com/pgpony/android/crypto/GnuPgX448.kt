// GnuPgX448.kt
// PGPony Android, 4.7.3
//
// ECDH on Curve448 as GnuPG writes it: public-key algorithm 18 with the
// curve OID 1.3.101.111, which GnuPG and Kleopatra use for the encryption
// subkey of an Ed448 key (a LibrePGP v5 key, or the occasional v4 one).
//
// GnuPG keeps the X448 public value as the bare 56-octet u-coordinate,
// writes the ephemeral value in a PKESK the same way, and stores the secret
// scalar in its native octet order (gnupg common/kem.c: X448 has neither a
// point prefix nor a reversed scalar). Bouncy Castle 1.85 only accepts the
// 0x40-prefixed 57-octet form for both public values and reverses the
// scalar, as it does for Curve25519. Against a GnuPG key that meant:
//   - encrypting to it failed with "exception constructing public key",
//     because BC refused the unprefixed public value;
//   - decrypting with it refused GnuPG's unprefixed ephemeral value, and
//     would have used the wrong scalar.
// Found through a user's v5 Ed448 + X448 key. This object does the ECDH,
// the RFC 6637 KDF and the key wrap itself for these keys; everything else
// still goes through Bouncy Castle.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.card.Rfc6637
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.bcpg.ContainedPacket
import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.ECSecretBCPGKey
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.crypto.agreement.X448Agreement
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.RFC3394WrapEngine
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.X448PrivateKeyParameters
import org.bouncycastle.crypto.params.X448PublicKeyParameters
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.util.BigIntegers
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

object GnuPgX448 {

    const val POINT_LEN = 56
    private const val PREFIX = 0x40
    private const val ECDH = PublicKeyAlgorithmTags.ECDH

    /** OID 1.3.101.111 as it appears in the RFC 6637 KDF parameter. */
    val CURVE_OID: ByteArray = byteArrayOf(0x2B, 0x65, 0x6F)

    /** ECDH (algorithm 18) on Curve448, in either point encoding. */
    fun isX448Ecdh(packet: PublicKeyPacket): Boolean =
        packet.algorithm == ECDH &&
            (packet.key as? ECDHPublicBCPGKey)?.curveOID == EdECObjectIdentifiers.id_X448

    /**
     * True when the public value is GnuPG's bare form, the one Bouncy Castle
     * cannot encrypt to. A 0x40-prefixed key still goes through BC.
     */
    fun isGnuPgEncoded(packet: PublicKeyPacket): Boolean =
        isX448Ecdh(packet) && rawPublicValue(packet).size <= POINT_LEN

    private fun rawPublicValue(packet: PublicKeyPacket): ByteArray =
        BigIntegers.asUnsignedByteArray((packet.key as ECDHPublicBCPGKey).encodedPoint)

    /** The 56-octet u-coordinate, from either encoding. */
    fun publicPoint(packet: PublicKeyPacket): ByteArray = point(rawPublicValue(packet))

    /** A received X448 value: 56 octets bare, or 57 with the 0x40 prefix. */
    fun point(value: ByteArray): ByteArray = when {
        value.size == POINT_LEN + 1 && (value[0].toInt() and 0xFF) == PREFIX ->
            value.copyOfRange(1, value.size)
        value.size <= POINT_LEN -> leftPad(value, POINT_LEN)
        else -> throw PGPException("X448 value has ${value.size} octets")
    }

    /**
     * The fingerprint the RFC 6637 KDF takes: all 20 octets of a v4 one, the
     * leftmost 20 of a v5 one (as GnuPG and Bouncy Castle both do).
     */
    fun kdfFingerprint(packet: PublicKeyPacket): ByteArray =
        BcKeyFingerprintCalculator().calculateFingerprint(packet).copyOf(20)

    private fun kek(packet: PublicKeyPacket, shared: ByteArray): ByteArray {
        val ecdh = packet.key as ECDHPublicBCPGKey
        val hashId = ecdh.hashAlgorithm.toInt() and 0xFF
        val kekId = ecdh.symmetricKeyAlgorithm.toInt() and 0xFF
        val param = Rfc6637.kdfParam(CURVE_OID, hashId, kekId, kdfFingerprint(packet))
        return Rfc6637.deriveKek(shared, param, hashId, kekId)
    }

    private fun agree(privateKey: X448PrivateKeyParameters, publicPoint: ByteArray): ByteArray {
        val agreement = X448Agreement()
        agreement.init(privateKey)
        val shared = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X448PublicKeyParameters(publicPoint, 0), shared, 0)
        return shared
    }

    /** symAlgo ‖ sessionKey ‖ 16-bit sum, the v3 PKESK session info. */
    fun sessionInfo(symAlgo: Int, sessionKey: ByteArray): ByteArray {
        var sum = 0
        for (b in sessionKey) sum = (sum + (b.toInt() and 0xFF)) and 0xFFFF
        return byteArrayOf(symAlgo.toByte()) + sessionKey + byteArrayOf((sum ushr 8).toByte(), sum.toByte())
    }

    /** RFC 6637 section 8: PKCS#5 padding to a multiple of 8 octets. */
    fun pad(data: ByteArray): ByteArray {
        val n = 8 - data.size % 8
        return data + ByteArray(n) { n.toByte() }
    }

    /**
     * The PKESK algorithm fields for [recipient]: the ephemeral value as GnuPG
     * writes it (bare 56 octets, bit count 448), the wrapped-key length and the
     * AES-wrapped padded session info.
     */
    fun encryptSessionInfo(recipient: PublicKeyPacket, sessionInfo: ByteArray, random: SecureRandom): ByteArray {
        val gen = X448KeyPairGenerator()
        gen.init(X448KeyGenerationParameters(random))
        val eph = gen.generateKeyPair()
        val ephPublic = (eph.public as X448PublicKeyParameters).encoded
        val shared = agree(eph.private as X448PrivateKeyParameters, publicPoint(recipient))
        val wrap = RFC3394WrapEngine(AESEngine.newInstance())
        wrap.init(true, KeyParameter(kek(recipient, shared)))
        val padded = pad(sessionInfo)
        val wrapped = wrap.wrap(padded, 0, padded.size)
        return ByteArrayOutputStream().apply {
            val bits = POINT_LEN * 8
            write(bits ushr 8)
            write(bits and 0xFF)
            write(ephPublic)
            write(wrapped.size)
            write(wrapped)
        }.toByteArray()
    }

    /**
     * The secret scalar of [privateKey] in native order. GnuPG stores it as is
     * and Bouncy Castle reversed; whichever order gives back the key's own
     * public value is the right one, so a key from either kind of tool works.
     */
    fun nativeScalar(privateKey: PGPPrivateKey): X448PrivateKeyParameters {
        val secret = privateKey.privateKeyDataPacket as? ECSecretBCPGKey
            ?: throw PGPException("not an ECDH secret key")
        val stored = leftPad(BigIntegers.asUnsignedByteArray(secret.x), POINT_LEN)
        val expected = publicPoint(privateKey.publicKeyPacket)
        for (candidate in listOf(stored, stored.reversedArray())) {
            val key = X448PrivateKeyParameters(candidate, 0)
            if (key.generatePublicKey().encoded.contentEquals(expected)) return key
        }
        throw PGPException("X448 secret key does not match its public key")
    }

    /**
     * Recover symAlgo ‖ sessionKey ‖ sum from an ECDH PKESK's fields
     * ([fields] = MPI ephemeral ‖ wrapLen ‖ wrapped), for BC to check and use.
     */
    fun recoverSessionInfo(privateKey: PGPPrivateKey, fields: ByteArray): ByteArray {
        try {
            val bits = ((fields[0].toInt() and 0xFF) shl 8) or (fields[1].toInt() and 0xFF)
            val len = (bits + 7) / 8
            val ephemeral = point(fields.copyOfRange(2, 2 + len))
            val wrappedLen = fields[2 + len].toInt() and 0xFF
            val wrapped = fields.copyOfRange(3 + len, 3 + len + wrappedLen)
            val shared = agree(nativeScalar(privateKey), ephemeral)
            val unwrapped = Rfc6637.aesKeyUnwrap(kek(privateKey.publicKeyPacket, shared), wrapped)
            return Rfc6637.stripPad(unwrapped)
        } catch (e: PGPException) {
            throw e
        } catch (e: Exception) {
            throw PGPException("X448 session key recovery failed: ${e.message}", e)
        }
    }

    /** The method generator for [key]: this object's for GnuPG's X448 form, BC's otherwise. */
    fun encryptionMethod(key: PGPPublicKey): PGPKeyEncryptionMethodGenerator =
        if (isGnuPgEncoded(key.publicKeyPacket)) EncryptionMethodGenerator(key)
        else BcPublicKeyKeyEncryptionMethodGenerator(key)

    /** v3 PKESK for a GnuPG X448 recipient. */
    class EncryptionMethodGenerator(
        private val recipient: PGPPublicKey,
        private val random: SecureRandom = SecureRandom()
    ) : PGPKeyEncryptionMethodGenerator {
        override fun generate(dataEncryptorBuilder: PGPDataEncryptorBuilder, sessionKey: ByteArray): ContainedPacket {
            val info = sessionInfo(dataEncryptorBuilder.algorithm, sessionKey)
            val fields = encryptSessionInfo(recipient.publicKeyPacket, info, random)
            return PublicKeyEncSessionPacket.createV3PKESKPacket(recipient.keyID, ECDH, arrayOf(fields))
        }
    }

    /**
     * Bouncy Castle's decryptor, except for ECDH on Curve448, which this object
     * opens in either point encoding and either scalar order.
     */
    class DecryptorFactory(private val privateKey: PGPPrivateKey) : BcPublicKeyDataDecryptorFactory(privateKey) {
        private val ours = isX448Ecdh(privateKey.publicKeyPacket)

        override fun recoverSessionData(keyAlgorithm: Int, secKeyData: Array<ByteArray>): ByteArray =
            if (ours && keyAlgorithm == ECDH) recoverSessionInfo(privateKey, secKeyData[0])
            else super.recoverSessionData(keyAlgorithm, secKeyData)

        override fun recoverSessionData(keyAlgorithm: Int, secKeyData: Array<ByteArray>, pkeskVersion: Int): ByteArray =
            if (ours && keyAlgorithm == ECDH) recoverSessionInfo(privateKey, secKeyData[0])
            else super.recoverSessionData(keyAlgorithm, secKeyData, pkeskVersion)
    }

    private fun leftPad(value: ByteArray, size: Int): ByteArray =
        if (value.size >= size) value else ByteArray(size - value.size) + value
}
