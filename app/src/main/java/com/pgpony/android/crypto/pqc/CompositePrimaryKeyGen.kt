// CompositePrimaryKeyGen.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Generate a v6 key whose PRIMARY is a post-quantum composite ML-DSA + EdDSA
// signing key (algo 30/31), self-certified. This is the keygen counterpart of
// CompositeSignSubkeyGen (which grafts a composite signing subkey onto a
// classical primary); here the composite key IS the primary, so it signs its
// own certifications with CompositeSigner.
//
// The emitted transferable secret key mirrors RFC 9980 Appendix A.3.1's
// primary portion:
//
//   * a v6 composite secret key packet (algo 30),
//   * a v6 Direct Key self-signature (Type ID 0x1F) carrying the key flags
//     {certify, sign} and features, and
//   * a User ID packet followed by a v6 positive certification self-signature
//     (Type ID 0x13).
//
// Both self-signatures are composite, made over the standard v6 hashes
// (RFC 9580 Section 5.2.4): the Direct Key signature over 0x9B || len || the
// primary key body; the certification over that key body followed by
// 0xB4 || 4-octet length || the User ID. CompositeSigHash builds each digest.
//
// [assemble] returns the raw unprotected ring octets and touches no
// BouncyCastle parsing, so its output can be verified with CompositeSigVerifier
// independently. [generate] additionally parses the ring through BouncyCastle
// (which routes the algo-30 key into UnknownBCPGKey) and applies passphrase
// protection.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.AEADAlgorithmTags
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Date

object CompositePrimaryKeyGen {

    private const val TAG_SECKEY = 5
    private const val TAG_SECSUBKEY = 7
    private const val TAG_SIGNATURE = 2
    private const val TAG_USERID = 13

    private const val SIGTYPE_SUBKEY_BINDING = 0x18

    /** The composite primary's encryption subkey: IETF ML-KEM-768 + X25519 (algo 35). */
    private val KEM_SUITE = CompositeSuite.IETF_768

    private const val HASH_SHA256 = 8
    private const val SALT_SHA256 = 16

    private const val SIGTYPE_POSITIVE_CERT = 0x13
    private const val SIGTYPE_DIRECT_KEY = 0x1F

    private const val SUBPKT_CREATION_TIME = 2
    private const val SUBPKT_KEY_EXPIRE = 9
    private const val SUBPKT_PREFERRED_HASH = 21
    private const val SUBPKT_KEY_FLAGS = 27
    private const val SUBPKT_FEATURES = 30
    private const val SUBPKT_ISSUER_FP = 33

    private const val KEY_FLAG_CERTIFY = 0x01
    private const val KEY_FLAG_SIGN = 0x02
    private const val KEY_FLAG_ENCRYPT_COMMS = 0x04
    private const val KEY_FLAG_ENCRYPT_STORAGE = 0x08
    private const val FEATURE_SEIPD_V1 = 0x01
    private const val FEATURE_SEIPD_V2 = 0x08

    /** Raw unprotected transferable secret key octets for a composite primary. */
    fun assemble(
        userId: String,
        suite: CompositeSignSuite = CompositeSignSuite.MLDSA65_ED25519,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date(),
        expirationSeconds: Long? = null
    ): ByteArray {
        // 1. Fresh composite material: EdDSA keypair + ML-DSA seed (expanded by BC).
        val (edPub, edSec) = when (suite.eddsa) {
            EdDsaCurve.ED25519 -> {
                val sk = Ed25519PrivateKeyParameters(random)
                sk.generatePublicKey().encoded to sk.encoded
            }
            EdDsaCurve.ED448 -> {
                val sk = Ed448PrivateKeyParameters(random)
                sk.generatePublicKey().encoded to sk.encoded
            }
        }
        val mldsaSeed = ByteArray(suite.mldsa.seedLen).also { random.nextBytes(it) }
        val mldsaPub = MLDSAPrivateKeyParameters(suite.mldsa.params, mldsaSeed)
            .publicKeyParameters.encoded
        val compositeSecret = suite.join(edSec, mldsaSeed)
        val ctime = (creationTime.time / 1000L).toInt()

        // 2. Emit the v6 primary packet bodies.
        val pubMat = suite.join(edPub, mldsaPub)
        val pubBody = ByteArrayOutputStream().apply {
            write(6)
            write(uint32(ctime))
            write(suite.algId)
            write(uint32(pubMat.size))
            write(pubMat)
        }.toByteArray()
        val secBody = ByteArrayOutputStream().apply {
            write(pubBody)
            write(0) // s2k usage: unprotected
            write(compositeSecret)
        }.toByteArray()

        val fingerprint = v6Fingerprint(pubBody)
        val keyOnly = keyFrame(pubBody)

        // 3. Direct Key self-signature (0x1F) over the primary key alone.
        val directHashed = ByteArrayOutputStream().apply {
            write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32(ctime)))
            write(subpacket(SUBPKT_KEY_FLAGS or 0x80, byteArrayOf((KEY_FLAG_CERTIFY or KEY_FLAG_SIGN).toByte())))
            if (expirationSeconds != null && expirationSeconds > 0L) {
                write(subpacket(SUBPKT_KEY_EXPIRE, uint32(expirationSeconds.toInt())))
            }
            write(subpacket(SUBPKT_PREFERRED_HASH, byteArrayOf(HASH_SHA256.toByte(), 10, 9)))
            write(subpacket(SUBPKT_FEATURES, byteArrayOf((FEATURE_SEIPD_V1 or FEATURE_SEIPD_V2).toByte())))
            write(issuerFingerprintSubpacket(fingerprint))
        }.toByteArray()
        val directSig = compositeSignaturePacket(
            suite, compositeSecret, SIGTYPE_DIRECT_KEY, keyOnly, directHashed, random
        )

        // 4. User ID and its positive certification self-signature (0x13).
        val uid = userId.toByteArray(Charsets.UTF_8)
        val certData = keyOnly + byteArrayOf(0xB4.toByte()) + uint32(uid.size) + uid
        val certHashed = ByteArrayOutputStream().apply {
            write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32(ctime)))
            write(subpacket(SUBPKT_KEY_FLAGS or 0x80, byteArrayOf((KEY_FLAG_CERTIFY or KEY_FLAG_SIGN).toByte())))
            write(issuerFingerprintSubpacket(fingerprint))
        }.toByteArray()
        val certSig = compositeSignaturePacket(
            suite, compositeSecret, SIGTYPE_POSITIVE_CERT, certData, certHashed, random
        )

        // 5. ML-KEM-768 + X25519 encryption subkey (algo 35), bound to the
        //    composite primary with a composite 0x18 binding (no back-signature,
        //    an encryption subkey does not make one).
        val xkp = X25519KeyPairGenerator()
            .apply { init(X25519KeyGenerationParameters(random)) }.generateKeyPair()
        val xPub = (xkp.public as X25519PublicKeyParameters).encoded
        val xSec = (xkp.private as X25519PrivateKeyParameters).encoded
        val mkp = MLKEMKeyPairGenerator()
            .apply { init(MLKEMKeyGenerationParameters(random, KEM_SUITE.mlkem.params)) }
            .generateKeyPair()
        val mPub = (mkp.public as MLKEMPublicKeyParameters).encoded
        val mSeed = (mkp.private as MLKEMPrivateKeyParameters).seed
            ?: error("BC ML-KEM keypair missing seed")

        val kemPubMat = xPub + mPub // 1216
        val kemPubBody = ByteArrayOutputStream().apply {
            write(6)
            write(uint32(ctime))
            write(KEM_SUITE.ietfAlgId) // 35
            write(uint32(kemPubMat.size))
            write(kemPubMat)
        }.toByteArray()
        val kemSecBody = ByteArrayOutputStream().apply {
            write(kemPubBody)
            write(0) // s2k usage: unprotected
            write(xSec)
            write(mSeed)
        }.toByteArray()

        val kemHashed = ByteArrayOutputStream().apply {
            write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32(ctime)))
            write(subpacket(SUBPKT_KEY_FLAGS or 0x80,
                byteArrayOf((KEY_FLAG_ENCRYPT_COMMS or KEY_FLAG_ENCRYPT_STORAGE).toByte())))
            if (expirationSeconds != null && expirationSeconds > 0L) {
                write(subpacket(SUBPKT_KEY_EXPIRE, uint32(expirationSeconds.toInt())))
            }
            write(issuerFingerprintSubpacket(fingerprint))
        }.toByteArray()
        val kemBindingData = keyOnly + keyFrame(kemPubBody)
        val kemBinding = compositeSignaturePacket(
            suite, compositeSecret, SIGTYPE_SUBKEY_BINDING, kemBindingData, kemHashed, random
        )

        // 6. Assemble the transferable secret key.
        return ByteArrayOutputStream().apply {
            write(packet(TAG_SECKEY, secBody))
            write(directSig)
            write(packet(TAG_USERID, uid))
            write(certSig)
            write(packet(TAG_SECSUBKEY, kemSecBody))
            write(kemBinding)
        }.toByteArray()
    }

    /**
     * Parse [assemble]'s output through BouncyCastle and, if [passphrase] is
     * set, protect the primary secret key with AEAD + Argon2 (matching the v6
     * composite subkey path). Throws if BouncyCastle cannot parse the ring.
     */
    fun generate(
        userId: String,
        suite: CompositeSignSuite = CompositeSignSuite.MLDSA65_ED25519,
        passphrase: String? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date(),
        expirationSeconds: Long? = null
    ): PGPSecretKeyRing {
        val raw = assemble(userId, suite, random, creationTime, expirationSeconds)
        var ring = PGPSecretKeyRing(ByteArrayInputStream(raw), JcaKeyFingerprintCalculator())
        if (!passphrase.isNullOrEmpty()) {
            val plain = ring.secretKey
            val encryptor = BcAEADSecretKeyEncryptorBuilder(
                AEADAlgorithmTags.OCB,
                SymmetricKeyAlgorithmTags.AES_256,
                S2K.Argon2Params.memoryConstrainedParameters()
            ).setSecureRandom(random)
                .build(passphrase.toCharArray(), plain.publicKey.publicKeyPacket)
            val protectedKey = PGPSecretKey.copyWithNewPassword(plain, null, encryptor)
            ring = PGPSecretKeyRing.insertSecretKey(ring, protectedKey)
        }
        return ring
    }

    // -- helpers ------------------------------------------------------

    private fun compositeSignaturePacket(
        suite: CompositeSignSuite,
        compositeSecret: ByteArray,
        sigType: Int,
        data: ByteArray,
        hashed: ByteArray,
        random: SecureRandom
    ): ByteArray {
        val salt = ByteArray(SALT_SHA256).also { random.nextBytes(it) }
        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = HASH_SHA256,
            salt = salt,
            data = data,
            signatureType = sigType,
            publicKeyAlgorithm = suite.algId,
            hashedSubpacketBody = hashed
        )
        val signature = CompositeSigner.sign(suite, compositeSecret, digest, random)
        val body = ByteArrayOutputStream().apply {
            write(6)
            write(sigType)
            write(suite.algId)
            write(HASH_SHA256)
            write(uint32(hashed.size))
            write(hashed)
            write(uint32(0)) // no unhashed subpackets
            write(digest[0].toInt() and 0xFF)
            write(digest[1].toInt() and 0xFF)
            write(salt.size)
            write(salt)
            write(signature)
        }.toByteArray()
        return packet(TAG_SIGNATURE, body)
    }

    /** v6 fingerprint: SHA-256 of 0x9B || 4-octet length || public key body. */
    private fun v6Fingerprint(pubBody: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(keyFrame(pubBody))

    private fun keyFrame(pubBody: ByteArray): ByteArray =
        byteArrayOf(0x9B.toByte()) + uint32(pubBody.size) + pubBody

    private fun issuerFingerprintSubpacket(fingerprint: ByteArray): ByteArray =
        subpacket(SUBPKT_ISSUER_FP, byteArrayOf(6) + fingerprint)

    private fun subpacket(type: Int, body: ByteArray): ByteArray {
        val len = body.size + 1
        val header = when {
            len < 192 -> byteArrayOf(len.toByte())
            len < 8384 -> {
                val l = len - 192
                byteArrayOf((0xC0 or (l shr 8)).toByte(), (l and 0xFF).toByte())
            }
            else -> byteArrayOf(0xFF.toByte()) + uint32(len)
        }
        return header + byteArrayOf(type.toByte()) + body
    }

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

    private fun uint32(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
}
