// CompositeSignSubkeyGen.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Add a post-quantum composite ML-DSA + EdDSA SIGNING subkey (algo 30/31) to
// an existing v6 secret key ring whose primary is a classical EdDSA v6 key
// (Ed25519 or Ed448). This is the signing counterpart of CompositeKeyGen,
// which grafts a composite ENCRYPTION subkey; the signing case is harder
// because a signing subkey MUST carry an embedded Primary Key Binding
// signature (Type ID 0x19) that the subkey makes over the primary
// (RFC 9580 Sections 5.2.1.8 and 5.2.1.9).
//
// BouncyCastle can neither generate an algo-30 keypair nor sign with it, but
// it PARSES the v6 composite public key packet (the 4-octet key-material
// length routes the unknown algorithm into UnknownBCPGKey) and computes its
// v6 fingerprint correctly, exactly as CompositeKeyGen relies on for algo 35.
// So we hand-emit the subkey packets and both signatures:
//
//   * the 0x19 back-signature is a v6 composite signature made by the new
//     subkey over primary || subkey, produced with CompositeSigner;
//   * the 0x18 subkey-binding signature is a v6 EdDSA signature made by the
//     classical primary over the same primary || subkey, carrying the 0x19
//     back-signature as an Embedded Signature subpacket (Type ID 32).
//
// Both hashes follow RFC 9580 Section 5.2.4: salt, then each key as
// 0x9B || 4-octet length || key packet body (primary first, then subkey),
// then the standard v6 trailer. That is exactly what CompositeSigHash builds,
// so the digest helper is reused for both.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.ClassicalSubkeyGen
import org.bouncycastle.bcpg.AEADAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.Ed448Signer
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

object CompositeSignSubkeyGen {

    private const val TAG_PUBSUBKEY = 14
    private const val TAG_SECSUBKEY = 7
    private const val TAG_SIGNATURE = 2

    private const val HASH_SHA256 = 8
    private const val SALT_SHA256 = 16

    private const val SIGTYPE_SUBKEY_BINDING = 0x18
    private const val SIGTYPE_PRIMARY_BINDING = 0x19

    // Signature subpacket type ids (critical bit 0x80 set where noted).
    private const val SUBPKT_CREATION_TIME = 2
    private const val SUBPKT_KEY_EXPIRE = 9
    private const val SUBPKT_KEY_FLAGS = 27
    private const val SUBPKT_EMBEDDED_SIG = 32
    private const val SUBPKT_ISSUER_FP = 33

    private const val KEY_FLAG_SIGN = 0x02

    /**
     * Append a freshly generated composite [suite] signing subkey (with its
     * embedded back-signature and a primary-made binding signature) to
     * [secretRing] and return the new ring. The primary MUST be a v6 EdDSA key.
     * [passphrase] unlocks the primary and re-protects the new subkey (null or
     * empty for a passphrase-less key). [expirationSeconds] > 0 sets the
     * subkey's own expiry. Throws ClassicalSubkeyGen.SubkeyAddError so callers
     * catch every add-subkey path the same way.
     */
    fun addCompositeSigningSubkey(
        secretRing: PGPSecretKeyRing,
        suite: CompositeSignSuite = CompositeSignSuite.MLDSA65_ED25519,
        passphrase: String? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date(),
        expirationSeconds: Long? = null
    ): PGPSecretKeyRing {
        val primaryPub = secretRing.publicKey
        if (primaryPub.version != 6) {
            throw ClassicalSubkeyGen.SubkeyAddError(
                "a composite signing subkey needs a v6 primary, found version ${primaryPub.version}"
            )
        }
        val primaryAlgo = primaryPub.algorithm
        if (primaryAlgo != PublicKeyAlgorithmTags.Ed25519 && primaryAlgo != PublicKeyAlgorithmTags.Ed448) {
            throw ClassicalSubkeyGen.SubkeyAddError(
                "a composite signing subkey needs an EdDSA v6 primary, found algorithm $primaryAlgo"
            )
        }

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

        // 2. Emit the v6 subkey packet bodies (public and unprotected secret).
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
            write(0) // s2k usage: unprotected; v6 carries no material length
            write(compositeSecret)
        }.toByteArray()

        // 3. Subkey fingerprint (issuer of the back-signature): parse a temp
        //    public ring so BC computes the v6 fingerprint of the algo-30 key.
        val primaryPubBody = packetBody(primaryPub.encoded)
        val tempPub = ByteArrayOutputStream().apply {
            write(primaryPub.encoded)
            write(packet(TAG_PUBSUBKEY, pubBody))
        }.toByteArray()
        val subPub = PGPPublicKeyRing(ByteArrayInputStream(tempPub), JcaKeyFingerprintCalculator())
            .publicKeys.asSequence().first { !it.isMasterKey }
        val subFingerprint = subPub.fingerprint
        val primaryFingerprint = primaryPub.fingerprint

        // The key-binding hash body: primary key, then subkey, each as
        // 0x9B || 4-octet length || packet body (RFC 9580 Section 5.2.4).
        val keyBindingData = keyFrame(primaryPubBody) + keyFrame(pubBody)

        // 4. The 0x19 back-signature, made by the composite subkey.
        val backSigBody = try {
            buildCompositeBackSignature(
                suite, compositeSecret, keyBindingData, ctime, subFingerprint, random
            )
        } catch (e: Exception) {
            throw ClassicalSubkeyGen.SubkeyAddError("Could not build the subkey back-signature: ${e.message}", e)
        }

        // 5. The 0x18 subkey-binding signature, made by the classical primary,
        //    carrying the back-signature as an Embedded Signature subpacket.
        val primaryPriv = try {
            secretRing.secretKey.extractPrivateKey(
                BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
                    .build((passphrase ?: "").toCharArray())
            )
        } catch (e: PGPException) {
            throw ClassicalSubkeyGen.SubkeyAddError(
                "Could not unlock the primary key to bind the new subkey: ${e.message}", e
            )
        }
        val bindingPacket = try {
            buildPrimaryBindingSignature(
                primaryPriv, primaryAlgo, keyBindingData, ctime,
                primaryFingerprint, backSigBody, expirationSeconds, random
            )
        } catch (e: Exception) {
            throw ClassicalSubkeyGen.SubkeyAddError("Could not bind the new composite subkey: ${e.message}", e)
        }

        // 6. Assemble the ring and re-parse through BC.
        val assembled = ByteArrayOutputStream().apply {
            write(secretRing.encoded)
            write(packet(TAG_SECSUBKEY, secBody))
            write(bindingPacket)
        }.toByteArray()
        var ring = PGPSecretKeyRing(ByteArrayInputStream(assembled), JcaKeyFingerprintCalculator())

        // 7. Match the primary's protection: AEAD + Argon2 (v6), mirroring
        //    CompositeKeyGen, so a protected ring stores a protected subkey.
        if (!passphrase.isNullOrEmpty()) {
            val plain = ring.secretKeys.asSequence().first { it.publicKey.algorithm == suite.algId }
            val encryptor = BcAEADSecretKeyEncryptorBuilder(
                AEADAlgorithmTags.OCB,
                SymmetricKeyAlgorithmTags.AES_256,
                S2K.Argon2Params.memoryConstrainedParameters()
            ).setSecureRandom(random)
                .build(passphrase.toCharArray(), plain.publicKey.publicKeyPacket)
            val protectedSub = PGPSecretKey.copyWithNewPassword(plain, null, encryptor)
            ring = PGPSecretKeyRing.insertSecretKey(ring, protectedSub)
        }
        return ring
    }

    /** Derive the public key ring for a ring produced by [addCompositeSigningSubkey]. */
    fun publicRingOf(secretRing: PGPSecretKeyRing): PGPPublicKeyRing =
        PGPPublicKeyRing(secretRing.publicKeys.asSequence().toList())

    // -- signatures ---------------------------------------------------

    /**
     * A v6 0x19 Primary Key Binding signature packet BODY (for embedding),
     * made by the composite subkey over [keyBindingData] (primary || subkey).
     */
    private fun buildCompositeBackSignature(
        suite: CompositeSignSuite,
        compositeSecret: ByteArray,
        keyBindingData: ByteArray,
        ctime: Int,
        subFingerprint: ByteArray,
        random: SecureRandom
    ): ByteArray {
        val hashed = ByteArrayOutputStream().apply {
            write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32(ctime)))
            write(issuerFingerprintSubpacket(subFingerprint))
        }.toByteArray()

        val salt = ByteArray(SALT_SHA256).also { random.nextBytes(it) }
        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = HASH_SHA256,
            salt = salt,
            data = keyBindingData,
            signatureType = SIGTYPE_PRIMARY_BINDING,
            publicKeyAlgorithm = suite.algId,
            hashedSubpacketBody = hashed
        )
        val signature = CompositeSigner.sign(suite, compositeSecret, digest, random)
        return v6SignatureBody(
            SIGTYPE_PRIMARY_BINDING, suite.algId, hashed, unhashed = ByteArray(0),
            digest = digest, salt = salt, signatureMaterial = signature
        )
    }

    /**
     * A full v6 0x18 Subkey Binding signature PACKET, made by the classical
     * [primaryAlgo] primary over [keyBindingData], carrying [backSigBody] as an
     * Embedded Signature subpacket and the SIGN key flag.
     */
    private fun buildPrimaryBindingSignature(
        primaryPriv: PGPPrivateKey,
        primaryAlgo: Int,
        keyBindingData: ByteArray,
        ctime: Int,
        primaryFingerprint: ByteArray,
        backSigBody: ByteArray,
        expirationSeconds: Long?,
        random: SecureRandom
    ): ByteArray {
        val hashed = ByteArrayOutputStream().apply {
            write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32(ctime)))
            write(subpacket(SUBPKT_KEY_FLAGS or 0x80, byteArrayOf(KEY_FLAG_SIGN.toByte())))
            if (expirationSeconds != null && expirationSeconds > 0L) {
                write(subpacket(SUBPKT_KEY_EXPIRE, uint32(expirationSeconds.toInt())))
            }
            write(issuerFingerprintSubpacket(primaryFingerprint))
            write(subpacket(SUBPKT_EMBEDDED_SIG, backSigBody))
        }.toByteArray()

        val salt = ByteArray(SALT_SHA256).also { random.nextBytes(it) }
        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = HASH_SHA256,
            salt = salt,
            data = keyBindingData,
            signatureType = SIGTYPE_SUBKEY_BINDING,
            publicKeyAlgorithm = primaryAlgo,
            hashedSubpacketBody = hashed
        )
        val signature = signWithPrimary(primaryPriv, primaryAlgo, digest)
        val body = v6SignatureBody(
            SIGTYPE_SUBKEY_BINDING, primaryAlgo, hashed, unhashed = ByteArray(0),
            digest = digest, salt = salt, signatureMaterial = signature
        )
        return packet(TAG_SIGNATURE, body)
    }

    /** Ed25519/Ed448 native signature over [digest] by the v6 primary. */
    private fun signWithPrimary(primaryPriv: PGPPrivateKey, primaryAlgo: Int, digest: ByteArray): ByteArray {
        val params = BcPGPKeyConverter().getPrivateKey(primaryPriv)
        val signer = when (primaryAlgo) {
            PublicKeyAlgorithmTags.Ed25519 -> Ed25519Signer()
            PublicKeyAlgorithmTags.Ed448 -> Ed448Signer(ByteArray(0))
            else -> throw IllegalArgumentException("unsupported primary algorithm $primaryAlgo")
        }
        signer.init(true, params)
        signer.update(digest, 0, digest.size)
        return signer.generateSignature()
    }

    /**
     * A v6 signature packet body: version, type, algorithm, hash, hashed and
     * unhashed subpackets (each with a 4-octet count), the left 16 bits of the
     * digest, the salt (size then value), and the native signature material.
     */
    private fun v6SignatureBody(
        sigType: Int,
        pubAlgo: Int,
        hashed: ByteArray,
        unhashed: ByteArray,
        digest: ByteArray,
        salt: ByteArray,
        signatureMaterial: ByteArray
    ): ByteArray = ByteArrayOutputStream().apply {
        write(6)
        write(sigType)
        write(pubAlgo)
        write(HASH_SHA256)
        write(uint32(hashed.size))
        write(hashed)
        write(uint32(unhashed.size))
        write(unhashed)
        write(digest[0].toInt() and 0xFF)
        write(digest[1].toInt() and 0xFF)
        write(salt.size)
        write(salt)
        write(signatureMaterial)
    }.toByteArray()

    // -- subpacket + framing helpers ----------------------------------

    /** 0x9B || 4-octet length || key packet body (RFC 9580 Section 5.2.4). */
    private fun keyFrame(keyBody: ByteArray): ByteArray =
        byteArrayOf(0x9B.toByte()) + uint32(keyBody.size) + keyBody

    /** Issuer Fingerprint subpacket (type 33): version octet + 32-octet v6 fp. */
    private fun issuerFingerprintSubpacket(fingerprint: ByteArray): ByteArray =
        subpacket(SUBPKT_ISSUER_FP, byteArrayOf(6) + fingerprint)

    /**
     * A signature subpacket: length (1/2/5-octet), then the type octet, then
     * the body. The length covers the type octet and the body.
     */
    private fun subpacket(type: Int, body: ByteArray): ByteArray {
        val len = body.size + 1 // includes the type octet
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

    /** Return exactly the first packet's body from a single/leading packet encoding. */
    private fun packetBody(encoded: ByteArray): ByteArray {
        var i = 1
        val c = encoded[0].toInt() and 0xFF
        val len: Int
        if (c and 0x40 != 0) {
            val l0 = encoded[i++].toInt() and 0xFF
            len = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (encoded[i++].toInt() and 0xFF) + 192
                l0 == 255 -> uint32read(encoded, i).also { i += 4 }
                else -> encoded.size - i
            }
        } else {
            len = when (c and 0x03) {
                0 -> encoded[i++].toInt() and 0xFF
                1 -> (((encoded[i].toInt() and 0xFF) shl 8) or (encoded[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> uint32read(encoded, i).also { i += 4 }
                else -> encoded.size - i
            }
        }
        return encoded.copyOfRange(i, i + len)
    }

    private fun uint32read(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)
}
