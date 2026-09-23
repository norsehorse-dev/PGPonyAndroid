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
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.X448PrivateKeyParameters
import org.bouncycastle.crypto.params.X448PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import com.pgpony.android.crypto.ClassicalSubkeyGen
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
    private const val SIGTYPE_SUBKEY_REVOCATION = 0x28

    /** The composite primary's encryption subkey: IETF ML-KEM-768 + X25519 (algo 35). */
    /**
     * 4.6.0 (item 3): the bundled encryption subkey matches the signing tier:
     * ML-DSA-65 + Ed25519 ships ML-KEM-768 + X25519, ML-DSA-87 + Ed448 ships
     * ML-KEM-1024 + X448.
     */
    fun kemSuiteFor(suite: CompositeSignSuite): CompositeSuite = when (suite) {
        CompositeSignSuite.MLDSA87_ED448 -> CompositeSuite.IETF_1024
        else -> CompositeSuite.IETF_768
    }

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
    private const val SUBPKT_REASON_FOR_REVOCATION = 29

    private const val KEY_FLAG_CERTIFY = 0x01
    private const val KEY_FLAG_SIGN = 0x02
    private const val KEY_FLAG_ENCRYPT_COMMS = 0x04
    private const val KEY_FLAG_ENCRYPT_STORAGE = 0x08
    private const val KEY_FLAG_AUTHENTICATE = 0x20
    private const val SIGTYPE_PRIMARY_BINDING = 0x19
    private const val SUBPKT_EMBEDDED_SIG = 32
    private const val TAG_PUBSUBKEY = 14
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

        // 5. ML-KEM encryption subkey (algo 35 or 36, see kemSuiteFor), bound to
        //    the composite primary with a composite 0x18 binding (no back-
        //    signature, an encryption subkey does not make one).
        val kemSuite = kemSuiteFor(suite)
        val (xPub, xSec) = when (kemSuite.curve) {
            EccCurve.X448 -> {
                val kp = X448KeyPairGenerator()
                    .apply { init(X448KeyGenerationParameters(random)) }.generateKeyPair()
                (kp.public as X448PublicKeyParameters).encoded to (kp.private as X448PrivateKeyParameters).encoded
            }
            else -> {
                val kp = X25519KeyPairGenerator()
                    .apply { init(X25519KeyGenerationParameters(random)) }.generateKeyPair()
                (kp.public as X25519PublicKeyParameters).encoded to (kp.private as X25519PrivateKeyParameters).encoded
            }
        }
        val mkp = MLKEMKeyPairGenerator()
            .apply { init(MLKEMKeyGenerationParameters(random, kemSuite.mlkem.params)) }
            .generateKeyPair()
        val mPub = (mkp.public as MLKEMPublicKeyParameters).encoded
        val mSeed = (mkp.private as MLKEMPrivateKeyParameters).seed
            ?: error("BC ML-KEM keypair missing seed")

        val kemPubMat = xPub + mPub // 1216 (768) or 1624 (1024)
        val kemPubBody = ByteArrayOutputStream().apply {
            write(6)
            write(uint32(ctime))
            write(kemSuite.ietfAlgId) // 35 or 36
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

    /**
     * item 4 (#55): add a User ID to an existing composite ML-DSA primary.
     * [ring] is the transferable secret key octets. Builds the User ID packet
     * plus a v6 composite positive certification (0x13) over the primary key
     * body and the new User ID, with the same composite signer keygen uses, and
     * splices both in before the first subkey (User IDs precede subkeys in a
     * transferable key). [passphrase] unlocks a protected primary; the returned
     * ring is UNPROTECTED (re-protect via CompositeKeyFacade.reprotect if the
     * original was protected).
     */
    fun addUserId(
        ring: ByteArray,
        newUserId: String,
        passphrase: CharArray? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date()
    ): ByteArray {
        val info = CompositeKeyFacade.parse(ring, passphrase)
        val compositeSecret = info.compositeSecret
            ?: throw IllegalStateException("composite primary secret is locked or unavailable")
        val suite = info.suite

        // Rebuild the primary public key body from the parsed material; it is
        // byte-identical to the original, so the fingerprint and the key hash
        // that the certification covers match.
        val pubBody = ByteArrayOutputStream().apply {
            write(6)
            write(uint32((info.creationTimeMillis / 1000L).toInt()))
            write(suite.algId)
            write(uint32(info.compositePublic.size))
            write(info.compositePublic)
        }.toByteArray()
        val keyOnly = keyFrame(pubBody)

        val uid = newUserId.toByteArray(Charsets.UTF_8)
        val certData = keyOnly + byteArrayOf(0xB4.toByte()) + uint32(uid.size) + uid
        val certHashed = ByteArrayOutputStream().apply {
            write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32((creationTime.time / 1000L).toInt())))
            write(subpacket(SUBPKT_KEY_FLAGS or 0x80, byteArrayOf((KEY_FLAG_CERTIFY or KEY_FLAG_SIGN).toByte())))
            write(issuerFingerprintSubpacket(info.fingerprint))
        }.toByteArray()
        val certSig = compositeSignaturePacket(
            suite, compositeSecret, SIGTYPE_POSITIVE_CERT, certData, certHashed, random
        )
        val uidPacket = packet(TAG_USERID, uid)

        val insertAt = firstSubkeyOffset(ring)
        return ByteArrayOutputStream().apply {
            write(ring, 0, insertAt)
            write(uidPacket)
            write(certSig)
            write(ring, insertAt, ring.size - insertAt)
        }.toByteArray()
    }

    /**
     * item 16 (#54): revoke a subkey of a composite ML-DSA primary. Builds a v6
     * composite subkey-revocation self-signature (Type ID 0x28) over the
     * primary key body followed by the target subkey body (the same data a
     * 0x18 binding covers), carrying a Reason for Revocation subpacket
     * (type 29: [reasonCode] octet then optional UTF-8 [reasonText]). The
     * revocation is spliced in after the subkey's existing signatures, so the
     * subkey stays present but marked revoked. [subkeyFingerprint] is the
     * target subkey's v6 fingerprint; [passphrase] unlocks a protected primary.
     * The returned ring is UNPROTECTED (re-protect via
     * CompositeKeyFacade.reprotect if the original was protected).
     */
    fun revokeSubkey(
        ring: ByteArray,
        subkeyFingerprint: ByteArray,
        reasonCode: Int = 0,
        reasonText: String = "",
        passphrase: CharArray? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date()
    ): ByteArray {
        val info = CompositeKeyFacade.parse(ring, passphrase)
        val compositeSecret = info.compositeSecret
            ?: throw IllegalStateException("composite primary secret is locked or unavailable")
        val suite = info.suite

        val primaryPubBody = ByteArrayOutputStream().apply {
            write(6)
            write(uint32((info.creationTimeMillis / 1000L).toInt()))
            write(suite.algId)
            write(uint32(info.compositePublic.size))
            write(info.compositePublic)
        }.toByteArray()
        val primaryFrame = keyFrame(primaryPubBody)

        // Find the target subkey and the end of its packet group (the subkey
        // packet plus every signature that already binds it).
        val spans = packetSpans(ring)
        var subkeyBody: ByteArray? = null
        var insertAt = -1
        for ((idx, span) in spans.withIndex()) {
            if (span.tag != TAG_SECSUBKEY && span.tag != 14) continue
            val subPubBody = publicKeyBody(span.body)
            if (!v6Fingerprint(subPubBody).contentEquals(subkeyFingerprint)) continue
            subkeyBody = subPubBody
            var j = idx + 1
            var end = span.end
            while (j < spans.size && spans[j].tag == TAG_SIGNATURE) {
                end = spans[j].end
                j++
            }
            insertAt = end
            break
        }
        val subPubBody = subkeyBody
            ?: throw IllegalArgumentException("subkey not found in this key")

        val revokeData = primaryFrame + keyFrame(subPubBody)
        val reasonBytes = reasonText.toByteArray(Charsets.UTF_8)
        val revHashed = ByteArrayOutputStream().apply {
            write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32((creationTime.time / 1000L).toInt())))
            write(subpacket(SUBPKT_REASON_FOR_REVOCATION, byteArrayOf(reasonCode.toByte()) + reasonBytes))
            write(issuerFingerprintSubpacket(info.fingerprint))
        }.toByteArray()
        val revSig = compositeSignaturePacket(
            suite, compositeSecret, SIGTYPE_SUBKEY_REVOCATION, revokeData, revHashed, random
        )

        return ByteArrayOutputStream().apply {
            write(ring, 0, insertAt)
            write(revSig)
            write(ring, insertAt, ring.size - insertAt)
        }.toByteArray()
    }

    /**
     * item 16 (#54): remove a subkey from a composite ML-DSA primary (local
     * delete, no revocation). Strips the target subkey packet and every
     * signature bound to it. [subkeyFingerprint] is the subkey's v6
     * fingerprint. Returns the ring without that subkey; throws if absent.
     */
    fun removeSubkey(ring: ByteArray, subkeyFingerprint: ByteArray): ByteArray {
        val spans = packetSpans(ring)
        var removeStart = -1
        var removeEnd = -1
        for ((idx, span) in spans.withIndex()) {
            if (span.tag != TAG_SECSUBKEY && span.tag != 14) continue
            if (!v6Fingerprint(publicKeyBody(span.body)).contentEquals(subkeyFingerprint)) continue
            removeStart = span.start
            var j = idx + 1
            var end = span.end
            while (j < spans.size && spans[j].tag == TAG_SIGNATURE) {
                end = spans[j].end
                j++
            }
            removeEnd = end
            break
        }
        if (removeStart < 0) throw IllegalArgumentException("subkey not found in this key")
        return ByteArrayOutputStream().apply {
            write(ring, 0, removeStart)
            write(ring, removeEnd, ring.size - removeEnd)
        }.toByteArray()
    }

    /**
     * 4.5.1: remove a User ID from a composite ML-DSA primary (local delete,
     * no revocation). Strips the matching User ID packet and every signature
     * bound to it. Purely structural: no signing, the protected primary is
     * untouched, and no passphrase is needed. Refuses the last User ID; throws
     * if the User ID is absent.
     */
    fun removeUserId(ring: ByteArray, userId: String): ByteArray {
        val target = userId.toByteArray(Charsets.UTF_8)
        val spans = packetSpans(ring)
        if (spans.count { it.tag == TAG_USERID } <= 1) {
            throw IllegalStateException("Cannot remove the only User ID on this key")
        }
        var removeStart = -1
        var removeEnd = -1
        for ((idx, span) in spans.withIndex()) {
            if (span.tag != TAG_USERID) continue
            if (!span.body.contentEquals(target)) continue
            removeStart = span.start
            var j = idx + 1
            var end = span.end
            while (j < spans.size && spans[j].tag == TAG_SIGNATURE) {
                end = spans[j].end
                j++
            }
            removeEnd = end
            break
        }
        if (removeStart < 0) throw IllegalArgumentException("User ID not found in this key")
        return ByteArrayOutputStream().apply {
            write(ring, 0, removeStart)
            write(ring, removeEnd, ring.size - removeEnd)
        }.toByteArray()
    }

    /** Byte offset of the first subkey packet (tag 7 secret / 14 public), where
     *  a new User ID and its certification must be inserted; ring end if none. */
    private fun firstSubkeyOffset(ring: ByteArray): Int {
        var i = 0
        while (i < ring.size) {
            val start = i
            val c = ring[i++].toInt() and 0xFF
            if (c and 0x80 == 0) break
            val tag: Int
            val len: Int
            if (c and 0x40 != 0) {
                tag = c and 0x3F
                val l0 = ring[i++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0
                    l0 < 224 -> ((l0 - 192) shl 8) + (ring[i++].toInt() and 0xFF) + 192
                    l0 == 255 -> beInt(ring, i).also { i += 4 }
                    else -> throw IllegalStateException("partial length unsupported in a composite key")
                }
            } else {
                tag = (c shr 2) and 0x0F
                len = when (c and 0x03) {
                    0 -> ring[i++].toInt() and 0xFF
                    1 -> (((ring[i].toInt() and 0xFF) shl 8) or (ring[i + 1].toInt() and 0xFF)).also { i += 2 }
                    2 -> beInt(ring, i).also { i += 4 }
                    else -> ring.size - i
                }
            }
            if (tag == TAG_SECSUBKEY || tag == 14) return start
            i += len
        }
        return ring.size
    }

    private fun beInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    private data class PacketSpan(val tag: Int, val start: Int, val end: Int, val body: ByteArray)

    /** Walk the ring into packet spans (tag, byte offsets, body), so a
     *  revocation can be spliced at an exact packet boundary. */
    private fun packetSpans(ring: ByteArray): List<PacketSpan> {
        val out = ArrayList<PacketSpan>()
        var i = 0
        while (i < ring.size) {
            val start = i
            val c = ring[i++].toInt() and 0xFF
            if (c and 0x80 == 0) break
            val tag: Int
            val len: Int
            if (c and 0x40 != 0) {
                tag = c and 0x3F
                val l0 = ring[i++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0
                    l0 < 224 -> ((l0 - 192) shl 8) + (ring[i++].toInt() and 0xFF) + 192
                    l0 == 255 -> beInt(ring, i).also { i += 4 }
                    else -> throw IllegalStateException("partial length unsupported in a composite key")
                }
            } else {
                tag = (c shr 2) and 0x0F
                len = when (c and 0x03) {
                    0 -> ring[i++].toInt() and 0xFF
                    1 -> (((ring[i].toInt() and 0xFF) shl 8) or (ring[i + 1].toInt() and 0xFF)).also { i += 2 }
                    2 -> beInt(ring, i).also { i += 4 }
                    else -> ring.size - i
                }
            }
            val body = ring.copyOfRange(i, i + len)
            i += len
            out.add(PacketSpan(tag, start, i, body))
        }
        return out
    }

    /** The leading public-key body of a (secret or public) key packet body. */
    private fun publicKeyBody(keyPacketBody: ByteArray): ByteArray {
        var q = 1 + 4 + 1
        val matLen = beInt(keyPacketBody, q); q += 4
        return keyPacketBody.copyOfRange(0, q + matLen)
    }

    // -- add subkey (raw composite primary) --------------------------

    private class PrimaryCtx(
        val suite: CompositeSignSuite,
        val secret: ByteArray,
        val fingerprint: ByteArray,
        val pubBody: ByteArray
    )

    /** Parse and unlock the composite primary, and rebuild its public body. */
    private fun primaryContext(ring: ByteArray, passphrase: CharArray?): PrimaryCtx {
        val info = CompositeKeyFacade.parse(ring, passphrase)
        val secret = info.compositeSecret
            ?: throw IllegalStateException("composite primary secret is locked or unavailable")
        val pubBody = v6PubBody((info.creationTimeMillis / 1000L).toInt(), info.suite.algId, info.compositePublic)
        return PrimaryCtx(info.suite, secret, info.fingerprint, pubBody)
    }

    private fun v6PubBody(ctime: Int, algId: Int, material: ByteArray): ByteArray =
        ByteArrayOutputStream().apply {
            write(6)
            write(uint32(ctime))
            write(algId)
            write(uint32(material.size))
            write(material)
        }.toByteArray()

    /**
     * Sign a v6 0x18 subkey-binding over primary||subkey with the composite
     * primary, then append the secret subkey packet and the binding to [ring].
     */
    private fun bindAndAppend(
        ring: ByteArray,
        ctx: PrimaryCtx,
        subPubBody: ByteArray,
        subSecBody: ByteArray,
        hashed: ByteArray,
        random: SecureRandom
    ): ByteArray {
        val bindingData = keyFrame(ctx.pubBody) + keyFrame(subPubBody)
        val binding = compositeSignaturePacket(ctx.suite, ctx.secret, SIGTYPE_SUBKEY_BINDING, bindingData, hashed, random)
        return ByteArrayOutputStream().apply {
            write(ring)
            write(packet(TAG_SECSUBKEY, subSecBody))
            write(binding)
        }.toByteArray()
    }

    private fun bindingHashed(
        ctime: Int,
        keyFlags: Int,
        primaryFingerprint: ByteArray,
        expirationSeconds: Long?,
        embeddedBackSig: ByteArray?
    ): ByteArray = ByteArrayOutputStream().apply {
        write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32(ctime)))
        write(subpacket(SUBPKT_KEY_FLAGS or 0x80, byteArrayOf(keyFlags.toByte())))
        if (expirationSeconds != null && expirationSeconds > 0L) {
            write(subpacket(SUBPKT_KEY_EXPIRE, uint32(expirationSeconds.toInt())))
        }
        write(issuerFingerprintSubpacket(primaryFingerprint))
        if (embeddedBackSig != null) write(subpacket(SUBPKT_EMBEDDED_SIG, embeddedBackSig))
    }.toByteArray()

    /**
     * Add a composite ML-KEM + ECDH encryption subkey (algo 35/36) to a
     * composite ML-DSA primary. Mirrors the encryption subkey [assemble] emits.
     * Returns the raw ring; the caller re-protects if the primary was protected.
     */
    fun addCompositeEncryptionSubkey(
        ring: ByteArray,
        kemSuite: CompositeSuite = CompositeSuite.IETF_768,
        expirationSeconds: Long? = null,
        passphrase: CharArray? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date()
    ): ByteArray {
        require(!kemSuite.isLibrePgp) { "only IETF v6 ML-KEM subkeys can be added to a composite v6 primary" }
        val ctx = primaryContext(ring, passphrase)
        val ctime = (creationTime.time / 1000L).toInt()

        val (eccPub, eccSec) = when (kemSuite.curve) {
            EccCurve.X25519 -> {
                val kp = X25519KeyPairGenerator()
                    .apply { init(X25519KeyGenerationParameters(random)) }.generateKeyPair()
                (kp.public as X25519PublicKeyParameters).encoded to (kp.private as X25519PrivateKeyParameters).encoded
            }
            EccCurve.X448 -> {
                val kp = X448KeyPairGenerator()
                    .apply { init(X448KeyGenerationParameters(random)) }.generateKeyPair()
                (kp.public as X448PublicKeyParameters).encoded to (kp.private as X448PrivateKeyParameters).encoded
            }
            else -> throw ClassicalSubkeyGen.SubkeyAddError("unsupported KEM curve ${kemSuite.curve}")
        }
        val mkp = MLKEMKeyPairGenerator()
            .apply { init(MLKEMKeyGenerationParameters(random, kemSuite.mlkem.params)) }.generateKeyPair()
        val mPub = (mkp.public as MLKEMPublicKeyParameters).encoded
        val mSeed = (mkp.private as MLKEMPrivateKeyParameters).seed ?: error("BC ML-KEM keypair missing seed")

        val pubBody = v6PubBody(ctime, kemSuite.ietfAlgId, eccPub + mPub)
        val secBody = pubBody + byteArrayOf(0) + eccSec + mSeed
        val hashed = bindingHashed(
            ctime, KEY_FLAG_ENCRYPT_COMMS or KEY_FLAG_ENCRYPT_STORAGE,
            ctx.fingerprint, expirationSeconds, embeddedBackSig = null
        )
        return bindAndAppend(ring, ctx, pubBody, secBody, hashed, random)
    }

    /**
     * Add a composite ML-DSA + EdDSA signing subkey (algo 30/31) to a composite
     * ML-DSA primary: a composite 0x19 back-signature made by the new subkey,
     * carried inside a composite 0x18 binding made by the primary.
     */
    fun addCompositeSigningSubkey(
        ring: ByteArray,
        signSuite: CompositeSignSuite = CompositeSignSuite.MLDSA65_ED25519,
        expirationSeconds: Long? = null,
        passphrase: CharArray? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date()
    ): ByteArray {
        val ctx = primaryContext(ring, passphrase)
        val ctime = (creationTime.time / 1000L).toInt()

        val (edPub, edSec) = when (signSuite.eddsa) {
            EdDsaCurve.ED25519 -> {
                val sk = Ed25519PrivateKeyParameters(random)
                sk.generatePublicKey().encoded to sk.encoded
            }
            EdDsaCurve.ED448 -> {
                val sk = Ed448PrivateKeyParameters(random)
                sk.generatePublicKey().encoded to sk.encoded
            }
        }
        val mldsaSeed = ByteArray(signSuite.mldsa.seedLen).also { random.nextBytes(it) }
        val mldsaPub = MLDSAPrivateKeyParameters(signSuite.mldsa.params, mldsaSeed).publicKeyParameters.encoded
        val subSecret = signSuite.join(edSec, mldsaSeed)
        val pubBody = v6PubBody(ctime, signSuite.algId, signSuite.join(edPub, mldsaPub))
        val secBody = pubBody + byteArrayOf(0) + subSecret
        val subFp = v6Fingerprint(pubBody)
        val bindingData = keyFrame(ctx.pubBody) + keyFrame(pubBody)

        val backHashed = ByteArrayOutputStream().apply {
            write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32(ctime)))
            write(issuerFingerprintSubpacket(subFp))
        }.toByteArray()
        val backSigBody = compositeSigBody(signSuite, subSecret, SIGTYPE_PRIMARY_BINDING, bindingData, backHashed, random)

        val hashed = bindingHashed(ctime, KEY_FLAG_SIGN, ctx.fingerprint, expirationSeconds, backSigBody)
        return bindAndAppend(ring, ctx, pubBody, secBody, hashed, random)
    }

    /**
     * Add a classical v6 Ed25519 / X25519 subkey to a composite ML-DSA primary.
     * The 0x18 binding is signed by the composite primary; an Ed25519 signing
     * subkey also carries its own 0x19 back-signature.
     */
    fun addClassicalSubkey(
        ring: ByteArray,
        type: ClassicalSubkeyGen.ClassicalSubkeyType,
        expirationSeconds: Long? = null,
        passphrase: CharArray? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date()
    ): ByteArray {
        val ctx = primaryContext(ring, passphrase)
        val ctime = (creationTime.time / 1000L).toInt()

        val algId: Int
        val keyFlags: Int
        val pub: ByteArray
        val sec: ByteArray
        var edSecForBackSig: ByteArray? = null
        var rsaSecForBackSig: org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters? = null
        when (type) {
            ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT -> {
                val kp = X25519KeyPairGenerator()
                    .apply { init(X25519KeyGenerationParameters(random)) }.generateKeyPair()
                pub = (kp.public as X25519PublicKeyParameters).encoded
                sec = (kp.private as X25519PrivateKeyParameters).encoded
                algId = PublicKeyAlgorithmTags.X25519
                keyFlags = KEY_FLAG_ENCRYPT_COMMS or KEY_FLAG_ENCRYPT_STORAGE
            }
            ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN -> {
                val sk = Ed25519PrivateKeyParameters(random)
                pub = sk.generatePublicKey().encoded
                sec = sk.encoded
                algId = PublicKeyAlgorithmTags.Ed25519
                keyFlags = KEY_FLAG_SIGN
                edSecForBackSig = sec
            }
            ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH -> {
                val sk = Ed25519PrivateKeyParameters(random)
                pub = sk.generatePublicKey().encoded
                sec = sk.encoded
                algId = PublicKeyAlgorithmTags.Ed25519
                keyFlags = KEY_FLAG_AUTHENTICATE
            }
            // 4.6.0 (item 21): RSA, v6-framed, so clients that cannot use the
            // ML-KEM subkey (Thunderbird's RNP) have a classical one to use.
            ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_ENCRYPT,
            ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_ENCRYPT,
            ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_SIGN,
            ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_SIGN,
            ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_AUTH,
            ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_AUTH -> {
                val bits = if (type.name.startsWith("RSA_4096")) 4096 else 2048
                val (rsaPub, rsaSec, priv) = rsaKeyMaterial(bits, random, ctime)
                pub = rsaPub
                sec = rsaSec
                algId = PublicKeyAlgorithmTags.RSA_GENERAL
                keyFlags = when (type.capability) {
                    ClassicalSubkeyGen.Capability.ENCRYPT -> KEY_FLAG_ENCRYPT_COMMS or KEY_FLAG_ENCRYPT_STORAGE
                    ClassicalSubkeyGen.Capability.SIGN -> KEY_FLAG_SIGN
                    else -> KEY_FLAG_AUTHENTICATE
                }
                if (type.capability == ClassicalSubkeyGen.Capability.SIGN) rsaSecForBackSig = priv
            }
            else -> throw ClassicalSubkeyGen.SubkeyAddError(
                "This subkey type is not supported on a composite key."
            )
        }

        val pubBody = v6PubBody(ctime, algId, pub)
        val secBody = pubBody + byteArrayOf(0) + sec
        val bindingData = keyFrame(ctx.pubBody) + keyFrame(pubBody)

        val rsaBack = rsaSecForBackSig
        val backSigBody: ByteArray? = if (rsaBack != null) {
            // A signing subkey needs a 0x19 back-signature made by itself.
            val subFp = v6Fingerprint(pubBody)
            val backHashed = ByteArrayOutputStream().apply {
                write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32(ctime)))
                write(issuerFingerprintSubpacket(subFp))
            }.toByteArray()
            val salt = ByteArray(SALT_SHA256).also { random.nextBytes(it) }
            val digest = CompositeSigHash.v6DocumentDigest(
                hashAlgorithm = HASH_SHA256,
                salt = salt,
                data = bindingData,
                signatureType = SIGTYPE_PRIMARY_BINDING,
                publicKeyAlgorithm = algId,
                hashedSubpacketBody = backHashed
            )
            v6SigBody(SIGTYPE_PRIMARY_BINDING, algId, backHashed, digest, salt, rsaSignSha256(rsaBack, digest))
        } else if (edSecForBackSig != null) {
            val subFp = v6Fingerprint(pubBody)
            val backHashed = ByteArrayOutputStream().apply {
                write(subpacket(SUBPKT_CREATION_TIME or 0x80, uint32(ctime)))
                write(issuerFingerprintSubpacket(subFp))
            }.toByteArray()
            val salt = ByteArray(SALT_SHA256).also { random.nextBytes(it) }
            val digest = CompositeSigHash.v6DocumentDigest(
                hashAlgorithm = HASH_SHA256,
                salt = salt,
                data = bindingData,
                signatureType = SIGTYPE_PRIMARY_BINDING,
                publicKeyAlgorithm = algId,
                hashedSubpacketBody = backHashed
            )
            v6SigBody(SIGTYPE_PRIMARY_BINDING, algId, backHashed, digest, salt, ed25519Sign(edSecForBackSig, digest))
        } else null

        val hashed = bindingHashed(ctime, keyFlags, ctx.fingerprint, expirationSeconds, backSigBody)
        return bindAndAppend(ring, ctx, pubBody, secBody, hashed, random)
    }

    /**
     * 4.6.0 (item 21): a fresh RSA key as v6 key material: the public MPIs (n, e),
     * the secret MPIs (d, p, q, u, as RFC 9580 orders them, with p < q), and the
     * private key for a back-signature. Bouncy Castle's own RSA packet classes
     * do the MPI encoding.
     */
    private fun rsaKeyMaterial(
        bits: Int,
        random: SecureRandom,
        ctime: Int
    ): Triple<ByteArray, ByteArray, org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters> {
        val gen = org.bouncycastle.crypto.generators.RSAKeyPairGenerator().apply {
            init(org.bouncycastle.crypto.params.RSAKeyGenerationParameters(
                java.math.BigInteger.valueOf(65537), random, bits, 100
            ))
        }
        val kp = gen.generateKeyPair()
        val pgp = org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair(
            org.bouncycastle.bcpg.PublicKeyPacket.VERSION_6,
            PublicKeyAlgorithmTags.RSA_GENERAL, kp, Date(ctime * 1000L)
        )
        val pub = pgp.publicKey.publicKeyPacket.key.encoded
        val sec = (pgp.privateKey.privateKeyDataPacket as org.bouncycastle.bcpg.RSASecretBCPGKey).encoded
        return Triple(pub, sec, kp.private as org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters)
    }

    /** RSASSA-PKCS1-v1_5 over an already computed SHA-256 [digest], as an OpenPGP MPI. */
    private fun rsaSignSha256(
        key: org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters,
        digest: ByteArray
    ): ByteArray {
        val prefix = byteArrayOf(
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00, 0x04, 0x20
        )
        val engine = org.bouncycastle.crypto.encodings.PKCS1Encoding(org.bouncycastle.crypto.engines.RSABlindedEngine())
        engine.init(true, key)
        val block = prefix + digest
        val sig = engine.processBlock(block, 0, block.size)
        val v = java.math.BigInteger(1, sig)
        val mag = org.bouncycastle.util.BigIntegers.asUnsignedByteArray(v)
        val bitLen = v.bitLength()
        return byteArrayOf((bitLen ushr 8).toByte(), bitLen.toByte()) + mag
    }

    private fun ed25519Sign(secret: ByteArray, digest: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(secret, 0))
        signer.update(digest, 0, digest.size)
        return signer.generateSignature()
    }


    // -- helpers ------------------------------------------------------

    private fun compositeSignaturePacket(
        suite: CompositeSignSuite,
        compositeSecret: ByteArray,
        sigType: Int,
        data: ByteArray,
        hashed: ByteArray,
        random: SecureRandom
    ): ByteArray = packet(TAG_SIGNATURE, compositeSigBody(suite, compositeSecret, sigType, data, hashed, random))

    /** A v6 composite signature packet BODY (no packet header), for embedding. */
    private fun compositeSigBody(
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
        return v6SigBody(sigType, suite.algId, hashed, digest, salt, signature)
    }

    /** A v6 signature packet body with an empty unhashed area. */
    private fun v6SigBody(
        sigType: Int,
        pubAlgo: Int,
        hashed: ByteArray,
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
        write(uint32(0))
        write(digest[0].toInt() and 0xFF)
        write(digest[1].toInt() and 0xFF)
        write(salt.size)
        write(salt)
        write(signatureMaterial)
    }.toByteArray()

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
