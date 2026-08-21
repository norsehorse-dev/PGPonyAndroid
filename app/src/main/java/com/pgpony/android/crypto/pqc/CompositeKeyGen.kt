// CompositeKeyGen.kt
// PGPony Android — 4.0.0 Phase 2b (composite keygen)
//
// Generate a post-quantum composite encryption subkey and graft it onto an
// existing classical secret key ring:
//
//   • IETF (algo 35):    v6 subkey under a v6 Ed25519 primary (RFC 9580 /
//                        draft-ietf-openpgp-pqc structure, like the draft's
//                        Appendix-A sample key)
//   • LibrePGP (algo 8): v5 subkey under a v4 EdDSA primary (GnuPG 2.5.x
//                        structure, like gpg's ky768_cv25519 keys)
//
// BouncyCastle can't EMIT either composite key packet, but it can PARSE
// both (the 4-octet key-material length routes unknown algos into
// UnknownBCPGKey) and it computes their fingerprints correctly (proven
// byte-identical to sq for v6 and to gpg's PKESK key IDs for v5). So we
// hand-emit only the subkey packet bodies — whose exact layouts were pinned
// against real sq / gpg keys in Phase 2b — then re-parse through BC and let
// BC generate the binding signature from the primary key.
//
// Secret material forms (both schemes): X25519 secret (32) || ML-KEM-768
// seed (64, FIPS-203 d||z). Emitted unprotected (usage 0), matching the
// app's default passphrase-less keygen; app-level passphrase protection of
// the ring is layered elsewhere.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.AEADAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.X448PrivateKeyParameters
import org.bouncycastle.crypto.params.X448PublicKeyParameters
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date
import java.math.BigInteger
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters

object CompositeKeyGen {

    enum class Scheme { IETF_V6, LIBREPGP_V5 }

    private const val TAG_PUBSUBKEY = 14
    private const val TAG_SECSUBKEY = 7

    /**
     * Append a freshly generated composite encryption subkey (with binding
     * signature from the primary) to [secretRing] and return the new ring.
     * [passphrase] unlocks the primary for signing (null/empty for
     * passphrase-less keys).
     */
    /**
     * Backward-compatible entry: the 4.0.0 [Scheme] selects the 768 suite.
     * New callers pass a [CompositeSuite] to reach the 1024 parameter sets.
     */
    fun addCompositeSubkey(
        secretRing: PGPSecretKeyRing,
        scheme: Scheme,
        passphrase: String? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date(),
        expirationSeconds: Long? = null
    ): PGPSecretKeyRing = addCompositeSubkey(
        secretRing,
        if (scheme == Scheme.IETF_V6) CompositeSuite.IETF_768 else CompositeSuite.LIBREPGP_768,
        passphrase, random, creationTime, expirationSeconds
    )

    fun addCompositeSubkey(
        secretRing: PGPSecretKeyRing,
        suite: CompositeSuite,
        passphrase: String? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date(),
        expirationSeconds: Long? = null
    ): PGPSecretKeyRing {
        // 1. Fresh composite material for the suite's curve and ML-KEM level.
        val (xSec, xPub) = if (suite.curve.weierstrass) {
            // issue #2: brainpool composite. Scalar left-padded to the field
            // length; public point is the uncompressed 0x04 || X || Y.
            val dom = brainpoolDomain(suite.curve)
            val kp = ECKeyPairGenerator()
                .apply { init(ECKeyGenerationParameters(dom, random)) }.generateKeyPair()
            bigIntToFixed((kp.private as ECPrivateKeyParameters).d, suite.curve.keyLen) to
                (kp.public as ECPublicKeyParameters).q.getEncoded(false)
        } else if (suite.curve == EccCurve.X448) {
            val kp = X448KeyPairGenerator()
                .apply { init(X448KeyGenerationParameters(random)) }.generateKeyPair()
            (kp.private as X448PrivateKeyParameters).encoded to
                (kp.public as X448PublicKeyParameters).encoded
        } else {
            val kp = X25519KeyPairGenerator()
                .apply { init(X25519KeyGenerationParameters(random)) }.generateKeyPair()
            (kp.private as X25519PrivateKeyParameters).encoded to
                (kp.public as X25519PublicKeyParameters).encoded
        }
        val mGen = MLKEMKeyPairGenerator().apply {
            init(MLKEMKeyGenerationParameters(random, suite.mlkem.params))
        }
        val mkp = mGen.generateKeyPair()
        val mPub = (mkp.public as MLKEMPublicKeyParameters).encoded
        val mSeed = (mkp.private as MLKEMPrivateKeyParameters).seed
            ?: error("BC ML-KEM keypair missing seed")

        val ctime = (creationTime.time / 1000L).toInt()

        // 2. Emit the subkey packets.
        val (pubBody, secBody) = if (suite.isLibrePgp)
            v5Bodies(ctime, xPub, mPub, xSec, mSeed, suite)
        else v6Bodies(ctime, xPub, mPub, xSec, mSeed, suite)
        val pubPacket = packet(TAG_PUBSUBKEY, pubBody)
        val secPacket = packet(TAG_SECSUBKEY, secBody)

        // 3. Parse a temp public ring (primary + new subkey) to obtain the
        //    subkey as a BC PGPPublicKey (BC computes its fingerprint).
        val primaryPub = secretRing.publicKey
        val tempPub = ByteArrayOutputStream().apply {
            write(primaryPub.encoded)
            write(pubPacket)
        }.toByteArray()
        val tempRing = PGPPublicKeyRing(ByteArrayInputStream(tempPub), JcaKeyFingerprintCalculator())
        val subPub = tempRing.publicKeys.asSequence().first { !it.isMasterKey }

        // 4. Binding signature from the primary.
        val primarySec = secretRing.secretKey
        val primaryPriv = primarySec.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
                .build((passphrase ?: "").toCharArray())
        )
        val bindingSigPacket: ByteArray = if (suite.isLibrePgp) {
            // Hand-rolled v4 subkey-binding signature. BC's generateCertification
            // re-serializes the algo-8 subkey (which it doesn't natively know) and
            // hashes it with v4 (0x99/2-octet) framing, so the hash GnuPG computes
            // over the real v5 packet doesn't match — gpg reports "1 bad signature"
            // and DROPS the composite subkey on import. We instead hash the EXACT
            // emitted subkey body with v5 (0x9A/4-octet) framing, matching iOS's
            // Ed25519KeyGenerator.buildSubkeyBindingSignature (gpg-verified), so
            // GnuPG accepts the binding and keeps the PQC subkey.
            buildV4V5SubkeyBindingSig(
                primaryPriv, packetBody(primaryPub.encoded), pubBody, ctime, primaryPub.keyID
            )
        } else {
            val sigGen = PGPSignatureGenerator(
                BcPGPContentSignerBuilder(primaryPub.algorithm, HashAlgorithmTags.SHA256),
                primaryPub
            )
            sigGen.init(PGPSignature.SUBKEY_BINDING, primaryPriv)
            val sub = PGPSignatureSubpacketGenerator()
            sub.setKeyFlags(true, org.bouncycastle.bcpg.sig.KeyFlags.ENCRYPT_COMMS or
                org.bouncycastle.bcpg.sig.KeyFlags.ENCRYPT_STORAGE)
            sub.setIssuerFingerprint(false, primaryPub)
            // issue #4 (SecTec): carry the key's expiration onto the composite
            // subkey binding signature too, so a PQ v6 key expires as one.
            if (expirationSeconds != null && expirationSeconds > 0L) {
                sub.setKeyExpirationTime(false, expirationSeconds)
            }
            sigGen.setHashedSubpackets(sub.generate())
            sigGen.generateCertification(primaryPub, subPub).encoded
        }

        // 5. Assemble: existing ring + secret subkey packet + binding sig.
        val out = ByteArrayOutputStream().apply {
            write(secretRing.encoded)
            write(secPacket)
            write(bindingSigPacket)
        }.toByteArray()
        var ring = PGPSecretKeyRing(ByteArrayInputStream(out), JcaKeyFingerprintCalculator())

        // 6. Match the base key's protection: if a passphrase is set, encrypt
        //    the (currently cleartext) composite subkey with it. BC's
        //    copyWithNewPassword re-encrypts the raw material without parsing
        //    the algo-35/8 key, matching the version's framing (v6 -> the
        //    encryptor's usage octet, v5 -> CFB/SHA-1).
        if (!passphrase.isNullOrEmpty()) {
            val algo = if (!suite.isLibrePgp) suite.ietfAlgId
            else CompositeKemLibrePGP.ALGORITHM_ID
            val plain = ring.secretKeys.asSequence().first { it.publicKey.algorithm == algo }
            val protectedSub = if (!suite.isLibrePgp) {
                // v6 (IETF): AEAD, S2K usage 253 + Argon2id — the RFC 9580
                // recommendation and what iOS emits. BC parses 253 back, so no
                // storage-path change is needed. (v6 forbids the bare-checksum
                // usage 255, and CFB/254 is off-spec/weaker for v6.)
                val encryptor = BcAEADSecretKeyEncryptorBuilder(
                    AEADAlgorithmTags.OCB,
                    SymmetricKeyAlgorithmTags.AES_256,
                    S2K.Argon2Params.memoryConstrainedParameters()
                ).setSecureRandom(random)
                    .build(passphrase.toCharArray(), plain.publicKey.publicKeyPacket)
                PGPSecretKey.copyWithNewPassword(plain, null, encryptor)
            } else {
                // v5 (LibrePGP): CFB, S2K usage 254 (SHA-1) — matches gpg's own
                // convention for v5 keys. (SHA-1 checksum calculator selects 254
                // over the default 255.)
                val encryptor = BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                    .setSecureRandom(random)
                    .build(passphrase.toCharArray())
                val sha1 = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
                PGPSecretKey.copyWithNewPassword(plain, null, encryptor, sha1)
            }
            ring = PGPSecretKeyRing.insertSecretKey(ring, protectedSub)
        }
        return ring
    }

    /** Derive the public key ring for a ring produced by [addCompositeSubkey]. */
    fun publicRingOf(secretRing: PGPSecretKeyRing): PGPPublicKeyRing =
        PGPPublicKeyRing(secretRing.publicKeys.asSequence().toList())

    // ── packet bodies ────────────────────────────────────────────────

    /** v6 (IETF algo 35): pub = X25519(32) || ML-KEM(1184); sec = usage0 + 96. */
    private fun v6Bodies(
        ctime: Int, xPub: ByteArray, mPub: ByteArray, xSec: ByteArray, mSeed: ByteArray,
        suite: CompositeSuite
    ): Pair<ByteArray, ByteArray> {
        val pubMat = xPub + mPub // 1216 (768) or 1624 (1024)
        val pub = ByteArrayOutputStream().apply {
            write(6)
            write(uint32(ctime))
            write(suite.ietfAlgId)   // 35 or 36
            write(uint32(pubMat.size))
            write(pubMat)
        }.toByteArray()
        val sec = ByteArrayOutputStream().apply {
            write(pub)
            write(0)      // s2k usage: unprotected; v6 carries no material length
            write(xSec)
            write(mSeed)
        }.toByteArray()
        return pub to sec
    }

    /**
     * v5 (LibrePGP algo 8): pub = OID(1.3.101.110) | MPI(0x40||point) |
     * kyberLen(4) | kyber(1184); sec = usage0 + matLen(4) + material + cksum(2).
     */
    private fun v5Bodies(
        ctime: Int, xPub: ByteArray, mPub: ByteArray, xSec: ByteArray, mSeed: ByteArray,
        suite: CompositeSuite
    ): Pair<ByteArray, ByteArray> {
        val oid = byteArrayOf(suite.curve.oidTail.size.toByte()) + suite.curve.oidTail
        // Composite ECC component: the raw curve point (no 0x40 native-point
        // prefix) as a MINIMAL-length OpenPGP MPI, byte-for-byte how gpg
        // 2.5.x stores and re-serializes it inside a composite (algo 8).
        // Two things this must get right, each found via gpg interop:
        //   - No 0x40 prefix. gpg's KEM wants the bare point; the prefixed
        //     form failed encryption with "pubkey_encrypt: Invalid data".
        //   - Minimal, not fixed width. gpg canonicalizes to a minimal MPI
        //     when it verifies the subkey binding signature, so a fixed-width
        //     point with a leading zero byte makes gpg report a bad binding
        //     and drop the subkey. gpg's KEM left-pads a short MPI back to
        //     the curve length, so minimal still decodes correctly.
        val pointMpi = canonicalMpi(xPub)
        val pubMat = oid + pointMpi + uint32(mPub.size) + mPub // 1227
        val pub = ByteArrayOutputStream().apply {
            write(5)
            write(uint32(ctime))
            write(CompositeKemLibrePGP.ALGORITHM_ID)  // 8
            write(uint32(pubMat.size))
            write(pubMat)
        }.toByteArray()
        val material = xSec + mSeed // 96
        var sum = 0
        for (b in material) sum = (sum + (b.toInt() and 0xFF)) and 0xFFFF
        val sec = ByteArrayOutputStream().apply {
            write(pub)
            write(0)                       // s2k usage: unprotected
            write(0)                       // v5 conditional-parameter length (no S2K params)
            write(uint32(material.size))   // v5 key-octet count; excludes checksum for usage-NONE
            write(material)
            write((sum ushr 8) and 0xFF)   // 2-octet checksum
            write(sum and 0xFF)
        }.toByteArray()
        return pub to sec
    }

    // ── emission helpers ─────────────────────────────────────────────

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

    // ── v5 (LibrePGP) subkey binding signature — iOS-parity, gpg-verified ──

    /**
     * Build a full v4 subkey-binding-signature PACKET (tag 2) over a v5
     * composite subkey, hashing the EXACT emitted [subkeyBody] with 0x9A /
     * 4-octet framing (v4 primary uses 0x99 / 2-octet). Mirrors iOS
     * Ed25519KeyGenerator.buildSubkeyBindingSignature so GnuPG accepts it.
     */
    private fun buildV4V5SubkeyBindingSig(
        primaryPriv: PGPPrivateKey,
        primaryPubBody: ByteArray,
        subkeyBody: ByteArray,
        ctime: Int,
        primaryKeyId: Long
    ): ByteArray {
        val hashed = ByteArrayOutputStream().apply {
            write(subpacket(2, uint32(ctime)))            // sig creation time
            write(subpacket(27, byteArrayOf(0x0C)))       // key flags: EC | ES
        }.toByteArray()
        val keyIdBytes = ByteArray(8) { ((primaryKeyId ushr (8 * (7 - it))) and 0xFF).toByte() }
        val unhashed = subpacket(16, keyIdBytes)          // issuer key ID

        val hashData = ByteArrayOutputStream().apply {
            write(0x99); write((primaryPubBody.size ushr 8) and 0xFF); write(primaryPubBody.size and 0xFF)
            write(primaryPubBody)
            write(0x9A); write(uint32(subkeyBody.size)); write(subkeyBody)
            write(4); write(0x18); write(22); write(8)    // ver, type(0x18), EdDSA(22), SHA-256(8)
            write((hashed.size ushr 8) and 0xFF); write(hashed.size and 0xFF); write(hashed)
            write(4); write(0xFF); write(uint32(6 + hashed.size))   // v4 final trailer
        }.toByteArray()
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(hashData)

        // OpenPGP EdDSA-legacy (algo 22): Ed25519-sign the SHA-256 digest.
        val signer = Ed25519Signer()
        signer.init(true, BcPGPKeyConverter().getPrivateKey(primaryPriv))
        signer.update(digest, 0, digest.size)
        val sig = signer.generateSignature()   // 64 octets, R || S

        val body = ByteArrayOutputStream().apply {
            write(4); write(0x18); write(22); write(8)
            write((hashed.size ushr 8) and 0xFF); write(hashed.size and 0xFF); write(hashed)
            write((unhashed.size ushr 8) and 0xFF); write(unhashed.size and 0xFF); write(unhashed)
            write(digest[0].toInt() and 0xFF); write(digest[1].toInt() and 0xFF)   // left 16 bits
            write(canonicalMpi(sig.copyOfRange(0, 32)))
            write(canonicalMpi(sig.copyOfRange(32, 64)))
        }.toByteArray()
        return packet(2, body)
    }

    private fun subpacket(type: Int, data: ByteArray): ByteArray =
        byteArrayOf((data.size + 1).toByte(), type.toByte()) + data

    /** Big-endian MPI with leading-zero octets stripped and an exact bit length. */
    private fun canonicalMpi(bytes: ByteArray): ByteArray {
        var start = 0
        while (start < bytes.size - 1 && bytes[start].toInt() == 0) start++
        val b = bytes.copyOfRange(start, bytes.size)
        if (b.size == 1 && b[0].toInt() == 0) return byteArrayOf(0, 0)
        val bits = (b.size - 1) * 8 + (32 - Integer.numberOfLeadingZeros(b[0].toInt() and 0xFF))
        return byteArrayOf((bits ushr 8).toByte(), bits.toByte()) + b
    }

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

    private fun brainpoolDomain(curve: EccCurve): ECDomainParameters {
        val name = when (curve) {
            EccCurve.BRAINPOOL_P384R1 -> "brainpoolP384r1"
            else -> throw IllegalArgumentException("no Weierstrass domain for $curve")
        }
        val x9 = TeleTrusTNamedCurves.getByName(name)
        return ECDomainParameters(x9.curve, x9.g, x9.n, x9.h)
    }

    private fun bigIntToFixed(v: BigInteger, len: Int): ByteArray {
        val b = v.toByteArray()
        return when {
            b.size == len -> b
            b.size == len + 1 && b[0].toInt() == 0 -> b.copyOfRange(1, b.size)
            b.size < len -> ByteArray(len - b.size) + b
            else -> b.copyOfRange(b.size - len, b.size)
        }
    }
}
