// CompositeKemLibrePGP.kt
// PGPony Android — 4.0.0 Phase 2b (LibrePGP composite, algorithm 8)
//
// The KEM core for the LibrePGP Kyber/ML-KEM-768 + X25519 composite
// (algorithm 8), as implemented by GnuPG 2.5.x. This is a DIFFERENT
// construction from the IETF algo-35 core (CompositeKem): a KMAC256-based
// combiner (GnuPG `gnupg_kem_combiner`, common/kem.c) rather than SHA3-256,
// with both ciphertexts and a fixedInfo fed in.
//
//   KEK = KMAC256(
//       key           = "OpenPGPCompositeKeyDerivationFunction",
//       customization = "KDF",
//       message       = 0x00000001 || ecc_ss || ecc_ct ||
//                       mlkem_ss || mlkem_ct || fixedInfo,
//       outLen        = 32 )
//   fixedInfo  = sessionKeySymAlgo(1) || recipientV5Fingerprint(32)
//   sessionKey = AES-256 RFC-3394 key-unwrap under KEK
//
// where on decrypt ecc_ss = X25519(recipientSec, ecc_ct) and ecc_ct is the
// ECC ephemeral public from the PKESK. mlkem_ss is the Kyber decapsulated
// secret, mlkem_ct the Kyber ciphertext.
//
// Interop-validated against GnuPG 2.5.21 composite messages.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.RFC3394WrapEngine
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.macs.KMAC
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.agreement.X448Agreement
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.X448PrivateKeyParameters
import org.bouncycastle.crypto.params.X448PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.SecureRandom
import java.math.BigInteger
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters

object CompositeKemLibrePGP {

    /** LibrePGP algorithm id for the Kyber/ML-KEM-768 + X25519 composite. */
    const val ALGORITHM_ID = 8

    const val X25519_KEY_LEN = 32
    const val MLKEM768_CT_LEN = 1088
    const val KEK_LEN = 32

    private val KMAC_KEY = "OpenPGPCompositeKeyDerivationFunction".toByteArray(Charsets.US_ASCII)
    private val KMAC_CUSTOM = "KDF".toByteArray(Charsets.US_ASCII)
    private val COUNTER = byteArrayOf(0x00, 0x00, 0x00, 0x01)

    /**
     * The KMAC256 key combiner. [fixedInfo] is
     * sessionKeySymAlgo(1) || recipientV5Fingerprint(32).
     */
    fun combine(
        eccShared: ByteArray,
        eccCiphertext: ByteArray,
        mlkemShared: ByteArray,
        mlkemCiphertext: ByteArray,
        fixedInfo: ByteArray
    ): ByteArray {
        val kmac = KMAC(256, KMAC_CUSTOM)
        kmac.init(KeyParameter(KMAC_KEY))
        kmac.update(COUNTER, 0, COUNTER.size)
        kmac.update(eccShared, 0, eccShared.size)
        kmac.update(eccCiphertext, 0, eccCiphertext.size)
        kmac.update(mlkemShared, 0, mlkemShared.size)
        kmac.update(mlkemCiphertext, 0, mlkemCiphertext.size)
        kmac.update(fixedInfo, 0, fixedInfo.size)
        val out = ByteArray(KEK_LEN)
        kmac.doFinal(out, 0, KEK_LEN)
        return out
    }

    /** fixedInfo = symAlgo(1) || v5 fingerprint(32). */
    fun fixedInfo(sessionKeySymAlgo: Int, recipientV5Fingerprint: ByteArray): ByteArray =
        byteArrayOf(sessionKeySymAlgo.toByte()) + recipientV5Fingerprint

    /**
     * The ECC-KEM shared secret fed into the composite combiner. GnuPG does
     * NOT use the raw X25519 output directly; it derives
     *   ecc_ss = SHA3-256( ecdh || ecc_ct || ecc_pk )
     * (gnupg_ecc_kem_simple_kdf, common/kem.c), where ecdh is the raw X25519
     * agreement, ecc_ct is the 32-byte ephemeral point, and ecc_pk is the
     * recipient's 32-byte X25519 public key.
     */
    private fun eccKemKdf(
        suite: CompositeSuite, ecdh: ByteArray, eccCt: ByteArray, eccPk: ByteArray
    ): ByteArray {
        // gpg's ECC key-share KDF hash scales with the curve (gpg common/kem.c
        // ecc_table): SHA3-256 for <=256-bit curves, SHA3-512 for >=384-bit ones
        // (X448, brainpoolP384r1). A wrong size yields a different eccKeyShare,
        // hence a different KEK and "checksum failed".
        val hashBits = suite.curve.kdfHashBits
        val d = SHA3Digest(hashBits)
        d.update(ecdh, 0, ecdh.size)
        d.update(eccCt, 0, eccCt.size)
        d.update(eccPk, 0, eccPk.size)
        val out = ByteArray(hashBits / 8)
        d.doFinal(out, 0)
        return out
    }

    /**
     * Recover the KEK from an ECC ephemeral + Kyber ciphertext using the
     * recipient's composite secret material.
     */
    fun decapsulate(
        eccCiphertext: ByteArray,
        mlkemCiphertext: ByteArray,
        recipientX25519Sec: ByteArray,
        recipientX25519Pub: ByteArray,
        recipientMlkemSec: MLKEMPrivateKeyParameters,
        fixedInfo: ByteArray,
        suite: CompositeSuite = CompositeSuite.LIBREPGP_768
    ): ByteArray {
        // Montgomery curves store a minimal-length point that must be re-padded
        // to the fixed curve length; a Weierstrass curve carries a full
        // uncompressed 0x04||X||Y point used verbatim (validated on decode).
        val eccCt = if (suite.curve.weierstrass) eccCiphertext
                    else suite.curve.normalizePoint(eccCiphertext)
        val recipPub = if (suite.curve.weierstrass) recipientX25519Pub
                       else suite.curve.normalizePoint(recipientX25519Pub)
        val ecdh = ecdhAgree(suite, recipientX25519Sec, eccCt)
        val eccSs = eccKemKdf(suite, ecdh, eccCt, recipPub)
        val mlkemShared = MLKEMExtractor(recipientMlkemSec).extractSecret(mlkemCiphertext)
        return combine(eccSs, eccCt, mlkemShared, mlkemCiphertext, fixedInfo)
    }

    /** RFC-3394 AES-256 key unwrap the session key blob under [kek]. */
    fun unwrapSessionKey(kek: ByteArray, wrapped: ByteArray): ByteArray =
        RFC3394WrapEngine(AESEngine.newInstance()).run {
            init(false, KeyParameter(kek))
            unwrap(wrapped, 0, wrapped.size)
        }

    /** RFC-3394 AES-256 key wrap the session key under [kek]. */
    fun wrapSessionKey(kek: ByteArray, sessionKey: ByteArray): ByteArray =
        RFC3394WrapEngine(AESEngine.newInstance()).run {
            init(true, KeyParameter(kek))
            wrap(sessionKey, 0, sessionKey.size)
        }

    /** Encapsulation result for encrypting to a LibrePGP composite key. */
    data class Encapsulation(
        val eccEphemeral: ByteArray,   // X25519 ephemeral public (32)
        val kyberCiphertext: ByteArray, // Kyber/ML-KEM ciphertext (1088)
        val kek: ByteArray              // derived KEK (32)
    )

    /**
     * Encapsulate to a recipient composite public key: generate an X25519
     * ephemeral + Kyber ciphertext and derive the KEK via the combiner.
     * The ephemeral public goes on the wire as a fixed 256-bit SOS (see
     * CompositeLibrePGPEncryptionMethodGenerator.eccSos), a full 32 octets
     * regardless of its high byte, so [eccEphemeral] is unambiguously the
     * combiner's ecc_ct and no regeneration guard or leading-zero
     * reconciliation with gpg is needed.
     */
    fun encapsulate(
        recipientX25519Pub: ByteArray,
        recipientKyberPub: ByteArray,
        fixedInfo: ByteArray,
        random: SecureRandom = SecureRandom(),
        suite: CompositeSuite = CompositeSuite.LIBREPGP_768
    ): Encapsulation {
        val (ephSec, ephPub) = genEphemeral(suite, random)

        val ecdh = ecdhAgree(suite, ephSec, recipientX25519Pub)
        val eccSs = eccKemKdf(suite, ecdh, ephPub, recipientX25519Pub)
        val mlkemPub = MLKEMPublicKeyParameters(suite.mlkem.params, recipientKyberPub)
        val enc = MLKEMGenerator(random).generateEncapsulated(mlkemPub)

        val kek = combine(eccSs, ephPub, enc.secret, enc.encapsulation, fixedInfo)
        return Encapsulation(ephPub, enc.encapsulation, kek)
    }

    /** Generate an ECC ephemeral for [suite]'s curve: (secret, public). */
    private fun genEphemeral(suite: CompositeSuite, random: SecureRandom): Pair<ByteArray, ByteArray> =
        if (suite.curve.weierstrass) {
            val kp = ECKeyPairGenerator()
                .apply { init(ECKeyGenerationParameters(domainOf(suite.curve), random)) }
                .generateKeyPair()
            val scalar = bigIntToFixed((kp.private as ECPrivateKeyParameters).d, suite.curve.keyLen)
            // getEncoded(false) is the uncompressed 0x04||X||Y point, which is
            // both the wire ephemeral and the KDF's ecc_ct.
            scalar to (kp.public as ECPublicKeyParameters).q.getEncoded(false)
        } else if (suite.curve == EccCurve.X448) {
            val kp = X448KeyPairGenerator()
                .apply { init(X448KeyGenerationParameters(random)) }
                .generateKeyPair()
            (kp.private as X448PrivateKeyParameters).encoded to
                (kp.public as X448PublicKeyParameters).encoded
        } else {
            val kp = X25519KeyPairGenerator()
                .apply { init(X25519KeyGenerationParameters(random)) }
                .generateKeyPair()
            (kp.private as X25519PrivateKeyParameters).encoded to
                (kp.public as X25519PublicKeyParameters).encoded
        }

    /** ECDH agreement on [suite]'s curve between a raw secret and peer public. */
    private fun ecdhAgree(suite: CompositeSuite, secret: ByteArray, peerPub: ByteArray): ByteArray =
        if (suite.curve.weierstrass) {
            val dom = domainOf(suite.curve)
            // decodePoint validates the peer point is on the curve (rejects an
            // invalid-curve point). gpg's composite ECC-KEM feeds the FULL
            // uncompressed shared point (0x04 || X || Y) into the ECC key-share
            // KDF, not just the X-coordinate: confirmed by unwrapping a real
            // gpg 2.5.x brainpool message. The X-coordinate alone yields a
            // different KEK and the session-key unwrap fails "checksum failed".
            val priv = BigInteger(1, secret)
            val shared = dom.curve.decodePoint(peerPub).multiply(priv).normalize()
            shared.getEncoded(false)
        } else if (suite.curve == EccCurve.X448) {
            val agr = X448Agreement().apply { init(X448PrivateKeyParameters(secret, 0)) }
            val out = ByteArray(agr.agreementSize)
            agr.calculateAgreement(X448PublicKeyParameters(peerPub, 0), out, 0)
            out
        } else {
            val agr = X25519Agreement().apply { init(X25519PrivateKeyParameters(secret, 0)) }
            val out = ByteArray(agr.agreementSize)
            agr.calculateAgreement(X25519PublicKeyParameters(peerPub, 0), out, 0)
            out
        }

    private val bp256: ECDomainParameters by lazy {
        val x9 = TeleTrusTNamedCurves.getByName("brainpoolP256r1")
        ECDomainParameters(x9.curve, x9.g, x9.n, x9.h)
    }

    private val bp384: ECDomainParameters by lazy {
        val x9 = TeleTrusTNamedCurves.getByName("brainpoolP384r1")
        ECDomainParameters(x9.curve, x9.g, x9.n, x9.h)
    }

    /** Weierstrass domain parameters for a supported composite curve. */
    private fun domainOf(curve: EccCurve): ECDomainParameters = when (curve) {
        EccCurve.BRAINPOOL_P384R1 -> bp384
        EccCurve.BRAINPOOL_P256R1 -> bp256
        else -> throw IllegalArgumentException("no Weierstrass domain for $curve")
    }

    /** Big-endian, exactly [len] octets, from a non-negative [v]. */
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
