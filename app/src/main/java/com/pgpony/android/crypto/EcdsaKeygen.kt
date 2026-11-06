// EcdsaKeygen.kt
// PGPony Android, 4.8.0 (4l, #109): curve parameters for generating v4 ECDSA
// keys on brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 and secp256k1.
//
// The request came from a user whose hardware-key provisioning app writes
// keys from PGPony to OpenPGP cards, several of which hold brainpool or
// secp256k1 keys. The key shape is the one gpg makes for these curves: an
// ECDSA primary (certify and sign) with an ECDH encryption subkey on the same
// curve.
//
// The ECDH KDF parameters are the RFC 6637 pairs gpg writes for the curve
// size: SHA-256 + AES-128 for 256-bit curves, SHA-384 + AES-192 for 384 and
// SHA-512 + AES-256 for 512. They are passed explicitly: Bouncy Castle picks
// the same pairs for brainpool on its own, but has no default for secp256k1
// and refuses it ("unknown curve"). The self-signatures use the same hash, so
// the hash is never shorter than the curve.

package com.pgpony.android.crypto

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECNamedDomainParameters
import org.bouncycastle.openpgp.PGPKdfParameters
import java.security.SecureRandom

internal object EcdsaKeygen {

    /** One generatable curve: its OID, the hash for self-signatures and the
     *  ECDH KDF, and the ECDH key-wrap cipher. */
    class Curve(
        val oid: ASN1ObjectIdentifier,
        val hashAlgorithm: Int,
        val kekAlgorithm: Int
    )

    private val BRAINPOOL_P256 = Curve(
        TeleTrusTObjectIdentifiers.brainpoolP256r1, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128
    )
    private val BRAINPOOL_P384 = Curve(
        TeleTrusTObjectIdentifiers.brainpoolP384r1, HashAlgorithmTags.SHA384, SymmetricKeyAlgorithmTags.AES_192
    )
    private val BRAINPOOL_P512 = Curve(
        TeleTrusTObjectIdentifiers.brainpoolP512r1, HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256
    )
    private val SECP256K1 = Curve(
        SECObjectIdentifiers.secp256k1, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128
    )

    /** The curve for [algorithm], or null when it is not a generatable ECDSA key. */
    fun curveFor(algorithm: KeyAlgorithm): Curve? = when (algorithm) {
        KeyAlgorithm.ECDSA_BRAINPOOL_P256 -> BRAINPOOL_P256
        KeyAlgorithm.ECDSA_BRAINPOOL_P384 -> BRAINPOOL_P384
        KeyAlgorithm.ECDSA_BRAINPOOL_P512 -> BRAINPOOL_P512
        KeyAlgorithm.ECDSA_SECP256K1 -> SECP256K1
        else -> null
    }

    /** The ECDH subkey's KDF parameters for [curve] (RFC 6637, as gpg writes them). */
    fun kdfParameters(curve: Curve): PGPKdfParameters =
        PGPKdfParameters(curve.hashAlgorithm, curve.kekAlgorithm)

    /**
     * A fresh key pair on [curve]. The domain carries the curve OID
     * (ECNamedDomainParameters), which Bouncy Castle's key converter needs to
     * write the OID into the OpenPGP key packet.
     */
    fun generateKeyPair(curve: Curve, random: SecureRandom = SecureRandom()): AsymmetricCipherKeyPair {
        val x9 = ECNamedCurveTable.getByOID(curve.oid)
            ?: throw PGPCryptoError.KeyGenerationFailed("Unknown curve ${curve.oid.id}")
        val domain = ECNamedDomainParameters(curve.oid, x9.curve, x9.g, x9.n, x9.h)
        val gen = ECKeyPairGenerator()
        gen.init(ECKeyGenerationParameters(domain, random))
        return gen.generateKeyPair()
    }
}
