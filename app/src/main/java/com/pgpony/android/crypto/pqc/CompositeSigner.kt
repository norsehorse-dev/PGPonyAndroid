// CompositeSigner.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Produces a composite ML-DSA + EdDSA signature: the signing counterpart of
// CompositeSigVerifier. RFC 9980 Section 5.2.3 requires BOTH component
// signatures over the SAME v6 dataDigest (RFC 9580 Section 5.2.4); this
// object signs the digest with each component and concatenates them in the
// layout CompositeSignSuite defines (EdDSA first).
//
//   EdDSA:  PureEdDSA over the digest, empty context (RFC 9980 Section 5.1.1)
//   ML-DSA: pure hedged ML-DSA over the digest, empty context
//           (RFC 9980 Section 5.1.2)
//
// BouncyCastle throws on the composite algorithm ids (30/31), so it will not
// sign these for us; the caller builds the v6 dataDigest with CompositeSigHash
// and hands it in, exactly as on the verify side.
//
// The ML-DSA secret is the 32-octet FIPS-204 seed xi (RFC 9980 Section
// 5.3.2.2). BouncyCastle's MLDSAPrivateKeyParameters takes the seed directly
// and expands it through ML-DSA.KeyGen_internal before signing.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.Ed448Signer
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import java.security.SecureRandom

object CompositeSigner {

    /**
     * The composite signature over [dataDigest]: EdDSA signature || ML-DSA
     * signature, per [suite]. [compositeSecret] is EdDSA secret || ML-DSA seed
     * (32 octets). [random] hedges the ML-DSA component; the EdDSA component is
     * deterministic (RFC 8032), so for a fixed key and digest its half is
     * reproducible.
     */
    fun sign(
        suite: CompositeSignSuite,
        compositeSecret: ByteArray,
        dataDigest: ByteArray,
        random: SecureRandom = SecureRandom()
    ): ByteArray {
        val (eddsaSecret, mldsaSeed) = suite.splitSecret(compositeSecret)
        val eddsaSignature = signEddsa(suite.eddsa, eddsaSecret, dataDigest)
        val mldsaSignature = signMldsa(suite.mldsa, mldsaSeed, dataDigest, random)
        return suite.join(eddsaSignature, mldsaSignature)
    }

    private fun signEddsa(
        curve: EdDsaCurve,
        secret: ByteArray,
        dataDigest: ByteArray
    ): ByteArray {
        val signer = when (curve) {
            EdDsaCurve.ED25519 -> Ed25519Signer().apply {
                init(true, Ed25519PrivateKeyParameters(secret, 0))
            }
            EdDsaCurve.ED448 -> Ed448Signer(ByteArray(0)).apply {
                init(true, Ed448PrivateKeyParameters(secret, 0))
            }
        }
        signer.update(dataDigest, 0, dataDigest.size)
        return signer.generateSignature()
    }

    private fun signMldsa(
        level: MldsaLevel,
        seed: ByteArray,
        dataDigest: ByteArray,
        random: SecureRandom
    ): ByteArray {
        // The 32-octet seed is expanded through ML-DSA.KeyGen_internal by BC.
        val priv = MLDSAPrivateKeyParameters(level.params, seed)
        val signer = MLDSASigner()
        signer.init(true, ParametersWithRandom(priv, random))
        signer.update(dataDigest, 0, dataDigest.size)
        return signer.generateSignature()
    }
}
