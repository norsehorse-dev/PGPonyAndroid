// CompositeSigVerifier.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Verifies a composite ML-DSA + EdDSA signature. RFC 9980 Section 5.2.3: an
// implementation MUST validate BOTH component signatures over the same v6
// dataDigest to accept the composite. Each component verifies independently:
//
//   EdDSA:  EdDSA.Verify(eddsaPublic, dataDigest, eddsaSignature)   [RFC 8032]
//   ML-DSA: ML-DSA.Verify(mldsaPublic, dataDigest, mldsaSignature)  [FIPS-204]
//
// The dataDigest is the standard v6 signature hash (RFC 9580 Section 5.2.4);
// this object takes it as input, because BouncyCastle throws on the composite
// algorithm ids (30/31) and will not compute it for us. The caller builds the
// digest and hands it in.
//
// Component byte layout comes from CompositeSignSuite: the composite public
// key is EdDSA public || ML-DSA public, and the signature value is EdDSA
// signature || ML-DSA signature, EdDSA first, all fixed-length.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.Ed448Signer
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner

object CompositeSigVerifier {

    /**
     * True only when BOTH the EdDSA and the ML-DSA component signatures verify
     * over [dataDigest]. [compositePublic] is EdDSA public || ML-DSA public and
     * [compositeSignature] is EdDSA sig || ML-DSA sig, per [suite].
     */
    fun verify(
        suite: CompositeSignSuite,
        compositePublic: ByteArray,
        compositeSignature: ByteArray,
        dataDigest: ByteArray
    ): Boolean {
        val (eddsaPublic, mldsaPublic) = suite.splitPublic(compositePublic)
        val (eddsaSignature, mldsaSignature) = suite.splitSignature(compositeSignature)

        val eddsaOk = verifyEddsa(suite.eddsa, eddsaPublic, dataDigest, eddsaSignature)
        val mldsaOk = verifyMldsa(suite.mldsa, mldsaPublic, dataDigest, mldsaSignature)
        return eddsaOk && mldsaOk
    }

    private fun verifyEddsa(
        curve: EdDsaCurve,
        publicKey: ByteArray,
        dataDigest: ByteArray,
        signature: ByteArray
    ): Boolean {
        // PureEdDSA with an empty context (RFC 9980 Section 5.1.1). The
        // dataDigest is the message signed, so it is fed as the update.
        val signer = when (curve) {
            EdDsaCurve.ED25519 -> Ed25519Signer().apply {
                init(false, Ed25519PublicKeyParameters(publicKey, 0))
            }
            EdDsaCurve.ED448 -> Ed448Signer(ByteArray(0)).apply {
                init(false, Ed448PublicKeyParameters(publicKey, 0))
            }
        }
        signer.update(dataDigest, 0, dataDigest.size)
        return signer.verifySignature(signature)
    }

    private fun verifyMldsa(
        level: MldsaLevel,
        publicKey: ByteArray,
        dataDigest: ByteArray,
        signature: ByteArray
    ): Boolean {
        // Pure hedged ML-DSA with an empty context (RFC 9980 Section 5.1.2).
        // dataDigest is the message; verification does not depend on hedging.
        val signer = MLDSASigner()
        signer.init(false, MLDSAPublicKeyParameters(level.params, publicKey))
        signer.update(dataDigest, 0, dataDigest.size)
        return signer.verifySignature(signature)
    }
}
