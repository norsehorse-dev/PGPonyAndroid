// AddSubkeyChoice.kt
// PGPony Android — 4.5.0 (item 7 / #55): the subkey kinds the Add Subkey sheet
// can create, classical or post-quantum, under one type so the sheet, view model
// and repository share a single dispatch.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite

sealed interface AddSubkeyChoice {
    /** A classical RSA / Ed25519 / X25519 subkey (ClassicalSubkeyGen). */
    data class Classical(val type: ClassicalSubkeyGen.ClassicalSubkeyType) : AddSubkeyChoice

    /** A composite ML-KEM + ECDH encryption subkey (CompositeKeyGen). */
    data class PqEncryption(val suite: CompositeSuite) : AddSubkeyChoice

    /** A composite ML-DSA + EdDSA signing subkey (CompositeSignSubkeyGen). */
    data class PqSigning(val suite: CompositeSignSuite) : AddSubkeyChoice

    companion object {
        /**
         * Classical subkey choices for a key of the given version. v6 keys take
         * Ed25519/X25519 subkeys; v4 keys also take RSA.
         */
        fun classicalFor(isV6: Boolean): List<Classical> =
            if (isV6) listOf(
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT)
            ) else ClassicalSubkeyGen.ClassicalSubkeyType.entries.map { Classical(it) }

        /**
         * Post-quantum subkey choices for a key of the given version. v6 keys take
         * ML-KEM (768/1024) encryption and ML-DSA (65/87) signing subkeys. v4 keys
         * take only ML-KEM-768, which grafts the RFC 9980 v4 algo-35 subkey and
         * converts the key to the v4 interop shape; ML-KEM-1024 and every ML-DSA
         * shape are v6-only.
         */
        fun postQuantumFor(isV6: Boolean): List<AddSubkeyChoice> =
            if (isV6) listOf(
                PqEncryption(CompositeSuite.IETF_768),
                PqEncryption(CompositeSuite.IETF_1024),
                PqSigning(CompositeSignSuite.MLDSA65_ED25519),
                PqSigning(CompositeSignSuite.MLDSA87_ED448)
            ) else listOf(
                PqEncryption(CompositeSuite.IETF_768)
            )
    }
}

/**
 * item 7 (#55): one subkey in an advanced granular keygen plan — the kind of
 * subkey plus its own expiry (null = never / inherit).
 */
data class GranularSubkeySpec(
    val choice: AddSubkeyChoice,
    val expirationSeconds: Long?
)
