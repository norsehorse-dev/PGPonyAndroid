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

    /** 4.8.0 RC10 (#109): the kind of key a subkey is added to. */
    enum class Base { V4, V6, V6_COMPOSITE_SIGN }

    /** 4.8.0 RC10 (#109): what a subkey is for; both subkey lists are grouped by it, in this order. */
    enum class Usage { SIGN, AUTHENTICATE, ENCRYPT }

    companion object {
        /**
         * Classical subkey choices for a key of the given version. v6 keys take
         * Ed25519/X25519 subkeys; v4 keys also take RSA. 4.6.0 (item 21): a
         * composite ML-DSA primary also takes RSA (v6-framed), for clients such
         * as Thunderbird that cannot encrypt to its ML-KEM subkey.
         */
        fun classicalFor(isV6: Boolean, isCompositeSign: Boolean = false): List<Classical> =
            if (isV6 && isCompositeSign) listOf(
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_ENCRYPT),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_ENCRYPT),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_SIGN),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_SIGN),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_AUTH),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_AUTH)
            ) else if (isV6) listOf(
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT)
            ) else ClassicalSubkeyGen.ClassicalSubkeyType.entries
                // 4.8.0 RC10 (#109): the ECDSA/ECDH entries come through [optionsFor], one curve at a time.
                .filter { it.curve == null }.map { Classical(it) }

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

        // ── 4.8.0 RC10 (#109): one list for Add subkey and the composer ──────

        fun usageOf(choice: AddSubkeyChoice): Usage = when (choice) {
            is Classical -> when (choice.type.capability) {
                ClassicalSubkeyGen.Capability.SIGN -> Usage.SIGN
                ClassicalSubkeyGen.Capability.AUTHENTICATE -> Usage.AUTHENTICATE
                ClassicalSubkeyGen.Capability.ENCRYPT -> Usage.ENCRYPT
            }
            is PqSigning -> Usage.SIGN
            is PqEncryption -> Usage.ENCRYPT
        }

        /** The base for a stored key. */
        fun baseFor(isV6: Boolean, isCompositeSign: Boolean): Base = when {
            isV6 && isCompositeSign -> Base.V6_COMPOSITE_SIGN
            isV6 -> Base.V6
            else -> Base.V4
        }

        /**
         * Whether [base] can take [choice]. The reasons, so the lists differ only here:
         * - ECDSA and ECDH: v4 only. PGPony generates keys on these curves as v4, and the
         *   v6 subkey path (V6SubkeyGen) makes Ed25519 and X25519 only.
         * - RSA: v4, and a v6 composite ML-DSA primary (v6-framed, 4.6.0 item 21, for mail
         *   apps that cannot use its ML-KEM subkey). A classical v6 key takes Ed25519 and
         *   X25519 only (V6SubkeyGen).
         * - ML-DSA and ML-KEM-1024: v6 only. The composite signing subkey and the algorithm
         *   36 subkey need a v6 key; an ML-DSA subkey on a classical v6 primary signs since
         *   4.8.0 item 4j.
         * - ML-KEM-768: every base (on v4 it is the RFC 9980 algorithm 35 subkey).
         */
        fun allowedOn(base: Base, choice: AddSubkeyChoice): Boolean = when (choice) {
            is Classical -> when {
                choice.type.curve != null -> base == Base.V4
                choice.type.name.startsWith("RSA") -> base != Base.V6
                else -> true
            }
            is PqEncryption -> choice.suite == CompositeSuite.IETF_768 || base != Base.V4
            is PqSigning -> base != Base.V4
        }

        /**
         * Every subkey kind in the order both lists show it: by [Usage], and within a
         * usage Ed25519 or X25519, then ECDSA or ECDH on [curve], RSA 2048, RSA 4096 and
         * the post-quantum kinds.
         */
        private fun ordered(curve: KeyAlgorithm): List<AddSubkeyChoice> {
            fun ec(cap: ClassicalSubkeyGen.Capability) =
                listOfNotNull(ClassicalSubkeyGen.ClassicalSubkeyType.ecdsa(curve, cap)?.let { Classical(it) })
            return listOf(Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN)) + ec(ClassicalSubkeyGen.Capability.SIGN) + listOf(
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_SIGN), Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_SIGN),
                PqSigning(CompositeSignSuite.MLDSA65_ED25519), PqSigning(CompositeSignSuite.MLDSA87_ED448),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH)
            ) + ec(ClassicalSubkeyGen.Capability.AUTHENTICATE) + listOf(
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_AUTH), Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_AUTH),
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT)
            ) + ec(ClassicalSubkeyGen.Capability.ENCRYPT) + listOf(
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_ENCRYPT), Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_ENCRYPT),
                PqEncryption(CompositeSuite.IETF_768), PqEncryption(CompositeSuite.IETF_1024)
            )
        }

        /**
         * The subkey kinds offered for [base], with ECDSA and ECDH on [curve], the one
         * list Add subkey and the composer both show (same order, same labels).
         * [postQuantum] false leaves the post-quantum kinds out, for a key linked to a
         * security key, whose card holds classical keys only.
         */
        fun optionsFor(
            base: Base,
            curve: KeyAlgorithm = KeyAlgorithm.ECDSA_NIST_P256,
            postQuantum: Boolean = true
        ): List<AddSubkeyChoice> = ordered(curve).filter { c ->
            allowedOn(base, c) && (postQuantum || c is Classical)
        }

        /** The curve a subkey list starts on: the key's own when it is a generated ECDSA key. */
        fun defaultCurve(keyAlgorithm: KeyAlgorithm?): KeyAlgorithm =
            keyAlgorithm?.takeIf { it in KeyAlgorithm.generatableEcdsa } ?: KeyAlgorithm.ECDSA_NIST_P256
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
