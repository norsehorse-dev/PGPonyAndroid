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
    enum class Base {
        /** A v4 key with an Ed25519 (EdDSA) primary. */
        V4,
        /** 4.8.0 RC11 (#109): a v4 key with an RSA or ECDSA primary. */
        V4_OTHER,
        V6,
        V6_COMPOSITE_SIGN
    }

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
        fun baseFor(isV6: Boolean, isCompositeSign: Boolean, algorithm: KeyAlgorithm? = null): Base = when {
            isV6 && isCompositeSign -> Base.V6_COMPOSITE_SIGN
            isV6 -> Base.V6
            // 4.8.0 RC11 (#109): only an Ed25519 v4 primary takes an ML-KEM-768
            // subkey (see allowedOn), so Base.V4 is an allow-list of the key types
            // whose primary is Ed25519; RSA, ECDSA and anything unknown are V4_OTHER.
            algorithm in ED25519_V4_PRIMARIES -> Base.V4
            else -> Base.V4_OTHER
        }

        /**
         * 4.8.0 RC11 (#109): v4 key types whose primary is Ed25519 (EdDSA legacy):
         * PGPony's Ed25519 key, the v4 ML-KEM-768 interop key and the LibrePGP keys
         * PGPony makes on an Ed25519 primary. ML-KEM-1024 + brainpoolP384r1 is left
         * out: gpg makes it on an ECDSA primary.
         */
        private val ED25519_V4_PRIMARIES = setOf(
            KeyAlgorithm.ED25519_CV25519, KeyAlgorithm.MLKEM768_X25519_V4, KeyAlgorithm.MLKEM768_X25519_LIBREPGP,
            KeyAlgorithm.MLKEM1024_X448_LIBREPGP, KeyAlgorithm.MLKEM768_BP256_LIBREPGP
        )

        /** 4.8.0 RC11 (#109): a subkey kind's family, for listing the primary's own family first. */
        private enum class Family { ED25519, ECDSA, RSA, OTHER }

        private fun familyOf(choice: AddSubkeyChoice): Family = when {
            choice !is Classical -> Family.OTHER
            choice.type.curve != null -> Family.ECDSA
            choice.type.name.startsWith("RSA") -> Family.RSA
            else -> Family.ED25519
        }

        private fun familyOf(primary: KeyAlgorithm?): Family = when {
            primary == null -> Family.OTHER
            primary in KeyAlgorithm.generatableEcdsa || primary == KeyAlgorithm.ECDSA -> Family.ECDSA
            primary.name.startsWith("RSA") -> Family.RSA
            primary == KeyAlgorithm.ED25519_CV25519 || primary == KeyAlgorithm.V6_ED25519 -> Family.ED25519
            else -> Family.OTHER
        }

        /**
         * 4.8.0 RC11 (#109): the signing subkey of [primary]'s own type, the one a
         * certify-only primary gets when none is composed: ECDSA on its curve, RSA
         * of its size, Ed25519 otherwise.
         */
        fun signingFor(primary: KeyAlgorithm): Classical = when (primary) {
            KeyAlgorithm.RSA_2048 -> Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_SIGN)
            KeyAlgorithm.RSA_4096 -> Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_SIGN)
            else -> ClassicalSubkeyGen.ClassicalSubkeyType.ecdsa(primary, ClassicalSubkeyGen.Capability.SIGN)
                ?.let { Classical(it) } ?: Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN)
        }

        /**
         * 4.8.0 RC11 (#109): the signing subkey a composed v4 key gets on top of
         * [chosen]: one of [primary]'s type when the primary certifies only and no
         * signing subkey was composed, so the key can still sign. Empty otherwise.
         */
        fun addedSigningSubkey(primary: KeyAlgorithm, certifyOnly: Boolean, chosen: List<AddSubkeyChoice>): List<Classical> =
            if (certifyOnly && chosen.none { usageOf(it) == Usage.SIGN }) listOf(signingFor(primary)) else emptyList()

        /**
         * 4.8.0 RC11 (#109): the base the composer builds on for a primary picked in
         * Generate Key, or null when it cannot compose on that primary. Ed25519 v6 is
         * the v6 composer; Ed25519, RSA and ECDSA build a v4 key. The post-quantum
         * choices are whole key shapes of their own (an ML-DSA primary is not a Bouncy
         * Castle ring, and the ML-KEM shapes are an Ed25519 key with a fixed subkey), so
         * they are composed from Ed25519 v6 instead.
         */
        fun composerBaseFor(primary: KeyAlgorithm): Base? = when {
            primary == KeyAlgorithm.V6_ED25519 -> Base.V6
            primary == KeyAlgorithm.ED25519_CV25519 -> Base.V4
            primary == KeyAlgorithm.RSA_2048 || primary == KeyAlgorithm.RSA_4096 -> Base.V4_OTHER
            primary in KeyAlgorithm.generatableEcdsa -> Base.V4_OTHER
            else -> null
        }

        /**
         * 4.8.0 RC11 (#109): the encryption subkey plain Generate gives [primary], which
         * the composer's "Include default encryption subkey" switch keeps: RSA of the same
         * size, ECDH on the same curve, X25519 (Cv25519 on v4) for Ed25519.
         */
        fun defaultEncryptionFor(primary: KeyAlgorithm): Classical? = when (primary) {
            KeyAlgorithm.RSA_2048 -> Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_ENCRYPT)
            KeyAlgorithm.RSA_4096 -> Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_ENCRYPT)
            KeyAlgorithm.ED25519_CV25519, KeyAlgorithm.V6_ED25519 ->
                Classical(ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT)
            else -> ClassicalSubkeyGen.ClassicalSubkeyType.ecdsa(primary, ClassicalSubkeyGen.Capability.ENCRYPT)
                ?.let { Classical(it) }
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
         * - ML-KEM-768: every base but an RSA or ECDSA v4 primary (on v4 it is the RFC 9980
         *   algorithm 35 subkey). 4.8.0 RC11 (#109): its v4 binding is an EdDSA signature
         *   made by hand (CompositeKeyGen.addV4Algo35SubkeyRings), so an RSA or ECDSA
         *   primary cannot sign it; Add subkey used to offer it there and fail.
         */
        fun allowedOn(base: Base, choice: AddSubkeyChoice): Boolean = when (choice) {
            is Classical -> when {
                choice.type.curve != null -> base == Base.V4 || base == Base.V4_OTHER
                choice.type.name.startsWith("RSA") -> base != Base.V6
                else -> true
            }
            is PqEncryption -> when (base) {
                Base.V4 -> choice.suite == CompositeSuite.IETF_768
                Base.V4_OTHER -> false
                else -> true
            }
            is PqSigning -> base == Base.V6 || base == Base.V6_COMPOSITE_SIGN
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
            postQuantum: Boolean = true,
            // 4.8.0 RC11 (#109): within each use, [primary]'s own family comes first
            // (on a brainpool key the brainpool ECDSA entry before Ed25519 and RSA).
            primary: KeyAlgorithm? = null
        ): List<AddSubkeyChoice> {
            val own = familyOf(primary)
            return ordered(curve)
                .filter { c -> allowedOn(base, c) && (postQuantum || c is Classical) }
                .sortedWith(compareBy({ usageOf(it).ordinal }, { if (own != Family.OTHER && familyOf(it) == own) 0 else 1 }))
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
