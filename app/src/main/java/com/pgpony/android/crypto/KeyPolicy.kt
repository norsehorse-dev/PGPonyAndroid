// KeyPolicy.kt
// PGPony Android, 3.0.0 checkpoint 5d-3: which keys the app still writes
// with, and which secret-key protections it accepts.
//
// Weak keys (decided 2026-09-29): RSA under 2048 bits, DSA and ElGamal are
// read-only, and so is every key of a certificate whose primary is weak. The
// app never encrypts to them and never signs with them, so no new message
// depends on them; old messages still decrypt and old signatures
// still verify, and the result carries a flag so the screen can say the key
// is weak. A caller that must refuse them outright (the SOP command line,
// which reports every operation on such a key as a failure) sets [strict].
//
// Secret-key protection (RFC 9580 3.7.2.1): a key whose passphrase goes
// through Argon2 must be protected with AEAD (S2K usage 253); a v6 key may
// not use the legacy forms (usage 255, the implicit MD5 form, or a Simple
// S2K). Such a key is refused at import, the one place every secret key
// enters the app, with a message that names the problem. So is a key whose
// Argon2 cost (memory, passes, parallelism) exceeds the hard ceilings in
// SecurityLimits; every unlock checks the same ceilings again
// (SecretKeyUnlock), together with the device's own memory budget.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing

object KeyPolicy {

    /** Smallest RSA modulus the app still encrypts to or signs with. */
    const val MIN_RSA_BITS = 2048

    /** When true, weak keys are refused for decryption and verification too. */
    @Volatile
    var strict: Boolean = false

    /** RSA under [MIN_RSA_BITS], DSA or ElGamal. */
    fun isWeak(key: PGPPublicKey): Boolean = when (key.algorithm) {
        PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_ENCRYPT, PublicKeyAlgorithmTags.RSA_SIGN ->
            key.bitStrength in 1 until MIN_RSA_BITS
        PublicKeyAlgorithmTags.DSA, PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, PublicKeyAlgorithmTags.ELGAMAL_GENERAL -> true
        else -> false
    }

    /** A short label for a weak key ("RSA 1024", "DSA", "ElGamal"), or null. */
    fun weakLabel(key: PGPPublicKey): String? {
        if (!isWeak(key)) return null
        return when (key.algorithm) {
            PublicKeyAlgorithmTags.DSA -> "DSA"
            PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, PublicKeyAlgorithmTags.ELGAMAL_GENERAL -> "ElGamal"
            else -> "RSA ${key.bitStrength}"
        }
    }

    /**
     * [key] or the [primary] that binds it is weak. A weak primary makes the
     * whole certificate weak: every binding and self-signature rests on it.
     */
    fun isWeak(key: PGPPublicKey, primary: PGPPublicKey?): Boolean =
        isWeak(key) || (primary != null && isWeak(primary))

    /** The label of [key] when it is weak, else of [primary] when that is weak, else null. */
    fun weakLabel(key: PGPPublicKey, primary: PGPPublicKey?): String? =
        weakLabel(key) ?: primary?.let { weakLabel(it) }

    /** The protection of [key] is one RFC 9580 forbids. */
    class RefusedProtection(msg: String) : Exception(msg)

    /**
     * Throws [RefusedProtection] when any secret key in [ring] uses a
     * protection RFC 9580 forbids. Unprotected keys and stubs (no secret
     * material, GNU extension) are not checked.
     */
    fun requireAcceptableProtection(ring: PGPSecretKeyRing) {
        val it = ring.secretKeys
        while (it.hasNext()) checkProtection(it.next())
    }

    private fun checkProtection(key: PGPSecretKey) {
        val usage = key.s2KUsage.toInt() and 0xFF
        if (usage == 0) return
        val s2k: S2K? = key.s2K
        if (s2k != null && s2k.type == S2K.GNU_DUMMY_S2K) return
        if (s2k != null && s2k.type == S2K.ARGON_2 && usage != 253) {
            throw RefusedProtection("the key is protected with Argon2 but without AEAD, which RFC 9580 forbids")
        }
        if (s2k != null && s2k.type == S2K.ARGON_2 && (
                s2k.memorySizeExponent > SecurityLimits.ARGON2_MAX_MEM_EXP ||
                    s2k.passes > SecurityLimits.ARGON2_MAX_PASSES ||
                    s2k.parallelism > SecurityLimits.ARGON2_MAX_PARALLELISM)
        ) {
            throw RefusedProtection("the key's Argon2 passphrase settings exceed what this app allows")
        }
        if (key.publicKey.version == 6) {
            when {
                usage == 255 || usage in 1..252 ->
                    throw RefusedProtection("the v6 key uses a legacy protection format, which RFC 9580 forbids")
                s2k != null && s2k.type == S2K.SIMPLE ->
                    throw RefusedProtection("the v6 key is protected with a simple S2K, which RFC 9580 forbids")
            }
        }
    }
}
