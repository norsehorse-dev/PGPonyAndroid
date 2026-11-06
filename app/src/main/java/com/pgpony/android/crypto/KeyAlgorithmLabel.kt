// KeyAlgorithmLabel.kt
// PGPony Android 4.8.0 (#88): an algorithm label read from the public key
// itself, for keys KeyAlgorithm does not model.
//
// The signer and certifier lookup cards showed KeyAlgorithm.displayName, so a
// DSA primary with an ElGamal subkey (common on older gpg keys) read
// "Unknown". The algorithm id and the key size (or curve) are always in the
// packet, so the card now shows those ("DSA 1024 + ElGamal 4096"). Unknown is
// left for a key whose algorithm id this file does not know either.
// KeyAlgorithm.UNKNOWN stays the fallback everywhere else.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing

object KeyAlgorithmLabel {

    /**
     * "RSA 3072", "DSA 1024", "ElGamal 4096", "ECDSA NIST P-256", "Ed25519",
     * "X25519" and so on for one key packet, or null when its algorithm id is
     * not one this function knows.
     */
    fun of(key: PGPPublicKey): String? {
        val bits = key.bitStrength.takeIf { it > 0 }
        fun sized(name: String) = if (bits != null) "$name $bits" else name
        val curve = EcCurveOid.label(key)
        return when (key.algorithm) {
            PublicKeyAlgorithmTags.RSA_GENERAL,
            PublicKeyAlgorithmTags.RSA_ENCRYPT,
            PublicKeyAlgorithmTags.RSA_SIGN -> sized("RSA")
            PublicKeyAlgorithmTags.DSA -> sized("DSA")
            PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT,
            PublicKeyAlgorithmTags.ELGAMAL_GENERAL -> sized("ElGamal")
            PublicKeyAlgorithmTags.ECDSA -> if (curve != null) "ECDSA $curve" else "ECDSA"
            // Same wording as the Subkeys list on Key Details.
            PublicKeyAlgorithmTags.ECDH -> when (curve) {
                "Curve25519", "X25519" -> "X25519"
                null -> "ECDH"
                else -> "ECDH $curve"
            }
            PublicKeyAlgorithmTags.EDDSA_LEGACY -> curve ?: "EdDSA"
            PublicKeyAlgorithmTags.Ed25519 -> "Ed25519"
            PublicKeyAlgorithmTags.Ed448 -> "Ed448"
            PublicKeyAlgorithmTags.X25519 -> "X25519"
            PublicKeyAlgorithmTags.X448 -> "X448"
            // Composites and the rest: whatever KeyAlgorithm knows by id.
            else -> KeyAlgorithm.from(key.algorithm, key.version)
                ?.takeIf { it != KeyAlgorithm.UNKNOWN }?.displayName
        }
    }

    /**
     * The line the signer and certifier lookup cards show. A key KeyAlgorithm
     * models keeps its usual name ([algorithm] from the import preview); any
     * other is labelled from [ring]: the primary, then the first usable
     * encryption subkey when it differs ("DSA 1024 + ElGamal 4096"). Unknown
     * only when the primary's algorithm id is unknown too.
     */
    fun lookupCard(algorithm: KeyAlgorithm, ring: PGPPublicKeyRing?): String {
        if (algorithm != KeyAlgorithm.UNKNOWN) return algorithm.displayName
        val primary = ring?.publicKey ?: return KeyAlgorithm.UNKNOWN.displayName
        val primaryLabel = of(primary) ?: return KeyAlgorithm.UNKNOWN.displayName
        val encryption = ring.publicKeys.asSequence()
            .filter { !it.isMasterKey && it.isEncryptionKey && !it.hasRevocation() }
            .mapNotNull { of(it) }
            .firstOrNull()
        return if (encryption != null && encryption != primaryLabel) "$primaryLabel + $encryption" else primaryLabel
    }
}
