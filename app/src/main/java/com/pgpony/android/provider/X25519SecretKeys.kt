// X25519SecretKeys.kt
// PGPony Android 4.8.2 (item 1): where the secret half of a Curve25519
// encryption subkey lives, for the provider's X25519 actions. Shared by the
// service (which lists only subkeys whose secret is here) and
// ProviderX25519Activity (which unlocks it).

package com.pgpony.android.provider

import com.pgpony.android.data.repository.KeyRepository
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.util.encoders.Hex

internal object X25519SecretKeys {

    /** The ordinary secret ring, or a composite ML-DSA key's carrier ring of
     *  its classical encryption subkeys (they keep their own protection). */
    fun ring(repo: KeyRepository, primaryFingerprint: String): PGPSecretKeyRing? =
        repo.loadSecretKeyRing(primaryFingerprint) ?: repo.loadCompositeClassicalDecryptionRing(primaryFingerprint)

    /** The secret key [fingerprintHex] in [ring], when its secret is really
     *  there (not a GnuPG stub pointing at a card). */
    fun key(ring: PGPSecretKeyRing, fingerprintHex: String): PGPSecretKey? =
        ring.secretKeys.asSequence().firstOrNull {
            Hex.toHexString(it.publicKey.fingerprint).equals(fingerprintHex, ignoreCase = true) &&
                !it.isPrivateKeyEmpty
        }
}
