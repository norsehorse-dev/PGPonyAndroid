// SshSigningKey.kt
// PGPony Android, 4.6.0 (item 16): unlock an authentication subkey's private
// key for SSH signing.
//
// The secret ring comes from the keyring as for any other private-key use: a
// Bouncy Castle ring for ordinary keys, or, for a composite ML-DSA primary
// (which Bouncy Castle cannot load), CompositeKeyFacade.classicalAuthRing,
// which carries only the key's classical subkeys. The subkey keeps its own
// protection, so the key's passphrase unlocks it either way.

package com.pgpony.android.crypto.ssh

import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter

object SshSigningKey {

    sealed class Unlock {
        class Ok(val key: AsymmetricKeyParameter) : Unlock()
        /** The subkey is protected and no passphrase was given. */
        object NeedsPassphrase : Unlock()
        /** The subkey is protected and the passphrase did not open it. */
        object WrongPassphrase : Unlock()
        /** No such secret subkey (a public-only or stub subkey, say). */
        class Missing(val reason: String) : Unlock()
    }

    fun unlock(ring: PGPSecretKeyRing, subkeyId: Long, passphrase: String?): Unlock {
        val secret = ring.getSecretKey(subkeyId)
            ?: return Unlock.Missing("The private part of the authentication subkey is not on this device")
        if (secret.isPrivateKeyEmpty) {
            return Unlock.Missing("The authentication subkey is a stub (its private part lives elsewhere)")
        }
        val protected = secret.s2KUsage.toInt() != 0
        if (protected && passphrase.isNullOrEmpty()) return Unlock.NeedsPassphrase
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
            .build((passphrase ?: "").toCharArray())
        val priv = try {
            secret.extractPrivateKey(decryptor)
        } catch (e: PGPException) {
            return if (protected) Unlock.WrongPassphrase
            else Unlock.Missing(e.message ?: "Could not read the authentication subkey")
        } ?: return Unlock.Missing("Could not read the authentication subkey")
        return Unlock.Ok(BcPGPKeyConverter().getPrivateKey(priv))
    }
}
