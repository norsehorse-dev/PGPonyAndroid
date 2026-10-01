// SecretKeyUnlock.kt
// PGPony Android: the one way to unlock a Bouncy Castle secret key.
//
// A secret key protected with Argon2 names its own memory size, passes and
// parallelism. A key from a GnuPG home, a backup, an archive or a paired
// device could name values large enough to exhaust memory or stall for
// minutes. Every unlock therefore checks the S2K against the Argon2 policy
// (enforceArgon2Policy, SecurityLimits) before the KDF runs: once on the key
// up front, and again inside the decryptor, where Bouncy Castle derives the
// key, so a path that hands the decryptor to Bouncy Castle directly is
// covered too.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.S2K
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider

object SecretKeyUnlock {

    /**
     * A secret-key decryptor for [passphrase] that refuses an Argon2 S2K
     * outside the policy (PGPCryptoError.ResourceLimitExceeded) before
     * deriving anything. Use it wherever BcPBESecretKeyDecryptorBuilder was
     * used to unlock a stored key.
     */
    fun decryptor(passphrase: CharArray?): PBESecretKeyDecryptor {
        val provider = BcPGPDigestCalculatorProvider()
        return Guarded(BcPBESecretKeyDecryptorBuilder(provider).build(passphrase), passphrase, provider)
    }

    /** [decryptor] for a String passphrase (null or empty for none). */
    fun decryptor(passphrase: String?): PBESecretKeyDecryptor = decryptor((passphrase ?: "").toCharArray())

    /**
     * Unlock [key] with [passphrase] after checking its S2K against the
     * Argon2 policy. Throws PGPCryptoError.ResourceLimitExceeded for a
     * refused S2K and Bouncy Castle's PGPException as before otherwise.
     */
    fun extract(key: PGPSecretKey, passphrase: CharArray?): PGPPrivateKey? {
        enforceArgon2Policy(key.s2K)
        return key.extractPrivateKey(decryptor(passphrase))
    }

    private class Guarded(
        private val inner: PBESecretKeyDecryptor,
        passphrase: CharArray?,
        provider: BcPGPDigestCalculatorProvider
    ) : PBESecretKeyDecryptor(passphrase, provider) {
        override fun makeKeyFromPassPhrase(keyAlgorithm: Int, s2k: S2K?): ByteArray {
            enforceArgon2Policy(s2k)
            return inner.makeKeyFromPassPhrase(keyAlgorithm, s2k)
        }

        override fun getChecksumCalculator(hashAlgorithm: Int): PGPDigestCalculator =
            inner.getChecksumCalculator(hashAlgorithm)

        override fun recoverKeyData(
            encAlgorithm: Int, key: ByteArray, iv: ByteArray, keyData: ByteArray, keyOff: Int, keyLen: Int
        ): ByteArray = inner.recoverKeyData(encAlgorithm, key, iv, keyData, keyOff, keyLen)

        override fun recoverKeyData(
            encAlgorithm: Int, aeadAlgorithm: Int, s2kKey: ByteArray, iv: ByteArray,
            packetTag: Int, keyVersion: Int, keyData: ByteArray, pubkeyData: ByteArray
        ): ByteArray = inner.recoverKeyData(encAlgorithm, aeadAlgorithm, s2kKey, iv, packetTag, keyVersion, keyData, pubkeyData)
    }
}
