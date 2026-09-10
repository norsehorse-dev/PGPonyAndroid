// Argon2PolicyTest.kt
// PGPony Android — 4.5.0 RC1 (Finding A / 11A)
//
// Unit-tests the Argon2 work-factor guard directly: our own parameters pass,
// an inflated memory exponent or pass count is rejected with the typed error,
// and a null S2K is a no-op. This is the pre-authentication DoS guard, so it
// must fail closed on abuse and never on a legitimate work factor.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.S2K
import org.junit.Assert.assertThrows
import org.junit.Test

class Argon2PolicyTest {

    private fun argon2(passes: Int, parallelism: Int, memoryExp: Int): S2K =
        S2K.argon2S2K(S2K.Argon2Params(ByteArray(16), passes, parallelism, memoryExp))

    @Test
    fun `our own 64 MiB parameters pass`() {
        enforceArgon2Policy(argon2(3, 4, 16))
    }

    @Test
    fun `a null s2k is a no-op`() {
        enforceArgon2Policy(null)
    }

    @Test
    fun `an oversized memory exponent is rejected`() {
        assertThrows(PGPCryptoError.ResourceLimitExceeded::class.java) {
            enforceArgon2Policy(argon2(3, 4, 30))
        }
    }

    @Test
    fun `an excessive pass count is rejected`() {
        assertThrows(PGPCryptoError.ResourceLimitExceeded::class.java) {
            enforceArgon2Policy(argon2(100, 4, 16))
        }
    }
}
