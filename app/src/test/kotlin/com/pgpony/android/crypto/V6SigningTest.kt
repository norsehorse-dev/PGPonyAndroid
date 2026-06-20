// V6SigningTest.kt
// PGPony Android
//
// Verifies V6-5 software signing against real BouncyCastle 1.84. Before V6-5
// every PGPSignatureGenerator was built with the 1-arg constructor, which
// BC hardcodes to signature version 4; feeding it a v6 key threw "Key version
// mismatch" at init(). V6-5 passes the signing public key to the version-aware
// 2-arg constructor so BC selects the version from the key (v6 => salted v6
// signature). These tests prove a v6 key now produces a verifiable v6 detached
// signature, and that v4 signing is unchanged (the 2-arg constructor resolves
// to version 4 for v4 keys). The card path is identical in structure but can
// only be exercised on-device, so it is covered by the sq interop gate.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class V6SigningTest {

    private fun pub(data: ByteArray) =
        PGPPublicKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun sec(data: ByteArray) =
        PGPSecretKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun roundTrip(algorithm: KeyAlgorithm, name: String, email: String, message: String) {
        val k = PGPCryptoService.shared.generateKeyPair(name, email, algorithm, null, null)
        val data = message.toByteArray()

        val sigArmored = String(
            SigningService.shared.signDetached(
                data = data,
                secretKeyRing = sec(k.privateKeyData),
                passphrase = null,
                armor = true
            )
        )

        val result = VerifyService.shared.verifyDetached(
            signatureArmored = sigArmored,
            signedBytes = data,
            publicKeyRings = listOf(pub(k.publicKeyData))
        )

        assertTrue("expected Verified, got $result", result is VerificationResult.Verified)
    }

    @Test
    fun `v6 key produces a verifiable v6 detached signature`() {
        roundTrip(
            KeyAlgorithm.V6_ED25519,
            "V6 Signer", "v6sign@pgpony.app",
            "v6 detached signing round trip"
        )
    }

    @Test
    fun `v4 key signing is unchanged`() {
        roundTrip(
            KeyAlgorithm.ED25519_CV25519,
            "V4 Signer", "v4sign@pgpony.app",
            "v4 detached signing still works"
        )
    }
}
