// S2kCountTest.kt
// PGPony Android, 4.6.0 (item 17.6)
//
// Passphrase-protected v4 secret keys are written with SHA-256 and a coded
// count of at least 0xE0 (16,777,216 octets), not Bouncy Castle's 0x60, and
// still unlock with the passphrase.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class S2kCountTest {

    private fun assertStrong(ring: PGPSecretKeyRing, pass: String) {
        for (sk in ring.secretKeys) {
            val s2k = sk.s2K ?: continue
            if (s2k.type != S2K.SALTED_AND_ITERATED) continue
            assertEquals("SHA-256 S2K", HashAlgorithmTags.SHA256, s2k.hashAlgorithm)
            assertTrue("coded count ${s2k.iterationCount} >= 0xE0", s2k.iterationCount >= S2kPolicy.MIN_CODED_COUNT)
            val dec = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(pass.toCharArray())
            assertNotNull(sk.extractPrivateKey(dec))
        }
    }

    @Test
    fun `generated v4 keys use a strong S2K`() {
        for (alg in listOf(KeyAlgorithm.ED25519_CV25519, KeyAlgorithm.RSA_2048)) {
            val k = PGPCryptoService.shared.generateKeyPair("S", "s@pgpony.app", alg, "hunter2 is weak")
            assertStrong(PGPSecretKeyRing(k.privateKeyData, BcKeyFingerprintCalculator()), "hunter2 is weak")
        }
    }

    @Test
    fun `coded count maps to the RFC octet counts`() {
        assertEquals(65_536L, S2kPolicy.octetsFor(0x60))
        assertEquals(16_777_216L, S2kPolicy.octetsFor(0xE0))
        assertEquals(65_011_712L, S2kPolicy.octetsFor(0xFF))
        assertTrue(S2kPolicy.codedCount in S2kPolicy.MIN_CODED_COUNT..S2kPolicy.MAX_CODED_COUNT)
    }
}
