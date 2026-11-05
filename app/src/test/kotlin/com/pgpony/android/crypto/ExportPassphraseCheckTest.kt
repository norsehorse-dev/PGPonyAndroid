// ExportPassphraseCheckTest.kt
// PGPony Android, 4.8.0 (item 3a): before a protected private key leaves the
// phone, the typed passphrase is checked by unlocking the stored secret. Every
// key type the keyring stores: v4 Ed25519, RSA, v6, a composite ML-DSA primary,
// a v4 key with the algorithm 35 ML-KEM subkey, and a v6 Ed25519 key with an
// ML-DSA signing subkey. An unprotected key asks nothing.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositePrimaryKeyGen
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class ExportPassphraseCheckTest {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"

    private fun assertChecks(label: String, secret: ByteArray) {
        assertTrue("$label asks for the passphrase", SecretKeyCheck.exportNeedsPassphrase(secret))
        assertTrue("$label unlocks with the right passphrase", SecretKeyCheck.passphraseUnlocks(secret, pass.toCharArray()))
        assertFalse("$label refuses a wrong passphrase", SecretKeyCheck.passphraseUnlocks(secret, "wrong".toCharArray()))
    }

    @Test
    fun `classical v4 keys`() {
        for (alg in listOf(KeyAlgorithm.ED25519_CV25519, KeyAlgorithm.RSA_2048)) {
            assertChecks(alg.name, svc.generateKeyPair("Owner", "owner@example.test", alg, pass).privateKeyData)
        }
    }

    @Test
    fun `a v6 key`() {
        assertChecks("v6", svc.generateKeyPair("Owner", "owner@example.test", KeyAlgorithm.V6_ED25519, pass).privateKeyData)
    }

    @Test
    fun `a composite ML-DSA primary`() {
        val raw = CompositePrimaryKeyGen.assemble("PQ <pq@example.test>", CompositeSignSuite.MLDSA65_ED25519, SecureRandom())
        assertFalse("unprotected, nothing to ask", SecretKeyCheck.exportNeedsPassphrase(raw))
        assertChecks("composite", CompositeKeyFacade.reprotect(raw, null, pass.toCharArray()))
    }

    @Test
    fun `a v4 key with the algorithm 35 ML-KEM subkey`() {
        val key = svc.assembleGranularV4(
            "Owner <owner@example.test>", includeDefaultEncryptionSubkey = true,
            subkeys = listOf(GranularSubkeySpec(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768), null)),
            passphrase = pass
        )
        assertTrue(key.hasV4Algo35)
        assertChecks("v4 algo 35", key.secret)
    }

    @Test
    fun `a v6 Ed25519 key with an ML-DSA signing subkey`() {
        val ring = svc.assembleGranularV6Ring(
            "Owner <owner@example.test>", includeDefaultEncryptionSubkey = true,
            subkeys = listOf(GranularSubkeySpec(AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA65_ED25519), null)),
            passphrase = pass
        )
        assertChecks("v6 with ML-DSA subkey", ring.encoded)
    }

    @Test
    fun `an unprotected key asks for nothing`() {
        val g = svc.generateKeyPair("Owner", "owner@example.test", KeyAlgorithm.ED25519_CV25519, null)
        assertFalse(SecretKeyCheck.exportNeedsPassphrase(g.privateKeyData))
        assertFalse(SecretKeyCheck.exportNeedsPassphrase(g.publicKeyData))
    }
}
