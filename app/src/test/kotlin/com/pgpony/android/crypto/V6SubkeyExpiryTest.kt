// V6SubkeyExpiryTest.kt
// PGPony issue #4 (SecTec): an OpenPGP v6 key generated with an expiration date must carry that
// expiry on EVERY key, including the signing subkey. BC's OpenPGPKeyGenerator writes no Key
// Expiration Time onto subkey binding signatures by default, so the fix routes the expiration
// callback through addSigningSubkey / addEncryptionSubkey. This pins that all three keys expire.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class V6SubkeyExpiryTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `v6 keygen expiry lands on primary and both subkeys`() {
        val expirySeconds = 2L * 365 * 24 * 60 * 60 // ~2 years
        val gen = svc.generateKeyPair(
            "V6 Exp", "v6exp@pgpony.app",
            KeyAlgorithm.V6_ED25519, passphrase = null, expirationSeconds = expirySeconds
        )
        val ring = PGPPublicKeyRing(ByteArrayInputStream(gen.publicKeyData), JcaKeyFingerprintCalculator())
        val keys = ring.publicKeys.asSequence().toList()
        assertTrue("expected primary + signing + encryption subkeys", keys.size >= 3)
        keys.forEach { k ->
            val role = if (k.isMasterKey) "primary" else "subkey ${java.lang.Long.toHexString(k.keyID)}"
            assertTrue("$role carries no key expiration (validSeconds=${k.validSeconds})", k.validSeconds > 0L)
        }
    }

    @Test
    fun `pq v6 keygen expiry lands on all keys including the composite subkey`() {
        val expirySeconds = 2L * 365 * 24 * 60 * 60
        val gen = svc.generateKeyPair(
            "PQ V6 Exp", "pqv6exp@pgpony.app",
            KeyAlgorithm.MLKEM768_X25519_V6, passphrase = null, expirationSeconds = expirySeconds
        )
        val ring = PGPPublicKeyRing(ByteArrayInputStream(gen.publicKeyData), JcaKeyFingerprintCalculator())
        val keys = ring.publicKeys.asSequence().toList()
        assertTrue("expected primary + sign + encrypt + composite subkeys", keys.size >= 4)
        keys.forEach { k ->
            val id = java.lang.Long.toHexString(k.keyID)
            assertTrue("key $id carries no expiration (validSeconds=${k.validSeconds})", k.validSeconds > 0L)
        }
    }

    @Test
    fun `v6 keygen without expiry leaves every key non-expiring`() {
        val gen = svc.generateKeyPair(
            "V6 NoExp", "v6noexp@pgpony.app",
            KeyAlgorithm.V6_ED25519, passphrase = null, expirationSeconds = null
        )
        val ring = PGPPublicKeyRing(ByteArrayInputStream(gen.publicKeyData), JcaKeyFingerprintCalculator())
        ring.publicKeys.asSequence().forEach { k ->
            assertTrue("expected no expiry, got validSeconds=${k.validSeconds}", k.validSeconds == 0L)
        }
    }
}
