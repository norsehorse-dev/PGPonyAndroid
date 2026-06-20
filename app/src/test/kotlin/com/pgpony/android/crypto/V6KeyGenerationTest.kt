// V6KeyGenerationTest.kt
// PGPony Android
//
// Verifies V6-3 key generation against real BouncyCastle 1.84 (BC is on the
// unit-test classpath, so this exercises the actual high-level OpenPGP API,
// not a mock). The structural assertions lock the key shape; the two
// expiration assertions probe whether the expiry we set on the v6 direct-key
// signature is reflected by PGPPublicKey.getValidSeconds() — the same call
// KeyRepository.generateKey uses to populate the entity's expiresAt.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class V6KeyGenerationTest {

    // RFC 9580 native algorithm IDs (mirrors KeyAlgorithm.from).
    private val ED25519 = 27
    private val X25519 = 25

    private fun parse(data: ByteArray): PGPPublicKeyRing =
        PGPPublicKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    @Test
    fun `generates a v6 ed25519 plus x25519 key with the expected shape`() {
        val result = PGPCryptoService.shared.generateKeyPair(
            name = "V6 Test",
            email = "v6@pgpony.app",
            algorithm = KeyAlgorithm.V6_ED25519,
            passphrase = null,
            expirationSeconds = null
        )

        // v6 fingerprint = 32 bytes = 64 hex chars
        assertEquals(64, result.fingerprint.length)

        val ring = parse(result.publicKeyData)
        val keys = ring.publicKeys.asSequence().toList()

        // cert-only primary + signing subkey + encryption subkey
        assertEquals(3, keys.size)

        val primary = ring.publicKey
        assertEquals(PublicKeyPacket.VERSION_6, primary.version)
        assertEquals(ED25519, primary.algorithm)

        // exactly one X25519 encryption subkey
        assertEquals(1, keys.count { it.algorithm == X25519 && it.isEncryptionKey })

        // every key in the ring is v6
        assertTrue(keys.all { it.version == PublicKeyPacket.VERSION_6 })
    }

    @Test
    fun `never-expiry produces a primary with no expiration`() {
        val result = PGPCryptoService.shared.generateKeyPair(
            "No Expiry", "noexp@pgpony.app", KeyAlgorithm.V6_ED25519, null, null
        )
        // getValidSeconds() == 0 means the key never expires
        assertEquals(0L, parse(result.publicKeyData).publicKey.validSeconds)
    }

    @Test
    fun `custom expiry is honored on the primary`() {
        val oneYear = 365L * 24 * 60 * 60
        val result = PGPCryptoService.shared.generateKeyPair(
            "Expiry", "exp@pgpony.app", KeyAlgorithm.V6_ED25519, null, oneYear
        )
        assertEquals(oneYear, parse(result.publicKeyData).publicKey.validSeconds)
    }
}
