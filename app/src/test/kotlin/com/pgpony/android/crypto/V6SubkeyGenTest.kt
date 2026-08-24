// V6SubkeyGenTest.kt
// PGPony Android, 4.4.0 RC2 (planning §1.1)
//
// Pins the v6 add-subkey path: adding an Ed25519 signing or X25519 encryption
// subkey to an existing v6 primary through BC's OpenPGPKeyEditor. Uses real
// crypto (PGPCryptoService.shared) end to end, the same way the v6 keygen
// tests do. KeyRepository is not exercised here because it needs an Android
// Context; V6SubkeyGen is pure crypto over a PGPSecretKeyRing.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class V6SubkeyGenTest {

    private val svc = PGPCryptoService.shared

    private fun v6Ring(passphrase: String?, expiry: Long? = null): PGPSecretKeyRing {
        val gen = svc.generateKeyPair(
            "V6 Sub", "v6sub@pgpony.app",
            KeyAlgorithm.V6_ED25519, passphrase = passphrase, expirationSeconds = expiry
        )
        return PGPSecretKeyRing(
            ByteArrayInputStream(gen.privateKeyData), JcaKeyFingerprintCalculator()
        )
    }

    private fun newSubkeyOf(before: PGPSecretKeyRing, after: PGPSecretKeyRing): List<PGPSecretKey> {
        val beforeIds = before.secretKeys.asSequence().map { it.keyID }.toSet()
        return after.secretKeys.asSequence().filter { it.keyID !in beforeIds }.toList()
    }

    private fun keyFlagsOf(pub: PGPPublicKey): Int {
        val binding = pub.signatures.asSequence()
            .firstOrNull { it.signatureType == PGPSignature.SUBKEY_BINDING }
        return binding?.hashedSubPackets?.keyFlags ?: 0
    }

    @Test
    fun `adds a v6 ed25519 signing subkey that is v6 and not an encryption key`() {
        val ring = v6Ring(passphrase = null)
        val primaryFp = ring.publicKey.fingerprint
        val updated = V6SubkeyGen.addSubkey(
            ring, V6SubkeyGen.V6SubkeyType.ED25519_SIGN, passphrase = null
        )

        val added = newSubkeyOf(ring, updated)
        assertEquals("exactly one new subkey", 1, added.size)
        val sub = added.first()
        assertEquals("subkey must be v6", 6, sub.publicKey.version)
        assertTrue("a signing subkey is not an encryption key", !sub.publicKey.isEncryptionKey)
        assertTrue(
            "primary fingerprint must be unchanged",
            primaryFp.contentEquals(updated.publicKey.fingerprint)
        )

        val reparsed = PGPSecretKeyRing(
            ByteArrayInputStream(updated.encoded), JcaKeyFingerprintCalculator()
        )
        assertEquals(
            updated.secretKeys.asSequence().count(),
            reparsed.secretKeys.asSequence().count()
        )
    }

    @Test
    fun `adds a v6 x25519 encryption subkey that is v6 and an encryption key`() {
        val ring = v6Ring(passphrase = null)
        val updated = V6SubkeyGen.addSubkey(
            ring, V6SubkeyGen.V6SubkeyType.X25519_ENCRYPT, passphrase = null
        )

        val sub = newSubkeyOf(ring, updated).single()
        assertEquals(6, sub.publicKey.version)
        assertTrue("an encryption subkey is an encryption key", sub.publicKey.isEncryptionKey)
    }

    @Test
    fun `a v6 subkey added to a protected key is itself passphrase protected`() {
        val pass = "correct horse"
        val ring = v6Ring(passphrase = pass)
        val updated = V6SubkeyGen.addSubkey(
            ring, V6SubkeyGen.V6SubkeyType.ED25519_SIGN, passphrase = pass
        )

        val sub = newSubkeyOf(ring, updated).single()
        assertNotEquals("a new secret subkey must not be stored unprotected", 0, sub.s2KUsage)
    }

    @Test
    fun `a v6 subkey honors a chosen expiry`() {
        val oneYear = 365L * 24 * 60 * 60
        val ring = v6Ring(passphrase = null)
        val updated = V6SubkeyGen.addSubkey(
            ring, V6SubkeyGen.V6SubkeyType.ED25519_SIGN,
            passphrase = null, expirationSeconds = oneYear
        )
        val sub = newSubkeyOf(ring, updated).single()
        assertTrue(
            "subkey should carry a positive expiry, got ${sub.publicKey.validSeconds}",
            sub.publicKey.validSeconds > 0L
        )
    }

    @Test
    fun `a v6 subkey with no expiry never expires`() {
        val ring = v6Ring(passphrase = null)
        val updated = V6SubkeyGen.addSubkey(
            ring, V6SubkeyGen.V6SubkeyType.X25519_ENCRYPT,
            passphrase = null, expirationSeconds = null
        )
        val sub = newSubkeyOf(ring, updated).single()
        assertEquals("subkey should be non-expiring", 0L, sub.publicKey.validSeconds)
    }

    @Test
    fun `adds a v6 authentication subkey carrying the AUTHENTICATE flag`() {
        val ring = v6Ring(passphrase = null)
        val updated = V6SubkeyGen.addSubkey(
            ring, V6SubkeyGen.V6SubkeyType.ED25519_AUTH, passphrase = null
        )
        val sub = newSubkeyOf(ring, updated).single()
        assertEquals(6, sub.publicKey.version)
        val flags = keyFlagsOf(sub.publicKey)
        assertTrue(
            "auth subkey must carry the AUTHENTICATION flag",
            flags and KeyFlags.AUTHENTICATION != 0
        )
        assertEquals("auth subkey must not carry the signing flag", 0, flags and KeyFlags.SIGN_DATA)
    }
}
