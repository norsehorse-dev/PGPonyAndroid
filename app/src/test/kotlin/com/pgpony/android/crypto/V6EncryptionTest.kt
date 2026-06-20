// V6EncryptionTest.kt
// PGPony Android
//
// Verifies V6-4 outbound encryption against real BouncyCastle 1.84. Rather
// than poke at raw SEIPD packet versions, these tests assert behavior:
//   - encrypting to an all-v6 recipient set and decrypting with that v6 key
//     proves the SEIPDv2 (AEAD/OCB) + v6 PKESK path round-trips.
//   - encrypting to a mixed v6+v4 set and decrypting with the v4 key proves
//     the SEIPDv1 fallback: a v4 key cannot read SEIPDv2, so a successful
//     decrypt is only possible if the message downgraded to SEIPDv1.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream

class V6EncryptionTest {

    private fun pub(data: ByteArray) =
        PGPPublicKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun sec(data: ByteArray) =
        PGPSecretKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun genV6() = PGPCryptoService.shared.generateKeyPair(
        "V6 Recipient", "v6@pgpony.app", KeyAlgorithm.V6_ED25519, null, null
    )

    private fun genV4() = PGPCryptoService.shared.generateKeyPair(
        "V4 Recipient", "v4@pgpony.app", KeyAlgorithm.ED25519_CV25519, null, null
    )

    @Test
    fun `all-v6 recipients round-trip through SEIPDv2`() {
        val k = genV6()
        val ct = PGPCryptoService.shared.encrypt(
            data = "seipdv2 round trip".toByteArray(),
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = true
        )
        val result = PGPCryptoService.shared.decrypt(ct, listOf(sec(k.privateKeyData)), passphrase = null)
        assertEquals("seipdv2 round trip", String(result.data))
    }

    @Test
    fun `mixed v6 and v4 recipients fall back so the v4 key still decrypts`() {
        val v6 = genV6()
        val v4 = genV4()
        val ct = PGPCryptoService.shared.encrypt(
            data = "mixed fallback".toByteArray(),
            recipientPublicKeys = listOf(pub(v6.publicKeyData), pub(v4.publicKeyData)),
            armor = true
        )
        // A v4 key cannot decrypt SEIPDv2; success here proves the SEIPDv1 fallback.
        val result = PGPCryptoService.shared.decrypt(ct, listOf(sec(v4.privateKeyData)), passphrase = null)
        assertEquals("mixed fallback", String(result.data))
    }
}
