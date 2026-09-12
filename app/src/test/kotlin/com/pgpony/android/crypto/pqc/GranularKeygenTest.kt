// GranularKeygenTest.kt
// PGPony Android — 4.5.0 (item 7 / #55): advanced granular keygen assembly.
//
// assembleGranularV6Ring builds a v6 Ed25519 primary, keeps or strips its default
// X25519 encryption subkey, and grafts a chosen subkey set. These tests lock the
// stripping and composition, and prove the composed key is usable: with the
// default stripped and a composite ML-KEM subkey added, the message encrypts to
// the post-quantum subkey with no classical encryption subkey to downgrade to.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.GranularSubkeySpec
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GranularKeygenTest {

    private val svc = PGPCryptoService.shared

    private val X25519_ALGO = 25
    private val COMPOSITE_MLKEM = 35
    private val COMPOSITE_MLDSA = 30

    @Test
    fun `stripping the default leaves a bare primary, keeping it adds the encryption subkey`() {
        val stripped = svc.assembleGranularV6Ring(
            "Bare <bare@example.test>", includeDefaultEncryptionSubkey = false,
            subkeys = emptyList(), passphrase = null
        )
        assertFalse(
            "stripped ring has no encryption subkey",
            stripped.publicKeys.asSequence().any { !it.isMasterKey && it.isEncryptionKey }
        )

        val kept = svc.assembleGranularV6Ring(
            "Kept <kept@example.test>", includeDefaultEncryptionSubkey = true,
            subkeys = emptyList(), passphrase = null
        )
        assertTrue(
            "kept ring has the default encryption subkey",
            kept.publicKeys.asSequence().any { !it.isMasterKey && it.isEncryptionKey }
        )
        assertEquals(
            "stripping removes exactly the default encryption subkey",
            stripped.publicKeys.asSequence().count() + 1,
            kept.publicKeys.asSequence().count()
        )
    }

    @Test
    fun `granular keygen composes the chosen subkey set and encrypts to the PQ subkey`() {
        val subkeys = listOf(
            GranularSubkeySpec(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768), null),
            GranularSubkeySpec(AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA65_ED25519), null)
        )
        val ring = svc.assembleGranularV6Ring(
            "Granular <g@example.test>", includeDefaultEncryptionSubkey = false,
            subkeys = subkeys, passphrase = null
        )
        val algos = ring.publicKeys.asSequence().map { it.algorithm }.toList()
        assertFalse("no standalone X25519 downgrade subkey", algos.contains(X25519_ALGO))
        assertTrue("composite ML-KEM encryption subkey present", algos.contains(COMPOSITE_MLKEM))
        assertTrue("composite ML-DSA signing subkey present", algos.contains(COMPOSITE_MLDSA))

        val pub = PGPPublicKeyRing(ring.publicKeys.asSequence().toList())
        val plaintext = "granular key, post-quantum only".toByteArray()
        val ciphertext = svc.encrypt(data = plaintext, recipientPublicKeys = listOf(pub), armor = false)
        val result = svc.decrypt(ciphertext, secretKeyRings = listOf(ring), passphrase = null)
        assertArrayEquals("encrypts to the composite subkey and decrypts back", plaintext, result.data)
    }
}
