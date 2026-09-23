// AutocryptKeyForTest.kt
// PGPony Android, 4.6.0 (item 17.4)
//
// Autocrypt keydata is supplied by whoever wrote the header. It is taken as a
// peer's key only when every User ID its primary certified is that peer's
// address, and never when it carries secret material.

package com.pgpony.android.autocrypt

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutocryptKeyForTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `a key whose User ID is the peer address is accepted`() {
        val k = svc.generateKeyPair("Bob", "bob@example.com", KeyAlgorithm.ED25519_CV25519, null)
        assertTrue(AutocryptPeerStore.isKeyFor("bob@example.com", k.armoredPublicKey))
        assertTrue(AutocryptPeerStore.isKeyFor("Bob <BOB@example.com>", k.armoredPublicKey))
    }

    @Test
    fun `a key for another address is refused`() {
        val k = svc.generateKeyPair("Mallory", "mallory@evil.example", KeyAlgorithm.ED25519_CV25519, null)
        assertFalse(AutocryptPeerStore.isKeyFor("bob@example.com", k.armoredPublicKey))
    }

    @Test
    fun `secret material is refused`() {
        val k = svc.generateKeyPair("Bob", "bob@example.com", KeyAlgorithm.ED25519_CV25519, null)
        assertFalse(AutocryptPeerStore.isKeyFor("bob@example.com", k.armoredPrivateKey))
    }
}
