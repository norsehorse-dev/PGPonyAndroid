// CompositeAddSubkeyV6Test.kt
// PGPony Android — 4.5.0 (item 7 / #55): add a PQ subkey to an existing v6 key.
//
// Grafting a composite ML-KEM-768+X25519 encryption subkey onto an existing v6
// classical key (Ed25519 primary + X25519 subkey) is the same CompositeKeyGen
// .addCompositeSubkey operation generation uses for MLKEM768_X25519_V6, only
// applied after the fact. This proves the grafted subkey is a real encryption
// target: encrypt to the updated public ring, decrypt with the updated secret
// ring, round-trip the plaintext.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class CompositeAddSubkeyV6Test {

    private val svc = PGPCryptoService.shared

    @Test
    fun `a composite ML-KEM subkey grafted onto an existing v6 key encrypts and decrypts`() {
        val gen = svc.generateKeyPair(
            name = "V6 Base", email = "v6base@example.test",
            algorithm = KeyAlgorithm.V6_ED25519, passphrase = null
        )
        val base = svc.importKeyData(gen.privateKeyData).secretKeyRing!!

        val updated = CompositeKeyGen.addCompositeSubkey(
            base, CompositeKeyGen.Scheme.IETF_V6
        )
        val pub = PGPPublicKeyRing(updated.publicKeys.asSequence().toList())

        val plaintext = "post-quantum subkey added after the fact".toByteArray()
        val ciphertext = svc.encrypt(
            data = plaintext, recipientPublicKeys = listOf(pub), armor = false
        )
        val result = svc.decrypt(ciphertext, secretKeyRings = listOf(updated), passphrase = null)
        assertArrayEquals(
            "plaintext round-trips through the grafted composite subkey",
            plaintext, result.data
        )
    }
}
