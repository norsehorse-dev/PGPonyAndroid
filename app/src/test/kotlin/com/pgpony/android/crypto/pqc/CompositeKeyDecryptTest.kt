// CompositeKeyDecryptTest.kt
// PGPony Android, 4.4.0 RC4 (#26 composite completeness: decrypt)
//
// Proves the raw composite-PRIMARY decrypt path's core: the ML-KEM subkey
// material extracted from the raw ring (via CompositeKeyFacade) is the right
// key. Encapsulate to its public halves, decapsulate with its recovered secret
// the way CompositeDecryptor.openRaw does, and the KEK must match on both
// sides. Also proves the passphrase gates the subkey (locked without it,
// unlocked with it), which is what makes a protected composite key refuse
// decryption until unlocked.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class CompositeKeyDecryptTest {

    private fun freshRaw() =
        CompositePrimaryKeyGen.assemble("KEM <kem@pgpony.app>", CompositeSignSuite.MLDSA65_ED25519)

    /** Recover the KEK the way CompositeDecryptor.openRaw does, from a facade
     *  subkey's public+secret material, and assert it equals the encapsulated one. */
    private fun kemRoundTrips(sub: CompositeKeyFacade.SubkeyInfo) {
        val suite = CompositeSuite.ietfFor(sub.algId)!!
        val (xPub, mPub) = CompositeKem.splitPublic(sub.publicMaterial, suite)
        val enc = CompositeKem.encapsulate(xPub, mPub, suite = suite)

        val secret = sub.secretMaterial!!
        val xSec = secret.copyOfRange(0, suite.curve.keyLen)
        val mlkemSeed = secret.copyOfRange(suite.curve.keyLen, secret.size)
        val mlkemSec = MLKEMPrivateKeyParameters(suite.mlkem.params, mlkemSeed)
        val kek = CompositeKem.decapsulate(
            ephemeralX25519 = enc.ephemeralX25519,
            mlkemCiphertext = enc.mlkemCiphertext,
            recipientX25519Sec = xSec,
            recipientMlkemSec = mlkemSec,
            recipientX25519Pub = xPub,
            suite = suite
        )
        assertArrayEquals("encaps and decaps must derive the same KEK", enc.kek, kek)
    }

    @Test
    fun `unprotected composite-primary subkey recovers the KEK`() {
        val sub = CompositeKeyFacade.parse(freshRaw()).encryptionSubkey
        assertNotNull("composite primary must carry an ML-KEM subkey", sub)
        kemRoundTrips(sub!!)
    }

    @Test
    fun `a passphrase gates the ML-KEM subkey and still decrypts when unlocked`() {
        val protectedRaw = CompositeKeyFacade.reprotect(freshRaw(), null, "kempass".toCharArray())

        assertNull(
            "no passphrase must leave the ML-KEM subkey secret locked",
            CompositeKeyFacade.parse(protectedRaw).encryptionSubkey?.secretMaterial
        )

        val unlocked = CompositeKeyFacade.parse(protectedRaw, "kempass".toCharArray()).encryptionSubkey
        assertNotNull("the right passphrase must recover the subkey", unlocked?.secretMaterial)
        kemRoundTrips(unlocked!!)
    }
}
