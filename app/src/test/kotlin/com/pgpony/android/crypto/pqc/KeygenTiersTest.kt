// KeygenTiersTest.kt
// PGPony Android, 4.6.0 (items 3 and 13)
//
// ML-DSA-87 keys ship an ML-KEM-1024 encryption subkey (ML-DSA-65 keeps
// ML-KEM-768), and the LibrePGP ML-KEM-768 + brainpoolP256r1 key generates,
// is recognized, and round-trips a message.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeygenTiersTest {

    private val svc = PGPCryptoService.shared

    private fun kemAlgos(raw: ByteArray) =
        CertificateBindings.analyze(CompositeKeyFacade.publicRingOf(raw))!!.subkeys.filter { it.bound }.map { it.algorithm }

    @Test
    fun `ML-DSA-87 ships ML-KEM-1024, ML-DSA-65 keeps ML-KEM-768`() {
        assertEquals(listOf(36), kemAlgos(CompositePrimaryKeyGen.assemble("A <a@example.org>", CompositeSignSuite.MLDSA87_ED448)))
        assertEquals(listOf(35), kemAlgos(CompositePrimaryKeyGen.assemble("B <b@example.org>", CompositeSignSuite.MLDSA65_ED25519)))
        assertTrue(KeyAlgorithm.MLDSA87_ED448_V6 in KeyAlgorithm.generatablePostQuantum)
        assertEquals("65 stays listed first", KeyAlgorithm.MLDSA65_ED25519_V6,
            KeyAlgorithm.generatablePostQuantum.first { it.isCompositeSign })
    }

    @Test
    fun `an ML-DSA-87 key decrypts a message to its ML-KEM-1024 subkey`() {
        val raw = CompositePrimaryKeyGen.assemble("C <c@example.org>", CompositeSignSuite.MLDSA87_ED448)
        val encRing = CompositeKeyFacade.encryptionSubkeyRing(CompositeKeyFacade.publicRingOf(raw))!!
        assertEquals(36, encRing.publicKeys.asSequence().single { !it.isMasterKey || it.algorithm == 36 }.algorithm)
        val pt = "max tier".toByteArray()
        val ct = svc.encrypt(pt, listOf(encRing))
        assertArrayEquals(pt, svc.decrypt(ct, emptyList(), null, compositePrimaryRings = listOf(raw)).data)
    }

    @Test
    fun `LibrePGP ML-KEM-768 + brainpoolP256r1 generates and round-trips`() {
        for (pass in listOf(null, "bp pass")) {
            val k = svc.generateKeyPair("Bp", "bp@example.org", KeyAlgorithm.MLKEM768_BP256_LIBREPGP, pass)
            val pub = PGPPublicKeyRing(k.publicKeyData, BcKeyFingerprintCalculator())
            assertEquals(KeyAlgorithm.MLKEM768_BP256_LIBREPGP, svc.detectAlgorithm(pub.publicKey, pub))
            val sub = pub.publicKeys.asSequence().single { it.algorithm == 8 }
            assertEquals(5, sub.version)
            assertEquals(CompositeSuite.LIBREPGP_768_BP256, CompositeLibrePGPKeyMaterial.suiteOf(sub.encoded))
            assertTrue(KeyAlgorithm.MLKEM768_BP256_LIBREPGP.isPostQuantum)
            val pt = "ky768_bp256".toByteArray()
            val ct = svc.encrypt(pt, listOf(pub))
            val sec = PGPSecretKeyRing(k.privateKeyData, BcKeyFingerprintCalculator())
            assertArrayEquals(pt, svc.decrypt(ct, listOf(sec), passphrase = pass).data)
        }
    }
}
