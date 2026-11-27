// LibrePgpWithoutX25519Test.kt
// PGPony Android 4.8.2 (item 4): a LibrePGP ML-KEM key without its classical
// Cv25519 encryption subkey. GnuPG's own ky768_cv25519 keys have only the
// Kyber subkey (already a hybrid with X25519); with the classical one there,
// GnuPG and Kleopatra may encrypt to it instead. Generate Key's "Include
// default encryption subkey" switch, off, leaves it out; on (the default)
// keeps the key as before. Either way a message to the key opens.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class LibrePgpWithoutX25519Test {

    private val svc = PGPCryptoService.shared

    private fun gen(alg: KeyAlgorithm, include: Boolean): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val g = svc.generateKeyPair("Libre", "libre@example.test", alg, "libre pass", null, include)
        return PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator()) to
            PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
    }

    private fun algorithms(ring: PGPPublicKeyRing) = ring.publicKeys.asSequence().filter { !it.isMasterKey }.map { it.algorithm }.toList()

    /** The algorithm of every PKESK in an armored message. */
    private fun pkeskAlgorithms(armored: ByteArray): List<Int> {
        val bin = ArmoredInputStream(ByteArrayInputStream(armored)).use { it.readBytes() }
        return com.pgpony.android.crypto.CertificateBindings.packets(bin).takeWhile { it.tag == 1 }.map { p ->
            // v3 PKESK: version(1) key id(8) algorithm(1).
            p.body[9].toInt() and 0xFF
        }
    }

    @Test
    fun `switch off leaves the classical subkey out and the key still decrypts`() {
        for (alg in listOf(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, KeyAlgorithm.MLKEM768_BP256_LIBREPGP, KeyAlgorithm.MLKEM1024_X448_LIBREPGP)) {
            val (sec, pub) = gen(alg, include = false)
            val subs = algorithms(pub)
            assertFalse("$alg: no ECDH subkey", 18 in subs)
            assertEquals("$alg: only the composite subkey", 1, subs.size)
            val pt = "to the kyber subkey only".toByteArray()
            val enc = svc.encrypt(pt, listOf(pub))
            assertEquals("$alg: one PKESK, the composite", listOf(8), pkeskAlgorithms(enc))
            assertArrayEquals(pt, svc.decrypt(enc, listOf(sec), passphrase = "libre pass").data)
        }
    }

    @Test
    fun `switch on keeps the key as before`() {
        val (_, pub) = gen(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, include = true)
        val subs = algorithms(pub)
        assertTrue(18 in subs)
        assertEquals(2, subs.size)
    }
}
