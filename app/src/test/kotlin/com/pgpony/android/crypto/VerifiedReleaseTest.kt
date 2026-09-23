// VerifiedReleaseTest.kt
// PGPony Android, 4.6.0 (item 17.2)
//
// decryptStream(releaseOnlyWhenVerified = true), the mode the OpenPGP API
// provider uses for the caller's pipe, must not let a single byte of a
// tampered non-AEAD message reach the output, must deliver an intact message
// in full (in memory and through the spill file), and must leave no spill
// file behind either way.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files

class VerifiedReleaseTest {

    private val svc = PGPCryptoService.shared

    private fun keys(alg: KeyAlgorithm): Pair<List<PGPSecretKeyRing>, List<PGPPublicKeyRing>> {
        val g = svc.generateKeyPair("Hold", "hold@pgpony.app", alg, null)
        return listOf(PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator())) to
            listOf(PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator()))
    }

    @Test
    fun `a tampered SEIPDv1 message releases nothing to the output`() {
        val (sec, pub) = keys(KeyAlgorithm.ED25519_CV25519)
        val ct = svc.encrypt(ByteArray(100 * 1024) { 'A'.code.toByte() }, pub, armor = false)
        val bad = ct.copyOf().also { it[it.size - 40] = (it[it.size - 40].toInt() xor 0xFF).toByte() }
        val dir = Files.createTempDirectory("hold").toFile()
        val captured = ByteArrayOutputStream()
        try {
            svc.decryptStream(ByteArrayInputStream(bad), captured, sec, null,
                releaseOnlyWhenVerified = true, holdDir = dir)
            fail("expected IntegrityCheckFailed")
        } catch (_: PGPCryptoError.IntegrityCheckFailed) { }
        assertEquals("no unverified plaintext released", 0, captured.size())
        assertEquals("no spill file left", 0, dir.listFiles()!!.size)
    }

    @Test
    fun `without the hold the old streaming behaviour is unchanged for in-app paths`() {
        val (sec, pub) = keys(KeyAlgorithm.ED25519_CV25519)
        val ct = svc.encrypt(ByteArray(100 * 1024) { 'A'.code.toByte() }, pub, armor = false)
        val bad = ct.copyOf().also { it[it.size - 40] = (it[it.size - 40].toInt() xor 0xFF).toByte() }
        try {
            svc.decryptStream(ByteArrayInputStream(bad), ByteArrayOutputStream(), sec, null)
            fail("expected IntegrityCheckFailed")
        } catch (_: PGPCryptoError.IntegrityCheckFailed) { }
    }

    @Test
    fun `an intact SEIPDv1 message is delivered in full, in memory and through the spill file`() {
        val (sec, pub) = keys(KeyAlgorithm.ED25519_CV25519)
        for (size in listOf(10 * 1024, 6 * 1024 * 1024)) {
            val plain = ByteArray(size) { (it * 31).toByte() }
            val ct = svc.encrypt(plain, pub, armor = false)
            val dir = Files.createTempDirectory("hold").toFile()
            val out = ByteArrayOutputStream()
            val r = svc.decryptStream(ByteArrayInputStream(ct), out, sec, null,
                releaseOnlyWhenVerified = true, holdDir = dir)
            assertArrayEquals(plain, out.toByteArray())
            assertEquals(size.toLong(), r.bytesWritten)
            assertEquals("spill file removed", 0, dir.listFiles()!!.size)
        }
    }

    @Test
    fun `an AEAD message streams through unchanged`() {
        val (sec, pub) = keys(KeyAlgorithm.V6_ED25519)
        val plain = ByteArray(200 * 1024) { (it * 7).toByte() }
        val ct = svc.encrypt(plain, pub, armor = false)
        val out = ByteArrayOutputStream()
        svc.decryptStream(ByteArrayInputStream(ct), out, sec, null, releaseOnlyWhenVerified = true, holdDir = null)
        assertArrayEquals(plain, out.toByteArray())
        assertTrue(out.size() > 0)
    }
}
