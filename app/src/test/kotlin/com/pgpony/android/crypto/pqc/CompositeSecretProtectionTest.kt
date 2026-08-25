// CompositeSecretProtectionTest.kt
// PGPony Android, 4.4.0 RC4 (#26 composite passphrase protection)
//
// Gate for CompositeSecretProtection: protecting the composite signing material
// under a passphrase and unlocking it must round-trip byte-for-byte, a wrong
// passphrase must fail, and an unprotected packet must pass through. If this is
// green, the temp-ring + BC-AEAD protect/unlock pair is self-consistent.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

class CompositeSecretProtectionTest {

    private val rnd = SecureRandom()

    private data class Material(val publicBody: ByteArray, val secret: ByteArray, val secretLen: Int)

    private fun freshMaterial(suite: CompositeSignSuite): Material {
        val edSecret = ByteArray(suite.eddsa.secretLen).also { rnd.nextBytes(it) }
        val mldsaSeed = ByteArray(suite.mldsa.seedLen).also { rnd.nextBytes(it) }
        val edPublic = when (suite.eddsa) {
            EdDsaCurve.ED25519 -> Ed25519PrivateKeyParameters(edSecret, 0).generatePublicKey().encoded
            EdDsaCurve.ED448 -> Ed448PrivateKeyParameters(edSecret, 0).generatePublicKey().encoded
        }
        val mldsaPublic = MLDSAPrivateKeyParameters(suite.mldsa.params, mldsaSeed).publicKeyParameters.encoded
        val secret = suite.join(edSecret, mldsaSeed)
        val publicMaterial = suite.join(edPublic, mldsaPublic)
        val publicBody = ByteArrayOutputStream().apply {
            write(6)
            write(uint32(0))          // creation time (fixed for the test)
            write(suite.algId)
            write(uint32(publicMaterial.size))
            write(publicMaterial)
        }.toByteArray()
        return Material(publicBody, secret, suite.compositeSecretLen)
    }

    private fun uint32(v: Int) =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun roundTrips(suite: CompositeSignSuite) {
        val m = freshMaterial(suite)
        val pass = "correct horse battery staple".toCharArray()

        val region = CompositeSecretProtection.protect(m.publicBody, m.secret, pass, rnd)
        val protectedBody = m.publicBody + region
        assertTrue("protected body must report protected", CompositeSecretProtection.isProtected(protectedBody))

        val recovered = CompositeSecretProtection.unlock(protectedBody, pass, m.secretLen)
        assertArrayEquals("unlock must recover the exact secret material", m.secret, recovered)
    }

    @Test
    fun `mldsa65 ed25519 protect and unlock round-trips`() {
        roundTrips(CompositeSignSuite.MLDSA65_ED25519)
    }

    @Test
    fun `mldsa87 ed448 protect and unlock round-trips`() {
        roundTrips(CompositeSignSuite.MLDSA87_ED448)
    }

    @Test
    fun `a wrong passphrase fails to unlock`() {
        val suite = CompositeSignSuite.MLDSA65_ED25519
        val m = freshMaterial(suite)
        val region = CompositeSecretProtection.protect(m.publicBody, m.secret, "right".toCharArray(), rnd)
        val protectedBody = m.publicBody + region
        try {
            val out = CompositeSecretProtection.unlock(protectedBody, "wrong".toCharArray(), m.secretLen)
            // AEAD must not return the true material under the wrong passphrase.
            assertFalse("a wrong passphrase must not recover the secret", out.contentEquals(m.secret))
            fail("expected the wrong passphrase to throw")
        } catch (expected: Exception) {
            // AEAD tag mismatch throws; that is the pass condition.
        }
    }

    @Test
    fun `an unprotected packet passes through`() {
        val suite = CompositeSignSuite.MLDSA65_ED25519
        val m = freshMaterial(suite)
        val unprotectedBody = m.publicBody + byteArrayOf(0) + m.secret
        assertFalse("usage 0 must report unprotected", CompositeSecretProtection.isProtected(unprotectedBody))
        val recovered = CompositeSecretProtection.unlock(unprotectedBody, null, m.secretLen)
        assertArrayEquals(m.secret, recovered)
    }
}
