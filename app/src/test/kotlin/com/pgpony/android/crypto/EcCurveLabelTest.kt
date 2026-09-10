// EcCurveLabelTest.kt
// PGPony Android — 4.5.0 (item 17 / Play review): ECC curve labels.
//
// NIST P-256 and brainpool keys were labeled "RSA 4096" (the detectAlgorithm
// catch-all). detectAlgorithm now reads the curve OID and labels the real
// curve, and the catch-all is a truthful "Unknown" instead of RSA 4096.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Security
import java.security.spec.ECGenParameterSpec
import java.util.Date

class EcCurveLabelTest {

    private val svc = PGPCryptoService.shared

    private fun ecdsaPublicKey(curveName: String): org.bouncycastle.openpgp.PGPPublicKey {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val kpg = KeyPairGenerator.getInstance("ECDSA", "BC")
        kpg.initialize(ECGenParameterSpec(curveName))
        val kp = kpg.generateKeyPair()
        return JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, kp, Date()).publicKey
    }

    @Test
    fun `NIST P-256 curve is resolved and labeled, not RSA 4096`() {
        val pub = ecdsaPublicKey("P-256")
        assertEquals("NIST P-256", EcCurveOid.label(pub))
        assertEquals(KeyAlgorithm.ECDSA_NIST_P256, svc.detectAlgorithm(pub))
        assertNotEquals(KeyAlgorithm.RSA_4096, svc.detectAlgorithm(pub))
    }

    @Test
    fun `brainpoolP256r1 curve is resolved and labeled`() {
        val pub = ecdsaPublicKey("brainpoolP256r1")
        assertEquals("brainpoolP256r1", EcCurveOid.label(pub))
        assertEquals(KeyAlgorithm.ECDSA_BRAINPOOL_P256, svc.detectAlgorithm(pub))
    }

    @Test
    fun `NIST P-384 curve is resolved`() {
        val pub = ecdsaPublicKey("P-384")
        assertEquals(KeyAlgorithm.ECDSA_NIST_P384, svc.detectAlgorithm(pub))
    }

    @Test
    fun `classical and RSA labels are unchanged`() {
        val pass = "correct horse battery staple"
        val ed = svc.importKeyData(
            svc.generateKeyPair("E", "e@example.test", KeyAlgorithm.ED25519_CV25519, pass).publicKeyData
        ).publicKeyRing!!
        // The primary of an ED25519_CV25519 key stays labeled as such.
        assertEquals(KeyAlgorithm.ED25519_CV25519, svc.detectAlgorithm(ed.publicKey))

        val rsa = svc.importKeyData(
            svc.generateKeyPair("R", "r@example.test", KeyAlgorithm.RSA_2048, pass).publicKeyData
        ).publicKeyRing!!
        assertEquals(KeyAlgorithm.RSA_2048, svc.detectAlgorithm(rsa.publicKey))
    }
}
