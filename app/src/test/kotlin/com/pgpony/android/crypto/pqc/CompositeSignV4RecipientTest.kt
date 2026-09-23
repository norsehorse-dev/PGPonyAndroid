// CompositeSignV4RecipientTest.kt
// PGPony Android, 4.6.0 (item 14): a composite ML-DSA signature is v6 framed.
// Inside a SEIPDv1 message (any v4 recipient) PGPony still reads it, but GnuPG
// exits with "unknown version 6" and RNP refuses the message, so the Encrypt
// screen asks. compositeSignatureInSeipdV1 flags the case; by default the
// signature is kept, and compositeSignInSeipdV1 = false ("Send unsigned")
// leaves it out. An all-v6 recipient set is always signed.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class CompositeSignV4RecipientTest {

    private val svc = PGPCryptoService.shared

    private fun pub(data: ByteArray) =
        PGPPublicKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun sec(data: ByteArray) =
        PGPSecretKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private val signer by lazy {
        CompositeKeyFacade.parse(
            CompositePrimaryKeyGen.assemble("PQ Signer <pq@example.org>", CompositeSignSuite.MLDSA65_ED25519)
        )
    }

    private fun encryptSigned(recipients: List<PGPPublicKeyRing>, text: String, keepInV1: Boolean = true) = svc.encrypt(
        data = text.toByteArray(),
        recipientPublicKeys = recipients,
        armor = true,
        compositeSignSuite = signer.suite,
        compositeSignSecret = signer.compositeSecret,
        compositeSignerFingerprint = signer.fingerprint,
        compositeSignInSeipdV1 = keepInV1
    )

    @Test
    fun `v4 recipient keeps the signature by default and PGPony reads it`() {
        val v4 = svc.generateKeyPair("V4", "v4@example.org", KeyAlgorithm.ED25519_CV25519, null, null)
        val rings = listOf(pub(v4.publicKeyData))
        assertTrue(svc.compositeSignatureInSeipdV1(rings))

        val ct = encryptSigned(rings, "signed to a v4 key")
        val result = svc.decrypt(ct, listOf(sec(v4.privateKeyData)), passphrase = null)
        assertEquals("signed to a v4 key", String(result.data))
        assertTrue("composite one-pass signed payload kept", result.compositeInline)
        assertTrue(
            CompositeDocumentVerifier.verifyInline(signer.compositePublic, result.compositeInlineBytes!!).valid
        )
    }

    @Test
    fun `send unsigned leaves the signature out for a v4 recipient`() {
        val v4 = svc.generateKeyPair("V4", "v4@example.org", KeyAlgorithm.ED25519_CV25519, null, null)
        val rings = listOf(pub(v4.publicKeyData))
        assertTrue(svc.compositeSignatureInSeipdV1(rings))

        val ct = encryptSigned(rings, "to a v4 key", keepInV1 = false)
        val result = svc.decrypt(ct, listOf(sec(v4.privateKeyData)), passphrase = null)
        assertEquals("to a v4 key", String(result.data))
        assertFalse("no signature packets inside SEIPDv1", result.hasSignature)
        assertFalse("no composite one-pass payload inside SEIPDv1", result.compositeInline)
    }

    @Test
    fun `send unsigned also applies to mixed v6 and v4 recipients`() {
        val v6 = svc.generateKeyPair("V6", "v6@example.org", KeyAlgorithm.V6_ED25519, null, null)
        val v4 = svc.generateKeyPair("V4", "v4@example.org", KeyAlgorithm.ED25519_CV25519, null, null)
        val rings = listOf(pub(v6.publicKeyData), pub(v4.publicKeyData))
        assertTrue(svc.compositeSignatureInSeipdV1(rings))

        val ct = encryptSigned(rings, "mixed", keepInV1 = false)
        val result = svc.decrypt(ct, listOf(sec(v6.privateKeyData)), passphrase = null)
        assertEquals("mixed", String(result.data))
        assertFalse(result.hasSignature)
        assertFalse(result.compositeInline)
    }

    @Test
    fun `all v6 recipients stay signed even with send unsigned`() {
        val v6 = svc.generateKeyPair("V6", "v6@example.org", KeyAlgorithm.V6_ED25519, null, null)
        val rings = listOf(pub(v6.publicKeyData))
        assertFalse(svc.compositeSignatureInSeipdV1(rings))

        val ct = encryptSigned(rings, "to a v6 key", keepInV1 = false)
        val result = svc.decrypt(ct, listOf(sec(v6.privateKeyData)), passphrase = null)
        assertEquals("to a v6 key", String(result.data))
        assertTrue("composite one-pass signed payload kept", result.compositeInline)
    }
}
