// CompositeAddSubkeyV4Test.kt
// PGPony Android — 4.5.0 (item 7 / #55): add a PQ subkey to an existing v4 key.
//
// Grafting a v4 algo-35 (ML-KEM-768 + X25519) subkey onto an existing v4 classical
// key (Ed25519 primary + Cv25519 subkey) converts it to the raw item-14 interop
// shape. Two properties must hold: the algo-35 subkey is a usable encryption
// target, and the BC-parseable base ring (what loadSecretKeyRing falls back to)
// still carries the Ed25519 signing primary and the classical subkey, so signing
// and classical decrypt survive the conversion.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CompositeAddSubkeyV4Test {

    private val svc = PGPCryptoService.shared

    @Test
    fun `grafting a v4 PQ subkey keeps the base ring signable and the subkey usable`() {
        val gen = svc.generateKeyPair(
            name = "V4 Base", email = "v4base@example.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = null
        )
        val base = svc.importKeyData(gen.privateKeyData).secretKeyRing!!
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base)

        // The base ring the fallback returns is BC-parseable and keeps the
        // Ed25519 signing primary plus the classical Cv25519 subkey.
        val baseBytes = CompositeKeyFacade.v4Algo35BaseBytes(rings.secretRaw)!!
        val baseRing = PGPSecretKeyRing(ByteArrayInputStream(baseBytes), JcaKeyFingerprintCalculator())
        assertEquals("primary is preserved", base.publicKey.keyID, baseRing.publicKey.keyID)
        assertTrue("primary and classical subkey both survive",
            baseRing.secretKeys.asSequence().count() >= 2)

        // The primary's private key still extracts, so signing survives.
        val primaryPriv = baseRing.secretKey.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0))
        )
        assertNotNull("primary private key extracts for signing", primaryPriv)

        // The grafted algo-35 subkey encrypts and decrypts.
        val subBody = CompositeKeyFacade.v4Algo35SubkeyBody(rings.publicRaw)!!
        val recipient = V4Algo35Recipient(
            CompositeKeyFacade.v4Algo35PublicMaterial(subBody),
            CompositeKeyFacade.v4Algo35SubkeyFingerprint(subBody)
        )
        val plaintext = "PQ subkey grafted onto an existing v4 key".toByteArray()
        val ciphertext = svc.encrypt(
            data = plaintext, recipientPublicKeys = emptyList(),
            armor = false, v4Algo35Recipients = listOf(recipient)
        )
        val result = CompositeDecryptor.tryDecrypt(
            ciphertext, emptyList(), null, listOf(rings.secretRaw)
        )!!
        var obj = PGPObjectFactory(result.stream, BcKeyFingerprintCalculator()).nextObject()
        if (obj is org.bouncycastle.openpgp.PGPCompressedData) {
            obj = PGPObjectFactory(obj.dataStream, BcKeyFingerprintCalculator()).nextObject()
        }
        val literal = obj as PGPLiteralData
        val recovered = ByteArrayOutputStream().apply { literal.inputStream.copyTo(this) }.toByteArray()
        assertArrayEquals("PQ subkey round-trips", plaintext, recovered)
    }
}
