// PresignedInlineTest.kt
// PGPony Android, 3.0.0 checkpoint 5d-4: encrypt() carries a signed message the
// caller built (several signers, or a text-mode signature) as it stands, and
// decrypt() pairs each one-pass packet with its own signature (RFC 9580 5.4:
// the signatures come in the reverse order of their one-pass packets).

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.Date

class PresignedInlineTest {

    private val svc = PGPCryptoService.shared

    private fun generator(ring: PGPSecretKeyRing, type: Int): PGPSignatureGenerator {
        val key = ring.secretKey
        val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(key.publicKey.algorithm, HashAlgorithmTags.SHA256), key.publicKey)
        gen.init(type, key.extractPrivateKey(null))
        return gen
    }

    /** One-pass signatures in signer order, the literal data, the signatures in reverse. */
    private fun signedBy(signers: List<PGPSecretKeyRing>, data: ByteArray, type: Int): ByteArray {
        val gens = signers.map { generator(it, type) }
        val out = ByteArrayOutputStream()
        gens.forEachIndexed { i, g -> g.generateOnePassVersion(i != gens.lastIndex).encode(out) }
        val lit = PGPLiteralDataGenerator()
        val format = if (type == PGPSignature.CANONICAL_TEXT_DOCUMENT) PGPLiteralData.UTF8 else PGPLiteralData.BINARY
        lit.open(out, format, "", data.size.toLong(), Date(0)).use { it.write(data) }
        gens.forEach { it.update(data) }
        gens.asReversed().forEach { it.generate().encode(out) }
        return out.toByteArray()
    }

    @Test
    fun `a message signed by two keys is encrypted as it stands and verifies`() {
        val r = svc.generateKeyPair("Recipient", "recipient@example.test", KeyAlgorithm.ED25519_CV25519, null)
        val a = svc.generateKeyPair("Signer A", "a@example.test", KeyAlgorithm.ED25519_CV25519, null)
        val b = svc.generateKeyPair("Signer B", "b@example.test", KeyAlgorithm.ED25519_CV25519, null)
        val rPub = svc.importKeyData(r.publicKeyData).publicKeyRing!!
        val rSec = svc.importKeyData(r.privateKeyData).secretKeyRing!!
        val aSec = svc.importKeyData(a.privateKeyData).secretKeyRing!!
        val bSec = svc.importKeyData(b.privateKeyData).secretKeyRing!!
        val aPub = svc.importKeyData(a.publicKeyData).publicKeyRing!!
        val bPub = svc.importKeyData(b.publicKeyData).publicKeyRing!!

        val data = "two signers\r\n".toByteArray()
        val inline = signedBy(listOf(aSec, bSec), data, PGPSignature.BINARY_DOCUMENT)
        val msg = svc.encrypt("ignored".toByteArray(), listOf(rPub), presignedInline = inline)

        // Either signer alone verifies: the one-pass packet of the held key is
        // paired with its own signature, which sits at the mirrored position.
        for (verifier in listOf(aPub, bPub)) {
            val res = svc.decrypt(msg, listOf(rSec), null, verificationKeys = listOf(verifier))
            assertEquals("two signers\r\n", String(res.data))
            assertTrue(res.signatureVerified)
        }
        val both = svc.decrypt(msg, listOf(rSec), null, verificationKeys = listOf(aPub, bPub))
        assertTrue(both.signatureVerified)
    }

    @Test
    fun `a text-mode signature survives encryption`() {
        val r = svc.generateKeyPair("Recipient", "recipient@example.test", KeyAlgorithm.ED25519_CV25519, null)
        val s = svc.generateKeyPair("Signer", "signer@example.test", KeyAlgorithm.ED25519_CV25519, null)
        val rPub = svc.importKeyData(r.publicKeyData).publicKeyRing!!
        val rSec = svc.importKeyData(r.privateKeyData).secretKeyRing!!
        val sSec = svc.importKeyData(s.privateKeyData).secretKeyRing!!
        val sPub = svc.importKeyData(s.publicKeyData).publicKeyRing!!

        val data = "text mode\n".toByteArray()
        val inline = signedBy(listOf(sSec), data, PGPSignature.CANONICAL_TEXT_DOCUMENT)
        val msg = svc.encrypt(data, listOf(rPub), presignedInline = inline)
        val res = svc.decrypt(msg, listOf(rSec), null, verificationKeys = listOf(sPub))
        assertEquals("text mode\n", String(res.data))
        assertTrue(res.signatureVerified)
    }
}
