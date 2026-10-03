// LiteralGuardTest.kt
// PGPony Android 4.6.3 (4.7.0 item 12a): the 4.6.x counterpart of main's
// ContentWalkerTest for the paths this branch has. A message may carry one
// literal: a second one, before or after a signed message, used to replace or
// follow the signed content while the signature still read as verified. The
// in-memory and signed-only paths also run MessageGrammar on the content.
// The card path takes the same guard and grammar check; it needs a card to
// exercise end to end.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Date

class LiteralGuardTest {

    private val svc = PGPCryptoService.shared

    private class Party(val sec: PGPSecretKeyRing, val pub: PGPPublicKeyRing)

    private fun party(name: String): Party {
        val g = svc.generateKeyPair(name, "$name@example.org", KeyAlgorithm.ED25519_CV25519, null)
        return Party(
            PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator()),
            PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
        )
    }

    private val alice by lazy { party("alice") }
    private val bob by lazy { party("bob") }

    private val signed = "Alice: the meeting is at 10\n".toByteArray()
    private val evil = "EVIL: wire 5000 EUR to MALLORY\n".toByteArray()

    private fun cat(vararg parts: ByteArray): ByteArray =
        ByteArrayOutputStream().apply { parts.forEach { write(it) } }.toByteArray()

    private fun lit(data: ByteArray): ByteArray {
        val bo = ByteArrayOutputStream()
        PGPLiteralDataGenerator().open(bo, PGPLiteralData.BINARY, "f", data.size.toLong(), Date()).use { it.write(data) }
        return bo.toByteArray()
    }

    private fun generator(p: Party): PGPSignatureGenerator {
        val sk = svc.pickSigningSecretKey(p.sec)!!
        val priv = sk.extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)))
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey)
        g.init(PGPSignature.BINARY_DOCUMENT, priv)
        val sp = PGPSignatureSubpacketGenerator()
        sp.setIssuerFingerprint(false, sk.publicKey)
        sp.setSignatureCreationTime(false, Date())
        g.setHashedSubpackets(sp.generate())
        return g
    }

    private fun ops(p: Party) =
        ByteArrayOutputStream().also { generator(p).generateOnePassVersion(false).encode(it) }.toByteArray()

    private fun sig(p: Party, data: ByteArray): ByteArray {
        val g = generator(p)
        g.update(data)
        return ByteArrayOutputStream().also { g.generate().encode(it) }.toByteArray()
    }

    private fun signedBy(p: Party, data: ByteArray = signed) = cat(ops(p), lit(data), sig(p, data))

    private fun encryptTo(plainPackets: ByteArray, to: Party): ByteArray {
        val bo = ByteArrayOutputStream()
        val g = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true)
        )
        g.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(to.pub.publicKeys.asSequence().first { it.isEncryptionKey && !it.isMasterKey }))
        g.open(bo, plainPackets.size.toLong()).use { it.write(plainPackets) }
        return bo.toByteArray()
    }

    private fun armor(bin: ByteArray): String {
        val bo = ByteArrayOutputStream()
        ArmoredOutputStream(bo).use { it.write(bin) }
        return bo.toString("UTF-8")
    }

    private fun memory(p: ByteArray) = svc.decrypt(encryptTo(p, bob), listOf(bob.sec), null, listOf(alice.pub))
    private fun signedOnly(p: ByteArray) = svc.decryptArmored(armor(p), listOf(bob.sec), null, listOf(alice.pub))

    private val forgeries by lazy {
        listOf(
            "literal after the signed message" to cat(signedBy(alice), lit(evil)),
            "literal before the signed message" to cat(lit(evil), signedBy(alice))
        )
    }

    @Test
    fun theInMemoryPath_refusesASecondLiteral() {
        for ((name, msg) in forgeries) {
            val r = runCatching { memory(msg) }
            assertTrue("$name accepted: ${r.getOrNull()?.signerStatus}", r.isFailure)
            assertTrue(name, r.exceptionOrNull() is PGPCryptoError)
        }
    }

    @Test
    fun theSignedOnlyPath_refusesASecondLiteral() {
        for ((name, msg) in forgeries) {
            val r = runCatching { signedOnly(msg) }
            assertTrue("$name accepted: ${r.getOrNull()?.signerStatus}", r.isFailure)
        }
    }

    @Test
    fun theStreamingPath_neverWritesTheSecondLiteral() {
        val out = ByteArrayOutputStream()
        val r = runCatching {
            svc.decryptStream(
                ByteArrayInputStream(encryptTo(cat(signedBy(alice), lit(evil)), bob)), out,
                listOf(bob.sec), null, listOf(alice.pub)
            )
        }
        assertTrue("accepted: ${r.getOrNull()?.signerStatus}", r.isFailure)
        assertFalse(String(out.toByteArray()).contains("EVIL"))
    }

    @Test
    fun anOrdinarySignedMessage_stillVerifiesOnEveryPath() {
        val m = memory(signedBy(alice))
        assertEquals(SignerStatus.VERIFIED, m.signerStatus)
        assertArrayEquals(signed, m.data)
        val s = signedOnly(signedBy(alice))
        assertEquals(SignerStatus.VERIFIED, s.signerStatus)
        assertArrayEquals(signed, s.data)
        val out = ByteArrayOutputStream()
        val st = svc.decryptStream(
            ByteArrayInputStream(encryptTo(signedBy(alice), bob)), out, listOf(bob.sec), null, listOf(alice.pub)
        )
        assertEquals(SignerStatus.VERIFIED, st.signerStatus)
        assertArrayEquals(signed, out.toByteArray())
    }
}
