// V4Algo35CarryTest.kt
// PGPony Android, 4.6.0 (item 19)
//
// Bouncy Castle loads a v4 key with an ML-KEM (algo 35) subkey without that
// subkey, so an edit stored from its ring used to drop it. The carry puts it
// back, keeps its secret usable and follows a passphrase change.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream

class V4Algo35CarryTest {

    private val svc = PGPCryptoService.shared

    private fun subkeyAlgos(raw: ByteArray): List<Int> =
        CertificateBindings.packets(raw).filter { it.tag == 7 || it.tag == 14 }.map { it.body[5].toInt() and 0xFF }

    private fun v4Key(pass: String? = null): CompositeKeyGen.V4Algo35Rings {
        val gen = svc.generateKeyPair("V4", "v4@example.test", KeyAlgorithm.ED25519_CV25519, pass)
        val base = svc.importKeyData(gen.privateKeyData).secretKeyRing!!
        return CompositeKeyGen.addV4Algo35SubkeyRings(base, passphrase = pass)
    }

    private fun decryptWith(secretRaw: ByteArray, subkeyBody: ByteArray, pass: String? = null): ByteArray {
        val recipient = V4Algo35Recipient(
            CompositeKeyFacade.v4Algo35PublicMaterial(subkeyBody),
            CompositeKeyFacade.v4Algo35SubkeyFingerprint(subkeyBody)
        )
        val plaintext = "to the original ML-KEM subkey".toByteArray()
        val ct = svc.encrypt(data = plaintext, recipientPublicKeys = emptyList(), armor = false,
            v4Algo35Recipients = listOf(recipient))
        val result = CompositeDecryptor.tryDecrypt(ct, emptyList(), pass, listOf(secretRaw))!!
        var obj = PGPObjectFactory(result.stream, BcKeyFingerprintCalculator()).nextObject()
        if (obj is org.bouncycastle.openpgp.PGPCompressedData) {
            obj = PGPObjectFactory(obj.dataStream, BcKeyFingerprintCalculator()).nextObject()
        }
        val out = ByteArrayOutputStream().apply { (obj as PGPLiteralData).inputStream.copyTo(this) }.toByteArray()
        assertArrayEquals(plaintext, out)
        return out
    }

    @Test
    fun `Bouncy Castle drops the ML-KEM subkey, which is why the carry exists`() {
        val k = v4Key()
        assertEquals(listOf(18, 35), subkeyAlgos(k.publicRaw))
        val bc = svc.importKeyData(k.secretRaw).secretKeyRing!!
        assertEquals(listOf(18), subkeyAlgos(bc.encoded))
    }

    @Test
    fun `adding a classical subkey keeps the ML-KEM subkey, secret included`() {
        val k = v4Key()
        val bc = svc.importKeyData(k.secretRaw).secretKeyRing!!
        val edited = ClassicalSubkeyGen.addSubkey(secretRing = bc,
            type = ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT, passphrase = null, expirationSeconds = null)
        val sec = V4Algo35Carry.carry(k.secretRaw, edited.encoded)
        val pub = V4Algo35Carry.carry(k.publicRaw,
            PGPPublicKeyRing(edited.publicKeys.asSequence().toList()).encoded)
        assertEquals(listOf(18, 18, 35), subkeyAlgos(sec))
        assertEquals(listOf(18, 18, 35), subkeyAlgos(pub))
        assertTrue("secret stays secret", CertificateBindings.packets(sec).any { it.tag == 7 && it.body[5].toInt() == 35 })
        assertTrue("public stays public", CertificateBindings.packets(pub).none { it.tag == 7 })
        // The carried subkey is still bound to the primary and still decrypts.
        val report = CertificateBindings.analyze(pub)!!
        assertTrue(report.subkeys.filter { it.algorithm == 35 }.all { it.bound })
        decryptWith(sec, CompositeKeyFacade.v4Algo35SubkeyBody(k.publicRaw)!!)
    }

    @Test
    fun `a second ML-KEM subkey no longer replaces the first`() {
        val k = v4Key()
        val bc = svc.importKeyData(k.secretRaw).secretKeyRing!!
        val second = CompositeKeyGen.addV4Algo35SubkeyRings(bc)
        val sec = V4Algo35Carry.carry(k.secretRaw, second.secretRaw)
        val pub = V4Algo35Carry.carry(k.publicRaw, second.publicRaw)
        assertEquals(listOf(18, 35, 35), subkeyAlgos(pub))
        assertEquals(listOf(18, 35, 35), subkeyAlgos(sec))
        decryptWith(sec, CompositeKeyFacade.v4Algo35SubkeyBodies(k.publicRaw).single())
        decryptWith(sec, CompositeKeyFacade.v4Algo35SubkeyBodies(second.publicRaw).single())
        // The newly added one stays last, so it is the one encryption picks.
        assertArrayEquals(CompositeKeyFacade.v4Algo35SubkeyBodies(second.publicRaw).single(),
            CompositeKeyFacade.v4Algo35SubkeyBodies(pub).last())
        // Export under a passphrase protects both ML-KEM secrets.
        val exported = CompositeKeyFacade.protectV4Algo35ForExport(sec, "export".toCharArray())
        val bodies = CompositeKeyFacade.v4Algo35SubkeyBodies(exported)
        assertEquals(2, bodies.size)
        bodies.forEach { assertTrue(V4Algo35Protection.isProtected(it)) }
    }

    @Test
    fun `carrying is idempotent and a no-op for other keys`() {
        val k = v4Key()
        assertArrayEquals(k.publicRaw, V4Algo35Carry.carry(k.publicRaw, k.publicRaw))
        val classical = svc.generateKeyPair("C", "c@example.test", KeyAlgorithm.ED25519_CV25519, null)
        assertArrayEquals(classical.publicKeyData, V4Algo35Carry.carry(classical.publicKeyData, classical.publicKeyData))
        assertArrayEquals(classical.publicKeyData, V4Algo35Carry.carry(null, classical.publicKeyData))
    }

    @Test
    fun `a passphrase change re-protects the carried ML-KEM secret`() {
        val k = v4Key("old pass")
        val bc = svc.importKeyData(k.secretRaw).secretKeyRing!!
        val changed = svc.changePassphrase(bc, "old pass", "new pass")
        val sec = V4Algo35Carry.carry(k.secretRaw, changed.encoded) { body ->
            V4Algo35Carry.reprotectBody(body, "old pass".toCharArray(), "new pass".toCharArray())
        }
        val body = CompositeKeyFacade.v4Algo35SubkeyBodies(sec).single()
        assertEquals(96, V4Algo35Protection.unlock(body, "new pass".toCharArray())!!.size)
        try {
            V4Algo35Protection.unlock(body, "old pass".toCharArray())
            fail("old passphrase must no longer open the ML-KEM subkey")
        } catch (_: Exception) { }
        // Removing the passphrase leaves it unprotected (usage 0, checksummed).
        val open = V4Algo35Carry.reprotectBody(body, "new pass".toCharArray(), null)
        assertEquals(96, V4Algo35Protection.unlock(open, null)!!.size)
        assertTrue(!V4Algo35Protection.isProtected(open))
    }

    @Test
    fun `a wrong old passphrase stops the change`() {
        val k = v4Key("old pass")
        val body = CompositeKeyFacade.v4Algo35SubkeyBodies(k.secretRaw).single()
        try {
            V4Algo35Carry.reprotectBody(body, "wrong".toCharArray(), "new".toCharArray())
            fail("expected a failure")
        } catch (_: Exception) { }
    }
}
