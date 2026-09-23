// CompositeRsaSubkeyTest.kt
// PGPony Android, 4.6.0 (item 21)
//
// A composite ML-DSA key takes an RSA subkey (v6-framed), bound by the
// composite primary, protected with the key's passphrase, and a message a
// classical client encrypts to that subkey decrypts in PGPony.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

class CompositeRsaSubkeyTest {

    private val svc = PGPCryptoService.shared

    private fun base() = CompositePrimaryKeyGen.assemble("Dee <dee@example.org>", CompositeSignSuite.MLDSA65_ED25519)

    private fun encryptTo(key: PGPPublicKey, text: String): ByteArray {
        val out = ByteArrayOutputStream()
        val gen = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true).setSecureRandom(SecureRandom())
        )
        gen.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(key))
        gen.open(out, ByteArray(1 shl 12)).use { enc ->
            PGPLiteralDataGenerator().open(enc, PGPLiteralData.BINARY, "", Date(), ByteArray(1 shl 12)).use {
                it.write(text.toByteArray())
            }
        }
        return out.toByteArray()
    }

    private fun rsaPublic(raw: ByteArray): PGPPublicKey =
        CompositeKeyFacade.classicalDecryptionRing(raw)!!.publicKeys.asSequence().single { it.algorithm == 1 }

    @Test
    fun `an RSA encryption subkey is bound and decrypts a classical message`() {
        val raw = CompositePrimaryKeyGen.addClassicalSubkey(base(), ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_ENCRYPT)
        val report = CertificateBindings.analyze(CompositeKeyFacade.publicRingOf(raw))!!
        val rsa = report.subkeys.single { it.algorithm == 1 }
        assertTrue(rsa.bound)
        assertEquals(0x0C, rsa.keyFlags)
        assertEquals(6, rsa.version)
        val pub = rsaPublic(raw)
        assertEquals(2048, pub.bitStrength)
        assertEquals(rsa.fingerprintHex, pub.fingerprint.joinToString("") { "%02X".format(it) })

        val msg = encryptTo(pub, "for Thunderbird's RSA subkey")
        val ring = CompositeKeyFacade.classicalDecryptionRing(raw)!!
        val result = svc.decrypt(msg, listOf(ring), null, compositePrimaryRings = listOf(raw))
        assertEquals("for Thunderbird's RSA subkey", result.plaintext)
    }

    @Test
    fun `a passphrase protects the RSA secret and is needed to decrypt`() {
        val added = CompositePrimaryKeyGen.addClassicalSubkey(base(), ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_ENCRYPT)
        val raw = CompositeKeyFacade.reprotect(added, null, "pony pass".toCharArray())
        val body = CompositeKeyFacade.let {
            CertificateBindings.packets(raw).single { p -> p.tag == 7 && p.body[5].toInt() == 1 }.body
        }
        assertTrue("RSA subkey protected", CompositeSecretProtection.isProtected(body))
        val msg = encryptTo(rsaPublic(raw), "locked")
        val ring = CompositeKeyFacade.classicalDecryptionRing(raw)!!
        assertEquals("locked", svc.decrypt(msg, listOf(ring), "pony pass", compositePrimaryRings = listOf(raw)).plaintext)
        val wrong = runCatching { svc.decrypt(msg, listOf(ring), "wrong", compositePrimaryRings = listOf(raw)) }
        assertTrue(wrong.isFailure)
        // Changing the passphrase re-protects it; the old one stops working.
        val changed = CompositeKeyFacade.reprotect(raw, "pony pass".toCharArray(), "new pass".toCharArray())
        val ring2 = CompositeKeyFacade.classicalDecryptionRing(changed)!!
        assertEquals("locked", svc.decrypt(msg, listOf(ring2), "new pass", compositePrimaryRings = listOf(changed)).plaintext)
        // And removing it leaves an unprotected, still usable secret.
        val open = CompositeKeyFacade.reprotect(changed, "new pass".toCharArray(), null)
        val ring3 = CompositeKeyFacade.classicalDecryptionRing(open)!!
        assertEquals("locked", svc.decrypt(msg, listOf(ring3), null, compositePrimaryRings = listOf(open)).plaintext)
    }

    @Test
    fun `an RSA signing subkey carries a verified back-signature`() {
        val raw = CompositePrimaryKeyGen.addClassicalSubkey(base(), ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_SIGN)
        val rsa = CertificateBindings.analyze(CompositeKeyFacade.publicRingOf(raw))!!.subkeys.single { it.algorithm == 1 }
        assertTrue(rsa.bound)
        assertTrue("0x19 back-signature verifies", rsa.backSigned)
        assertEquals(0x02, rsa.keyFlags)
    }

    @Test
    fun `an X25519 subkey on a composite key decrypts too, and a key without one has no ring`() {
        assertNull(CompositeKeyFacade.classicalDecryptionRing(base()))
        val raw = CompositePrimaryKeyGen.addClassicalSubkey(base(), ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT)
        val ring = CompositeKeyFacade.classicalDecryptionRing(raw)
        assertNotNull(ring)
        val x = ring!!.publicKeys.asSequence().single { it.algorithm == 25 }
        val msg = encryptTo(x, "x25519 too")
        assertEquals("x25519 too", svc.decrypt(msg, listOf(ring), null, compositePrimaryRings = listOf(raw)).plaintext)
    }
}
