// CompositeV4Algo35ProtectionTest.kt
// PGPony Android — 4.5.0 (item 14 / #56): v4 algo-35 subkey at-rest protection.
//
// A passphrase-set v4 interop key must protect its ML-KEM subkey secret in
// gpg's own v4 form: S2K usage 254 (SHA-1 integrity), AES-256 in OpenPGP CFB.
// These tests cover the protection primitive in isolation (round-trip, wrong
// passphrase, integrity) and end to end: a protected v4 key still decrypts a
// message to its subkey, but only with the passphrase.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.AEADAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

class CompositeV4Algo35ProtectionTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `protect then unlock round-trips the material`() {
        val material = ByteArray(V4Algo35Protection.MATERIAL_LEN) { (it + 7).toByte() }
        val region = V4Algo35Protection.protect(material, "correct horse".toCharArray(), SecureRandom())

        // The region is a usage-254 (SHA-1) protection: usage octet then AES-256.
        assertEquals("usage octet is 254 (SHA-1)", 254, region[0].toInt() and 0xFF)
        assertEquals("symmetric algorithm is AES-256", SymmetricKeyAlgorithmTags.AES_256, region[1].toInt() and 0xFF)

        // Reassemble a minimal subkey body (public prefix is only sized, not read
        // by unlock beyond PUB_END) and recover the material with the passphrase.
        val body = ByteArray(1 + 4 + 1 + 1216) + region
        val recovered = V4Algo35Protection.unlock(body, "correct horse".toCharArray())
        assertArrayEquals("material survives protect then unlock", material, recovered)
    }

    @Test
    fun `unlock with the wrong passphrase fails the integrity check`() {
        val material = ByteArray(V4Algo35Protection.MATERIAL_LEN) { it.toByte() }
        val region = V4Algo35Protection.protect(material, "right".toCharArray(), SecureRandom())
        val body = ByteArray(1 + 4 + 1 + 1216) + region
        try {
            V4Algo35Protection.unlock(body, "wrong".toCharArray())
            fail("a wrong passphrase must not silently return material")
        } catch (e: V4Algo35Protection.ProtectedKeyException) {
            // expected: SHA-1 integrity check rejects the wrong key
        }
    }

    @Test
    fun `a passphrase-set v4 key protects its subkey yet still decrypts with the passphrase`() {
        val pass = "s3cret-interop"
        val base = svc.buildV4InteropBaseSecretRing("V4 Protected <v4p@example.test>", pass)
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base, pass)

        // The stored SECRET subkey is protected (usage 254); the PUBLIC ring is
        // untouched and yields the recipient material as usual.
        val secBody = CompositeKeyFacade.v4Algo35SubkeyBody(rings.secretRaw)!!
        assertTrue("secret subkey is protected at rest", CompositeKeyFacade.v4Algo35IsProtected(secBody))

        val pubBodyRing = CompositeKeyFacade.v4Algo35SubkeyBody(rings.publicRaw)!!
        assertFalse("public subkey carries no protection", CompositeKeyFacade.v4Algo35IsProtected(pubBodyRing))
        val pubMat = CompositeKeyFacade.v4Algo35PublicMaterial(pubBodyRing)
        val fp = CompositeKeyFacade.v4Algo35SubkeyFingerprint(pubBodyRing)

        val plaintext = "protected at rest, delivered post-quantum".toByteArray()
        val encBuilder = BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
            .setWithAEAD(AEADAlgorithmTags.OCB, 16)
            .setUseV6AEAD()
            .setSecureRandom(SecureRandom())
        val encGen = PGPEncryptedDataGenerator(encBuilder)
        encGen.addMethod(V4Algo35EncryptionMethodGenerator(pubMat, fp))
        val out = ByteArrayOutputStream()
        val encOut = encGen.open(out, ByteArray(4096))
        val litGen = PGPLiteralDataGenerator()
        val litOut = litGen.open(encOut, PGPLiteralData.BINARY, "", plaintext.size.toLong(), Date())
        litOut.write(plaintext)
        litGen.close()
        encGen.close()
        val ciphertext = out.toByteArray()

        // With the passphrase: decrypts back to plaintext.
        val ok = CompositeDecryptor.tryDecrypt(ciphertext, emptyList(), pass, listOf(rings.secretRaw))!!
        val factory = PGPObjectFactory(ok.stream, BcKeyFingerprintCalculator())
        val literal = factory.nextObject() as PGPLiteralData
        val recovered = ByteArrayOutputStream().apply { literal.inputStream.copyTo(this) }.toByteArray()
        assertArrayEquals("protected v4 key decrypts with the passphrase", plaintext, recovered)

        // Without the passphrase: the protected subkey cannot be opened.
        try {
            CompositeDecryptor.tryDecrypt(ciphertext, emptyList(), null, listOf(rings.secretRaw))
            fail("a protected v4 subkey must not decrypt without the passphrase")
        } catch (e: Exception) {
            // expected: ProtectedKeyException (composite or v4) / NoMatchingKey
        }
    }

    @Test
    fun `an unprotected v4 key reprotected for export decrypts only with the export passphrase`() {
        val base = svc.buildV4InteropBaseSecretRing("V4 Export <v4e@example.test>", null)
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base) // passphrase-less: unprotected
        assertFalse(
            "freshly generated passphrase-less subkey is unprotected",
            CompositeKeyFacade.v4Algo35IsProtected(CompositeKeyFacade.v4Algo35SubkeyBody(rings.secretRaw)!!)
        )

        val exportPass = "export-guard"
        val protectedRaw = CompositeKeyFacade.protectV4Algo35ForExport(rings.secretRaw, exportPass.toCharArray())
        assertTrue(
            "reprotected subkey is protected",
            CompositeKeyFacade.v4Algo35IsProtected(CompositeKeyFacade.v4Algo35SubkeyBody(protectedRaw)!!)
        )

        // Encrypt to the (unchanged) public subkey, then confirm the reprotected
        // secret ring decrypts with the export passphrase and refuses without it.
        val pubBody = CompositeKeyFacade.v4Algo35SubkeyBody(rings.publicRaw)!!
        val ciphertext = encryptToV4(
            CompositeKeyFacade.v4Algo35PublicMaterial(pubBody),
            CompositeKeyFacade.v4Algo35SubkeyFingerprint(pubBody),
            "reprotected then exported".toByteArray()
        )

        val ok = CompositeDecryptor.tryDecrypt(ciphertext, emptyList(), exportPass, listOf(protectedRaw))!!
        val literal = PGPObjectFactory(ok.stream, BcKeyFingerprintCalculator()).nextObject() as PGPLiteralData
        val recovered = ByteArrayOutputStream().apply { literal.inputStream.copyTo(this) }.toByteArray()
        assertArrayEquals("reprotected ring decrypts with export passphrase",
            "reprotected then exported".toByteArray(), recovered)

        try {
            CompositeDecryptor.tryDecrypt(ciphertext, emptyList(), null, listOf(protectedRaw))
            fail("reprotected ring must not decrypt without the export passphrase")
        } catch (e: Exception) {
            // expected
        }
    }

    private fun encryptToV4(pubMat: ByteArray, fp: ByteArray, plaintext: ByteArray): ByteArray {
        val encBuilder = BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
            .setWithAEAD(AEADAlgorithmTags.OCB, 16)
            .setUseV6AEAD()
            .setSecureRandom(SecureRandom())
        val encGen = PGPEncryptedDataGenerator(encBuilder)
        encGen.addMethod(V4Algo35EncryptionMethodGenerator(pubMat, fp))
        val out = ByteArrayOutputStream()
        val encOut = encGen.open(out, ByteArray(4096))
        val litGen = PGPLiteralDataGenerator()
        val litOut = litGen.open(encOut, PGPLiteralData.BINARY, "", plaintext.size.toLong(), Date())
        litOut.write(plaintext)
        litGen.close()
        encGen.close()
        return out.toByteArray()
    }
}
