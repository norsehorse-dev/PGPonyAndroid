// LiteralFilenameTest.kt
// PGPony Android, 4.6.0 (item 17.3)
//
// A literal-data filename is attacker-chosen. Decrypt hands callers only a
// base name, and ScratchFiles.safeChild never yields a file outside its parent.

package com.pgpony.android.crypto

import com.pgpony.android.ui.util.ScratchFiles
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.security.SecureRandom
import java.util.Date

class LiteralFilenameTest {

    private val svc = PGPCryptoService.shared
    private val hostile = "../../files/secure_keystore_v2/pgpony_key_0123_private"

    private fun messageNamed(name: String, pub: PGPPublicKeyRing): ByteArray {
        val out = ByteArrayOutputStream()
        val enc = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true).setSecureRandom(SecureRandom())
        )
        val encKey = pub.publicKeys.asSequence().first { !it.isMasterKey }
        enc.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(encKey))
        enc.open(out, ByteArray(1 shl 12)).use { eo ->
            val lit = PGPLiteralDataGenerator()
            lit.open(eo, PGPLiteralData.BINARY, name, 5L, Date()).use { it.write("owned".toByteArray()) }
        }
        return out.toByteArray()
    }

    @Test
    fun `decrypt reports only the base name of a hostile literal filename`() {
        val g = svc.generateKeyPair("F", "f@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val pub = PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
        val sec = PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator())
        val ct = messageNamed(hostile, pub)
        val r = svc.decrypt(ct, listOf(sec), passphrase = null)
        assertEquals("pgpony_key_0123_private", r.filename)
        val sr = svc.decryptStream(ByteArrayInputStream(ct), ByteArrayOutputStream(), listOf(sec), null)
        assertEquals("pgpony_key_0123_private", sr.filename)
    }

    @Test
    fun `sanitize strips paths, controls and dot names`() {
        assertEquals("x", LiteralFilename.sanitize("a\\b\\..\\x"))
        assertEquals("ab", LiteralFilename.sanitize("a\u0000b"))
        assertNull(LiteralFilename.sanitize(".."))
        assertNull(LiteralFilename.sanitize("foo/.."))
        assertNull(LiteralFilename.sanitize(""))
        assertEquals("report.pdf", LiteralFilename.sanitize("report.pdf"))
    }

    @Test
    fun `safeChild never escapes its parent`() {
        val parent = Files.createTempDirectory("exports").toFile()
        for (n in listOf(hostile, "..", ".", "a/../../b", "..\\..\\c", "", null, "ok.txt")) {
            val f = ScratchFiles.safeChild(parent, n, "fallback")
            assertEquals(parent.canonicalFile, f.canonicalFile.parentFile)
        }
        assertTrue(ScratchFiles.safeChild(parent, "..", "fallback").name == "fallback")
    }
}
