// CompositeV4Algo35MessageTest.kt
// PGPony Android — 4.5.0 (item 14 / #56): v4 algo-35 message round-trip.
//
// The full self round-trip: assemble a SEIPDv2 (AEAD) message to a v4 Ed25519
// + algo-35 interop key's subkey with V4Algo35EncryptionMethodGenerator (the
// same BC PGPEncryptedDataGenerator path PGPCryptoService.encrypt uses for a
// composite recipient), then decrypt it through CompositeDecryptor with the raw
// v4 secret ring. This exercises the v6-PKESK/SEIPDv2 pairing, the 20-octet
// fingerprint match, and v4 secret-material decapsulation together. gpg 2.5.x /
// sq interop is the on-device check.

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
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

class CompositeV4Algo35MessageTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `a SEIPDv2 message encrypted to a v4 algo-35 subkey decrypts back to plaintext`() {
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "V4 Interop", email = "v4@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = null
            ).privateKeyData
        ).secretKeyRing!!
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base)

        val subBody = CompositeKeyFacade.v4Algo35SubkeyBody(rings.publicRaw)!!
        val pubMat = CompositeKeyFacade.v4Algo35PublicMaterial(subBody)
        val fp = CompositeKeyFacade.v4Algo35SubkeyFingerprint(subBody)

        val plaintext = "harvest now, decrypt never".toByteArray()

        // Assemble a SEIPDv2 (AEAD/OCB) message with the v4 algo-35 method
        // generator, exactly as PGPCryptoService.encrypt does for a composite
        // recipient (a v6 PKESK MUST pair with SEIPDv2 per RFC 9580 5.1).
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

        // Decrypt through the composite path with the raw v4 secret ring.
        val result = CompositeDecryptor.tryDecrypt(
            ciphertext, emptyList(), null, listOf(rings.secretRaw)
        )!!
        val factory = PGPObjectFactory(result.stream, BcKeyFingerprintCalculator())
        val literal = factory.nextObject() as PGPLiteralData
        // copyTo (not readBytes): BC's nested AEAD stream reports a huge
        // available(), which readBytes uses to pre-size its buffer (OOM).
        val recovered = java.io.ByteArrayOutputStream().apply { literal.inputStream.copyTo(this) }.toByteArray()

        assertArrayEquals("plaintext survives encrypt-to-v4 then decrypt", plaintext, recovered)
    }
}
