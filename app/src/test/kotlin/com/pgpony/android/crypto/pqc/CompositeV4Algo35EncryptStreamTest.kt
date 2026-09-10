// CompositeV4Algo35EncryptStreamTest.kt
// PGPony Android — 4.5.0 (item 14 / #56): encryptStream to a v4 algo-35 recipient.
//
// The streaming encrypt entry point (PGPCryptoService.encryptStream, used by the
// Encrypt tab's file and bundle flows) must reach a v4 Ed25519 + algo-35 recipient
// through the v4Algo35Recipients channel and force SEIPDv2, exactly as the buffered
// encrypt() does. Round-trips through CompositeDecryptor with the raw v4 secret ring.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CompositeV4Algo35EncryptStreamTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `encryptStream to a v4 algo-35 recipient round-trips through decrypt`() {
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "V4 Stream", email = "v4s@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = null
            ).privateKeyData
        ).secretKeyRing!!
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base)

        val subBody = CompositeKeyFacade.v4Algo35SubkeyBody(rings.publicRaw)!!
        val recipient = V4Algo35Recipient(
            CompositeKeyFacade.v4Algo35PublicMaterial(subBody),
            CompositeKeyFacade.v4Algo35SubkeyFingerprint(subBody)
        )

        val plaintext = "streamed post-quantum over v4".toByteArray()
        val out = ByteArrayOutputStream()
        svc.encryptStream(
            input = ByteArrayInputStream(plaintext),
            output = out,
            recipientPublicKeys = emptyList(),
            armor = false,
            v4Algo35Recipients = listOf(recipient)
        )

        val result = CompositeDecryptor.tryDecrypt(
            out.toByteArray(), emptyList(), null, listOf(rings.secretRaw)
        )!!
        val factory = PGPObjectFactory(result.stream, BcKeyFingerprintCalculator())
        var obj = factory.nextObject()
        if (obj is org.bouncycastle.openpgp.PGPCompressedData) {
            obj = PGPObjectFactory(obj.dataStream, BcKeyFingerprintCalculator()).nextObject()
        }
        val literal = obj as PGPLiteralData
        val recovered = ByteArrayOutputStream().apply { literal.inputStream.copyTo(this) }.toByteArray()
        assertArrayEquals("plaintext survives encryptStream to a v4 recipient then decrypt", plaintext, recovered)
    }
}
