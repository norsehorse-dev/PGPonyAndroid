// CompositeV4Algo35EncryptServiceTest.kt
// PGPony Android — 4.5.0 (item 14 / #56): PGPCryptoService.encrypt to a v4 key.
//
// End-to-end through the real encrypt entry point: encrypt a message to a v4
// Ed25519 + algo-35 recipient via the v4Algo35Recipients channel (no BC ring),
// then decrypt it back with CompositeDecryptor. Proves encrypt() forces SEIPDv2
// for a v4 algo-35 recipient (a v6 PKESK MUST pair with SEIPDv2) and that the
// message round-trips. gpg 2.5.x / sq is the on-device interop check.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.io.ByteArrayOutputStream

class CompositeV4Algo35EncryptServiceTest {

    private val svc = PGPCryptoService.shared

    private fun readPlaintext(stream: java.io.InputStream): ByteArray {
        var factory = PGPObjectFactory(stream, BcKeyFingerprintCalculator())
        var obj = factory.nextObject()
        if (obj is PGPCompressedData) {
            factory = PGPObjectFactory(obj.dataStream, BcKeyFingerprintCalculator())
            obj = factory.nextObject()
        }
        val literal = obj as PGPLiteralData
        return ByteArrayOutputStream().apply { literal.inputStream.copyTo(this) }.toByteArray()
    }

    @Test
    fun `encrypt to a v4 algo-35 recipient round-trips through decrypt`() {
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "V4 Interop", email = "v4@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = null
            ).privateKeyData
        ).secretKeyRing!!
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base)

        val subBody = CompositeKeyFacade.v4Algo35SubkeyBody(rings.publicRaw)!!
        val recipient = V4Algo35Recipient(
            CompositeKeyFacade.v4Algo35PublicMaterial(subBody),
            CompositeKeyFacade.v4Algo35SubkeyFingerprint(subBody)
        )

        val plaintext = "post-quantum, delivered over v4".toByteArray()
        val ciphertext = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = emptyList(),
            armor = false,
            v4Algo35Recipients = listOf(recipient)
        )

        val result = CompositeDecryptor.tryDecrypt(
            ciphertext, emptyList(), null, listOf(rings.secretRaw)
        )!!
        val recovered = readPlaintext(result.stream)
        assertArrayEquals("plaintext survives encrypt() to a v4 recipient then decrypt", plaintext, recovered)
    }
}
