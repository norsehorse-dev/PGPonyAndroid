// CompositeV4Algo35ImportTest.kt
// PGPony Android — 4.5.0 (item 14 / #56): v4 algo-35 key import derivation.
//
// A v4 interop key is stored as raw octets (BC cannot parse the algo-35 subkey),
// so import reads its metadata from the BC-parseable base ring and derives the
// public transferable ring itself. These tests lock the two facade helpers the
// import path relies on: v4Algo35BaseBytes (BC parses it, exposing the primary
// fingerprint) and v4Algo35PublicRingOf (derives a usable recipient from a
// secret ring; returns a public ring unchanged).

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CompositeV4Algo35ImportTest {

    private val svc = PGPCryptoService.shared

    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }

    @Test
    fun `import derivation preserves the fingerprint and yields a usable recipient`() {
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "V4 Import", email = "v4i@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = null
            ).privateKeyData
        ).secretKeyRing!!
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base)

        // The base ring is BC-parseable and carries the key's own fingerprint.
        val baseBytes = CompositeKeyFacade.v4Algo35BaseBytes(rings.secretRaw)!!
        val baseRing = PGPSecretKeyRing(ByteArrayInputStream(baseBytes), JcaKeyFingerprintCalculator())
        assertEquals(
            "base ring fingerprint matches the generated primary",
            rings.primaryFingerprintHex.uppercase(),
            hex(baseRing.publicKey.fingerprint).uppercase()
        )

        // Deriving the public ring from the secret ring reproduces the subkey's
        // public material and v4 fingerprint that generation emitted.
        val derivedPub = CompositeKeyFacade.v4Algo35PublicRingOf(rings.secretRaw)
        val subDerived = CompositeKeyFacade.v4Algo35SubkeyBody(derivedPub)!!
        val subGenerated = CompositeKeyFacade.v4Algo35SubkeyBody(rings.publicRaw)!!
        assertArrayEquals(
            "derived public material equals the generated public material",
            CompositeKeyFacade.v4Algo35PublicMaterial(subGenerated),
            CompositeKeyFacade.v4Algo35PublicMaterial(subDerived)
        )
        assertArrayEquals(
            "derived subkey fingerprint equals the generated one",
            CompositeKeyFacade.v4Algo35SubkeyFingerprint(subGenerated),
            CompositeKeyFacade.v4Algo35SubkeyFingerprint(subDerived)
        )

        // A public-only import is already public and returned unchanged.
        assertArrayEquals(
            "public import is returned unchanged",
            rings.publicRaw,
            CompositeKeyFacade.v4Algo35PublicRingOf(rings.publicRaw)
        )

        // The derived recipient encrypts, and the secret ring decrypts it back.
        val recipient = V4Algo35Recipient(
            CompositeKeyFacade.v4Algo35PublicMaterial(subDerived),
            CompositeKeyFacade.v4Algo35SubkeyFingerprint(subDerived)
        )
        val plaintext = "imported v4 key, still a recipient".toByteArray()
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
        assertArrayEquals("round-trips through the derived recipient", plaintext, recovered)
    }
}
