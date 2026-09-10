// CompositeV4Algo35EncryptTest.kt
// PGPony Android — 4.5.0 (item 14 / #56): v4 algo-35 encrypt method generator.
//
// Exercises V4Algo35EncryptionMethodGenerator end to end: it must emit a
// version-6 PKESK whose TARGET key-version octet is 4 and whose recipient
// fingerprint is the subkey's 20-octet v4 SHA-1, and the session key it wraps
// must decapsulate back with the subkey's secret material. This confirms BC's
// createV6PKESKPacket writes the key-version octet we pass (4) and that the
// generator's framing round-trips. gpg 2.5.x / sq is the on-device interop
// check.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class CompositeV4Algo35EncryptTest {

    private val svc = PGPCryptoService.shared

    /** Strip a new-format packet header, returning the body. */
    private fun stripHeader(pkt: ByteArray): ByteArray {
        val c = pkt[0].toInt() and 0xFF
        require(c and 0x80 != 0) { "not a packet header: 0x${c.toString(16)}" }
        var i = 1
        if (c and 0x40 != 0) {
            // new-format: one length octet, then 0/1/4 more depending on value.
            val l0 = pkt[i++].toInt() and 0xFF
            when {
                l0 < 192 -> {}
                l0 < 224 -> i += 1
                l0 == 255 -> i += 4
                else -> throw IllegalStateException("partial length not expected")
            }
        } else {
            // old-format: length-type in the low two bits of the tag octet.
            when (c and 0x03) {
                0 -> i += 1
                1 -> i += 2
                2 -> i += 4
                else -> throw IllegalStateException("indeterminate length not expected")
            }
        }
        return pkt.copyOfRange(i, pkt.size)
    }

    @Test
    fun `the v4 encrypt generator emits a decapsulatable key-version-4 PKESK`() {
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "V4 Interop", email = "v4@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = null
            ).privateKeyData
        ).secretKeyRing!!
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base)
        val suite = CompositeSuite.IETF_768

        val subBody = CompositeKeyFacade.v4Algo35SubkeyBody(rings.secretRaw)!!
        val pubMat = CompositeKeyFacade.v4Algo35PublicMaterial(subBody)
        val secMat = CompositeKeyFacade.v4Algo35SecretMaterial(subBody)!!
        val fp = CompositeKeyFacade.v4Algo35SubkeyFingerprint(subBody)

        val sessionKey = ByteArray(32) { (it * 3 + 1).toByte() }
        val gen = V4Algo35EncryptionMethodGenerator(pubMat, fp)
        val packet = gen.generate(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256), sessionKey
        ).getEncoded()

        val body = stripHeader(packet)
        assertEquals("PKESK is version 6", 6, body[0].toInt() and 0xFF)
        assertEquals("count = keyVersion(1) + fingerprint(20)", 1 + 20, body[1].toInt() and 0xFF)
        assertEquals("target key-version octet is 4", 4, body[2].toInt() and 0xFF)

        val parsed = CompositePkesk.parseBody(body)!!
        assertArrayEquals("addresses the v4 subkey fingerprint", fp, parsed.recipientFingerprint)

        val xSec = secMat.copyOfRange(0, suite.curve.keyLen)
        val mlkemSeed = secMat.copyOfRange(suite.curve.keyLen, secMat.size)
        val (xPub, _) = CompositeKem.splitPublic(pubMat, suite)
        val kek = CompositeKem.decapsulate(
            parsed.ephemeralX25519, parsed.mlkemCiphertext, xSec,
            MLKEMPrivateKeyParameters(suite.mlkem.params, mlkemSeed), xPub, suite
        )
        val recovered = CompositeKem.unwrapSessionKey(kek, parsed.wrappedSessionKey)
        assertArrayEquals("session key round-trips through the generator PKESK", sessionKey, recovered)
    }
}
