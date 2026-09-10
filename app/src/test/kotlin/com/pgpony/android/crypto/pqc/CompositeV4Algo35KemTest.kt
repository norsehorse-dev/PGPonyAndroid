// CompositeV4Algo35KemTest.kt
// PGPony Android — 4.5.0 (item 14 / #56): v4 ML-KEM-768+X25519 (algo 35) KEM.
//
// Proves the v4 interop key's encryption round-trip at the crypto core,
// offline: extract the subkey's public + secret material (a v4 packet has no
// 4-octet material-length field), encapsulate to the public material, frame
// the result as the v4-targeted v6 PKESK (key-version octet 4, 20-octet SHA-1
// fingerprint, per RFC 9580 5.1), parse it back, decapsulate with the secret
// material, and confirm the session key survives. The composite KEM itself is
// version-agnostic; only the material extraction and the PKESK target framing
// differ from the v6 path. gpg 2.5.x / sq interop is the on-device check.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.SecureRandom

class CompositeV4Algo35KemTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `v4 algo-35 encapsulate and decapsulate round-trips a session key through the PKESK`() {
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "V4 Interop", email = "v4@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = null
            ).privateKeyData
        ).secretKeyRing!!
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base)
        val suite = CompositeSuite.IETF_768

        val subBody = CompositeKeyFacade.v4Algo35SubkeyBody(rings.secretRaw)!!
        val pubMat = CompositeKeyFacade.v4Algo35PublicMaterial(subBody)   // 1216
        val secMat = CompositeKeyFacade.v4Algo35SecretMaterial(subBody)!! // 96
        val fp = CompositeKeyFacade.v4Algo35SubkeyFingerprint(subBody)    // 20

        val (xPub, mPub) = CompositeKem.splitPublic(pubMat, suite)
        val xSec = secMat.copyOfRange(0, suite.curve.keyLen)
        val mlkemSeed = secMat.copyOfRange(suite.curve.keyLen, secMat.size)
        val mlkemSec = MLKEMPrivateKeyParameters(suite.mlkem.params, mlkemSeed)

        val sessionKey = ByteArray(32) { (it + 1).toByte() }
        val enc = CompositeKem.encapsulate(xPub, mPub, SecureRandom(), suite)
        val wrapped = CompositeKem.wrapSessionKey(enc.kek, sessionKey)

        // Frame it as the v4-targeted v6 PKESK, then parse it back.
        val body = CompositePkesk.encodeBody(
            fp, enc.ephemeralX25519, enc.mlkemCiphertext, wrapped, suite
        )
        // Body: version(6) | count | keyVersion | fingerprint | algo | fields.
        assertEquals("PKESK count = keyVersion(1) + fingerprint(20)", 1 + 20, body[1].toInt() and 0xFF)
        assertEquals("target key version octet is 4 for a v4 subkey", 4, body[2].toInt() and 0xFF)

        val parsed = CompositePkesk.parseBody(body)!!
        assertArrayEquals("recipient fingerprint is the 20-octet v4 SHA-1", fp, parsed.recipientFingerprint)

        val kek = CompositeKem.decapsulate(
            ephemeralX25519 = parsed.ephemeralX25519,
            mlkemCiphertext = parsed.mlkemCiphertext,
            recipientX25519Sec = xSec,
            recipientMlkemSec = mlkemSec,
            recipientX25519Pub = xPub,
            suite = suite
        )
        val recovered = CompositeKem.unwrapSessionKey(kek, parsed.wrappedSessionKey)
        assertArrayEquals("session key survives the v4 KEM + PKESK round-trip", sessionKey, recovered)
    }
}
