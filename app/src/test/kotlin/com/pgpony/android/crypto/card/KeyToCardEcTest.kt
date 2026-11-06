// KeyToCardEcTest.kt
// PGPony Android, 4.8.0 (4l, #109): Move to Security Key for ECDSA and ECDH
// keys on brainpool and secp256k1 (and the NIST curves, which take the same
// path). The slot attributes are algorithm ID 13 (ECDSA) or 12 (ECDH)
// followed by the curve OID, as in the OpenPGP card 3.4 spec (4.4.3.10), and
// the private key goes into tag 92 left-padded to the field length.

package com.pgpony.android.crypto.card

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ECSecretBCPGKey
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class KeyToCardEcTest {

    private val svc = PGPCryptoService.shared

    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }

    private fun secretRing(algorithm: KeyAlgorithm): PGPSecretKeyRing =
        svc.importKeyData(svc.generateKeyPair("Card", "card@example.test", algorithm, null).privateKeyData)
            .secretKeyRing!!

    private fun unlock(ring: PGPSecretKeyRing, pub: PGPPublicKey): PGPPrivateKey =
        ring.getSecretKey(pub.keyID).extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(charArrayOf())
        )

    private fun subkey(ring: PGPSecretKeyRing): PGPPublicKey =
        ring.publicKeys.asSequence().single { !it.isMasterKey }

    @Test
    fun `the primary goes to signature or authentication, the ECDH subkey to decryption`() {
        val cases = listOf(
            KeyAlgorithm.ECDSA_BRAINPOOL_P256 to "1.3.36.3.3.2.8.1.1.7",
            KeyAlgorithm.ECDSA_BRAINPOOL_P384 to "1.3.36.3.3.2.8.1.1.11",
            KeyAlgorithm.ECDSA_BRAINPOOL_P512 to "1.3.36.3.3.2.8.1.1.13",
            KeyAlgorithm.ECDSA_SECP256K1 to "1.3.132.0.10"
        )
        for ((algorithm, oid) in cases) {
            val ring = secretRing(algorithm)
            assertEquals(
                KeyToCard.Eligibility.Movable(KeyToCard.Kind.EC_SIGN, curveOid = oid),
                KeyToCard.eligibility(ring.publicKey)
            )
            assertEquals(
                KeyToCard.Eligibility.Movable(KeyToCard.Kind.EC_DECRYPT, curveOid = oid),
                KeyToCard.eligibility(subkey(ring))
            )
        }
        val sign = KeyToCard.Kind.EC_SIGN
        val decrypt = KeyToCard.Kind.EC_DECRYPT
        assertTrue(KeyToCard.fitsSlot(sign, CardSlot.SIGNATURE, true, false, false))
        assertTrue(KeyToCard.fitsSlot(sign, CardSlot.SIGNATURE, false, false, false, primaryCanCertify = true))
        assertTrue(KeyToCard.fitsSlot(sign, CardSlot.AUTHENTICATION, false, false, true))
        assertFalse(KeyToCard.fitsSlot(sign, CardSlot.DECRYPTION, true, true, false))
        assertTrue(KeyToCard.fitsSlot(decrypt, CardSlot.DECRYPTION, false, true, false))
        assertFalse(KeyToCard.fitsSlot(decrypt, CardSlot.SIGNATURE, true, true, false))
        assertFalse(KeyToCard.fitsSlot(decrypt, CardSlot.AUTHENTICATION, false, true, true))
    }

    @Test
    fun `EC attributes are the algorithm ID and the curve OID`() {
        assertEquals(
            "132B2403030208010107",
            hex(KeyToCard.attributes(KeyToCard.Kind.EC_SIGN, 0, 0, 0, "1.3.36.3.3.2.8.1.1.7"))
        )
        assertEquals(
            "122B240303020801010B",
            hex(KeyToCard.attributes(KeyToCard.Kind.EC_DECRYPT, 0, 0, 0, "1.3.36.3.3.2.8.1.1.11"))
        )
        assertEquals(
            "132B240303020801010D",
            hex(KeyToCard.attributes(KeyToCard.Kind.EC_SIGN, 0, 0, 0, "1.3.36.3.3.2.8.1.1.13"))
        )
        assertEquals("122B8104000A", hex(KeyToCard.attributes(KeyToCard.Kind.EC_DECRYPT, 0, 0, 0, "1.3.132.0.10")))
        // CardAlgorithmAttributes reads them back as the same curve.
        val parsed = CardAlgorithmAttributes.parse(
            KeyToCard.attributes(KeyToCard.Kind.EC_SIGN, 0, 0, 0, "1.3.132.0.10")
        )
        assertEquals(KeyAlgorithm.ECDSA_SECP256K1, parsed?.mappedAlgorithm)
        // A slot that appends the import-format octet counts as the same attributes.
        val bp = KeyToCard.attributes(KeyToCard.Kind.EC_SIGN, 0, 0, 0, "1.3.36.3.3.2.8.1.1.7")
        assertTrue(KeyToCard.sameAttributes(bp + byteArrayOf(0xFF.toByte()), bp))
    }

    @Test
    fun `the EC secret is the private scalar padded to the field length`() {
        val sizes = listOf(
            KeyAlgorithm.ECDSA_BRAINPOOL_P256 to 32,
            KeyAlgorithm.ECDSA_BRAINPOOL_P384 to 48,
            KeyAlgorithm.ECDSA_BRAINPOOL_P512 to 64,
            KeyAlgorithm.ECDSA_SECP256K1 to 32
        )
        for ((algorithm, size) in sizes) {
            val ring = secretRing(algorithm)
            for (pub in listOf(ring.publicKey, subkey(ring))) {
                val priv = unlock(ring, pub)
                val secret = KeyToCard.weierstrassSecret(pub, priv)
                assertEquals("$algorithm", size, secret.size)
                assertEquals((priv.privateKeyDataPacket as ECSecretBCPGKey).x, BigInteger(1, secret))
                val ehl = KeyToCard.extendedHeaderList(CardSlot.SIGNATURE, KeyToCard.ecParts(secret))
                assertEquals("92" + hex(KeyToCard.berLength(size)), hex(ehl.copyOfRange(7, 9)))
            }
        }
    }
}
