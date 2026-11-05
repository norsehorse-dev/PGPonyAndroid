// GranularKeygenV4Test.kt
// PGPony Android, 4.8.0 (item 4i): the subkey composer on a v4 Ed25519 base.
//
// assembleGranularV4 starts from the v4 Ed25519 + Cv25519 ring the normal
// keygen makes, keeps or strips the Cv25519 subkey, adds classical subkeys with
// their own expiry and grafts an ML-KEM-768 subkey last as the v4 algorithm 35
// interop subkey. Every key packet must be version 4, SEIPDv2 is advertised only
// when the algo-35 subkey is there, and the subkeys must work.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType
import com.pgpony.android.crypto.GranularSubkeySpec
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class GranularKeygenV4Test {

    private val svc = PGPCryptoService.shared
    private val uid = "Granular V4 <granular-v4@example.test>"
    private val oneYear = 365L * 24 * 60 * 60

    private fun keyPackets(raw: ByteArray) =
        CertificateBindings.packets(raw).filter { it.tag == 5 || it.tag == 6 || it.tag == 7 || it.tag == 14 }

    private fun subkeyAlgos(raw: ByteArray): List<Int> =
        keyPackets(raw).filter { it.tag == 7 || it.tag == 14 }.map { it.body[5].toInt() and 0xFF }

    private fun assertAllV4(raw: ByteArray) =
        keyPackets(raw).forEach { assertEquals("every key packet is version 4", 4, it.body[0].toInt()) }

    private fun advertisesSeipdV2(primary: PGPPublicKey): Boolean =
        primary.signatures.asSequence().filterIsInstance<PGPSignature>().any { sig ->
            val f = sig.hashedSubPackets?.getSubpacket(SignatureSubpacketTags.FEATURES) ?: return@any false
            f.data.isNotEmpty() && (f.data[0].toInt() and 0x08) != 0
        }

    @Test
    fun `classical subkeys on a v4 base, default stripped`() {
        val key = svc.assembleGranularV4(
            uid, includeDefaultEncryptionSubkey = false,
            subkeys = listOf(
                GranularSubkeySpec(AddSubkeyChoice.Classical(ClassicalSubkeyType.RSA_2048_ENCRYPT), oneYear),
                GranularSubkeySpec(AddSubkeyChoice.Classical(ClassicalSubkeyType.ED25519_SIGN), null)
            ),
            passphrase = null
        )
        assertFalse("no algo-35 subkey", key.hasV4Algo35)
        val pub = key.publicRing!!
        assertAllV4(key.public)
        val algos = subkeyAlgos(key.public)
        assertFalse("the default Cv25519 subkey is gone", algos.contains(18))
        assertTrue("the RSA subkey is there", algos.contains(1))
        assertEquals("two subkeys", 2, algos.size)
        assertFalse("a classical v4 key does not advertise SEIPDv2", advertisesSeipdV2(pub.publicKey))

        val rsa = pub.publicKeys.asSequence().first { !it.isMasterKey && it.algorithm == 1 }
        val sign = pub.publicKeys.asSequence().first { !it.isMasterKey && it.algorithm != 1 }
        assertEquals("the RSA subkey keeps its own expiry", oneYear, rsa.validSeconds)
        assertEquals("the signing subkey keeps its own (no) expiry", 0L, sign.validSeconds)

        val secret = PGPSecretKeyRing(ByteArrayInputStream(key.secret), JcaKeyFingerprintCalculator())
        val plaintext = "to the RSA subkey of a v4 granular key".toByteArray()
        val ct = svc.encrypt(data = plaintext, recipientPublicKeys = listOf(pub), armor = false)
        assertArrayEquals("encrypts to the RSA subkey and decrypts", plaintext, svc.decrypt(ct, listOf(secret), null).data)
    }

    @Test
    fun `an ML-KEM-768 subkey on a v4 base is the algo-35 interop subkey`() {
        val key = svc.assembleGranularV4(
            uid, includeDefaultEncryptionSubkey = true,
            subkeys = listOf(GranularSubkeySpec(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768), null)),
            passphrase = null
        )
        assertTrue("algo-35 subkey", key.hasV4Algo35)
        assertNull("stored as raw octets", key.publicRing)
        assertAllV4(key.public)
        assertEquals("Cv25519 kept, algo 35 grafted last", listOf(18, 35), subkeyAlgos(key.public))

        val base = PGPPublicKeyRing(
            ByteArrayInputStream(CompositeKeyFacade.v4Algo35BaseBytes(key.public)!!), JcaKeyFingerprintCalculator()
        )
        assertTrue("advertises SEIPDv2 so senders reach the algo-35 subkey", advertisesSeipdV2(base.publicKey))

        val body = CompositeKeyFacade.v4Algo35SubkeyBody(key.public)!!
        val recipient = V4Algo35Recipient(
            CompositeKeyFacade.v4Algo35PublicMaterial(body),
            CompositeKeyFacade.v4Algo35SubkeyFingerprint(body)
        )
        val plaintext = "to the ML-KEM-768 subkey of a v4 granular key".toByteArray()
        val ct = svc.encrypt(data = plaintext, recipientPublicKeys = emptyList(), armor = false, v4Algo35Recipients = listOf(recipient))
        val result = CompositeDecryptor.tryDecrypt(ct, emptyList(), null, listOf(key.secret))!!
        var obj = PGPObjectFactory(result.stream, BcKeyFingerprintCalculator()).nextObject()
        if (obj is org.bouncycastle.openpgp.PGPCompressedData) {
            obj = PGPObjectFactory(obj.dataStream, BcKeyFingerprintCalculator()).nextObject()
        }
        val out = ByteArrayOutputStream().apply { (obj as PGPLiteralData).inputStream.copyTo(this) }.toByteArray()
        assertArrayEquals("the algo-35 subkey round-trips", plaintext, out)
    }

    @Test
    fun `a protected v4 granular key with classical and ML-KEM subkeys`() {
        val pass = "correct horse"
        val key = svc.assembleGranularV4(
            uid, includeDefaultEncryptionSubkey = false,
            subkeys = listOf(
                GranularSubkeySpec(AddSubkeyChoice.Classical(ClassicalSubkeyType.ED25519_AUTH), null),
                GranularSubkeySpec(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768), oneYear)
            ),
            passphrase = pass
        )
        assertAllV4(key.secret)
        assertEquals(2, subkeyAlgos(key.secret).size)
        assertTrue(subkeyAlgos(key.secret).last() == 35)
        assertTrue("the algo-35 subkey is protected", CompositeKeyFacade.v4Algo35IsProtected(CompositeKeyFacade.v4Algo35SubkeyBody(key.secret)!!))
    }

    @Test
    fun `v6-only subkeys are refused on a v4 base`() {
        fun build(vararg c: AddSubkeyChoice) = svc.assembleGranularV4(
            uid, includeDefaultEncryptionSubkey = true, subkeys = c.map { GranularSubkeySpec(it, null) }, passphrase = null
        )
        assertThrows(IllegalArgumentException::class.java) { build(AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA65_ED25519)) }
        assertThrows(IllegalArgumentException::class.java) { build(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_1024)) }
        assertThrows(IllegalArgumentException::class.java) {
            build(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768), AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768))
        }
    }
}
