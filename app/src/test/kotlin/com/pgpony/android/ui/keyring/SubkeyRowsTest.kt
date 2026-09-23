// SubkeyRowsTest.kt
// PGPony Android, 4.6.0 (item 19)
//
// Key Detail lists every subkey of a classical-primary key that carries a
// composite ML-KEM subkey, with the right labels and capabilities.

package com.pgpony.android.ui.keyring

import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SubkeyCapability
import com.pgpony.android.crypto.pqc.CompositeKeyGen
import com.pgpony.android.crypto.pqc.V4Algo35Carry
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SubkeyRowsTest {

    private val svc = PGPCryptoService.shared

    private fun v4Rings() = svc.generateKeyPair("V4", "v4@example.test", KeyAlgorithm.ED25519_CV25519, null)
        .let { svc.importKeyData(it.privateKeyData).secretKeyRing!! }
        .let { CompositeKeyGen.addV4Algo35SubkeyRings(it) }

    @Test
    fun `an mlkem-768v4 key shows its ML-KEM subkey`() {
        val raw = v4Rings().publicRaw
        assertTrue(SubkeyRows.hasCompositeSubkey(raw))
        val rows = SubkeyRows.fromCertificate(raw, isCardBacked = false)!!
        assertEquals(listOf("X25519", "ML-KEM-768 + X25519"), rows.map { it.algorithmLabel })
        rows.forEach { assertEquals(SubkeyCapability.Encrypt.flag, it.capabilities) }
        rows.forEach { assertEquals(40, it.fingerprint.length); assertEquals(it.fingerprint.takeLast(16), it.keyId) }
    }

    @Test
    fun `an added classical subkey and a second ML-KEM subkey both show next to the first`() {
        val k = v4Rings()
        val bc = svc.importKeyData(k.secretRaw).secretKeyRing!!
        val signing = ClassicalSubkeyGen.addSubkey(secretRing = bc,
            type = ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN, passphrase = null, expirationSeconds = null)
        var pub = V4Algo35Carry.carry(k.publicRaw, PGPPublicKeyRing(signing.publicKeys.asSequence().toList()).encoded)
        val more = CompositeKeyGen.addV4Algo35SubkeyRings(svc.importKeyData(V4Algo35Carry.carry(k.secretRaw, signing.encoded)).secretKeyRing!!)
        pub = V4Algo35Carry.carry(pub, more.publicRaw)
        val rows = SubkeyRows.fromCertificate(pub, isCardBacked = false)!!
        assertEquals(4, rows.size)
        assertEquals(2, rows.count { it.algorithmLabel == "ML-KEM-768 + X25519" })
        val sign = rows.single { it.algorithmLabel == "Ed25519" }
        assertTrue(sign.capabilities and SubkeyCapability.Sign.flag != 0)
        assertEquals(4, rows.map { it.fingerprint }.toSet().size)
    }

    @Test
    fun `the RFC 9980 v4 sample key lists its ML-KEM subkey`() {
        val raw = javaClass.getResourceAsStream("/pqc/rfc9980-a2-v4-ed25519-mlkem768-pub.asc")!!
            .readBytes().let { ArmoredInputStream(it.inputStream()).readBytes() }
        val rows = SubkeyRows.fromCertificate(raw, false)
        assertNotNull(rows)
        assertTrue(rows!!.any { it.algorithmLabel == "ML-KEM-768 + X25519" && it.capabilities and SubkeyCapability.Encrypt.flag != 0 })
    }

    @Test
    fun `a v6 ML-KEM key is listed from its certificate too`() {
        val k = svc.generateKeyPair("V6", "v6@example.test", KeyAlgorithm.MLKEM768_X25519_V6, null)
        assertTrue(SubkeyRows.hasCompositeSubkey(k.publicKeyData))
        val rows = SubkeyRows.fromCertificate(k.publicKeyData, false)!!
        assertTrue(rows.any { it.algorithmLabel == "ML-KEM-768 + X25519" })
        rows.forEach { assertEquals(64, it.fingerprint.length) }
    }

    @Test
    fun `a classical key keeps the Bouncy Castle path`() {
        val k = svc.generateKeyPair("C", "c@example.test", KeyAlgorithm.ED25519_CV25519, null)
        assertFalse(SubkeyRows.hasCompositeSubkey(k.publicKeyData))
    }
}
