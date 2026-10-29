// GnuPgX448Test.kt
// PGPony Android, 4.7.3
//
// Keys here are built in the test, shaped the way GnuPG writes an X448
// encryption subkey: ECDH (algorithm 18) on OID 1.3.101.111 with the bare
// 56-octet public value, as a v5 or a v4 subkey. GnuPG interop itself is
// checked separately against vectors made with gpg.

package com.pgpony.android.crypto

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.ECSecretBCPGKey
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.PublicSubkeyPacket
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.X448PrivateKeyParameters
import org.bouncycastle.crypto.params.X448PublicKeyParameters
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

class GnuPgX448Test {

    private val random = SecureRandom()
    private val data = "4.7.3 X448".toByteArray()

    private class TestKey(val pub: PGPPublicKey, val priv: PGPPrivateKey, val rawPublic: ByteArray)

    /**
     * An X448 ECDH subkey. [prefixed] writes the public value the way Bouncy
     * Castle does (0x40 ‖ 56 octets), otherwise bare like GnuPG. [reversed]
     * stores the scalar reversed, as Bouncy Castle does, otherwise native like
     * GnuPG.
     */
    private fun key(version: Int, prefixed: Boolean = false, reversed: Boolean = false): TestKey {
        val gen = X448KeyPairGenerator()
        gen.init(X448KeyGenerationParameters(random))
        val kp = gen.generateKeyPair()
        val rawPublic = (kp.public as X448PublicKeyParameters).encoded
        val scalar = (kp.private as X448PrivateKeyParameters).encoded
        val value = if (prefixed) byteArrayOf(0x40) + rawPublic else rawPublic
        val ecdh = ECDHPublicBCPGKey(
            EdECObjectIdentifiers.id_X448, BigInteger(1, value),
            HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256
        )
        val packet = PublicSubkeyPacket(version, PublicKeyAlgorithmTags.ECDH, Date(), ecdh)
        val pub = PGPPublicKey(packet, BcKeyFingerprintCalculator())
        val stored = if (reversed) scalar.reversedArray() else scalar
        val priv = PGPPrivateKey(pub.keyID, packet, ECSecretBCPGKey(BigInteger(1, stored)))
        return TestKey(pub, priv, rawPublic)
    }

    private fun encrypt(method: org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator): ByteArray {
        val gen = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true).setSecureRandom(random)
        )
        gen.addMethod(method)
        val out = ByteArrayOutputStream()
        gen.open(out, data.size.toLong()).use { it.write(data) }
        return out.toByteArray()
    }

    private fun pkesk(message: ByteArray): PGPPublicKeyEncryptedData =
        (BcPGPObjectFactory(message).nextObject() as PGPEncryptedDataList)[0] as PGPPublicKeyEncryptedData

    private fun decrypt(message: ByteArray, priv: PGPPrivateKey): ByteArray {
        val pked = pkesk(message)
        val back = pked.getDataStream(GnuPgX448.DecryptorFactory(priv)).use { it.readBytes() }
        assertTrue(pked.verify())
        return back
    }

    @Test
    fun bouncyCastleCannotEncryptToTheBareForm() {
        val k = key(PublicKeyPacket.LIBREPGP_5)
        assertThrows(PGPException::class.java) { encrypt(BcPublicKeyKeyEncryptionMethodGenerator(k.pub)) }
    }

    @Test
    fun roundTripV5() {
        val k = key(PublicKeyPacket.LIBREPGP_5)
        assertTrue(GnuPgX448.isGnuPgEncoded(k.pub.publicKeyPacket))
        assertArrayEquals(data, decrypt(encrypt(GnuPgX448.encryptionMethod(k.pub)), k.priv))
    }

    @Test
    fun roundTripV4() {
        val k = key(PublicKeyPacket.VERSION_4)
        assertArrayEquals(data, decrypt(encrypt(GnuPgX448.encryptionMethod(k.pub)), k.priv))
    }

    @Test
    fun reversedScalarStillOpens() {
        val k = key(PublicKeyPacket.LIBREPGP_5, reversed = true)
        assertArrayEquals(data, decrypt(encrypt(GnuPgX448.encryptionMethod(k.pub)), k.priv))
    }

    @Test
    fun bouncyCastleMessageToAPrefixedKeyOpens() {
        // BC writes the 0x40-prefixed ephemeral value; the factory reads both forms.
        val k = key(PublicKeyPacket.VERSION_4, prefixed = true, reversed = true)
        assertFalse(GnuPgX448.isGnuPgEncoded(k.pub.publicKeyPacket))
        val message = encrypt(GnuPgX448.encryptionMethod(k.pub))
        assertArrayEquals(data, decrypt(message, k.priv))
        val stock = pkesk(message).getDataStream(BcPublicKeyDataDecryptorFactory(k.priv)).use { it.readBytes() }
        assertArrayEquals(data, stock)
    }

    @Test
    fun pkeskIsWrittenTheWayGnuPgWritesIt() {
        val k = key(PublicKeyPacket.LIBREPGP_5)
        val message = encrypt(GnuPgX448.encryptionMethod(k.pub))
        // Packet 1 is the PKESK (tag 1): version 3, key ID, algorithm 18, then
        // the ephemeral MPI. BC may write either header format.
        val h = message[0].toInt() and 0xFF
        val body = if (h and 0x40 != 0) {
            assertEquals(1, h and 0x3F)
            2
        } else {
            assertEquals(1, (h shr 2) and 0x0F)
            when (h and 0x03) { 0 -> 2; 1 -> 3; else -> 5 }
        }
        assertEquals(3, message[body].toInt())
        val keyId = message.copyOfRange(body + 1, body + 9)
        assertArrayEquals(k.pub.fingerprint.copyOf(8), keyId)
        assertEquals(18, message[body + 9].toInt())
        val bits = ((message[body + 10].toInt() and 0xFF) shl 8) or (message[body + 11].toInt() and 0xFF)
        assertEquals(448, bits)
    }

    @Test
    fun kdfUsesTheLeftmost20OctetsOfAV5Fingerprint() {
        val k = key(PublicKeyPacket.LIBREPGP_5)
        assertEquals(32, k.pub.fingerprint.size)
        assertArrayEquals(k.pub.fingerprint.copyOf(20), GnuPgX448.kdfFingerprint(k.pub.publicKeyPacket))
    }

    @Test
    fun publicPointFromEitherEncoding() {
        val bare = key(PublicKeyPacket.LIBREPGP_5)
        val prefixed = key(PublicKeyPacket.VERSION_4, prefixed = true)
        assertArrayEquals(bare.rawPublic, GnuPgX448.publicPoint(bare.pub.publicKeyPacket))
        assertArrayEquals(prefixed.rawPublic, GnuPgX448.publicPoint(prefixed.pub.publicKeyPacket))
    }

    @Test
    fun wrongKeyFails() {
        val k = key(PublicKeyPacket.LIBREPGP_5)
        val other = key(PublicKeyPacket.LIBREPGP_5)
        val message = encrypt(GnuPgX448.encryptionMethod(k.pub))
        val wrong = PGPPrivateKey(k.pub.keyID, k.pub.publicKeyPacket, other.priv.privateKeyDataPacket)
        assertThrows(Exception::class.java) { decrypt(message, wrong) }
    }

    @Test
    fun paddingIsPkcs5ToEightOctets() {
        assertEquals(8, GnuPgX448.pad(ByteArray(0)).size)
        assertEquals(40, GnuPgX448.pad(ByteArray(35)).size)
        assertEquals(48, GnuPgX448.pad(ByteArray(40)).size)
        assertEquals(5, GnuPgX448.pad(ByteArray(35)).last().toInt())
    }
}
