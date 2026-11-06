// CardMseTest.kt
// PGPony Android, 4.8.0 RC4 (#108)
//
// Decrypting through the card's authentication slot. A user keeps an ADSK
// (key flags 20 04) in the authentication slot of a card whose decryption
// slot got no packet. OpenPGP card 3.3 and later lets PSO:DECIPHER use that
// key after MANAGE SECURITY ENVIRONMENT. Covered here without a card: the MSE
// APDU bytes, the Extended Capabilities (C0) flag, the session's MSE around
// one PSO:DECIPHER (restored on failure too), and a whole session-key
// recovery through the authentication slot against a fake card that does
// the RSA or X25519 step in software.

package com.pgpony.android.crypto.card

import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.encodings.PKCS1Encoding
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

class CardMseTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    private val ok = bytes(0x90, 0x00)

    // ── MSE APDU ─────────────────────────────────────────────────────

    @Test
    fun `MSE to the authentication key is 00 22 41 B8 03 83 01 03`() {
        assertArrayEquals(
            bytes(0x00, 0x22, 0x41, 0xB8, 0x03, 0x83, 0x01, 0x03),
            CommandApdu.mseSetDecipherKey(OpenPgpCard.MSE_KEY_REF_AUTHENTICATION).toBytes()
        )
    }

    @Test
    fun `MSE back to the decryption key is 00 22 41 B8 03 83 01 02`() {
        assertArrayEquals(
            bytes(0x00, 0x22, 0x41, 0xB8, 0x03, 0x83, 0x01, 0x02),
            CommandApdu.mseSetDecipherKey(OpenPgpCard.MSE_KEY_REF_DECRYPTION).toBytes()
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `MSE refuses the signature key reference`() {
        CommandApdu.mseSetDecipherKey(0x01)
    }

    // ── Extended Capabilities (C0) ───────────────────────────────────

    /** A 3.4-style C0: bitmap, SM algorithm, challenge, certificate and
     *  special DO lengths, PIN block 2 format, then [mse]. */
    private fun c0(mse: Int) = bytes(0x7D, 0x00, 0x0B, 0xFE, 0x08, 0x00, 0x00, 0xFF, 0x00, mse)

    @Test
    fun `MSE is supported when a 3_3 or later card sets the tenth C0 octet`() {
        assertTrue(ApplicationRelatedData.mseSupportedBy(0x0304, c0(0x01)))
        assertTrue(ApplicationRelatedData.mseSupportedBy(0x0303, c0(0x01)))
    }

    @Test
    fun `MSE is not supported when the tenth C0 octet is zero`() {
        assertFalse(ApplicationRelatedData.mseSupportedBy(0x0304, c0(0x00)))
    }

    @Test
    fun `an older card never counts, whatever its tenth C0 octet`() {
        // On a 2.x card that octet is the low byte of the maximum response length.
        assertFalse(ApplicationRelatedData.mseSupportedBy(0x0201, c0(0x01)))
        assertFalse(ApplicationRelatedData.mseSupportedBy(0x0302, c0(0x01)))
    }

    @Test
    fun `a missing or short C0 means no MSE`() {
        assertFalse(ApplicationRelatedData.mseSupportedBy(0x0304, null))
        assertFalse(ApplicationRelatedData.mseSupportedBy(0x0304, bytes(0x7D, 0x00, 0x0B, 0xFE)))
    }

    private fun tlv(tag: Int, value: ByteArray): ByteArray {
        val tagBytes = if (tag <= 0xFF) byteArrayOf(tag.toByte()) else byteArrayOf((tag shr 8).toByte(), tag.toByte())
        val lenBytes = when {
            value.size < 0x80 -> byteArrayOf(value.size.toByte())
            value.size < 0x100 -> byteArrayOf(0x81.toByte(), value.size.toByte())
            else -> byteArrayOf(0x82.toByte(), (value.size shr 8).toByte(), value.size.toByte())
        }
        return tagBytes + lenBytes + value
    }

    private fun ard(version: Int, c0: ByteArray?, decFp: ByteArray, authFp: ByteArray): ByteArray {
        val aid = bytes(
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
            (version shr 8) and 0xFF, version and 0xFF,
            0x00, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00
        )
        val c5 = ByteArray(20) + decFp + authFp
        val disc = (c0?.let { tlv(0xC0, it) } ?: ByteArray(0)) + tlv(0xC5, c5)
        return tlv(OpenPgpCard.DO_AID, aid) + tlv(OpenPgpCard.DO_DISCRETIONARY, disc)
    }

    @Test
    fun `the Application Related Data parse reads the version and the MSE flag`() {
        val dec = ByteArray(20) { 0xBD.toByte() }
        val auth = ByteArray(20) { 0xB9.toByte() }
        val withMse = ApplicationRelatedData.parse(ard(0x0304, c0(0x01), dec, auth))
        assertEquals(0x0304, withMse.specVersion)
        assertTrue(withMse.mseSupported)
        assertEquals("B9".repeat(20), withMse.authFingerprint)
        assertFalse(ApplicationRelatedData.parse(ard(0x0304, c0(0x00), dec, auth)).mseSupported)
        assertFalse(ApplicationRelatedData.parse(ard(0x0304, null, dec, auth)).mseSupported)
        assertFalse(ApplicationRelatedData.parse(ard(0x0200, c0(0x01), dec, auth)).mseSupported)
    }

    // ── the session's MSE around PSO:DECIPHER ────────────────────────

    private class Scripted(private val reply: (ByteArray) -> ByteArray) : CardTransport {
        val sent = mutableListOf<ByteArray>()
        override fun transceive(commandApdu: ByteArray): ByteArray {
            val c = commandApdu.copyOf() // the session wipes the array once sent
            sent.add(c)
            return reply(c)
        }
    }

    private fun ins(c: ByteArray) = c[1].toInt() and 0xFF

    @Test
    fun `the authentication slot wraps PSO_DECIPHER in MSE 3 and MSE 2`() {
        val shared = ByteArray(32) { 0x5A.toByte() }
        val t = Scripted { c -> if (ins(c) == 0x2A) shared + ok else ok }
        val out = OpenPgpCardSession(t).decipher(ByteArray(40) { it.toByte() }, CardSlot.AUTHENTICATION)
        assertArrayEquals(shared, out)
        assertEquals(listOf(0x22, 0x2A, 0x22), t.sent.map { ins(it) })
        assertArrayEquals(CommandApdu.mseSetDecipherKey(3).toBytes(), t.sent[0])
        assertArrayEquals(CommandApdu.mseSetDecipherKey(2).toBytes(), t.sent[2])
    }

    @Test
    fun `the decryption slot sends no MSE`() {
        val t = Scripted { c -> if (ins(c) == 0x2A) ByteArray(32) + ok else ok }
        OpenPgpCardSession(t).decipher(ByteArray(40), CardSlot.DECRYPTION)
        assertEquals(listOf(0x2A), t.sent.map { ins(it) })
    }

    @Test
    fun `a failed PSO_DECIPHER still restores the decryption key`() {
        val t = Scripted { c -> if (ins(c) == 0x2A) bytes(0x6A, 0x80) else ok }
        try {
            OpenPgpCardSession(t).decipherRsa(ByteArray(256) { 1.toByte() }, 256, CardSlot.AUTHENTICATION)
            fail("the card refused the cryptogram")
        } catch (e: OpenPgpCardException) {
            // expected
        }
        val seq = t.sent.map { ins(it) }
        assertEquals("MSE first", 0x22, seq.first())
        assertArrayEquals("MSE 2 last", CommandApdu.mseSetDecipherKey(2).toBytes(), t.sent.last())
    }

    @Test
    fun `a card that refuses MSE gets no PSO_DECIPHER`() {
        val t = Scripted { c -> if (ins(c) == 0x22) bytes(0x6D, 0x00) else ok }
        try {
            OpenPgpCardSession(t).decipher(ByteArray(40), CardSlot.AUTHENTICATION)
            fail("MSE was refused")
        } catch (e: OpenPgpCardException) {
            // expected
        }
        assertFalse(t.sent.any { ins(it) == 0x2A })
    }

    // ── a whole session-key recovery through the authentication slot ──

    /**
     * A card that does PSO:DECIPHER in software with the key MSE selected:
     * key 2 (decryption) by default, key 3 (authentication) after MSE 83 01 03.
     * RSA cryptograms arrive chained (00 padding indicator plus 256 octets);
     * ECDH ones as A6 { 7F49 { 86 point } } and get the raw X25519 output.
     */
    private class SoftCard(
        private val decKey: AsymmetricCipherKeyPair?,
        private val authKey: AsymmetricCipherKeyPair
    ) : CardTransport {
        val sent = mutableListOf<ByteArray>()
        private var keyRef = 2
        private val chained = ByteArrayOutputStream()

        override fun transceive(commandApdu: ByteArray): ByteArray {
            val c = commandApdu.copyOf()
            sent.add(c)
            val ok = byteArrayOf(0x90.toByte(), 0x00)
            val wrongData = byteArrayOf(0x6A, 0x80.toByte())
            return when (c[1].toInt() and 0xFF) {
                0x22 -> { keyRef = c[7].toInt(); ok }
                0x2A -> {
                    val lc = c[4].toInt() and 0xFF
                    chained.write(c, 5, lc)
                    if ((c[0].toInt() and 0x10) != 0) return ok
                    val data = chained.toByteArray()
                    chained.reset()
                    val key = (if (keyRef == 3) authKey else decKey) ?: return wrongData
                    val priv = key.private
                    if (priv is X25519PrivateKeyParameters) {
                        val agreement = X25519Agreement().apply { init(priv) }
                        val shared = ByteArray(agreement.agreementSize)
                        agreement.calculateAgreement(X25519PublicKeyParameters(data, data.size - 32), shared, 0)
                        shared + ok
                    } else {
                        val rsa = PKCS1Encoding(RSAEngine()).apply { init(false, priv as RSAKeyParameters) }
                        try {
                            rsa.processBlock(data, 1, data.size - 1) + ok
                        } catch (e: InvalidCipherTextException) {
                            wrongData
                        }
                    }
                }
                else -> byteArrayOf(0x6D, 0x00)
            }
        }
    }

    private val created = Date(System.currentTimeMillis() - 24 * 3600 * 1000L)

    private fun rsa(): AsymmetricCipherKeyPair = RSAKeyPairGenerator().apply {
        init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), SecureRandom(), 2048, 12))
    }.generateKeyPair()

    private fun x25519(): AsymmetricCipherKeyPair = org.bouncycastle.crypto.generators.X25519KeyPairGenerator().apply {
        init(org.bouncycastle.crypto.params.X25519KeyGenerationParameters(SecureRandom()))
    }.generateKeyPair()

    private fun ed25519(): AsymmetricCipherKeyPair = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator().apply {
        init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
    }.generateKeyPair()

    /** Ed25519 primary, an X25519 encryption subkey, and [adsk] as an ADSK
     *  with key flags 20 04 (authentication plus ADSK), as in issue #108. */
    private fun ringWithAdsk(adsk: AsymmetricCipherKeyPair, adskAlgorithm: Int): Pair<PGPPublicKeyRing, Long> {
        val master = BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, ed25519(), created)
        val enc = BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, x25519(), created)
        val adskPair = BcPGPKeyPair(adskAlgorithm, adsk, created)
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, master, "card <card@example.test>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA) }.generate(),
            null, BcPGPContentSignerBuilder(master.publicKey.algorithm, HashAlgorithmTags.SHA256), null
        )
        gen.addSubKey(
            enc,
            PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE) }.generate(),
            null
        )
        gen.addSubKey(
            adskPair,
            PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.AUTHENTICATION or 0x0400) }.generate(),
            null
        )
        return gen.generatePublicKeyRing() to adskPair.keyID
    }

    private fun pkesks(ciphertext: ByteArray): List<PGPPublicKeyEncryptedData> {
        val f = BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(ciphertext)))
        var o = f.nextObject()
        while (o != null && o !is PGPEncryptedDataList) o = f.nextObject()
        val list = o as PGPEncryptedDataList
        return (0 until list.size()).mapNotNull { list[it] as? PGPPublicKeyEncryptedData }
    }

    /** Encrypt to [ring], then open the ADSK's packet on a card that holds the
     *  ADSK in its authentication slot and nothing for this message in its
     *  decryption slot (card B in issue #108). */
    private fun openThroughAuthSlot(ring: PGPPublicKeyRing, adskId: Long, card: SoftCard): String {
        val ct = PGPCryptoService.shared.encrypt("through the auth slot".toByteArray(), listOf(ring), armor = false)
        val packets = pkesks(ct)
        val ids = packets.map { it.keyID }
        assertTrue("the message carries the ADSK's packet", adskId in ids)

        // Card B: its decryption slot key is in no packet, its authentication
        // slot holds the ADSK, and it supports MSE.
        val pick = CardPkeskSelection.pickForCard(
            ids, decSlotKeyId = 0x0123456789ABCDEFL, authSlotKeyId = adskId, mseSupported = true
        ) { ring.getPublicKey(it) != null }
        assertTrue(pick is CardPkeskSelection.CardPick.Open)
        pick as CardPkeskSelection.CardPick.Open
        assertEquals(CardSlot.AUTHENTICATION, pick.slot)
        assertEquals(adskId, ids[pick.index])

        val pked = packets[pick.index]
        val session = OpenPgpCardSession(card)
        val clear = pked.getDataStream(CardPublicKeyDataDecryptorFactory(session, ring.getPublicKey(adskId), pick.slot))
        val plain = clear.readBytes()
        assertTrue("integrity", pked.verify())
        return String(CardDecryptService.shared.readContent(plain, null).data, Charsets.UTF_8)
    }

    @Test
    fun `an RSA ADSK in the authentication slot opens the message through MSE`() {
        val adsk = rsa()
        val (ring, adskId) = ringWithAdsk(adsk, PublicKeyAlgorithmTags.RSA_GENERAL)
        val card = SoftCard(decKey = null, authKey = adsk)
        assertEquals("through the auth slot", openThroughAuthSlot(ring, adskId, card))
        val seq = card.sent.map { it[1].toInt() and 0xFF }
        assertEquals("MSE 3 first", 0x22, seq.first())
        assertEquals(0x03, card.sent.first()[7].toInt())
        assertArrayEquals("MSE 2 last", CommandApdu.mseSetDecipherKey(2).toBytes(), card.sent.last())
        assertTrue("PSO:DECIPHER in between", seq.drop(1).dropLast(1).all { it == 0x2A })
    }

    @Test
    fun `an X25519 ADSK in the authentication slot opens the message through MSE`() {
        val adsk = x25519()
        val (ring, adskId) = ringWithAdsk(adsk, PublicKeyAlgorithmTags.ECDH)
        val card = SoftCard(decKey = null, authKey = adsk)
        assertEquals("through the auth slot", openThroughAuthSlot(ring, adskId, card))
        assertEquals(listOf(0x22, 0x2A, 0x22), card.sent.map { it[1].toInt() and 0xFF })
    }
}
