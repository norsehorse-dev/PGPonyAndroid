// AdskEncryptionTest.kt
// PGPony Android, 4.8.0 RC4 (#108)
//
// Additional decryption subkeys (ADSK, key flag 0x0400, GnuPG 2.4.1 and
// later). Encrypting to a key that has one adds a PKESK for it next to the
// chosen encryption subkey, as GnuPG does; an expired or revoked ADSK is left
// out; the per-recipient subkey choice still decides the main key; and a
// holder of only the ADSK's secret can decrypt. The ADSK here carries key
// flags 20 04 (authentication plus ADSK), the layout from issue #108.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
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
import java.security.SecureRandom
import java.util.Date

class AdskEncryptionTest {

    private val svc = PGPCryptoService.shared

    /** Authentication (0x20) plus ADSK (0x0400): octets 20 04 on the wire. */
    private val authAdskFlags = KeyFlags.AUTHENTICATION or 0x0400

    /** Keys are made two days back so a short key expiration lies in the past. */
    private val created = Date(System.currentTimeMillis() - 2 * 24 * 3600 * 1000L)

    private fun ed25519Pair(): PGPKeyPair {
        val g = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
        g.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
        return BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, g.generateKeyPair(), created)
    }

    private fun x25519Pair(at: Date = created): PGPKeyPair {
        val g = org.bouncycastle.crypto.generators.X25519KeyPairGenerator()
        g.init(org.bouncycastle.crypto.params.X25519KeyGenerationParameters(SecureRandom()))
        return BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, g.generateKeyPair(), at)
    }

    private class Sub(val pair: PGPKeyPair, val flags: Int, val expirySeconds: Long? = null)

    private class Built(val secret: PGPSecretKeyRing, val public: PGPPublicKeyRing)

    /** An Ed25519 certify + sign primary with the given X25519 subkeys, built with Bouncy Castle. */
    private fun build(vararg subs: Sub): Built {
        val master = ed25519Pair()
        val sha1 = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        val mh = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
        }
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, master, "ADSK test <adsk@example.test>", sha1, mh.generate(), null,
            BcPGPContentSignerBuilder(master.publicKey.algorithm, HashAlgorithmTags.SHA256), null
        )
        for (s in subs) {
            val h = PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, s.flags)
                s.expirySeconds?.let { setKeyExpirationTime(false, it) }
            }
            gen.addSubKey(s.pair, h.generate(), null)
        }
        return Built(gen.generateSecretKeyRing(), gen.generatePublicKeyRing())
    }

    /** [ring] with [sub] revoked by the primary (a 0x28 with no reason, so a hard one). */
    private fun revoke(built: Built, sub: PGPPublicKey): PGPPublicKeyRing {
        val sk = built.secret.secretKey
        val priv = sk.extractPrivateKey(null)
        val g = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey
        )
        g.init(PGPSignature.SUBKEY_REVOCATION, priv)
        val rev = g.generateCertification(built.public.publicKey, sub)
        val revoked = PGPPublicKey.addCertification(built.public.getPublicKey(sub.keyID), rev)
        return PGPPublicKeyRing.insertPublicKey(built.public, revoked)
    }

    private fun recipientKeyIds(ciphertext: ByteArray): List<Long> {
        val f = BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(ciphertext)))
        var o = f.nextObject()
        while (o != null && o !is PGPEncryptedDataList) o = f.nextObject()
        val list = o as PGPEncryptedDataList
        return (0 until list.size()).mapNotNull { (list[it] as? PGPPublicKeyEncryptedData)?.keyID }
    }

    private fun fp(k: PGPPublicKey) = svc.fingerprintHex(k)

    // ── the test key itself ──────────────────────────────────────────

    @Test
    fun `the ADSK flag is written as 20 04 and read as an ADSK, not an encryption key`() {
        val enc = x25519Pair()
        val adsk = x25519Pair()
        val b = build(Sub(enc, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE), Sub(adsk, authAdskFlags))
        val binding = b.public.getPublicKey(adsk.keyID).signatures.next() as PGPSignature
        assertArrayEquals(
            "raw key flags octets",
            byteArrayOf(0x20, 0x04),
            binding.hashedSubPackets.getSubpacket(SignatureSubpacketTags.KEY_FLAGS).data
        )

        val report = CertificateBindings.analyze(b.public)!!
        val state = report.subkeyByFingerprint(fp(adsk.publicKey))!!
        assertEquals("first octet only", 0x20, state.keyFlags)
        assertTrue("ADSK flag read from the second octet", state.adsk)
        val now = System.currentTimeMillis()
        assertTrue(report.isUsableAdsk(fp(adsk.publicKey), now))
        assertFalse("not an ordinary encryption key", report.isUsableEncryptionKey(fp(adsk.publicKey), now))
        assertFalse("the encryption subkey is not an ADSK", report.isUsableAdsk(fp(enc.publicKey), now))
        assertTrue("its secret may decrypt", report.mayDecryptWith(fp(adsk.publicKey)))
        // Authentication plus ADSK is no signing key; it is graded, not thrown on.
        assertEquals(
            CertificateBindings.SignerValidity.NOT_SIGNING,
            report.signerValidityAt(fp(adsk.publicKey), now)
        )
        // Not offered in the encryption subkey picker, and not the automatic pick.
        assertEquals(listOf(enc.keyID), svc.encryptionKeyOptions(b.public).map { it.keyId })
    }

    // ── encrypt ──────────────────────────────────────────────────────

    @Test
    fun `encrypting to a key with an ADSK adds a PKESK for it`() {
        val enc = x25519Pair()
        val adsk = x25519Pair()
        val b = build(Sub(enc, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE), Sub(adsk, authAdskFlags))
        val ct = svc.encrypt("hi".toByteArray(), listOf(b.public), armor = false)
        assertEquals("encryption subkey first, then the ADSK", listOf(enc.keyID, adsk.keyID), recipientKeyIds(ct))
    }

    @Test
    fun `a key without an ADSK still gets one PKESK`() {
        val enc = x25519Pair()
        val auth = x25519Pair()
        val b = build(Sub(enc, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE), Sub(auth, KeyFlags.AUTHENTICATION))
        val ct = svc.encrypt("hi".toByteArray(), listOf(b.public), armor = false)
        assertEquals(listOf(enc.keyID), recipientKeyIds(ct))
    }

    @Test
    fun `an expired ADSK is left out`() {
        val enc = x25519Pair()
        val adsk = x25519Pair()
        // Created two days ago, valid for one minute.
        val b = build(
            Sub(enc, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE),
            Sub(adsk, authAdskFlags, expirySeconds = 60L)
        )
        val ct = svc.encrypt("hi".toByteArray(), listOf(b.public), armor = false)
        assertEquals(listOf(enc.keyID), recipientKeyIds(ct))
    }

    @Test
    fun `a revoked ADSK is left out`() {
        val enc = x25519Pair()
        val adsk = x25519Pair()
        val b = build(Sub(enc, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE), Sub(adsk, authAdskFlags))
        val revoked = revoke(b, b.public.getPublicKey(adsk.keyID))
        val ct = svc.encrypt("hi".toByteArray(), listOf(revoked), armor = false)
        assertEquals(listOf(enc.keyID), recipientKeyIds(ct))
    }

    @Test
    fun `the per-recipient subkey choice still picks the main key, and other encryption subkeys are not added`() {
        val enc1 = x25519Pair()
        val enc2 = x25519Pair()
        val adsk = x25519Pair()
        val encFlags = KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE
        val b = build(Sub(enc1, encFlags), Sub(enc2, encFlags), Sub(adsk, authAdskFlags))

        // Automatic: the newest usable encryption subkey plus the ADSK, as GnuPG
        // does (newest encryption subkey plus ADSKs), not every encryption subkey.
        val auto = recipientKeyIds(svc.encrypt("hi".toByteArray(), listOf(b.public), armor = false))
        assertEquals(2, auto.size)
        assertTrue(adsk.keyID in auto)
        assertTrue("exactly one ordinary encryption subkey", (enc1.keyID in auto) != (enc2.keyID in auto))
        val autoMain = if (enc1.keyID in auto) enc1.keyID else enc2.keyID
        val other = if (autoMain == enc1.keyID) enc2.keyID else enc1.keyID

        // Chosen: the other encryption subkey replaces the automatic one; the ADSK stays.
        val chosen = recipientKeyIds(
            svc.encrypt(
                "hi".toByteArray(), listOf(b.public), armor = false,
                recipientSubkeyChoices = mapOf(fp(b.public.publicKey) to other)
            )
        )
        assertEquals(listOf(other, adsk.keyID), chosen)

        // Choosing the ADSK itself is not honoured: it is not an encryption key,
        // so the automatic pick stands, and the ADSK is still there once.
        val adskChosen = recipientKeyIds(
            svc.encrypt(
                "hi".toByteArray(), listOf(b.public), armor = false,
                recipientSubkeyChoices = mapOf(fp(b.public.publicKey) to adsk.keyID)
            )
        )
        assertEquals(listOf(autoMain, adsk.keyID), adskChosen)
    }

    @Test
    fun `the newest encryption subkey is the main pick, wherever it sits in the ring`() {
        // 4.8.0 (#108): GnuPG encrypts to the newest valid encryption subkey. The
        // reporter's key lists its oldest one first, and taking the first one
        // sent the message to a subkey no card held.
        val encFlags = KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE
        val day = 24 * 3600 * 1000L
        val older = x25519Pair(Date(created.time + day / 2))
        val newer = x25519Pair(Date(created.time + day))
        val adsk = x25519Pair()

        val oldFirst = build(Sub(older, encFlags), Sub(newer, encFlags), Sub(adsk, authAdskFlags))
        assertEquals(
            listOf(newer.keyID, adsk.keyID),
            recipientKeyIds(svc.encrypt("hi".toByteArray(), listOf(oldFirst.public), armor = false))
        )

        val newFirst = build(Sub(newer, encFlags), Sub(older, encFlags))
        assertEquals(
            listOf(newer.keyID),
            recipientKeyIds(svc.encrypt("hi".toByteArray(), listOf(newFirst.public), armor = false))
        )
    }

    @Test
    fun `an ADSK alone does not make a key a recipient`() {
        val adsk = x25519Pair()
        val b = build(Sub(adsk, authAdskFlags))
        try {
            svc.encrypt("hi".toByteArray(), listOf(b.public), armor = false)
            fail("encrypting to a key with only an ADSK must fail")
        } catch (e: PGPCryptoError) {
            // expected: no encryption key
        }
    }

    // ── decrypt ──────────────────────────────────────────────────────

    @Test
    fun `a software key holding only the ADSK secret decrypts`() {
        val enc = x25519Pair()
        val adsk = x25519Pair()
        val b = build(Sub(enc, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE), Sub(adsk, authAdskFlags))
        val ct = svc.encrypt("only the ADSK".toByteArray(), listOf(b.public), armor = false)

        val adskOnly = PGPSecretKeyRing.removeSecretKey(b.secret, b.secret.getSecretKey(enc.keyID))
        assertTrue("the encryption subkey's secret is gone", adskOnly.getSecretKey(enc.keyID) == null)

        val result = svc.decrypt(ct, listOf(adskOnly), null)
        assertEquals("only the ADSK", String(result.data, Charsets.UTF_8))
        assertEquals("the ADSK opened it", adsk.keyID, result.decryptingKeyIdRaw)
    }

    @Test
    fun `the full key still opens the message with its encryption subkey`() {
        val enc = x25519Pair()
        val adsk = x25519Pair()
        val b = build(Sub(enc, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE), Sub(adsk, authAdskFlags))
        val ct = svc.encrypt("both".toByteArray(), listOf(b.public), armor = false)
        val result = svc.decrypt(ct, listOf(b.secret), null)
        assertEquals("both", String(result.data, Charsets.UTF_8))
        assertEquals("first PKESK held wins", enc.keyID, result.decryptingKeyIdRaw)
    }
}
