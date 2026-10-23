// CardSigningFormatTest.kt
// PGPony Android — HW Phase 2b tests

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CardSigningFormatTest {

    private val digest = ByteArray(32) { it.toByte() }

    @Test
    fun rsaPrependsSha256DigestInfoPrefix() {
        val out = CardSigningFormat.prepareInput(1, digest)
        assertEquals(CardSigningFormat.SHA256_DIGESTINFO_PREFIX.size + 32, out.size)
        assertArrayEquals(
            CardSigningFormat.SHA256_DIGESTINFO_PREFIX,
            out.copyOfRange(0, CardSigningFormat.SHA256_DIGESTINFO_PREFIX.size)
        )
        assertArrayEquals(digest, out.copyOfRange(CardSigningFormat.SHA256_DIGESTINFO_PREFIX.size, out.size))
    }

    @Test
    fun rsaSignVariantAlsoPrepends() {
        // algo 3 = RSA_SIGN
        assertEquals(CardSigningFormat.SHA256_DIGESTINFO_PREFIX.size + 32, CardSigningFormat.prepareInput(3, digest).size)
    }

    @Test
    fun eddsaPassesDigestThrough() {
        // algo 22 = EdDSA-legacy
        assertArrayEquals(digest, CardSigningFormat.prepareInput(22, digest))
    }

    @Test
    fun prefixIsCanonicalSha256DigestInfo() {
        // 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        val expected = byteArrayOf(
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48,
            0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
        )
        assertArrayEquals(expected, CardSigningFormat.SHA256_DIGESTINFO_PREFIX)
    }

    @Test
    fun isRsaClassification() {
        assertTrue(CardSigningFormat.isRsa(1))
        assertTrue(CardSigningFormat.isRsa(2))
        assertTrue(CardSigningFormat.isRsa(3))
        assertFalse(CardSigningFormat.isRsa(22))
        assertFalse(CardSigningFormat.isRsa(19))
    }

    // 4.7.1 (#102): ECDSA card signatures, r and s back to back, become DER.

    private fun derParts(der: ByteArray): Pair<java.math.BigInteger, java.math.BigInteger> {
        val seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(der)
        val r = (seq.getObjectAt(0) as org.bouncycastle.asn1.ASN1Integer).positiveValue
        val s = (seq.getObjectAt(1) as org.bouncycastle.asn1.ASN1Integer).positiveValue
        return r to s
    }

    @Test
    fun ecdsaRawToDerKeepsRAndS() {
        val r = ByteArray(32) { (it + 1).toByte() }
        val s = ByteArray(32) { (0xF0 - it).toByte() }
        val (dr, ds) = derParts(CardSigningFormat.rawEcdsaToDer(r + s))
        assertEquals(java.math.BigInteger(1, r), dr)
        assertEquals(java.math.BigInteger(1, s), ds)
    }

    @Test
    fun ecdsaHighBitGetsALeadingZeroAndLeadingZerosAreDropped() {
        val r = ByteArray(32).also { it[0] = 0x80.toByte(); it[31] = 1 }
        val s = ByteArray(32).also { it[2] = 0x12; it[31] = 2 }
        val der = CardSigningFormat.rawEcdsaToDer(r + s)
        // SEQUENCE, length, INTEGER 33 bytes (0x00 then r), INTEGER 30 bytes.
        assertEquals(0x30, der[0].toInt() and 0xFF)
        assertEquals(0x02, der[2].toInt() and 0xFF)
        assertEquals(33, der[3].toInt())
        assertEquals(0, der[4].toInt())
        assertEquals(0x02, der[4 + 33].toInt() and 0xFF)
        assertEquals(30, der[5 + 33].toInt())
        val (dr, ds) = derParts(der)
        assertEquals(java.math.BigInteger(1, r), dr)
        assertEquals(java.math.BigInteger(1, s), ds)
    }

    @Test
    fun ecdsaP521UsesLongFormLength() {
        val r = ByteArray(66) { 0x7F }
        val s = ByteArray(66) { 0x55 }
        val der = CardSigningFormat.rawEcdsaToDer(r + s)
        assertEquals(0x81, der[1].toInt() and 0xFF)
        val (dr, ds) = derParts(der)
        assertEquals(java.math.BigInteger(1, r), dr)
        assertEquals(java.math.BigInteger(1, s), ds)
    }

    @Test
    fun ecdsaSignatureFromTheCardVerifies() {
        val params = org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256k1")
        val domain = org.bouncycastle.crypto.params.ECDomainParameters(params.curve, params.g, params.n, params.h)
        val gen = org.bouncycastle.crypto.generators.ECKeyPairGenerator()
        gen.init(org.bouncycastle.crypto.params.ECKeyGenerationParameters(domain, java.security.SecureRandom()))
        val kp = gen.generateKeyPair()
        val hash = java.security.MessageDigest.getInstance("SHA-256").digest("card".toByteArray())
        val signer = org.bouncycastle.crypto.signers.ECDSASigner()
        signer.init(true, kp.private)
        val (r, s) = signer.generateSignature(hash).let { it[0] to it[1] }
        fun fixed(v: java.math.BigInteger): ByteArray {
            val b = org.bouncycastle.util.BigIntegers.asUnsignedByteArray(32, v)
            return b
        }
        val (dr, ds) = derParts(CardSigningFormat.rawEcdsaToDer(fixed(r) + fixed(s)))
        signer.init(false, kp.public)
        assertTrue(signer.verifySignature(hash, dr, ds))
    }

    @Test
    fun ecdsaHashFollowsTheCurve() {
        assertEquals(CardSigningFormat.HASH_SHA256, CardSigningFormat.ecdsaHashFor("1.3.132.0.10"))
        assertEquals(CardSigningFormat.HASH_SHA256, CardSigningFormat.ecdsaHashFor("1.2.840.10045.3.1.7"))
        assertEquals(CardSigningFormat.HASH_SHA384, CardSigningFormat.ecdsaHashFor("1.3.132.0.34"))
        assertEquals(CardSigningFormat.HASH_SHA512, CardSigningFormat.ecdsaHashFor("1.3.132.0.35"))
        assertEquals(CardSigningFormat.HASH_SHA512, CardSigningFormat.ecdsaHashFor("1.3.36.3.3.2.8.1.1.13"))
        assertEquals(CardSigningFormat.HASH_SHA256, CardSigningFormat.ecdsaHashFor(null))
        assertEquals("SHA-384", CardSigningFormat.digestName(CardSigningFormat.HASH_SHA384))
    }

    @Test
    fun ecdsaInputIsTheRawDigest() {
        assertArrayEquals(digest, CardSigningFormat.prepareInput(CardSigningFormat.ECDSA, digest))
    }
}
