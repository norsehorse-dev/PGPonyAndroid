// X25519AgreementTest.kt
// PGPony Android 4.8.2 (item 1): raw X25519 key agreement for the provider's
// X25519_AGREE action (StegPony). The software agreement against the RFC 7748
// vectors, on a bare scalar, a v4 Curve25519Legacy key and a v6 X25519 key;
// a real protected key agreeing with a fresh ephemeral the way StegPony
// checks it; the refusals (length, batch size, low-order points, all-zero
// secrets); which subkeys qualify; the card's answer and Cipher DO; the op key.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.card.EcdhCipherData
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.SecureRandom
import java.util.Date

class X25519AgreementTest {

    private fun hex(s: String) = org.bouncycastle.util.encoders.Hex.decode(s)

    // RFC 7748 section 6.1.
    private val aliceSk = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    private val alicePk = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    private val bobSk = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    private val bobPk = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    private val shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    private fun refusal(block: () -> Unit): X25519Agreement.Refusal {
        try {
            block()
        } catch (e: X25519Agreement.RefusedException) {
            return e.refusal
        }
        fail("expected a refusal")
        throw AssertionError()
    }

    @Test
    fun `the RFC 7748 vectors`() {
        // Section 5.2.
        assertArrayEquals(
            hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
            X25519Agreement.agree(
                hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                listOf(hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
            )
        )
        assertArrayEquals(
            hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
            X25519Agreement.agree(
                hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                listOf(hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))
            )
        )
        // Section 6.1, both ways, and a batch keeps its order.
        assertArrayEquals(shared, X25519Agreement.agree(aliceSk, listOf(bobPk)))
        assertArrayEquals(shared, X25519Agreement.agree(bobSk, listOf(alicePk)))
        val two = X25519Agreement.agree(aliceSk, listOf(bobPk, alicePk))
        assertEquals(64, two.size)
        assertArrayEquals(shared, two.copyOfRange(0, 32))
        assertArrayEquals(X25519Agreement.agree(aliceSk, listOf(alicePk)), two.copyOfRange(32, 64))
    }

    private fun aliceKeyPair(version: Int, alg: Int): BcPGPKeyPair {
        val priv = X25519PrivateKeyParameters(aliceSk, 0)
        val kp = AsymmetricCipherKeyPair(priv.generatePublicKey(), priv)
        return BcPGPKeyPair(version, alg, kp, Date(1_700_000_000_000L))
    }

    private fun publicBody(kp: BcPGPKeyPair): ByteArray = kp.publicKey.publicKeyPacket.encodedContents

    @Test
    fun `a v4 Curve25519Legacy key and a v6 X25519 key agree as RFC 7748 says`() {
        val legacy = aliceKeyPair(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.ECDH)
        assertArrayEquals(alicePk, X25519Agreement.curve25519Point(publicBody(legacy)))
        assertArrayEquals(shared, X25519Agreement.agree(legacy.privateKey, listOf(bobPk)))

        val v6 = aliceKeyPair(PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.X25519)
        assertArrayEquals(alicePk, X25519Agreement.curve25519Point(publicBody(v6)))
        assertArrayEquals(shared, X25519Agreement.agree(v6.privateKey, listOf(bobPk)))
    }

    /** What StegPony does to check an answer: a fresh ephemeral, X25519 both ways. */
    private fun checkLikeStegPony(ring: PGPSecretKeyRing, pass: String) {
        val cert = certOf(ring)
        val subs = X25519Subkeys.usable(cert, System.currentTimeMillis())
        assertEquals(1, subs.size)
        val sub = subs[0]
        val secretKey = ring.secretKeys.asSequence().first {
            org.bouncycastle.util.encoders.Hex.toHexString(it.publicKey.fingerprint).equals(sub.fingerprintHex, ignoreCase = true)
        }
        val priv = SecretKeyUnlock.extract(secretKey, pass.toCharArray())!!
        val rnd = SecureRandom()
        val ephemerals = (0 until 3).map { ByteArray(32).also { rnd.nextBytes(it) } }
        val points = ephemerals.map { e -> ByteArray(32).also { X25519.scalarMultBase(e, 0, it, 0) } }
        val answer = X25519Agreement.agree(priv, points)
        for ((i, e) in ephemerals.withIndex()) {
            val expect = ByteArray(32)
            assertTrue(X25519.calculateAgreement(e, 0, sub.point, 0, expect, 0))
            assertArrayEquals("point $i", expect, answer.copyOfRange(i * 32, i * 32 + 32))
        }
    }

    private fun certOf(ring: PGPSecretKeyRing): ByteArray =
        org.bouncycastle.openpgp.PGPPublicKeyRing(ring.publicKeys.asSequence().toList()).encoded

    private fun gen(alg: KeyAlgorithm, pass: String?, expirationSeconds: Long? = null): PGPSecretKeyRing {
        val g = PGPCryptoService.shared.generateKeyPair("Rev", "rev@example.test", alg, pass, expirationSeconds)
        return PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator())
    }

    @Test
    fun `a protected v4 key and a protected v6 key answer a fresh ephemeral`() {
        checkLikeStegPony(gen(KeyAlgorithm.ED25519_CV25519, "pony pass"), "pony pass")
        checkLikeStegPony(gen(KeyAlgorithm.V6_ED25519, "pony pass"), "pony pass")
    }

    @Test
    fun `only usable Curve25519 encryption subkeys qualify`() {
        val now = System.currentTimeMillis()
        val ed = gen(KeyAlgorithm.ED25519_CV25519, null)
        val edCert = certOf(ed)
        val primaryFp = org.bouncycastle.util.encoders.Hex.toHexString(ed.publicKey.fingerprint)
        assertTrue(X25519Subkeys.classify(edCert, primaryFp, now) is X25519Subkeys.Lookup.NotCurve25519)
        assertTrue(X25519Subkeys.classify(edCert, "AB".repeat(20), now) is X25519Subkeys.Lookup.Absent)
        val subFp = X25519Subkeys.usable(edCert, now).single().fingerprintHex
        assertTrue(X25519Subkeys.classify(edCert, subFp.lowercase(), now) is X25519Subkeys.Lookup.Usable)

        val rsa = gen(KeyAlgorithm.RSA_2048, null)
        val rsaCert = certOf(rsa)
        assertTrue(X25519Subkeys.usable(rsaCert, now).isEmpty())
        val rsaSub = rsa.publicKeys.asSequence().first { !it.isMasterKey }
        assertTrue(
            X25519Subkeys.classify(rsaCert, org.bouncycastle.util.encoders.Hex.toHexString(rsaSub.fingerprint), now)
                is X25519Subkeys.Lookup.NotCurve25519
        )

        val p256 = gen(KeyAlgorithm.ECDSA_NIST_P256, null)
        assertTrue(X25519Subkeys.usable(certOf(p256), now).isEmpty())

        // Expired: a key made to expire in a day, asked about a year on.
        val short = gen(KeyAlgorithm.ED25519_CV25519, null, expirationSeconds = 86_400L)
        val shortCert = certOf(short)
        val later = now + 365L * 86_400_000L
        val shortSub = X25519Subkeys.usable(shortCert, now).single().fingerprintHex
        assertTrue(X25519Subkeys.usable(shortCert, later).isEmpty())
        assertTrue(X25519Subkeys.classify(shortCert, shortSub, later) is X25519Subkeys.Lookup.NotUsable)
    }

    @Test
    fun `malformed batches are refused`() {
        assertEquals(X25519Agreement.Refusal.INVALID_REQUEST, refusal { X25519Agreement.splitPoints(null) })
        assertEquals(X25519Agreement.Refusal.INVALID_REQUEST, refusal { X25519Agreement.splitPoints(ByteArray(0)) })
        assertEquals(X25519Agreement.Refusal.INVALID_REQUEST, refusal { X25519Agreement.splitPoints(ByteArray(31) { 9 }) })
        assertEquals(X25519Agreement.Refusal.INVALID_REQUEST, refusal { X25519Agreement.splitPoints(ByteArray(33) { 9 }) })
        val max = ByteArray(32 * X25519Agreement.MAX_POINTS).also { b -> for (i in b.indices step 32) bobPk.copyInto(b, i) }
        assertEquals(X25519Agreement.MAX_POINTS, X25519Agreement.splitPoints(max).size)
        assertEquals(X25519Agreement.Refusal.TOO_MANY_POINTS, refusal { X25519Agreement.splitPoints(max + bobPk) })
    }

    private val lowOrder = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    )

    @Test
    fun `low-order points are refused, with or without bit 255`() {
        for (h in lowOrder) {
            val u = hex(h)
            assertTrue(h, X25519Agreement.isLowOrder(u))
            val high = u.copyOf().also { it[31] = (it[31].toInt() or 0x80).toByte() }
            assertTrue("$h with bit 255", X25519Agreement.isLowOrder(high))
            assertEquals(h, X25519Agreement.Refusal.LOW_ORDER_POINT, refusal { X25519Agreement.splitPoints(bobPk + u) })
        }
        assertFalse(X25519Agreement.isLowOrder(bobPk))
        assertFalse(X25519Agreement.isLowOrder(alicePk))
    }

    @Test
    fun `an all-zero secret fails the whole call`() {
        // splitPoints keeps such a point out; agree refuses one on its own too.
        assertEquals(
            X25519Agreement.Refusal.AGREEMENT_FAILED,
            refusal { X25519Agreement.agree(aliceSk, listOf(bobPk, hex(lowOrder[3]))) }
        )
        assertTrue(X25519Agreement.isAllZero(ByteArray(32)))
        assertFalse(X25519Agreement.isAllZero(shared))
    }

    @Test
    fun `fingerprints are normalized or rejected`() {
        val v4 = "AB12".repeat(10)
        assertEquals(v4, X25519Agreement.normalizeFingerprint(v4.lowercase()))
        assertEquals(v4, X25519Agreement.normalizeFingerprint(v4.chunked(4).joinToString(" ")))
        assertEquals("CD".repeat(32), X25519Agreement.normalizeFingerprint("cd".repeat(32)))
        assertNull(X25519Agreement.normalizeFingerprint(null))
        assertNull(X25519Agreement.normalizeFingerprint("AB".repeat(8)))
        assertNull(X25519Agreement.normalizeFingerprint("ZZ".repeat(20)))
    }

    @Test
    fun `the card's answer and the Cipher DO`() {
        assertArrayEquals(shared, X25519Agreement.cardSecret(shared))
        assertArrayEquals(shared, X25519Agreement.cardSecret(byteArrayOf(0x40) + shared))
        assertNull(X25519Agreement.cardSecret(byteArrayOf(0x04) + shared))
        assertNull(X25519Agreement.cardSecret(shared + shared))
        // A6 25 { 7F49 22 { 86 20 <u> } }: the raw 32-byte point, no 0x40.
        val cipherDo = EcdhCipherData.cipherDoForPoint(bobPk)
        assertArrayEquals(hex("a6257f49228620") + bobPk, cipherDo)
    }

    @Test
    fun `the op key binds the app, the subkey and the points`() {
        val a = "com.pgpony.android.action.X25519_AGREE"
        val fp = "AB12".repeat(10)
        val base = X25519Agreement.opKey(a, "app.stegpony", fp, bobPk)
        assertEquals(base, X25519Agreement.opKey(a, "app.stegpony", fp.lowercase(), bobPk))
        assertNotEquals(base, X25519Agreement.opKey(a, "app.other", fp, bobPk))
        assertNotEquals(base, X25519Agreement.opKey(a, "app.stegpony", "CD34".repeat(10), bobPk))
        assertNotEquals(base, X25519Agreement.opKey(a, "app.stegpony", fp, alicePk))
        // The separator keeps "ab" + "c" apart from "a" + "bc".
        assertNotEquals(X25519Agreement.opKey(a, "ab", "c", bobPk), X25519Agreement.opKey(a, "a", "bc", bobPk))
    }
}
