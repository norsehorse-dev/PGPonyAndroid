// KeyToCardAttributePlanTest.kt
// PGPony Android, 4.8.0 RC5 (4p): Move to Security Key on a YubiKey NEO.
//
// A tester's NEO refused every move with 6A83 while gpg's keytocard put the
// same RSA 2048 key on it. The NEO is an OpenPGP card 2.0 with fixed RSA 2048
// attributes (01 0800 0011 03), a C0 whose first octet is F8 (attributes not
// changeable) and no PUT DATA for C1 to C3 at all. gpg leaves an RSA slot of
// the key's size alone; KeyToCard.attributePlan now decides the same way.
// Covered here: the plan, the C0 flag, the RSA import parts in format 03
// against Bouncy Castle's own CRT values, and a write against a fake NEO that
// answers PUT DATA C1 to C3 with 6A83 (none is sent when the slot is kept).

package com.pgpony.android.crypto.card

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

class KeyToCardAttributePlanTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }
    private val now = Date(System.currentTimeMillis() - 60_000)

    /** The NEO's attributes in every slot: RSA 2048, e 17 bits, CRT with modulus. */
    private val neo = bytes(0x01, 0x08, 0x00, 0x00, 0x11, 0x03)

    private fun rsa(bits: Int, current: ByteArray?, changeable: Boolean?, e: Int = 17) =
        KeyToCard.attributePlan(KeyToCard.Kind.RSA, bits, e, current, changeable)

    private fun keptAttributes(plan: KeyToCard.AttributePlan): String {
        if (plan !is KeyToCard.AttributePlan.Keep) fail("expected Keep, got ${plan::class.simpleName}")
        return hex((plan as KeyToCard.AttributePlan.Keep).attributes)
    }

    private fun writtenAttributes(plan: KeyToCard.AttributePlan): String {
        if (plan !is KeyToCard.AttributePlan.Write) fail("expected Write, got ${plan::class.simpleName}")
        return hex((plan as KeyToCard.AttributePlan.Write).attributes)
    }

    // ── The plan ─────────────────────────────────────────────────────

    @Test
    fun `an RSA 2048 key goes into the NEO as it is, with no attribute write`() {
        assertEquals("010800001103", keptAttributes(rsa(2048, neo, changeable = false)))
        assertEquals("010800001103", keptAttributes(rsa(2048, neo, changeable = null)))
        // A fitting slot is never rewritten, even on a card that could change it.
        assertEquals("010800001103", keptAttributes(rsa(2048, neo, changeable = true)))
    }

    @Test
    fun `a slot with no format octet is kept with the standard format`() {
        val fiveOctets = bytes(0x01, 0x08, 0x00, 0x00, 0x11)
        assertEquals("010800001100", keptAttributes(rsa(2048, fiveOctets, changeable = false)))
    }

    @Test
    fun `the slot's exponent length and format are kept`() {
        val wide = bytes(0x01, 0x08, 0x00, 0x00, 0x20, 0x00)
        assertEquals("010800002000", keptAttributes(rsa(2048, wide, changeable = true)))
    }

    @Test
    fun `an exponent wider than the slot's needs a write`() {
        assertEquals("010800002003", writtenAttributes(rsa(2048, neo, changeable = null, e = 32)))
        assertTrue(rsa(2048, neo, changeable = false, e = 32) is KeyToCard.AttributePlan.Refuse)
    }

    @Test
    fun `a 4096 key on the NEO is refused when the card cannot change, written otherwise`() {
        val refused = rsa(4096, neo, changeable = false)
        if (refused !is KeyToCard.AttributePlan.Refuse) fail("expected Refuse")
        assertTrue((refused as KeyToCard.AttributePlan.Refuse).detail.contains("010800001103"))
        assertEquals("011000001103", writtenAttributes(rsa(4096, neo, changeable = true)))
        assertEquals("011000001103", writtenAttributes(rsa(4096, neo, changeable = null)))
    }

    @Test
    fun `a slot that reports nothing gets a standard RSA write`() {
        assertEquals("010800001100", writtenAttributes(rsa(2048, null, changeable = null)))
        val refused = rsa(2048, null, changeable = false)
        if (refused !is KeyToCard.AttributePlan.Refuse) fail("expected Refuse")
        assertTrue((refused as KeyToCard.AttributePlan.Refuse).detail.contains("none"))
    }

    @Test
    fun `Ed25519 and Cv25519 keys into an RSA-only slot are refused, matching slots kept`() {
        val ed = KeyToCard.attributes(KeyToCard.Kind.ED25519, 0, 0, 0)
        val cv = KeyToCard.attributes(KeyToCard.Kind.CV25519, 0, 0, 0)
        fun plan(kind: KeyToCard.Kind, current: ByteArray?, changeable: Boolean?) =
            KeyToCard.attributePlan(kind, 0, 0, current, changeable)
        assertTrue(plan(KeyToCard.Kind.ED25519, neo, false) is KeyToCard.AttributePlan.Refuse)
        assertTrue(plan(KeyToCard.Kind.CV25519, neo, false) is KeyToCard.AttributePlan.Refuse)
        assertEquals(hex(ed), writtenAttributes(plan(KeyToCard.Kind.ED25519, neo, true)))
        assertEquals(hex(cv), writtenAttributes(plan(KeyToCard.Kind.CV25519, neo, null)))
        assertEquals(hex(ed), keptAttributes(plan(KeyToCard.Kind.ED25519, ed, false)))
        // A trailing import-format octet after the OID still counts as the same.
        assertEquals(hex(ed), keptAttributes(plan(KeyToCard.Kind.ED25519, ed + bytes(0xFF), false)))
        assertEquals(hex(cv), keptAttributes(plan(KeyToCard.Kind.CV25519, cv, null)))
    }

    @Test
    fun `ECDSA and ECDH keys follow the same rule as Ed25519`() {
        val p256 = "1.2.840.10045.3.1.7"
        val ecdsa = KeyToCard.attributes(KeyToCard.Kind.EC_SIGN, 0, 0, 0, p256)
        fun plan(kind: KeyToCard.Kind, current: ByteArray?, changeable: Boolean?) =
            KeyToCard.attributePlan(kind, 0, 0, current, changeable, curveOid = p256)
        assertEquals(hex(ecdsa), keptAttributes(plan(KeyToCard.Kind.EC_SIGN, ecdsa, false)))
        assertTrue(plan(KeyToCard.Kind.EC_SIGN, neo, false) is KeyToCard.AttributePlan.Refuse)
        assertTrue(plan(KeyToCard.Kind.EC_DECRYPT, neo, false) is KeyToCard.AttributePlan.Refuse)
        assertEquals(hex(ecdsa), writtenAttributes(plan(KeyToCard.Kind.EC_SIGN, neo, true)))
    }

    @Test
    fun `slots are named by their CRT tag`() {
        assertEquals("slot B6", KeyToCard.statusName(CardSlot.SIGNATURE))
        assertEquals("slot B8", KeyToCard.statusName(CardSlot.DECRYPTION))
        assertEquals("slot A4", KeyToCard.statusName(CardSlot.AUTHENTICATION))
    }

    @Test
    fun `the error keeps the usual message and adds the detail`() {
        val e = OpenPgpCardException.CardRefused("slot B6: key import, status 6A80")
        val message = e.message ?: ""
        assertTrue(message.startsWith(KeyToCardService.UNSUPPORTED_MESSAGE))
        assertTrue(message.endsWith(" (slot B6: key import, status 6A80)"))
    }

    // ── C0 ───────────────────────────────────────────────────────────

    @Test
    fun `C0 bit 04 of the first octet says whether the attributes may change`() {
        // The NEO: F8, bit clear.
        assertEquals(false, ApplicationRelatedData.attributesChangeableBy(bytes(0xF8, 0x00, 0x00, 0xFF, 0x04, 0xC0, 0x00, 0xFF, 0x00, 0xFF)))
        // A YubiKey 5: 7D, bit set.
        assertEquals(true, ApplicationRelatedData.attributesChangeableBy(bytes(0x7D, 0x00, 0x0B, 0xFE, 0x08, 0x00, 0x00, 0xFF, 0x00, 0x00)))
        assertNull(ApplicationRelatedData.attributesChangeableBy(null))
        assertNull(ApplicationRelatedData.attributesChangeableBy(ByteArray(0)))
    }

    @Test
    fun `the Application Related Data parse reads the C0 flag`() {
        assertEquals(false, ApplicationRelatedData.parse(neoArd(neoC0)).attributesChangeable)
        assertEquals(true, ApplicationRelatedData.parse(neoArd(bytes(0x7C) + neoC0.copyOfRange(1, neoC0.size))).attributesChangeable)
        assertNull(ApplicationRelatedData.parse(neoArd(null)).attributesChangeable)
    }

    // ── The RSA import parts against Bouncy Castle ───────────────────

    private fun rsaKeyPair(bits: Int): AsymmetricCipherKeyPair =
        RSAKeyPairGenerator().apply {
            init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), SecureRandom(), bits, 80))
        }.generateKeyPair()

    /**
     * Format 03 parts of a [bits] key, in the NEO's order 91 to 97, checked
     * value by value against Bouncy Castle's own CRT key, and used once: a
     * block encrypted under the public key must decrypt with a CRT key built
     * only from the parts.
     */
    private fun checkCrtWithModulus(bits: Int) {
        val kp = rsaKeyPair(bits)
        val bc = kp.private as RSAPrivateCrtKeyParameters
        val pgp = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kp, now)
        val (e, p, q, d) = KeyToCard.rsaSecret(pgp.publicKey, pgp.privateKey)
        val plan = KeyToCard.attributePlan(
            KeyToCard.Kind.RSA, bits, KeyToCard.rsaExponentBits(pgp.publicKey),
            KeyToCard.attributes(KeyToCard.Kind.RSA, bits, 17, 0x03), changeable = false
        )
        val kept = (plan as? KeyToCard.AttributePlan.Keep)?.attributes ?: return fail("expected Keep")
        val eBits = KeyToCard.rsaExponentBitsOf(kept)!!
        val format = KeyToCard.rsaFormatOf(kept)!!
        assertEquals(17, eBits)
        assertEquals(0x03, format)
        val parts = KeyToCard.rsaParts(e, p, q, d, bits, eBits, format)
        assertEquals(listOf(0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97), parts.map { it.tag })
        val half = bits / 16
        assertEquals(listOf(3, half, half, half, half, half, bits / 8), parts.map { it.value.size })
        fun v(i: Int) = BigInteger(1, parts[i].value)

        assertEquals(bc.getPublicExponent(), v(0))
        assertEquals(bc.getModulus(), v(6))
        // OpenPGP keeps p < q, so the packet may hold Bouncy Castle's primes
        // the other way round; the CRT values follow the primes.
        if (v(1) == bc.getP()) {
            assertEquals(bc.getQ(), v(2))
            assertEquals(bc.getQInv(), v(3))
            assertEquals(bc.getDP(), v(4))
            assertEquals(bc.getDQ(), v(5))
        } else {
            assertEquals(bc.getQ(), v(1))
            assertEquals(bc.getP(), v(2))
            assertEquals(bc.getP().modInverse(bc.getQ()), v(3))
            assertEquals(bc.getDQ(), v(4))
            assertEquals(bc.getDP(), v(5))
        }

        val fromParts = RSAPrivateCrtKeyParameters(v(6), v(0), d, v(1), v(2), v(4), v(5), v(3))
        val block = BigInteger(1, ByteArray(bits / 8 - 1).also { SecureRandom().nextBytes(it) })
        val pub = kp.public as RSAKeyParameters
        val enc = RSAEngine().apply { init(true, pub) }
        val dec = RSAEngine().apply { init(false, fromParts) }
        val input = org.bouncycastle.util.BigIntegers.asUnsignedByteArray(bits / 8 - 1, block)
        val c = enc.processBlock(input, 0, input.size)
        assertEquals(block, BigInteger(1, dec.processBlock(c, 0, c.size)))

        val ehl = KeyToCard.extendedHeaderList(CardSlot.SIGNATURE, parts)
        // The NEO takes import data under 1221 octets; 2048 bits in format 03 fits.
        if (bits == 2048) assertTrue("EHL is ${ehl.size} octets", ehl.size < 1221)
        KeyToCard.wipe(ehl)
        KeyToCard.wipe(parts)
    }

    @Test
    fun `RSA 2048 import parts in format 03 match Bouncy Castle's CRT values`() = checkCrtWithModulus(2048)

    @Test
    fun `RSA 4096 import parts in format 03 match Bouncy Castle's CRT values`() = checkCrtWithModulus(4096)

    // ── A write against a fake NEO ───────────────────────────────────

    private val neoC0 = bytes(0xF8, 0x00, 0x00, 0xFF, 0x04, 0xC0, 0x00, 0xFF, 0x00, 0xFF)

    private fun tlv(tag: Int, value: ByteArray): ByteArray {
        val tagBytes = if (tag <= 0xFF) byteArrayOf(tag.toByte()) else byteArrayOf((tag shr 8).toByte(), tag.toByte())
        val lenBytes = when {
            value.size < 0x80 -> byteArrayOf(value.size.toByte())
            value.size < 0x100 -> byteArrayOf(0x81.toByte(), value.size.toByte())
            else -> byteArrayOf(0x82.toByte(), (value.size shr 8).toByte(), value.size.toByte())
        }
        return tagBytes + lenBytes + value
    }

    /** A NEO's Application Related Data: a 2.0 AID, [c0] and RSA 2048 in every slot. */
    private fun neoArd(c0: ByteArray?, attrs: ByteArray = neo): ByteArray {
        val aid = bytes(0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x02, 0x00, 0x00, 0x06, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00)
        val disc = (c0?.let { tlv(OpenPgpCard.DO_EXTENDED_CAPABILITIES, it) } ?: ByteArray(0)) +
            tlv(OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_SIG, attrs) +
            tlv(OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_DEC, attrs) +
            tlv(OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_AUTH, attrs) +
            tlv(OpenPgpCard.DO_FINGERPRINTS, ByteArray(60))
        return tlv(OpenPgpCard.DO_AID, aid) + tlv(OpenPgpCard.DO_DISCRETIONARY, disc)
    }

    /**
     * Answers like a NEO: the ARD for GET DATA 6E, 6A83 for any PUT DATA C1
     * to C3, [importStatus] for the last import command, 9000 otherwise.
     */
    private class FakeNeo(private val ard: ByteArray, private val importStatus: Int = 0x9000) : CardTransport {
        val sent = mutableListOf<ByteArray>()
        override fun transceive(commandApdu: ByteArray): ByteArray {
            val c = commandApdu.copyOf() // the session wipes the array once sent
            sent.add(c)
            val ins = c[1].toInt() and 0xFF
            val p1p2 = ((c[2].toInt() and 0xFF) shl 8) or (c[3].toInt() and 0xFF)
            val ok = byteArrayOf(0x90.toByte(), 0x00)
            return when {
                ins == 0xCA && p1p2 == 0x006E -> ard + ok
                ins == 0xDA && p1p2 in 0x00C1..0x00C3 -> byteArrayOf(0x6A, 0x83.toByte())
                ins == 0xDB && (c[0].toInt() and 0x10) == 0 ->
                    byteArrayOf((importStatus shr 8).toByte(), importStatus.toByte())
                else -> ok
            }
        }

        fun putData(): List<Int> = sent
            .filter { (it[1].toInt() and 0xFF) == 0xDA }
            .map { ((it[2].toInt() and 0xFF) shl 8) or (it[3].toInt() and 0xFF) }
        fun imports(): Int = sent.count { (it[1].toInt() and 0xFF) == 0xDB }
    }

    /** One RSA 2048 key for the fake-card tests, made once. */
    private val key2048: BcPGPKeyPair
        get() = shared ?: BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsaKeyPair(2048), now).also { shared = it }

    private fun move(slot: CardSlot): Pair<KeyToCardService.Move, KeyToCard.Eligibility.Movable> {
        val m = KeyToCardService.Move(slot, key2048.publicKey, key2048.privateKey)
        val k = KeyToCard.eligibility(key2048.publicKey) as KeyToCard.Eligibility.Movable
        return m to k
    }

    @Test
    fun `a kept NEO slot gets the import and no PUT DATA C1 to C3`() {
        val card = FakeNeo(neoArd(neoC0))
        val (m, k) = move(CardSlot.SIGNATURE)
        KeyToCardService.write(OpenPgpCardSession(card), m, k, cv25519Native = false, changeable = false)
        // Only the fingerprint (C7) and the creation time (CE) are written.
        assertEquals(listOf(0x00C7, 0x00CE), card.putData())
        assertTrue(card.imports() > 1) // chained: the import is longer than 255 octets
        // The import data carries e in three octets (the slot's 17 bits) and
        // the modulus (format 03): 91 03 92 81 80 93 81 80 ... 97 82 01 00.
        val chained = card.sent.filter { (it[1].toInt() and 0xFF) == 0xDB }
            .fold(ByteArray(0)) { acc, c -> acc + c.copyOfRange(5, 5 + (c[4].toInt() and 0xFF)) }
        assertTrue(hex(chained).contains("7F48" + "15" + "9103" + "928180" + "938180" + "948180" + "958180" + "968180" + "97820100"))
    }

    @Test
    fun `an attribute write the card refuses names the slot, the command and the status`() {
        // A slot that reports RSA 4096: a 2048 key needs a write, which the NEO answers 6A83.
        val card = FakeNeo(neoArd(null, attrs = bytes(0x01, 0x10, 0x00, 0x00, 0x11, 0x03)))
        val (m, k) = move(CardSlot.DECRYPTION)
        try {
            KeyToCardService.write(OpenPgpCardSession(card), m, k, cv25519Native = false, changeable = null)
            fail("expected CardRefused")
        } catch (e: OpenPgpCardException.CardRefused) {
            assertEquals("slot B8: PUT DATA 00C2, status 6A83", e.detail)
            assertTrue(e.message!!.startsWith(KeyToCardService.UNSUPPORTED_MESSAGE))
        }
        assertEquals(0, card.imports())
    }

    @Test
    fun `an import the card refuses names the slot and the status`() {
        val card = FakeNeo(neoArd(neoC0), importStatus = 0x6A80)
        val (m, k) = move(CardSlot.AUTHENTICATION)
        try {
            KeyToCardService.write(OpenPgpCardSession(card), m, k, cv25519Native = false, changeable = false)
            fail("expected CardRefused")
        } catch (e: OpenPgpCardException.CardRefused) {
            assertEquals("slot A4: key import, status 6A80", e.detail)
            assertTrue(e.message!!.endsWith(" (slot A4: key import, status 6A80)"))
        }
        assertFalse(card.putData().any { it in 0x00C1..0x00C3 })
    }

    @Test
    fun `a slot the plan refuses sends nothing to the card`() {
        val card = FakeNeo(neoArd(neoC0, attrs = bytes(0x01, 0x10, 0x00, 0x00, 0x11, 0x03)))
        val (m, k) = move(CardSlot.SIGNATURE)
        try {
            KeyToCardService.write(OpenPgpCardSession(card), m, k, cv25519Native = false, changeable = false)
            fail("expected CardRefused")
        } catch (e: OpenPgpCardException.CardRefused) {
            assertTrue(e.detail.startsWith("slot B6: attributes 011000001103"))
        }
        assertEquals(emptyList<Int>(), card.putData())
        assertEquals(0, card.imports())
    }

    /** Cv25519 attributes, what a slot reports after an Ed25519 key pair was moved in. */
    private val cv25519Attrs = bytes(0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01)

    /**
     * Answers like a Token2 (a JavaCard applet that cannot compute n): PUT
     * DATA C2 is taken, and the import is refused with 6984 unless the last
     * C2 written asks for format 03 (the CRT values and the modulus), or
     * always when [refuseAll].
     */
    private class FakeToken2(private val ard: ByteArray, private val refuseAll: Boolean = false) : CardTransport {
        val sent = mutableListOf<ByteArray>()
        var decAttrs: ByteArray? = null
        override fun transceive(commandApdu: ByteArray): ByteArray {
            val c = commandApdu.copyOf()
            sent.add(c)
            val ins = c[1].toInt() and 0xFF
            val p1p2 = ((c[2].toInt() and 0xFF) shl 8) or (c[3].toInt() and 0xFF)
            val ok = byteArrayOf(0x90.toByte(), 0x00)
            return when {
                ins == 0xCA && p1p2 == 0x006E -> ard + ok
                ins == 0xDA && p1p2 == 0x00C2 -> {
                    decAttrs = c.copyOfRange(5, 5 + (c[4].toInt() and 0xFF))
                    ok
                }
                ins == 0xDB && (c[0].toInt() and 0x10) == 0 ->
                    if (!refuseAll && (decAttrs?.getOrNull(5)?.toInt() ?: -1) == 0x03) ok
                    else byteArrayOf(0x69, 0x84.toByte())
                else -> ok
            }
        }

        fun putData(): List<Int> = sent
            .filter { (it[1].toInt() and 0xFF) == 0xDA }
            .map { ((it[2].toInt() and 0xFF) shl 8) or (it[3].toInt() and 0xFF) }
    }

    @Test
    fun `an RSA key into a slot that held Cv25519 retries as format 03 when the card refuses format 00`() {
        val card = FakeToken2(neoArd(null, attrs = cv25519Attrs))
        val (m, k) = move(CardSlot.DECRYPTION)
        KeyToCardService.write(OpenPgpCardSession(card), m, k, cv25519Native = false, changeable = true)
        assertEquals("C2 written as format 00, then as 03", 2, card.putData().count { it == 0x00C2 })
        assertEquals("010800001103", hex(card.decAttrs!!))
    }

    @Test
    fun `a card that refuses format 03 too names both answers`() {
        val card = FakeToken2(neoArd(null, attrs = cv25519Attrs), refuseAll = true)
        val (m, k) = move(CardSlot.DECRYPTION)
        try {
            KeyToCardService.write(OpenPgpCardSession(card), m, k, cv25519Native = false, changeable = true)
            fail("expected CardRefused")
        } catch (e: OpenPgpCardException.CardRefused) {
            assertEquals("slot B8: key import, status 6984, then format 03 import, status 6984", e.detail)
        }
    }

    @Test
    fun `only a written RSA slot without the modulus is retried`() {
        val write00 = KeyToCard.AttributePlan.Write(bytes(0x01, 0x08, 0x00, 0x00, 0x11, 0x00))
        val write03 = KeyToCard.AttributePlan.Write(bytes(0x01, 0x08, 0x00, 0x00, 0x11, 0x03))
        val keep00 = KeyToCard.AttributePlan.Keep(write00.attributes)
        assertEquals(0x03, KeyToCard.rsaModulusRetryFormat(KeyToCard.Kind.RSA, write00, write00.attributes, 0x6984))
        assertEquals(0x03, KeyToCard.rsaModulusRetryFormat(KeyToCard.Kind.RSA, write00, write00.attributes, 0x6A80))
        assertEquals(null, KeyToCard.rsaModulusRetryFormat(KeyToCard.Kind.RSA, write00, write00.attributes, 0x6982))
        assertEquals(null, KeyToCard.rsaModulusRetryFormat(KeyToCard.Kind.RSA, write03, write03.attributes, 0x6984))
        assertEquals(null, KeyToCard.rsaModulusRetryFormat(KeyToCard.Kind.RSA, keep00, keep00.attributes, 0x6984))
        assertEquals(null, KeyToCard.rsaModulusRetryFormat(KeyToCard.Kind.ED25519, write00, write00.attributes, 0x6984))
    }

    companion object {
        private var shared: BcPGPKeyPair? = null
    }
}
