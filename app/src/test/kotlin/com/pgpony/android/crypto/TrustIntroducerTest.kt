// TrustIntroducerTest.kt
// PGPony Android 4.8.0 RC10 (#115): trusted introducers through trust
// signatures. A (your Ultimate key) trust-signs O at level 2, full amount; O
// certifies C, so C is valid, also when C is your own key pair left at
// Unknown. A plain certification A -> O does not let O vouch; a level 1 trust
// signature lets O vouch but not name further introducers; a partial amount or
// a Regular Expression makes no introducer; a cycle ends; withdrawing A's
// trust signature or O expiring drops C; and a key pair at Unverified keeps
// its level.

package com.pgpony.android.crypto

import com.pgpony.android.data.TrustLevel
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class TrustIntroducerTest {

    private val rule = TrustFromCertification
    private val now = System.currentTimeMillis()
    private val created = Date(now - 86_400_000L)

    /** One key of the fixture keyring: its pair, its User ID, and its public key as it grows. */
    private inner class K(val uid: String, keyExpirySeconds: Long = 0) {
        val pair: PGPKeyPair = run {
            val g = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
            g.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
            BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, g.generateKeyPair(), created)
        }
        var pub: PGPPublicKey = run {
            val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(pair.publicKey.algorithm, HashAlgorithmTags.SHA256), pair.publicKey)
            g.init(PGPSignature.POSITIVE_CERTIFICATION, pair.privateKey)
            g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
                setSignatureCreationTime(false, Date(created.time + 1_000L))
                setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
                setIssuerFingerprint(false, pair.publicKey)
                if (keyExpirySeconds > 0) setKeyExpirationTime(false, keyExpirySeconds)
            }.generate())
            PGPPublicKey.addCertification(pair.publicKey, uid, g.generateCertification(uid, pair.publicKey))
        }
        val fp: String get() = pub.fingerprint.joinToString("") { "%02X".format(it) }
        fun ring() = PGPPublicKeyRing(listOf(pub))
    }

    /** [by] certifies [target]'s User ID; with [level] it is a trust signature of that level and [amount]. */
    private fun certify(
        by: K,
        target: K,
        level: Int = 0,
        amount: Int = 120,
        regex: String? = null,
        type: Int = PGPSignature.DEFAULT_CERTIFICATION,
        at: Date = Date(now - 60_000L),
        expirySeconds: Long = 0
    ) {
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(by.pair.publicKey.algorithm, HashAlgorithmTags.SHA512), by.pair.publicKey)
        g.init(type, by.pair.privateKey)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, at)
            setIssuerFingerprint(false, by.pair.publicKey)
            if (level > 0) setTrust(false, level, amount)
            if (regex != null) addRegularExpression(true, regex)
            if (expirySeconds > 0) setSignatureExpirationTime(true, expirySeconds)
        }.generate())
        target.pub = PGPPublicKey.addCertification(target.pub, target.uid, g.generateCertification(target.uid, target.pub))
    }

    private fun input(k: K, root: Boolean = false, mayIntroduce: Boolean = true) =
        TrustFromCertification.KeyInput(k.fp, k.ring(), emptyList(), root, mayIntroduce)

    private fun valid(g: TrustFromCertification.Graph, k: K): TrustFromCertification.Path? = g.valid[k.fp]?.get(k.uid)

    @Test
    fun `A trust-signs O at level 2, O certifies C, so C is valid through O`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2)
        certify(o, c)
        val g = rule.graph(listOf(input(a, root = true), input(o), input(c)), now)
        assertEquals(a.fp, valid(g, o)?.certifierFingerprint)
        val p = valid(g, c)
        assertNotNull("C is valid", p)
        assertEquals(o.fp, p!!.certifierFingerprint)
        assertEquals(a.fp, p.rootFingerprint)
        // C is your own key pair left at Unknown: raised like a public key.
        assertEquals(TrustLevel.VERIFIED, rule.effective(TrustLevel.UNKNOWN, shownUserIdValid = true))
        // A key pair you set to Unverified keeps it.
        assertEquals(TrustLevel.UNVERIFIED, rule.effective(TrustLevel.UNVERIFIED, shownUserIdValid = true))
    }

    @Test
    fun `a plain certification by your key does not make an introducer`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o)
        certify(o, c)
        val g = rule.graph(listOf(input(a, root = true), input(o), input(c)), now)
        assertNotNull("O itself is valid", valid(g, o))
        assertNull("O does not vouch for C", valid(g, c))
    }

    @Test
    fun `level 1 lets O vouch but not name further introducers`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        val d = K("D <d@pgpony.app>")
        certify(a, o, level = 1)
        certify(o, c, level = 1)
        certify(c, d)
        val g = rule.graph(listOf(input(a, root = true), input(o), input(c), input(d)), now)
        assertNotNull("O vouches for C", valid(g, c))
        assertNull("C is not an introducer", valid(g, d))
        // At level 2 from A, O's level 1 signature makes C an introducer of depth 1.
        val a2 = K("A2 <a2@pgpony.app>")
        val o2 = K("O2 <o2@pgpony.app>")
        val c2 = K("C2 <c2@pgpony.app>")
        val d2 = K("D2 <d2@pgpony.app>")
        certify(a2, o2, level = 2)
        certify(o2, c2, level = 5)
        certify(c2, d2, level = 3)
        val e2 = K("E2 <e2@pgpony.app>")
        certify(d2, e2)
        val g2 = rule.graph(listOf(input(a2, root = true), input(o2), input(c2), input(d2), input(e2)), now)
        assertNotNull("C2 vouches for D2", valid(g2, d2))
        assertNull("D2 is depth 0: vouches for nothing", valid(g2, e2))
    }

    @Test
    fun `a partial amount does not count`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2, amount = 60)
        certify(o, c)
        val g = rule.graph(listOf(input(a, root = true), input(o), input(c)), now)
        assertNotNull(valid(g, o))
        assertNull(valid(g, c))
    }

    @Test
    fun `a Regular Expression makes no introducer`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2, regex = "<[^>]+[@.]pgpony\\.app>$")
        certify(o, c)
        val g = rule.graph(listOf(input(a, root = true), input(o), input(c)), now)
        assertNotNull("the certification itself still counts", valid(g, o))
        assertNull(valid(g, c))
    }

    @Test
    fun `a cycle ends`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 8)
        certify(o, c, level = 8)
        certify(c, o, level = 8)
        val g = rule.graph(listOf(input(a, root = true), input(o), input(c)), now)
        assertNotNull(valid(g, o))
        assertNotNull(valid(g, c))
        // A cycle with no root reaching it: nothing valid, and it still ends.
        val x = K("X <x@pgpony.app>")
        val y = K("Y <y@pgpony.app>")
        certify(x, y, level = 8)
        certify(y, x, level = 8)
        val g2 = rule.graph(listOf(input(x), input(y)), now)
        assertTrue(g2.valid.isEmpty())
    }

    @Test
    fun `withdrawing A's trust signature drops C`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2, at = Date(now - 60_000L))
        certify(o, c)
        certify(a, o, type = PGPSignature.CERTIFICATION_REVOCATION, at = Date(now - 30_000L))
        val g = rule.graph(listOf(input(a, root = true), input(o), input(c)), now)
        assertNull(valid(g, o))
        assertNull(valid(g, c))
        // A newer plain certification replaces the trust signature: O valid, C not.
        certify(a, o, at = Date(now - 10_000L))
        val g2 = rule.graph(listOf(input(a, root = true), input(o), input(c)), now)
        assertNotNull(valid(g2, o))
        assertNull(valid(g2, c))
    }

    @Test
    fun `O expiring drops C, and C's answer ends when O does`() {
        val a = K("A <a@pgpony.app>")
        // O expires 25 hours after it was made, an hour from now.
        val o = K("O <o@pgpony.app>", keyExpirySeconds = 25L * 3600L)
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2)
        certify(o, c)
        val g = rule.graph(listOf(input(a, root = true), input(o), input(c)), now)
        val p = valid(g, c)
        assertNotNull(p)
        val oExpires = created.time / 1000L * 1000L + 25L * 3600L * 1000L
        assertEquals(oExpires, p!!.untilMs)
        assertEquals(oExpires, g.checkAgainAtMs)
        // Two hours on, O has expired: C is no longer valid.
        val later = rule.graph(listOf(input(a, root = true), input(o), input(c)), now + 2L * 3_600_000L)
        assertNull(valid(later, c))
    }

    @Test
    fun `a key marked Don't use is never an introducer`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2)
        certify(o, c)
        val g = rule.graph(listOf(input(a, root = true), input(o, mayIntroduce = false), input(c)), now)
        assertNull(valid(g, c))
        assertEquals(false, rule.mayIntroduce(TrustLevel.DONT_USE, isRevoked = false, isExpired = false))
        assertEquals(true, rule.mayIntroduce(TrustLevel.UNKNOWN, isRevoked = false, isExpired = false))
    }

    @Test
    fun `a key set to Unverified is never an introducer, nor a root`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2)
        certify(o, c)
        val unverified = rule.mayIntroduce(TrustLevel.UNVERIFIED, isRevoked = false, isExpired = false)
        assertEquals(false, unverified)
        val g = rule.graph(listOf(input(a, root = true), input(o, mayIntroduce = unverified), input(c)), now)
        assertNotNull("O itself is still valid", valid(g, o))
        assertNull(valid(g, c))
        assertEquals(false, rule.mayVouch(TrustLevel.UNVERIFIED, isOwnKey = true, isRevoked = false, isExpired = false))
    }

    @Test
    fun `a newer plain certification stays in force, so its expiry never revives the older trust signature`() {
        val hour = 3_600_000L
        // E2: A trust-signs O, then later certifies O plainly for 30 days.
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2, at = Date(now - 20 * hour))
        certify(a, o, at = Date(now - 10 * hour), expirySeconds = 30L * 86_400L)
        certify(o, c)
        val inputs = listOf(input(a, root = true), input(o), input(c))
        val g = rule.graph(inputs, now)
        assertNotNull("O valid through the plain certification", valid(g, o))
        assertNull("O is no introducer", valid(g, c))
        val later = rule.graph(inputs, now + 31L * 86_400_000L)
        assertNull("the newer certification expired: nothing from A", valid(later, o))
        assertNull("and the older trust signature does not come back", valid(later, c))
        // E: the newer plain certification has already expired.
        val a2 = K("A2 <a2@pgpony.app>")
        val o2 = K("O2 <o2@pgpony.app>")
        val c2 = K("C2 <c2@pgpony.app>")
        certify(a2, o2, level = 2, at = Date(now - 20 * hour))
        certify(a2, o2, at = Date(now - 10 * hour), expirySeconds = 5L * 3_600L)
        certify(o2, c2)
        val g2 = rule.graph(listOf(input(a2, root = true), input(o2), input(c2)), now)
        assertNull(valid(g2, o2))
        assertNull(valid(g2, c2))
    }

    @Test
    fun `runs that share parsed signatures across threads agree`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val cs = (0 until 12).map { K("C$it <c$it@pgpony.app>") }
        certify(a, o, level = 2, at = Date(now - 60_000L))
        cs.forEach { certify(o, it) }
        // Withdrawn: nothing below A is valid, and no run may say otherwise.
        certify(a, o, type = PGPSignature.CERTIFICATION_REVOCATION, at = Date(now - 30_000L))
        val withdrawn = listOf(input(a, root = true), input(o)) + cs.map { input(it) }
        val b = K("B <b@pgpony.app>")
        val p = K("P <p@pgpony.app>")
        val ds = (0 until 12).map { K("D$it <d$it@pgpony.app>") }
        certify(b, p, level = 2)
        ds.forEach { certify(p, it) }
        val positive = listOf(input(b, root = true), input(p)) + ds.map { input(it) }
        val baseW = rule.graph(withdrawn, now).valid.size
        val baseP = rule.graph(positive, now).valid.size
        assertEquals(0, baseW)
        assertEquals(13, baseP)
        val bad = java.util.concurrent.atomic.AtomicInteger()
        val threads = (0 until 4).map {
            Thread {
                repeat(40) {
                    if (rule.graph(withdrawn, now).valid.size != baseW) bad.incrementAndGet()
                    if (rule.graph(positive, now).valid.size != baseP) bad.incrementAndGet()
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        assertEquals(0, bad.get())
    }

    @Test
    fun `cached edges give the same answer and change with a stamp`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2)
        certify(o, c)
        val cache = TrustFromCertification.EdgeCache()
        fun inputs(oStamp: String) = listOf(
            TrustFromCertification.KeyInput(a.fp, a.ring(), emptyList(), true, true, "a1"),
            TrustFromCertification.KeyInput(o.fp, o.ring(), emptyList(), false, true, oStamp),
            TrustFromCertification.KeyInput(c.fp, c.ring(), emptyList(), false, true, "c1")
        )
        assertNotNull(valid(rule.graph(inputs("o1"), now, cache), c))
        assertEquals(2, cache.size)
        assertNotNull(valid(rule.graph(inputs("o1"), now, cache), c))
        // A withdraws its trust signature; O's stamp changes with its certificate.
        certify(a, o, type = PGPSignature.CERTIFICATION_REVOCATION, at = Date(now - 30_000L))
        assertNull(valid(rule.graph(inputs("o2"), now, cache), c))
    }
}
