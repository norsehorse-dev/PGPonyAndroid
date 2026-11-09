// TrustFromCertificationTest.kt
// PGPony Android 4.8.0 RC8 (#115): a public key certified by one of your own
// Ultimate keys shows as Verified. Certified by your Ultimate key: Verified.
// Your key at any other level, a SHA-1 certification, a withdrawn or expired
// certification, a revoked or expired certifier, and a different key that
// carries the same User ID (or names your key as issuer) all leave it as
// stored. Only a stored Unknown is raised: Unverified, Don't use, a Verified
// or Ultimate set by hand, and your own keys are never changed. A
// certification covers one User ID: another User ID added to the key later is
// not verified by it, by name or by address. Each answer says when it stops
// holding.

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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class TrustFromCertificationTest {

    private val rule = TrustFromCertification
    private val now = System.currentTimeMillis()
    private val created = Date(now - 86_400_000L)
    private val mineUid = "Me <me@pgpony.app>"
    private val theirUid = "Old Key <old@pgpony.app>"

    private fun ed25519(): PGPKeyPair {
        val g = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
        g.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
        return BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, g.generateKeyPair(), created)
    }

    /** [pair]'s public key with a SHA-256 positive self-certification of [uid]. */
    private fun selfCertified(pair: PGPKeyPair, uid: String, hash: Int = HashAlgorithmTags.SHA256): PGPPublicKey {
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(pair.publicKey.algorithm, hash), pair.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, pair.privateKey)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date(now - 3_600_000L))
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
            setIssuerFingerprint(false, pair.publicKey)
        }.generate())
        return PGPPublicKey.addCertification(pair.publicKey, uid, g.generateCertification(uid, pair.publicKey))
    }

    /** A signature of [type] by [signer] over [target]'s [uid]; [issuer] is the key it names. */
    private fun thirdParty(
        signer: PGPKeyPair,
        target: PGPPublicKey,
        uid: String,
        type: Int = PGPSignature.DEFAULT_CERTIFICATION,
        hash: Int = HashAlgorithmTags.SHA512,
        at: Date = Date(now - 60_000L),
        expirySeconds: Long = 0,
        issuer: PGPPublicKey = signer.publicKey
    ): PGPSignature {
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(signer.publicKey.algorithm, hash), signer.publicKey)
        g.init(type, signer.privateKey)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, at)
            setIssuerFingerprint(false, issuer)
            if (expirySeconds > 0) setSignatureExpirationTime(true, expirySeconds)
        }.generate())
        return g.generateCertification(uid, target)
    }

    private fun ring(key: PGPPublicKey): PGPPublicKeyRing = PGPPublicKeyRing(listOf(key))

    private fun vouchers(vararg keys: PGPPublicKey) = keys.map { TrustFromCertification.Voucher(it, null) }

    /** The key that certifies [target]'s first certified User ID, or null. */
    private fun by(target: PGPPublicKeyRing, local: List<Pair<String, PGPSignature>>, certifiers: List<PGPPublicKey>, nowMs: Long): PGPPublicKey? =
        rule.findings(target, local, certifiers.map { TrustFromCertification.Voucher(it, null) }, nowMs).byUserId.values.firstOrNull()

    private fun withSigs(target: PGPPublicKey, uid: String, vararg sigs: PGPSignature): PGPPublicKeyRing {
        var k = target
        for (s in sigs) k = PGPPublicKey.addCertification(k, uid, s)
        return ring(k)
    }

    // Fixture: my key pair and someone's public key.
    private val me = ed25519()
    private val mePub = selfCertified(me, mineUid)
    private val them = ed25519()
    private val themPub = selfCertified(them, theirUid)

    @Test
    fun `certified by your Ultimate key shows Verified`() {
        val target = withSigs(themPub, theirUid, thirdParty(me, themPub, theirUid))
        assertTrue(rule.isUsableCertifier(ring(mePub), now))
        assertSame(mePub, by(target, emptyList(), listOf(mePub), now))
        assertEquals(TrustLevel.VERIFIED, rule.effective(TrustLevel.UNKNOWN, isOwnKey = false, shownUserIdCertified = true))
        val f = rule.findings(target, emptyList(), vouchers(mePub), now)
        assertEquals(setOf(theirUid), f.byUserId.keys)
        assertEquals(setOf(theirUid), f.boundUserIds)
        assertNull("no time limit", f.validUntilMs)
        assertTrue(rule.certifiesAddress(f.byUserId.keys, "OLD@pgpony.app"))
        // Every certification level counts.
        for (type in listOf(PGPSignature.NO_CERTIFICATION, PGPSignature.CASUAL_CERTIFICATION, PGPSignature.POSITIVE_CERTIFICATION)) {
            val t = withSigs(themPub, theirUid, thirdParty(me, themPub, theirUid, type = type))
            assertSame("type $type", mePub, by(t, emptyList(), listOf(mePub), now))
        }
    }

    @Test
    fun `a local-only certification counts too`() {
        val local = listOf(theirUid to thirdParty(me, themPub, theirUid))
        assertSame(mePub, by(ring(themPub), local, listOf(mePub), now))
    }

    @Test
    fun `only your own keys at Ultimate may vouch`() {
        assertTrue(rule.mayVouch(TrustLevel.ULTIMATE, isOwnKey = true, isRevoked = false, isExpired = false))
        for (level in listOf(TrustLevel.UNKNOWN, TrustLevel.UNVERIFIED, TrustLevel.VERIFIED, TrustLevel.DONT_USE)) {
            assertFalse(level.name, rule.mayVouch(level, isOwnKey = true, isRevoked = false, isExpired = false))
        }
        assertFalse("someone else's key", rule.mayVouch(TrustLevel.ULTIMATE, isOwnKey = false, isRevoked = false, isExpired = false))
        assertFalse("revoked", rule.mayVouch(TrustLevel.ULTIMATE, isOwnKey = true, isRevoked = true, isExpired = false))
        assertFalse("expired", rule.mayVouch(TrustLevel.ULTIMATE, isOwnKey = true, isRevoked = false, isExpired = true))
        // With no key allowed to vouch, the certification on the key changes nothing.
        val target = withSigs(themPub, theirUid, thirdParty(me, themPub, theirUid))
        assertNull(by(target, emptyList(), emptyList(), now))
    }

    @Test
    fun `a SHA-1 certification does not count, before or after the cutoff`() {
        for (at in listOf(Date(now - 60_000L), Date(1_420_070_400_000L))) {
            val target = withSigs(themPub, theirUid, thirdParty(me, themPub, theirUid, hash = HashAlgorithmTags.SHA1, at = at))
            assertNull("SHA-1 at $at", by(target, emptyList(), listOf(mePub), now))
        }
        val ripemd = withSigs(themPub, theirUid, thirdParty(me, themPub, theirUid, hash = HashAlgorithmTags.RIPEMD160))
        assertNull(by(ripemd, emptyList(), listOf(mePub), now))
        assertTrue(SignaturePolicy.isStrongDigest(HashAlgorithmTags.SHA256))
        assertFalse(SignaturePolicy.isStrongDigest(HashAlgorithmTags.SHA1))
    }

    @Test
    fun `a withdrawn certification does not count, and a newer one does again`() {
        val cert = thirdParty(me, themPub, theirUid, at = Date(now - 60_000L))
        val withdrawn = thirdParty(me, themPub, theirUid, type = PGPSignature.CERTIFICATION_REVOCATION, at = Date(now - 30_000L))
        assertNull(by(withSigs(themPub, theirUid, cert, withdrawn), emptyList(), listOf(mePub), now))
        val again = thirdParty(me, themPub, theirUid, at = Date(now - 10_000L))
        assertSame(mePub, by(withSigs(themPub, theirUid, cert, withdrawn, again), emptyList(), listOf(mePub), now))
    }

    @Test
    fun `an expired certification does not count`() {
        val cert = thirdParty(me, themPub, theirUid, at = Date(now - 7_200_000L), expirySeconds = 3_600L)
        assertNull(by(withSigs(themPub, theirUid, cert), emptyList(), listOf(mePub), now))
    }

    @Test
    fun `a revoked certifier does not count`() {
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(me.publicKey.algorithm, HashAlgorithmTags.SHA256), me.publicKey)
        g.init(PGPSignature.KEY_REVOCATION, me.privateKey)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date(now - 1_000L))
            setIssuerFingerprint(false, me.publicKey)
            setRevocationReason(false, org.bouncycastle.bcpg.sig.RevocationReasonTags.KEY_COMPROMISED, "")
        }.generate())
        val revokedMe = PGPPublicKey.addCertification(mePub, g.generateCertification(mePub))
        assertFalse(rule.isUsableCertifier(ring(revokedMe), now))
    }

    @Test
    fun `an expired certifier does not count`() {
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(me.publicKey.algorithm, HashAlgorithmTags.SHA256), me.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, me.privateKey)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date(now - 3_600_000L))
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
            setIssuerFingerprint(false, me.publicKey)
            setKeyExpirationTime(false, 60L) // a minute after creation, a day ago
        }.generate())
        val expiredMe = PGPPublicKey.addCertification(me.publicKey, mineUid, g.generateCertification(mineUid, me.publicKey))
        assertFalse(rule.isUsableCertifier(ring(expiredMe), now))
    }

    @Test
    fun `a different key with your User ID does not count`() {
        val impostor = ed25519()
        val impostorPub = selfCertified(impostor, mineUid)
        // Its own issuer: not one of your keys.
        val byImpostor = withSigs(themPub, theirUid, thirdParty(impostor, themPub, theirUid))
        assertNull(by(byImpostor, emptyList(), listOf(mePub), now))
        // Naming your key as issuer: the signature does not verify under it.
        val forged = withSigs(themPub, theirUid, thirdParty(impostor, themPub, theirUid, issuer = mePub))
        assertNull(by(forged, emptyList(), listOf(mePub), now))
        // The impostor itself would be accepted only if it were one of yours.
        assertSame(impostorPub, by(byImpostor, emptyList(), listOf(mePub, impostorPub), now))
    }

    @Test
    fun `a User ID bound only with SHA-1 does not count`() {
        val weak = selfCertified(them, theirUid, hash = HashAlgorithmTags.SHA1)
        val target = withSigs(weak, theirUid, thirdParty(me, weak, theirUid))
        assertNull(by(target, emptyList(), listOf(mePub), now))
    }

    @Test
    fun `only Unknown is raised, every level the user set stays`() {
        assertEquals(TrustLevel.UNVERIFIED, rule.effective(TrustLevel.UNVERIFIED, isOwnKey = false, shownUserIdCertified = true))
        assertEquals(TrustLevel.DONT_USE, rule.effective(TrustLevel.DONT_USE, isOwnKey = false, shownUserIdCertified = true))
        assertEquals(TrustLevel.VERIFIED, rule.effective(TrustLevel.VERIFIED, isOwnKey = false, shownUserIdCertified = true))
        assertEquals(TrustLevel.ULTIMATE, rule.effective(TrustLevel.ULTIMATE, isOwnKey = false, shownUserIdCertified = true))
        assertEquals(TrustLevel.UNKNOWN, rule.effective(TrustLevel.UNKNOWN, isOwnKey = true, shownUserIdCertified = true))
        assertEquals(TrustLevel.UNKNOWN, rule.effective(TrustLevel.UNKNOWN, isOwnKey = false, shownUserIdCertified = false))
        assertTrue(rule.canRaise(TrustLevel.UNKNOWN, isOwnKey = false))
        for (level in listOf(TrustLevel.UNVERIFIED, TrustLevel.VERIFIED, TrustLevel.ULTIMATE, TrustLevel.DONT_USE)) {
            assertFalse(level.name, rule.canRaise(level, isOwnKey = false))
        }
    }

    @Test
    fun `a User ID added after you certified another is not verified, by name or address`() {
        // You certified "Mallory <m@y>"; Mallory then adds a self-signed CEO User ID.
        val malloryUid = "Mallory <m@y.example>"
        val ceoUid = "CEO <ceo@corp.example>"
        val mallory = ed25519()
        var key = selfCertified(mallory, malloryUid)
        key = PGPPublicKey.addCertification(key, malloryUid, thirdParty(me, key, malloryUid))
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(mallory.publicKey.algorithm, HashAlgorithmTags.SHA256), mallory.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, mallory.privateKey)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date(now - 1_000L))
            setPrimaryUserID(false, true)
            setIssuerFingerprint(false, mallory.publicKey)
        }.generate())
        key = PGPPublicKey.addCertification(key, ceoUid, g.generateCertification(ceoUid, key))
        val f = rule.findings(ring(key), emptyList(), vouchers(mePub), now)
        assertEquals(setOf(malloryUid, ceoUid), f.boundUserIds)
        assertEquals("only the certified User ID", setOf(malloryUid), f.byUserId.keys)
        // Shown as the CEO: not raised.
        assertEquals(TrustLevel.UNKNOWN, rule.effective(TrustLevel.UNKNOWN, false, shownUserIdCertified = ceoUid in f.byUserId))
        // Shown as Mallory: raised.
        assertEquals(TrustLevel.VERIFIED, rule.effective(TrustLevel.UNKNOWN, false, shownUserIdCertified = malloryUid in f.byUserId))
        // The provider's address check.
        assertFalse(rule.certifiesAddress(f.byUserId.keys, "ceo@corp.example"))
        assertFalse(rule.certifiesAddress(f.byUserId.keys, "CEO <ceo@corp.example>"))
        assertTrue(rule.certifiesAddress(f.byUserId.keys, "m@y.example"))
        assertFalse(rule.certifiesAddress(f.byUserId.keys, ""))
    }

    @Test
    fun `an answer holds until the earliest expiry`() {
        val day = 86_400L
        val certAt = Date(now - 60_000L)
        val cert = thirdParty(me, themPub, theirUid, at = certAt, expirySeconds = 30 * day)
        val target = withSigs(themPub, theirUid, cert)
        val certEnds = certAt.time / 1000L * 1000L + 30 * day * 1000L
        assertEquals(certEnds, rule.findings(target, emptyList(), vouchers(mePub), now).validUntilMs)
        // Your key expires sooner than the certification.
        val sooner = now + day * 1000L
        assertEquals(sooner, rule.findings(target, emptyList(), listOf(TrustFromCertification.Voucher(mePub, sooner)), now).validUntilMs)
        // A second, unlimited certification by another of your keys keeps it holding.
        val other = ed25519()
        val otherPub = selfCertified(other, "Me too <me2@pgpony.app>")
        val both = withSigs(themPub, theirUid, cert, thirdParty(other, themPub, theirUid))
        assertNull(rule.findings(both, emptyList(), vouchers(mePub, otherPub), now).validUntilMs)
        // A negative answer has no time limit.
        assertNull(rule.findings(ring(themPub), emptyList(), vouchers(mePub), now).validUntilMs)
    }

    @Test
    fun `a revoked or expired key is not raised and needs no re-check`() {
        // Expired: a self-certification setting the key to expire an hour after creation (a day ago).
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(them.publicKey.algorithm, HashAlgorithmTags.SHA256), them.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, them.privateKey)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date(created.time + 1_000L))
            setIssuerFingerprint(false, them.publicKey)
            setKeyExpirationTime(false, 3_600L)
        }.generate())
        var expired = PGPPublicKey.addCertification(them.publicKey, theirUid, g.generateCertification(theirUid, them.publicKey))
        expired = PGPPublicKey.addCertification(expired, theirUid, thirdParty(me, expired, theirUid))
        val fe = rule.findings(ring(expired), emptyList(), vouchers(mePub), now)
        assertTrue(fe.byUserId.isEmpty())
        assertNull(fe.validUntilMs)

        // Revoked: a key revocation by its owner.
        val r = PGPSignatureGenerator(BcPGPContentSignerBuilder(them.publicKey.algorithm, HashAlgorithmTags.SHA256), them.publicKey)
        r.init(PGPSignature.KEY_REVOCATION, them.privateKey)
        r.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date(now - 1_000L))
            setIssuerFingerprint(false, them.publicKey)
            setRevocationReason(false, org.bouncycastle.bcpg.sig.RevocationReasonTags.KEY_RETIRED, "")
        }.generate())
        var revoked = PGPPublicKey.addCertification(themPub, theirUid, thirdParty(me, themPub, theirUid))
        revoked = PGPPublicKey.addCertification(revoked, r.generateCertification(revoked))
        val fr = rule.findings(ring(revoked), emptyList(), vouchers(mePub), now)
        assertTrue(fr.byUserId.isEmpty())
        assertNull(fr.validUntilMs)
    }

    @Test
    fun `a certification dated ahead of the clock does not count yet but sets a re-check`() {
        val ahead = Date(now + 3L * 86_400_000L)
        val target = withSigs(themPub, theirUid, thirdParty(me, themPub, theirUid, at = ahead))
        val f = rule.findings(target, emptyList(), vouchers(mePub), now)
        assertTrue(f.byUserId.isEmpty())
        assertEquals(SignaturePolicy.notFromTheFutureAtMs(Date(ahead.time / 1000L * 1000L)), f.validUntilMs)
        // Within the clock-skew allowance it already counts.
        val skew = withSigs(themPub, theirUid, thirdParty(me, themPub, theirUid, at = Date(now + 3_600_000L)))
        assertSame(mePub, by(skew, emptyList(), listOf(mePub), now))
    }
}
