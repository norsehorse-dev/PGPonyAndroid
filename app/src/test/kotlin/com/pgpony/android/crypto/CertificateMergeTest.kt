// CertificateMergeTest.kt
// PGPony Android, 4.6.0 (items 17.1 and 12)
//
// The refresh / re-import merge is a verified union, not a replacement.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SecretKeyPacket
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

class CertificateMergeTest {

    private val svc = PGPCryptoService.shared

    private fun gen(uid: String) = svc.generateKeyPair(uid.substringBefore(" <"), uid.substringAfter("<").trimEnd('>'),
        KeyAlgorithm.ED25519_CV25519, null, null)

    private fun secret(k: GeneratedKeyResult) = PGPSecretKeyRing(k.privateKeyData, BcKeyFingerprintCalculator())
    private fun pub(raw: ByteArray) = PGPPublicKeyRing(raw, BcKeyFingerprintCalculator())

    private fun uids(raw: ByteArray) = pub(raw).publicKey.userIDs.asSequence().toSet()

    /** [ring] with an extra User ID self-certified by its own primary. */
    private fun withUid(sec: PGPSecretKeyRing, uid: String): ByteArray {
        val sk = sec.secretKey
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, sk.extractPrivateKey(null))
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply { setSignatureCreationTime(false, Date()) }.generate())
        val cert = g.generateCertification(uid, sk.publicKey)
        val pubRing = PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
        val withCert = PGPPublicKey.addCertification(pubRing.publicKey, uid, cert)
        return PGPPublicKeyRing.insertPublicKey(pubRing, withCert).encoded
    }

    private fun revoked(sec: PGPSecretKeyRing): ByteArray {
        val sk = sec.secretKey
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey)
        g.init(PGPSignature.KEY_REVOCATION, sk.extractPrivateKey(null))
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply { setSignatureCreationTime(false, Date()) }.generate())
        val rev = g.generateCertification(sk.publicKey)
        val pubRing = PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
        return PGPPublicKeyRing.insertPublicKey(pubRing, PGPPublicKey.addCertification(pubRing.publicKey, rev)).encoded
    }

    @Test
    fun `a server copy missing a User ID does not remove it`() {
        val k = gen("Alice <alice@pgpony.app>")
        val local = withUid(secret(k), "Alice Work <alice@work.example>")
        val server = k.publicKeyData // only the first User ID
        val merged = CertificateMerge.merge(local, server, isKeyPair = false)
        assertEquals(uids(local), uids(merged))
    }

    @Test
    fun `a public-only key gains a new self-certified User ID but not a removed one`() {
        val k = gen("Bob <bob@pgpony.app>")
        val server = withUid(secret(k), "Bob New <bob@new.example>")
        val merged = CertificateMerge.merge(k.publicKeyData, server, isKeyPair = false)
        assertTrue("Bob New <bob@new.example>" in uids(merged))
        val tomb = CertificateMerge.merge(k.publicKeyData, server, isKeyPair = false,
            removedUserIds = setOf("Bob New <bob@new.example>"))
        assertFalse("Bob New <bob@new.example>" in uids(tomb))
    }

    @Test
    fun `a key pair takes only revocations from a fetched copy`() {
        val k = gen("Carol <carol@pgpony.app>")
        val sec = secret(k)
        val serverWithUid = withUid(sec, "Carol Extra <carol@extra.example>")
        val m1 = CertificateMerge.merge(k.publicKeyData, serverWithUid, isKeyPair = true)
        assertFalse("no new User ID on a key pair", "Carol Extra <carol@extra.example>" in uids(m1))
        val m2 = CertificateMerge.merge(k.publicKeyData, revoked(sec), isKeyPair = true)
        assertTrue("revocation arrives", CertificateBindings.analyze(m2)!!.primaryRevoked)
    }

    /** The public ring of [sec] with its first User ID re-certified at [at], preferring [hashes]. */
    private fun recertified(sec: PGPSecretKeyRing, at: Date, hashes: IntArray, base: ByteArray? = null): ByteArray {
        val sk = sec.secretKey
        val uid = sk.publicKey.userIDs.next()
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA512), sk.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, sk.extractPrivateKey(null))
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, at)
            setIssuerFingerprint(false, sk.publicKey)
            setPreferredHashAlgorithms(false, hashes)
        }.generate())
        val cert = g.generateCertification(uid, sk.publicKey)
        val pubRing = base?.let { pub(it) } ?: PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
        return PGPPublicKeyRing.insertPublicKey(pubRing, PGPPublicKey.addCertification(pubRing.publicKey, uid, cert)).encoded
    }

    private fun newestCertPrefs(raw: ByteArray): List<Int> {
        val key = pub(raw).publicKey
        val uid = key.userIDs.next()
        val newest = key.getSignaturesForID(uid).asSequence().maxBy { it.creationTime.time }
        return newest.hashedSubPackets.preferredHashAlgorithms?.toList().orEmpty()
    }

    @Test
    fun `a key pair takes its owner's newer self-certification (#78)`() {
        val k = gen("Erin <erin@pgpony.app>")
        val sec = secret(k)
        val edited = recertified(sec, Date(System.currentTimeMillis() + 5_000L), intArrayOf(HashAlgorithmTags.SHA512))
        val result = CertificateMerge.mergeDetailed(k.publicKeyData, edited, isKeyPair = true)
        assertEquals(1, result.selfSignaturesApplied)
        assertEquals(listOf(HashAlgorithmTags.SHA512), newestCertPrefs(result.bytes))
        assertEquals(uids(k.publicKeyData), uids(result.bytes))
    }

    @Test
    fun `a replayed older self-certification is ignored`() {
        val k = gen("Finn <finn@pgpony.app>")
        val sec = secret(k)
        val now = System.currentTimeMillis()
        val older = recertified(sec, Date(now + 5_000L), intArrayOf(HashAlgorithmTags.SHA256))
        val local = recertified(sec, Date(now + 10_000L), intArrayOf(HashAlgorithmTags.SHA512))
        val result = CertificateMerge.mergeDetailed(local, older, isKeyPair = true)
        assertEquals(0, result.selfSignaturesApplied)
        assertEquals(listOf(HashAlgorithmTags.SHA512), newestCertPrefs(result.bytes))
    }

    @Test
    fun `a key pair keeps a User ID a server copy stripped`() {
        val k = gen("Gale <gale@pgpony.app>")
        val local = withUid(secret(k), "Gale Work <gale@work.example>")
        val result = CertificateMerge.mergeDetailed(local, k.publicKeyData, isKeyPair = true)
        assertEquals(0, result.selfSignaturesApplied)
        assertEquals(uids(local), uids(result.bytes))
    }

    @Test
    fun `a User ID the primary never certified does not arrive`() {
        val k = gen("Dan <dan@pgpony.app>")
        val other = gen("Mallory <m@evil.example>")
        // Mallory certifies a "Dan" User ID with Mallory's key and appends it.
        val msk = secret(other).secretKey
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(msk.publicKey.algorithm, HashAlgorithmTags.SHA256), msk.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, msk.extractPrivateKey(null))
        val danPub = pub(k.publicKeyData)
        val fake = g.generateCertification("Dan <dan@bank.example>", danPub.publicKey)
        val server = PGPPublicKeyRing.insertPublicKey(
            danPub, PGPPublicKey.addCertification(danPub.publicKey, "Dan <dan@bank.example>", fake)
        ).encoded
        val merged = CertificateMerge.merge(k.publicKeyData, server, isKeyPair = false)
        assertFalse("Dan <dan@bank.example>" in uids(merged))
    }

    // ── 4.8.0 (#78): a usage change made in gpg, re-imported ─────────────

    private val certifySign = KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA

    /** The public ring of [sec] (or [base]) with its first User ID re-certified
     *  at [at], the primary's key flags set to [flags]. */
    private fun flaggedUidCert(sec: PGPSecretKeyRing, at: Date, flags: Int, base: ByteArray? = null): ByteArray {
        val sk = sec.secretKey
        val uid = sk.publicKey.userIDs.next()
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA512), sk.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, sk.extractPrivateKey(null))
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, at)
            setIssuerFingerprint(false, sk.publicKey)
            setKeyFlags(false, flags)
        }.generate())
        val cert = g.generateCertification(uid, sk.publicKey)
        val pubRing = base?.let { pub(it) } ?: PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
        return PGPPublicKeyRing.insertPublicKey(pubRing, PGPPublicKey.addCertification(pubRing.publicKey, uid, cert)).encoded
    }

    /** [base] with a direct-key signature (0x1F) at [at] setting the primary's key flags to [flags]. */
    private fun flaggedDirectKey(sec: PGPSecretKeyRing, at: Date, flags: Int, base: ByteArray): ByteArray {
        val sk = sec.secretKey
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA512), sk.publicKey)
        g.init(PGPSignature.DIRECT_KEY, sk.extractPrivateKey(null))
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, at)
            setIssuerFingerprint(false, sk.publicKey)
            setKeyFlags(false, flags)
        }.generate())
        val sig = g.generateCertification(sk.publicKey)
        val pubRing = pub(base)
        return PGPPublicKeyRing.insertPublicKey(pubRing, PGPPublicKey.addCertification(pubRing.publicKey, sig)).encoded
    }

    /**
     * The key flags of the newest self-signature on [primary] that carries
     * them: the same pick as KeyDetailViewModel.primaryUsageOf (private there),
     * which the Usage row on Key Details reads.
     */
    private fun primaryFlags(primary: PGPPublicKey): Int? {
        val selfTypes = setOf(
            PGPSignature.DEFAULT_CERTIFICATION,
            PGPSignature.NO_CERTIFICATION,
            PGPSignature.CASUAL_CERTIFICATION,
            PGPSignature.POSITIVE_CERTIFICATION,
            PGPSignature.DIRECT_KEY
        )
        var newest: PGPSignature? = null
        for (sig in primary.signatures.asSequence()) {
            if (sig.keyID != primary.keyID || sig.signatureType !in selfTypes) continue
            if (sig.hashedSubPackets?.hasSubpacket(SignatureSubpacketTags.KEY_FLAGS) != true) continue
            val current = newest
            if (current == null || sig.creationTime.after(current.creationTime)) newest = sig
        }
        return newest?.hashedSubPackets?.keyFlags
    }

    /** [key] as gpg exports an offline primary: GNU S2K mode 1001, no secret material. */
    private fun offlineStub(key: PGPSecretKey): PGPSecretKey {
        val pk = key.publicKey
        val packet = SecretKeyPacket(
            pk.publicKeyPacket, SymmetricKeyAlgorithmTags.NULL, SecretKeyPacket.USAGE_CHECKSUM,
            S2K.gnuDummyS2K(S2K.GNUDummyParams.noPrivateKey()), null, ByteArray(0)
        )
        return PGPSecretKey(packet, pk)
    }

    /**
     * The stub leg: [k]'s secret ring with its primary turned into an offline
     * stub takes the public parts of [merged] the way
     * KeyDeduplicationService.updateSecretRingPublicParts does (private there,
     * repeated here). The primary must stay a stub, the subkey secret must
     * still extract, and the primary must read C and S.
     */
    private fun assertStubTakesUsage(k: GeneratedKeyResult, merged: ByteArray) {
        val stubbed = PGPSecretKeyRing(
            secret(k).secretKeys.asSequence().map { if (it.isMasterKey) offlineStub(it) else it }.toList()
        )
        val stored = PGPSecretKeyRing(stubbed.encoded, BcKeyFingerprintCalculator())
        assertTrue("the stored primary is a stub", OfflineStub.isStub(stored.secretKey))

        val publicRing = pub(merged)
        val updated = stored.secretKeys.asSequence().map { sk ->
            val pk = publicRing.getPublicKey(sk.keyID)
            if (pk != null && pk.fingerprint.contentEquals(sk.publicKey.fingerprint)) PGPSecretKey.replacePublicKey(sk, pk)
            else sk
        }.toList()
        val reread = PGPSecretKeyRing(PGPSecretKeyRing(updated).encoded, BcKeyFingerprintCalculator())

        assertTrue("the primary is still a stub", OfflineStub.isStub(reread.secretKey))
        assertEquals(OfflineStub.Kind.OFFLINE, OfflineStub.primaryKind(reread))
        val sub = reread.secretKeys.asSequence().first { !it.isMasterKey }
        assertFalse(OfflineStub.isStub(sub))
        assertNotNull("the subkey secret still extracts", sub.extractPrivateKey(null))
        assertEquals(certifySign, primaryFlags(reread.publicKey))
    }

    @Test
    fun `a usage change as a newer User ID certification is taken for a key pair, stub primary too (#78)`() {
        val k = gen("Hana <hana@pgpony.app>")
        val sec = secret(k)
        val now = System.currentTimeMillis()
        // Stored: the primary certify-only. Re-imported: gpg made it C and S.
        val stored = flaggedUidCert(sec, Date(now + 2_000L), KeyFlags.CERTIFY_OTHER)
        assertEquals(KeyFlags.CERTIFY_OTHER, primaryFlags(pub(stored).publicKey))
        val edited = flaggedUidCert(sec, Date(now + 5_000L), certifySign, base = stored)

        val result = CertificateMerge.mergeDetailed(stored, edited, isKeyPair = true)
        assertEquals(1, result.selfSignaturesApplied)
        assertEquals(certifySign, primaryFlags(pub(result.bytes).publicKey))
        assertEquals(uids(stored), uids(result.bytes))

        assertStubTakesUsage(k, result.bytes)
    }

    @Test
    fun `a usage change as a direct-key signature is taken for a key pair, stub primary too (#78)`() {
        val k = gen("Ivo <ivo@pgpony.app>")
        val sec = secret(k)
        val now = System.currentTimeMillis()
        val stored = flaggedUidCert(sec, Date(now + 2_000L), KeyFlags.CERTIFY_OTHER)
        val edited = flaggedDirectKey(sec, Date(now + 5_000L), certifySign, base = stored)

        val result = CertificateMerge.mergeDetailed(stored, edited, isKeyPair = true)
        assertEquals(1, result.selfSignaturesApplied)
        val primary = pub(result.bytes).publicKey
        assertTrue(
            "the direct-key signature arrives",
            primary.getSignaturesOfType(PGPSignature.DIRECT_KEY).asSequence().any()
        )
        assertEquals(certifySign, primaryFlags(primary))

        assertStubTakesUsage(k, result.bytes)
    }

    @Test
    fun `a different certificate is never merged in`() {
        val a = gen("A <a@pgpony.app>")
        val b = gen("B <b@pgpony.app>")
        val merged = CertificateMerge.merge(a.publicKeyData, b.publicKeyData, isKeyPair = false)
        assertTrue(merged.contentEquals(a.publicKeyData))
        assertNull(pub(merged).getPublicKey(pub(b.publicKeyData).publicKey.keyID))
    }
}
