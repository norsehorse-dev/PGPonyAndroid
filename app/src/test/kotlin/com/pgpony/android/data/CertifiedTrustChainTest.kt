// CertifiedTrustChainTest.kt
// PGPony Android 4.8.0 RC10 (#115): the cache with trusted introducers, the
// tester's case. A is your Ultimate key, O an old public key that A
// trust-signed, C your current key pair left at Unknown that O certified. C
// shows Verified, and Key Details names O as a trusted introducer for A. A key
// pair at Unverified stays. Withdrawing A's trust signature (a new stamp on O)
// drops C on the next refresh, and an older keyring read never brings it back.

package com.pgpony.android.data

import com.pgpony.android.crypto.KeyAlgorithm
import kotlinx.coroutines.runBlocking
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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class CertifiedTrustChainTest {

    private val now = System.currentTimeMillis()
    private val created = Date(now - 86_400_000L)

    private inner class K(val uid: String) {
        val pair: PGPKeyPair = run {
            val g = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
            g.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
            BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, g.generateKeyPair(), created)
        }
        var pub: PGPPublicKey = PGPPublicKey.addCertification(
            pair.publicKey, uid, sign(pair, pair.publicKey, uid, PGPSignature.POSITIVE_CERTIFICATION, Date(created.time + 1_000L), 0, 0)
        )
        var stamp = 0
        val fp: String get() = pub.fingerprint.joinToString("") { "%02X".format(it) }
        fun entity(trust: TrustLevel, keyPair: Boolean) = PGPKeyEntity(
            id = "id-$fp",
            fingerprint = fp,
            userID = uid,
            userName = PGPKeyEntity.parseUserID(uid).first,
            userEmail = PGPKeyEntity.parseUserID(uid).second,
            algorithm = KeyAlgorithm.ED25519_CV25519,
            isKeyPair = keyPair,
            createdAt = created.time,
            trustLevel = trust
        )
    }

    private fun sign(by: PGPKeyPair, target: PGPPublicKey, uid: String, type: Int, at: Date, level: Int, amount: Int): PGPSignature {
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(by.publicKey.algorithm, HashAlgorithmTags.SHA512), by.publicKey)
        g.init(type, by.privateKey)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, at)
            setIssuerFingerprint(false, by.publicKey)
            if (type == PGPSignature.POSITIVE_CERTIFICATION) setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
            if (level > 0) setTrust(false, level, amount)
        }.generate())
        return g.generateCertification(uid, target)
    }

    private fun certify(by: K, target: K, level: Int = 0, type: Int = PGPSignature.DEFAULT_CERTIFICATION, at: Date = Date(now - 60_000L)) {
        target.pub = PGPPublicKey.addCertification(target.pub, target.uid, sign(by.pair, target.pub, target.uid, type, at, level, 120))
        target.stamp++
    }

    private fun refresh(all: List<K>, seq: Long, keys: List<PGPKeyEntity>) = runBlocking {
        val byFp = all.associateBy { it.fp }
        CertifiedTrust.refresh(
            seq, keys, null,
            { fp -> byFp[fp.uppercase()]?.let { PGPPublicKeyRing(listOf(it.pub)) } },
            { emptyList() },
            { fp -> "s" + (byFp[fp.uppercase()]?.stamp ?: -1) }
        )
    }

    @Test
    fun `the tester's chain A to O to C raises C, a key pair at Unknown`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2)
        certify(o, c)
        certify(c, o) // C certifies O back: a cycle, as in the report
        val all = listOf(a, o, c)
        val aE = a.entity(TrustLevel.ULTIMATE, keyPair = true)
        val oE = o.entity(TrustLevel.UNKNOWN, keyPair = false)
        val cE = c.entity(TrustLevel.UNKNOWN, keyPair = true)
        refresh(all, CertifiedTrust.nextSeq(), listOf(aE, oE, cE))
        assertEquals(TrustLevel.VERIFIED, CertifiedTrust.effective(oE))
        assertEquals(TrustLevel.VERIFIED, CertifiedTrust.effective(cE))
        val v = CertifiedTrust.verificationFor(cE)
        assertEquals("O", v?.certifierLabel)
        assertEquals("A", v?.introducerFor)
        assertNull(v?.onlyUserIds)
        // O was certified by A itself: no introducer named.
        assertNull(CertifiedTrust.verificationFor(oE)?.introducerFor)
        assertTrue(CertifiedTrust.isConfirmedFor(cE, "c@pgpony.app"))
        // C set to Unverified by hand stays.
        assertEquals(TrustLevel.UNVERIFIED, CertifiedTrust.effective(cE.copy(trustLevel = TrustLevel.UNVERIFIED)))
    }

    @Test
    fun `withdrawing A's trust signature drops C, and an older read does not bring it back`() {
        val a = K("A <a@pgpony.app>")
        val o = K("O <o@pgpony.app>")
        val c = K("C <c@pgpony.app>")
        certify(a, o, level = 2, at = Date(now - 60_000L))
        certify(o, c)
        val all = listOf(a, o, c)
        val keys = listOf(
            a.entity(TrustLevel.ULTIMATE, keyPair = true),
            o.entity(TrustLevel.UNKNOWN, keyPair = false),
            c.entity(TrustLevel.UNKNOWN, keyPair = true)
        )
        refresh(all, CertifiedTrust.nextSeq(), keys)
        assertEquals(TrustLevel.VERIFIED, CertifiedTrust.effective(keys[2]))
        val oldSeq = CertifiedTrust.nextSeq()
        // A withdraws its trust signature on O: O's certificate (and stamp) changes.
        certify(a, o, type = PGPSignature.CERTIFICATION_REVOCATION, at = Date(now - 30_000L))
        refresh(all, CertifiedTrust.nextSeq(), keys)
        assertEquals(TrustLevel.UNKNOWN, CertifiedTrust.effective(keys[1]))
        assertEquals(TrustLevel.UNKNOWN, CertifiedTrust.effective(keys[2]))
        // A request that read the keyring before the withdrawal finishes last.
        refresh(all, oldSeq, keys)
        assertEquals(TrustLevel.UNKNOWN, CertifiedTrust.effective(keys[2]))
    }
}
