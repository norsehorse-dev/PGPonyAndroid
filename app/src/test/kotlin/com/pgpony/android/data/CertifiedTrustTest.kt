// CertifiedTrustTest.kt
// PGPony Android 4.8.0 RC8 (#115): the cache of trust worked out from your
// own Ultimate keys' certifications. A request holding an older keyring read
// (your key still Ultimate, or not yet deleted) never brings the raised level
// back after a newer read; the OpenPGP provider's signature result confirms
// only the certified User IDs, with the one for the sender as primary; and a
// shown answer stops holding once its certification expires, before any
// refresh.

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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class CertifiedTrustTest {

    private val now = System.currentTimeMillis()

    private fun ed25519(): PGPKeyPair {
        val g = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
        g.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
        return BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, g.generateKeyPair(), Date(now - 86_400_000L))
    }

    private fun sig(signer: PGPKeyPair, target: PGPPublicKey, uid: String, type: Int, at: Date = Date(now - 60_000L), expirySeconds: Long = 0): PGPSignature {
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(signer.publicKey.algorithm, HashAlgorithmTags.SHA256), signer.publicKey)
        g.init(type, signer.privateKey)
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, at)
            setIssuerFingerprint(false, signer.publicKey)
            if (type == PGPSignature.POSITIVE_CERTIFICATION) setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
            if (expirySeconds > 0) setSignatureExpirationTime(true, expirySeconds)
        }.generate())
        return g.generateCertification(uid, target)
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }

    private fun entity(key: PGPPublicKey, uid: String, trust: TrustLevel, keyPair: Boolean) = PGPKeyEntity(
        id = "id-" + hex(key.fingerprint),
        fingerprint = hex(key.fingerprint),
        userID = uid,
        userName = PGPKeyEntity.parseUserID(uid).first,
        userEmail = PGPKeyEntity.parseUserID(uid).second,
        algorithm = KeyAlgorithm.ED25519_CV25519,
        isKeyPair = keyPair,
        createdAt = now - 86_400_000L,
        trustLevel = trust
    )

    /** My Ultimate key and a public key whose [certified] User ID it certified; [extra] User IDs are self-signed only. */
    private class Fixture(val me: PGPKeyEntity, val them: PGPKeyEntity, val rings: Map<String, PGPPublicKeyRing>, val ringUserIds: List<String>)

    private fun fixture(certified: String, vararg extra: String, certExpirySeconds: Long = 0, certAt: Date = Date(now - 60_000L)): Fixture {
        val me = ed25519()
        val them = ed25519()
        val mePub = PGPPublicKey.addCertification(me.publicKey, "Me <me@pgpony.app>", sig(me, me.publicKey, "Me <me@pgpony.app>", PGPSignature.POSITIVE_CERTIFICATION))
        var themPub = PGPPublicKey.addCertification(them.publicKey, certified, sig(them, them.publicKey, certified, PGPSignature.POSITIVE_CERTIFICATION))
        for (u in extra) themPub = PGPPublicKey.addCertification(themPub, u, sig(them, themPub, u, PGPSignature.POSITIVE_CERTIFICATION))
        themPub = PGPPublicKey.addCertification(
            themPub, certified,
            sig(me, themPub, certified, PGPSignature.DEFAULT_CERTIFICATION, at = certAt, expirySeconds = certExpirySeconds)
        )
        val rings = mapOf(hex(mePub.fingerprint) to PGPPublicKeyRing(listOf(mePub)), hex(themPub.fingerprint) to PGPPublicKeyRing(listOf(themPub)))
        return Fixture(
            entity(mePub, "Me <me@pgpony.app>", TrustLevel.ULTIMATE, keyPair = true),
            entity(themPub, certified, TrustLevel.UNKNOWN, keyPair = false),
            rings,
            listOf(certified) + extra
        )
    }

    private fun refresh(f: Fixture, seq: Long, keys: List<PGPKeyEntity>, only: List<String>? = null) = runBlocking {
        CertifiedTrust.refresh(seq, keys, only, { f.rings[it.uppercase()] }, { emptyList() }, { "same" })
    }

    @Test
    fun `an older keyring read never brings back a demoted certifier`() {
        val f = fixture("Them <t@pgpony.app>")
        refresh(f, CertifiedTrust.nextSeq(), listOf(f.me, f.them))
        assertEquals(TrustLevel.VERIFIED, CertifiedTrust.effective(f.them))
        // A background request read the keys while your key was still Ultimate...
        val oldSeq = CertifiedTrust.nextSeq()
        val oldKeys = listOf(f.me, f.them)
        // ...then you set it to Verified, and Key Details checks again.
        val newSeq = CertifiedTrust.nextSeq()
        refresh(f, newSeq, listOf(f.me.copy(trustLevel = TrustLevel.VERIFIED), f.them), only = listOf(f.them.fingerprint))
        assertEquals(TrustLevel.UNKNOWN, CertifiedTrust.effective(f.them))
        // The older request finishes last.
        refresh(f, oldSeq, oldKeys)
        assertEquals(TrustLevel.UNKNOWN, CertifiedTrust.effective(f.them))
        assertFalse(CertifiedTrust.isConfirmedFor(f.them, "t@pgpony.app"))
    }

    @Test
    fun `an older keyring read never brings back a deleted certifier`() {
        val f = fixture("Them <t@pgpony.app>")
        refresh(f, CertifiedTrust.nextSeq(), listOf(f.me, f.them))
        assertEquals(TrustLevel.VERIFIED, CertifiedTrust.effective(f.them))
        val oldSeq = CertifiedTrust.nextSeq()
        refresh(f, CertifiedTrust.nextSeq(), listOf(f.them))
        refresh(f, oldSeq, listOf(f.me, f.them))
        assertEquals(TrustLevel.UNKNOWN, CertifiedTrust.effective(f.them))
        // A newer read with your key back raises it again.
        refresh(f, CertifiedTrust.nextSeq(), listOf(f.me, f.them))
        assertEquals(TrustLevel.VERIFIED, CertifiedTrust.effective(f.them))
    }

    @Test
    fun `the signature result confirms only the certified User ID`() {
        val mallory = "Mallory <m@y.example>"
        val ceo = "CEO <ceo@corp.example>"
        val f = fixture(mallory, ceo)
        refresh(f, CertifiedTrust.nextSeq(), listOf(f.me, f.them))
        val shownAsCeo = f.them.copy(userID = ceo)
        // Mail from Mallory's address: confirmed, Mallory as primary, only Mallory listed.
        val c = CertifiedTrust.confirmationFor(shownAsCeo, f.ringUserIds, "m@y.example")
        assertEquals(mallory, c?.primaryUserId)
        assertEquals(listOf(mallory), c?.confirmedUserIds)
        // Mail from the CEO address, or no address with the CEO shown: not confirmed.
        assertNull(CertifiedTrust.confirmationFor(shownAsCeo, f.ringUserIds, "ceo@corp.example"))
        assertNull(CertifiedTrust.confirmationFor(shownAsCeo, f.ringUserIds, null))
        assertFalse(CertifiedTrust.isConfirmedFor(shownAsCeo, "ceo@corp.example"))
        assertEquals(TrustLevel.UNKNOWN, CertifiedTrust.effective(shownAsCeo))
        // A level you set by hand confirms every User ID, as before.
        val manual = CertifiedTrust.confirmationFor(shownAsCeo.copy(trustLevel = TrustLevel.VERIFIED), f.ringUserIds, "ceo@corp.example")
        assertEquals(ceo, manual?.primaryUserId)
        assertEquals(f.ringUserIds, manual?.confirmedUserIds)
    }

    @Test
    fun `a shown answer stops holding when its certification expires`() {
        // Made a second ago, valid for three seconds.
        val f = fixture("Them <t@pgpony.app>", certExpirySeconds = 3, certAt = Date(now - 1_000L))
        refresh(f, CertifiedTrust.nextSeq(), listOf(f.me, f.them))
        assertEquals(TrustLevel.VERIFIED, CertifiedTrust.effective(f.them))
        assertTrue(CertifiedTrust.isConfirmedFor(f.them, "t@pgpony.app"))
        Thread.sleep(3_500L)
        // No refresh in between.
        assertEquals(TrustLevel.UNKNOWN, CertifiedTrust.effective(f.them))
        assertFalse(CertifiedTrust.isConfirmedFor(f.them, "t@pgpony.app"))
    }
}
