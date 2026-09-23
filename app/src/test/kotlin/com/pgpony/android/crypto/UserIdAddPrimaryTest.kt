// UserIdAddPrimaryTest.kt
// PGPony Android — 4.5.0 (limbodiver, email Sep 2026): adding a second User ID must
// not silently make the new address primary.
//
// A freshly generated key has one UID with no explicit IsPrimaryUserId flag, so
// it is only implicitly primary (first UID). Adding a second UID stamps a newer
// self-cert; without pinning, a keyserver or gpg treats the newest self-sig as
// primary and the just-added address wins. addUserId(makePrimary = false) now
// reissues the original UID's self-cert WITH the primary flag so the explicit
// flag beats recency. addUserId(makePrimary = true) still moves it.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UserIdAddPrimaryTest {

    private val svc = PGPCryptoService.shared
    private val uidSvc = UserIdService.shared
    private val pass = "correct horse battery staple"

    private fun freshRings(): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val imported = svc.importKeyData(
            svc.generateKeyPair(
                name = "Alex",
                email = "alex@first.test",
                algorithm = KeyAlgorithm.ED25519_CV25519,
                passphrase = pass
            ).privateKeyData
        )
        return imported.secretKeyRing!! to imported.publicKeyRing!!
    }

    private fun isExplicitPrimary(pub: PGPPublicKey, uid: String): Boolean {
        var latest: PGPSignature? = null
        pub.getSignaturesForID(uid)?.forEach { sig ->
            if (sig.keyID == pub.keyID && sig.signatureType == PGPSignature.POSITIVE_CERTIFICATION) {
                if (latest == null || sig.creationTime.after(latest!!.creationTime)) latest = sig
            }
        }
        return latest?.hashedSubPackets?.isPrimaryUserID == true
    }

    @Test
    fun `adding a non-primary UID pins the original as explicit primary`() {
        val (sec, pub) = freshRings()
        val firstUid = pub.publicKey.userIDs.asSequence().first()
        val newUid = "Alex <alex@second.test>"

        val updated = uidSvc.addUserId(sec, pub, newUid, makePrimary = false, passphrase = pass)
        val p = updated.publicRing.publicKey

        assertEquals(firstUid, uidSvc.currentPrimaryUserId(p))
        assertTrue("original UID must carry an explicit primary flag", isExplicitPrimary(p, firstUid))
        assertFalse("newly added UID must not be primary", isExplicitPrimary(p, newUid))
    }

    @Test
    fun `adding a primary UID makes the new one primary and clears the old`() {
        val (sec, pub) = freshRings()
        val firstUid = pub.publicKey.userIDs.asSequence().first()
        val newUid = "Alex <alex@second.test>"

        val updated = uidSvc.addUserId(sec, pub, newUid, makePrimary = true, passphrase = pass)
        val p = updated.publicRing.publicKey

        assertEquals(newUid, uidSvc.currentPrimaryUserId(p))
        assertTrue("new UID must be the explicit primary", isExplicitPrimary(p, newUid))
        assertFalse("old UID must no longer be primary", isExplicitPrimary(p, firstUid))
    }
}
