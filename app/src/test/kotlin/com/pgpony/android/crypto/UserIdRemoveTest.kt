// UserIdRemoveTest.kt
// PGPony Android — 4.5.1: local delete of a User ID (the UID analog of the
// item-16 subkey remove). Strips the UID and its self-cert from the ring;
// refuses the last remaining UID.

package com.pgpony.android.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class UserIdRemoveTest {

    private val svc = PGPCryptoService.shared
    private val uidSvc = UserIdService.shared
    private val pass = "correct horse battery staple"

    @Test
    fun `remove strips the User ID and keeps the other`() {
        val imported = svc.importKeyData(
            svc.generateKeyPair(
                name = "Alex", email = "alex@first.test",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = pass
            ).privateKeyData
        )
        val two = uidSvc.addUserId(
            imported.secretKeyRing!!, imported.publicKeyRing!!,
            "Alex <alex@second.test>", makePrimary = false, passphrase = pass
        )
        val target = "Alex <alex@second.test>"

        val updated = uidSvc.removeUserId(two.secretRing, two.publicRing, target)

        val pubUids = updated.publicRing.publicKey.userIDs.asSequence().toList()
        assertFalse("removed UID must be gone from the public ring", pubUids.contains(target))
        assertEquals("exactly one UID remains", 1, pubUids.size)
        val secUids = updated.secretRing.secretKey.userIDs.asSequence().toList()
        assertFalse("removal must propagate to the secret ring", secUids.contains(target))
    }

    @Test
    fun `remove refuses the last User ID`() {
        val imported = svc.importKeyData(
            svc.generateKeyPair(
                name = "Solo", email = "solo@test.example",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = pass
            ).privateKeyData
        )
        val only = imported.publicKeyRing!!.publicKey.userIDs.asSequence().first()
        assertThrows(UserIdService.UserIdError.UnsupportedKey::class.java) {
            uidSvc.removeUserId(imported.secretKeyRing!!, imported.publicKeyRing!!, only)
        }
    }
}
