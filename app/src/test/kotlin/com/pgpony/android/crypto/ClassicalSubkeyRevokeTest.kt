// ClassicalSubkeyRevokeTest.kt
// PGPony Android — 4.5.0 (item 16 / issue #54): revoke a subkey of a classical
// key.
//
// The classical counterpart of CompositeRevokeSubkeyTest. Generates a v4
// Ed25519 + CV25519 key, revokes its encryption subkey through RevocationService
// (BC's SUBKEY_REVOCATION, 0x28), applies the certificate, and confirms the
// subkey reads as revoked while the primary does not.

package com.pgpony.android.crypto

import com.pgpony.android.data.RevocationReason
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ClassicalSubkeyRevokeTest {

    private val svc = PGPCryptoService.shared
    private val revocation = RevocationService.shared
    private val pass = "correct horse battery staple"

    private fun freshKey() = svc.importKeyData(
        svc.generateKeyPair(
            name = "Subkey Revoker",
            email = "subrevoke@example.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = pass
        ).privateKeyData
    )

    @Test
    fun `subkey revocation marks the subkey revoked and leaves the primary intact`() {
        val imported = freshKey()
        val secRing = imported.secretKeyRing!!
        val pubRing = imported.publicKeyRing!!
        val subkeyId = secRing.publicKeys.asSequence().first { !it.isMasterKey }.keyID

        val cert = revocation.generateSubkeyRevocation(
            secRing, subkeyId, RevocationReason.SUPERSEDED, "rotating encryption subkey", pass
        )
        assertTrue("cert must be ASCII-armored", cert.trimStart().startsWith("-----BEGIN PGP"))

        val updated = revocation.applySubkeyRevocation(pubRing, subkeyId, cert)

        assertTrue("the subkey must read as revoked", updated.getPublicKey(subkeyId)!!.hasRevocation())
        assertFalse("the primary must remain unrevoked", updated.publicKey.hasRevocation())
    }

    @Test
    fun `revoking the primary through the subkey path is rejected`() {
        val secRing = freshKey().secretKeyRing!!
        val primaryId = secRing.secretKey.keyID
        assertThrows(RevocationError.UnsupportedKey::class.java) {
            revocation.generateSubkeyRevocation(
                secRing, primaryId, RevocationReason.RETIRED, "", pass
            )
        }
    }
}
