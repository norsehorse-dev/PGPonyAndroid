// SignerStatusTest.kt
// PGPony Android — 4.5.0 (item 11 / Finding C): signer trust grading.
//
// A valid crypto check is not enough: a signature from a revoked, expired, or
// non-signing key must not read as Verified. These tests pin every SignerStatus
// SignerEvaluator returns, using real generated keys (no gpg fixtures).

package com.pgpony.android.crypto

import com.pgpony.android.data.RevocationReason
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Date

class SignerStatusTest {

    private val svc = PGPCryptoService.shared
    private val revocation = RevocationService.shared
    private val pass = "correct horse battery staple"

    private fun genPublicRing(expirationSeconds: Long? = null) =
        svc.importKeyData(
            svc.generateKeyPair(
                name = "Signer",
                email = "signer@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519,
                passphrase = pass,
                expirationSeconds = expirationSeconds
            ).publicKeyData
        ).publicKeyRing!!

    @Test
    fun `a good held signing key is VERIFIED`() {
        val ring = genPublicRing()
        assertEquals(
            SignerStatus.VERIFIED,
            SignerEvaluator.evaluate(ring.publicKey.keyID, Date(), listOf(ring))
        )
    }

    @Test
    fun `an unheld signer is UNKNOWN_SIGNER`() {
        val ring = genPublicRing()
        assertEquals(
            SignerStatus.UNKNOWN_SIGNER,
            SignerEvaluator.evaluate(0x0123456789ABCDEFL, Date(), listOf(ring))
        )
    }

    @Test
    fun `the encryption subkey is NOT_SIGNING_KEY`() {
        val ring = genPublicRing()
        val subkeyId = ring.publicKeys.asSequence().first { !it.isMasterKey }.keyID
        assertEquals(
            SignerStatus.NOT_SIGNING_KEY,
            SignerEvaluator.evaluate(subkeyId, Date(), listOf(ring))
        )
    }

    @Test
    fun `a revoked key is REVOKED_KEY`() {
        val gen = svc.generateKeyPair(
            name = "Signer", email = "signer@example.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = pass
        )
        val secRing = svc.importKeyData(gen.privateKeyData).secretKeyRing!!
        val pubRing = svc.importKeyData(gen.publicKeyData).publicKeyRing!!
        val cert = revocation.generateRevocationCertificate(secRing, RevocationReason.COMPROMISED, null, pass)
        val revokedRing = revocation.applyRevocation(pubRing, cert)
        assertEquals(
            SignerStatus.REVOKED_KEY,
            SignerEvaluator.evaluate(revokedRing.publicKey.keyID, Date(), listOf(revokedRing))
        )
    }

    @Test
    fun `expiry is honored relative to the signature time`() {
        val ring = genPublicRing(expirationSeconds = 3600L)
        val primary = ring.publicKey
        val beforeExpiry = Date(primary.creationTime.time + 60_000L)
        val afterExpiry = Date(primary.creationTime.time + (primary.validSeconds + 60) * 1000L)

        assertEquals(
            "a signature made while the key was valid stays trusted",
            SignerStatus.VERIFIED,
            SignerEvaluator.evaluate(primary.keyID, beforeExpiry, listOf(ring))
        )
        assertEquals(
            "a signature dated after expiry is EXPIRED_KEY",
            SignerStatus.EXPIRED_KEY,
            SignerEvaluator.evaluate(primary.keyID, afterExpiry, listOf(ring))
        )
    }
}
