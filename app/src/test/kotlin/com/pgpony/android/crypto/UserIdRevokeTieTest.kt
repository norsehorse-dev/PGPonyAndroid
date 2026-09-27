// UserIdRevokeTieTest.kt
// PGPony Android 4.7.0 (item 18): a User ID revocation wins a tie with the newest
// certification. Signature times have one-second resolution, so revoking a User ID in the
// same second it was last certified (just added, or re-signed by a make-primary) used to
// leave it reading as not revoked.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

class UserIdRevokeTieTest {

    private val svc = PGPCryptoService.shared
    private val pass = "revoke tie passphrase"

    /** The key's primary with a User ID revocation dated [offsetMs] from its newest certification. */
    private fun revokedAt(offsetMs: Long): Pair<PGPPublicKey, String> {
        val imported = svc.importKeyData(
            svc.generateKeyPair("Tie", "tie@pgpony.test", KeyAlgorithm.ED25519_CV25519, pass).privateKeyData
        )
        val sec = imported.secretKeyRing!!
        val primary = imported.publicKeyRing!!.publicKey
        val uid = primary.userIDs.next()
        val certTime = primary.getSignaturesForID(uid).asSequence()
            .filter { it.keyID == primary.keyID && it.signatureType == PGPSignature.POSITIVE_CERTIFICATION }
            .maxOf { it.creationTime.time }

        val priv = sec.secretKey.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(pass.toCharArray())
        )
        val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(primary.algorithm, HashAlgorithmTags.SHA256), primary)
        gen.init(PGPSignature.CERTIFICATION_REVOCATION, priv)
        gen.setHashedSubpackets(
            PGPSignatureSubpacketGenerator().apply {
                setSignatureCreationTime(false, Date(certTime + offsetMs))
                setIssuerFingerprint(false, primary)
            }.generate()
        )
        val revocation = gen.generateCertification(uid, primary)
        return PGPPublicKey.addCertification(primary, uid, revocation) to uid
    }

    @Test
    fun `a revocation in the same second as the certification revokes`() {
        val (primary, uid) = revokedAt(0)
        assertTrue(UserIdService.shared.isRevoked(primary, uid))
    }

    @Test
    fun `a later revocation revokes`() {
        val (primary, uid) = revokedAt(5_000)
        assertTrue(UserIdService.shared.isRevoked(primary, uid))
    }

    @Test
    fun `a certification newer than the revocation reinstates the User ID`() {
        val (primary, uid) = revokedAt(-5_000)
        assertFalse(UserIdService.shared.isRevoked(primary, uid))
    }
}
