// OwnKeyCertifyTest.kt
// PGPony Android 4.8.2 (item 5, #126): one of your key pairs certifies
// another. A key pair's edits rebuild its public copy from the secret ring, so
// KeyRepository.keepCertifications also puts the certification on the secret
// ring's primary (PGPSecretKey.replacePublicKey). This runs those steps: the
// certification survives a later edit (Add subkey), and the secret still
// opens with its passphrase.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.io.ByteArrayInputStream

class OwnKeyCertifyTest {

    private val svc = PGPCryptoService.shared

    private fun gen(name: String, alg: KeyAlgorithm, pass: String): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val g = svc.generateKeyPair(name, "${name.lowercase()}@example.test", alg, pass)
        return PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator()) to
            PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
    }

    private fun certificationsBy(ring: PGPPublicKeyRing, issuer: Long): Int =
        ring.publicKey.signatures.asSequence().count { it.keyID == issuer && it.isCertification }

    @Test
    fun `a certification of your own key pair survives the next edit`() {
        for (alg in listOf(KeyAlgorithm.ED25519_CV25519, KeyAlgorithm.V6_ED25519)) {
            val (a, _) = gen("Work", KeyAlgorithm.ED25519_CV25519, "a pass")
            val (bSec, bPub) = gen("Home", alg, "b pass")
            val made = CertificationService.certify(
                a, "a pass", bPub, listOf(bPub.publicKey.userIDs.next()),
                CertificationService.Level.POSITIVE, null, exportable = true
            )
            val certified = CertificationService.withSignatures(bPub, made)
            assertEquals(alg.name, 1, certificationsBy(certified, a.secretKey.keyID))

            // KeyRepository.keepInSecretRing.
            val bSec2 = PGPSecretKeyRing.insertSecretKey(bSec, PGPSecretKey.replacePublicKey(bSec.secretKey, certified.publicKey))
            assertNotNull(SecretKeyUnlock.extract(bSec2.secretKey, "b pass".toCharArray()))

            // A later edit, as KeyRepository.addSubkey rebuilds the public copy.
            val edited = if (alg.isV6) {
                V6SubkeyGen.addSubkey(bSec2, V6SubkeyGen.V6SubkeyType.ED25519_AUTH, "b pass", null)
            } else {
                ClassicalSubkeyGen.addSubkey(bSec2, ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH, "b pass")
            }
            val rebuilt = PGPPublicKeyRing(edited.publicKeys.asSequence().toList())
            assertEquals(alg.name, 1, certificationsBy(rebuilt, a.secretKey.keyID))
            assertNotNull(SecretKeyUnlock.extract(edited.secretKey, "b pass".toCharArray()))
        }
    }
}
