// KeyExpirationEditTest.kt
// PGPony issue #4 (SecTec): editing the expiration of a v6 key (the desktop path, since the
// desktop New Key dialog has no expiry field) must set the expiry on the signing subkey too, not
// just the primary and encryption subkey. That requires rebuilding the signing subkey's binding
// signature with a fresh embedded 0x19 back-signature. This pins that every key expires and that
// every rebuilt subkey binding still verifies against the primary.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPKeyFlags
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class KeyExpirationEditTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `editing expiry sets it on every key including the signing subkey`() {
        val gen = svc.generateKeyPair(
            "Edit Exp", "editexp@pgpony.app", KeyAlgorithm.V6_ED25519, passphrase = null, expirationSeconds = null
        )
        val secretRing = PGPSecretKeyRing(ByteArrayInputStream(gen.privateKeyData), JcaKeyFingerprintCalculator())
        val publicRing = PGPPublicKeyRing(ByteArrayInputStream(gen.publicKeyData), JcaKeyFingerprintCalculator())

        val expiresAt = System.currentTimeMillis() / 1000L + 2L * 365 * 24 * 60 * 60
        val updated = KeyExpirationService.shared.setExpirationSoftware(secretRing, publicRing, expiresAt, null)
        val ring = updated.publicRing
        val primary = ring.publicKey

        val keys = ring.publicKeys.asSequence().toList()
        assertTrue("expected primary + signing + encryption subkeys", keys.size >= 3)
        keys.forEach { k ->
            val id = java.lang.Long.toHexString(k.keyID)
            assertTrue("key $id carries no expiration (validSeconds=${k.validSeconds})", k.validSeconds > 0L)
        }

        // Every rebuilt subkey binding must verify against the primary, and a
        // signing subkey must additionally carry a valid embedded 0x19 back-sig.
        ring.publicKeys.asSequence().filter { !it.isMasterKey }.forEach { sub ->
            val id = java.lang.Long.toHexString(sub.keyID)
            val binding = sub.signatures.asSequence()
                .filter { it.signatureType == PGPSignature.SUBKEY_BINDING }
                .maxByOrNull { it.creationTime }!!
            binding.init(BcPGPContentVerifierBuilderProvider(), primary)
            assertTrue("subkey $id binding does not verify", binding.verifyCertification(primary, sub))

            val flags = binding.hashedSubPackets?.keyFlags ?: 0
            val embedded = binding.hashedSubPackets?.embeddedSignatures
            if ((flags and PGPKeyFlags.CAN_SIGN) != 0) {
                assertTrue("signing subkey $id has no embedded back-signature", embedded != null && embedded.size() > 0)
            }
            if (embedded != null) {
                for (i in 0 until embedded.size()) {
                    val back = embedded[i]
                    back.init(BcPGPContentVerifierBuilderProvider(), sub)
                    assertTrue("subkey $id back-signature does not verify", back.verifyCertification(primary, sub))
                }
            }
        }
    }
}
