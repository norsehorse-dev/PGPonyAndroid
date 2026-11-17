// NoKeyFlagsSigningTest.kt
// PGPony Android, 4.8.1: an Ed25519 key pair whose User ID certification
// carries no Key Flags subpacket said "No signing-capable key found" (a
// Proton key, reported by email on 4.8.0). RFC 9580 puts no limit on a key
// without Key Flags, and CertificateBindings already reads it that way; the
// capability fallback now does too, so the primary signs.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class NoKeyFlagsSigningTest {

    private fun keyWithoutPrimaryFlags(): org.bouncycastle.openpgp.PGPSecretKeyRing {
        val at = Date(1_703_370_235_000L)
        val primary = BcPGPKeyPair(
            PublicKeyAlgorithmTags.EDDSA_LEGACY,
            Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(), at
        )
        val sub = BcPGPKeyPair(
            PublicKeyAlgorithmTags.ECDH,
            X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(), at
        )
        // The User ID certification has only a creation time and the primary User ID flag.
        val certHashed = PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(true, at)
            setPrimaryUserID(false, true)
        }.generate()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, primary, "No flags <noflags@pgpony.test>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), certHashed, null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256), null
        )
        gen.addSubKey(sub, PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(true, at)
            setKeyFlags(true, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        }.generate(), null)
        return gen.generateSecretKeyRing()
    }

    @Test
    fun `the primary of a key without Key Flags signs`() {
        val ring = keyWithoutPrimaryFlags()
        val picked = PGPCryptoService.shared.pickSigningSecretKey(ring)
        assertEquals(ring.publicKey.keyID, picked?.keyID)
        val signed = SigningService.shared.signClear("test", ring)
        assertTrue(signed.startsWith("-----BEGIN PGP SIGNED MESSAGE-----"))
    }
}
