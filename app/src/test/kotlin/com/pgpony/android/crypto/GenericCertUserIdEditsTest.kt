// GenericCertUserIdEditsTest.kt
// PGPony Android, 4.8.1: User ID edits on a key whose User ID is certified
// with 0x10 (OpenPGP.js and Proton keys). UserIdService looked for 0x13 only,
// so it found no certification to copy from: Add User ID, Make primary and
// notations reissued the existing User ID's certification with nothing but
// the primary-User-ID flag. The key lost its Key Flags and preferences, and
// PGPony then found no key to sign with (reported by email on 4.8.0). These
// pin that every edit carries the 0x10 certification's subpackets forward.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
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

class GenericCertUserIdEditsTest {

    private val uid = "Proton style <proton@pgpony.test>"
    private val prefs = intArrayOf(SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_128)

    /** Ed25519 + Cv25519, the User ID certified with 0x10 carrying Certify and Sign, as OpenPGP.js does. */
    private fun protonStyleKey(): PGPSecretKeyRing {
        val at = Date(1_703_370_235_000L)
        val primary = BcPGPKeyPair(
            PublicKeyAlgorithmTags.EDDSA_LEGACY,
            Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(), at
        )
        val sub = BcPGPKeyPair(
            PublicKeyAlgorithmTags.ECDH,
            X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(), at
        )
        val certHashed = PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(true, at)
            setKeyFlags(true, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
            setPreferredSymmetricAlgorithms(false, prefs)
        }.generate()
        val gen = PGPKeyRingGenerator(
            PGPSignature.DEFAULT_CERTIFICATION, primary, uid,
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), certHashed, null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256), null
        )
        gen.addSubKey(sub, PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(true, at)
            setKeyFlags(true, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        }.generate(), null)
        return gen.generateSecretKeyRing()
    }

    private fun pub(ring: PGPSecretKeyRing) = PGPPublicKeyRing(ring.publicKeys.asSequence().toList())

    /** The newest self-certification on [userId]. */
    private fun newestCert(primary: PGPPublicKey, userId: String): PGPSignature =
        primary.getSignaturesForID(userId).asSequence()
            .filter { it.keyID == primary.keyID && it.signatureType in 0x10..0x13 }
            .maxBy { it.creationTime.time }

    private fun assertCarried(primary: PGPPublicKey, userId: String) {
        val h = newestCert(primary, userId).hashedSubPackets
        assertEquals(KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA, h.keyFlags)
        assertTrue(h.preferredSymmetricAlgorithms.contentEquals(prefs))
    }

    @Test
    fun `adding a User ID keeps the existing one's flags and preferences`() {
        val ring = protonStyleKey()
        val out = UserIdService.shared.addUserId(ring, pub(ring), "Second <second@pgpony.test>", makePrimary = false, passphrase = null)
        val primary = out.publicRing.publicKey
        assertCarried(primary, uid)
        assertCarried(primary, "Second <second@pgpony.test>")
        assertTrue(SigningService.shared.signClear("test", out.secretRing).startsWith("-----BEGIN PGP SIGNED MESSAGE-----"))
    }

    @Test
    fun `making a User ID primary keeps its flags and preferences`() {
        val ring = protonStyleKey()
        val two = UserIdService.shared.addUserId(ring, pub(ring), "Second <second@pgpony.test>", makePrimary = false, passphrase = null)
        val out = UserIdService.shared.setPrimaryUserId(two.secretRing, two.publicRing, "Second <second@pgpony.test>", passphrase = null)
        assertCarried(out.publicRing.publicKey, uid)
        assertCarried(out.publicRing.publicKey, "Second <second@pgpony.test>")
    }

    @Test
    fun `notations keep the flags and preferences`() {
        val ring = protonStyleKey()
        val out = UserIdService.shared.setNotations(ring, pub(ring), listOf(UserIdService.Notation("a@pgpony.test", "1")), passphrase = null)
        assertCarried(out.publicRing.publicKey, uid)
    }
}
