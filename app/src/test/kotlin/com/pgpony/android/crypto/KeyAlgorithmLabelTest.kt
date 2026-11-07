// KeyAlgorithmLabelTest.kt
// PGPony Android 4.8.0 (#88): the algorithm line on the signer and certifier
// lookup cards is read from the key, so a DSA + ElGamal key no longer reads
// Unknown, and a key KeyAlgorithm models keeps its usual name.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator
import org.bouncycastle.crypto.generators.DSAParametersGenerator
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters
import org.bouncycastle.crypto.params.ElGamalParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.bouncycastle.bcpg.ArmoredOutputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class KeyAlgorithmLabelTest {

    private val svc = PGPCryptoService.shared

    /** A DSA 1024 primary with an ElGamal encryption subkey, the shape of an old gpg default key.
     *  The ElGamal key uses the DSA group, which keeps the test fast (no safe-prime search). */
    private fun dsaElGamalRing(): PGPPublicKeyRing {
        val rnd = SecureRandom()
        val now = Date()
        val paramsGen = DSAParametersGenerator().apply { init(1024, 80, rnd) }
        val params = paramsGen.generateParameters()
        val dsaGen = DSAKeyPairGenerator().apply { init(DSAKeyGenerationParameters(rnd, params)) }
        val dsa = BcPGPKeyPair(PublicKeyAlgorithmTags.DSA, dsaGen.generateKeyPair(), now)
        val elgGen = ElGamalKeyPairGenerator().apply {
            init(ElGamalKeyGenerationParameters(rnd, ElGamalParameters(params.p, params.g)))
        }
        val elg = BcPGPKeyPair(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, elgGen.generateKeyPair(), now)

        val primaryFlags = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
        }.generate()
        val subFlags = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        }.generate()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            dsa,
            "Old Key <old@example.test>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            primaryFlags,
            null,
            BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA256),
            null
        )
        gen.addSubKey(elg, subFlags, null)
        return gen.generatePublicKeyRing()
    }

    @Test
    fun `a DSA and ElGamal key reads its algorithms and sizes, not Unknown (#88)`() {
        val ring = dsaElGamalRing()
        val primary = ring.publicKey
        val sub = ring.publicKeys.asSequence().first { !it.isMasterKey }
        assertEquals("precondition: KeyAlgorithm does not model DSA", KeyAlgorithm.UNKNOWN, svc.detectAlgorithm(primary, ring))

        assertEquals("DSA 1024", KeyAlgorithmLabel.of(primary))
        assertEquals("ElGamal 1024", KeyAlgorithmLabel.of(sub))
        assertEquals(
            "DSA 1024 + ElGamal 1024",
            KeyAlgorithmLabel.lookupCard(svc.detectAlgorithm(primary, ring), ring)
        )
    }

    @Test
    fun `an Ed25519 key keeps its usual name and labels each packet (#88)`() {
        val k = svc.generateKeyPair("Ed", "ed@example.test", KeyAlgorithm.ED25519_CV25519, null, null)
        val preview = svc.importKeyData(k.publicKeyData)
        val ring = preview.publicKeyRing!!
        val sub = ring.publicKeys.asSequence().first { !it.isMasterKey }

        assertEquals("Ed25519", KeyAlgorithmLabel.of(ring.publicKey))
        assertEquals("X25519", KeyAlgorithmLabel.of(sub))
        // A modeled key: the card line is what it was before.
        assertEquals(KeyAlgorithm.ED25519_CV25519.displayName, KeyAlgorithmLabel.lookupCard(preview.algorithm, ring))
        // The fallback path reads the same key from its packets.
        assertEquals("Ed25519 + X25519", KeyAlgorithmLabel.lookupCard(KeyAlgorithm.UNKNOWN, ring))
    }

    private fun armor(ring: PGPPublicKeyRing): String {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { ring.encode(it) }
        return out.toString(Charsets.US_ASCII.name())
    }

    @Test
    fun `a stored DSA and ElGamal key is labelled from its armor on the Keyring and in Key Details (#88)`() {
        val ring = dsaElGamalRing()
        val fp = org.bouncycastle.util.encoders.Hex.toHexString(ring.publicKey.fingerprint)
        val armored = armor(ring)
        assertEquals("DSA 1024", KeyAlgorithmLabel.badge(KeyAlgorithm.UNKNOWN, fp, armored))
        assertEquals("DSA 1024 + ElGamal 1024", KeyAlgorithmLabel.full(KeyAlgorithm.UNKNOWN, fp, armored))
        val sub = ring.publicKeys.asSequence().first { !it.isMasterKey }
        assertEquals("ElGamal 1024", KeyAlgorithmLabel.packet(sub, KeyAlgorithm.UNKNOWN, short = true))
    }

    @Test
    fun `a modeled or unreadable stored key keeps KeyAlgorithm's names`() {
        assertEquals(KeyAlgorithm.RSA_4096.shortName, KeyAlgorithmLabel.badge(KeyAlgorithm.RSA_4096, "00", null))
        assertEquals(KeyAlgorithm.RSA_4096.displayName, KeyAlgorithmLabel.full(KeyAlgorithm.RSA_4096, "00", null))
        assertEquals("Unknown", KeyAlgorithmLabel.badge(KeyAlgorithm.UNKNOWN, "11", null))
        assertEquals("Unknown", KeyAlgorithmLabel.full(KeyAlgorithm.UNKNOWN, "22", "not a key"))
    }

    @Test
    fun `no key at all is Unknown`() {
        assertEquals("Unknown", KeyAlgorithmLabel.lookupCard(KeyAlgorithm.UNKNOWN, null))
    }
}
