// EcdsaSubkeyTest.kt
// PGPony Android, 4.8.0 RC10 (#109): ECDSA and ECDH subkeys added to an
// existing v4 key (Add subkey) and composed into a new one (the composer's v4
// base), on the NIST, brainpool and secp256k1 curves.
//
// Each added subkey is v4 on the asked curve with the asked flags. A signing
// subkey carries its back-signature with the curve's hash and signs documents
// that verify. An encryption subkey has gpg's KDF for the curve and decrypts.
// An Authenticate subkey on a NIST curve signs for SSH; on brainpool or
// secp256k1 it is kept (for a security key's AUT slot) and SSH passes it over.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType
import com.pgpony.android.crypto.ssh.SshAuth
import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.ECPublicBCPGKey
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.Security

class EcdsaSubkeyTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun installBouncyCastle() {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        private const val PASS = "ecdsa subkeys"
    }

    private val svc = PGPCryptoService.shared

    private fun keyPair(algorithm: KeyAlgorithm, pass: String?): PGPSecretKeyRing {
        val gen = svc.generateKeyPair("Sub Test", "sub@example.test", algorithm, pass)
        return PGPSecretKeyRing(gen.privateKeyData, JcaKeyFingerprintCalculator())
    }

    private fun pubOf(ring: PGPSecretKeyRing) = PGPPublicKeyRing(ring.publicKeys.asSequence().toList())

    private fun added(before: PGPSecretKeyRing, after: PGPSecretKeyRing): PGPPublicKey {
        val old = before.publicKeys.asSequence().map { it.keyID }.toSet()
        return after.publicKeys.asSequence().single { it.keyID !in old }
    }

    private fun curveOid(key: PGPPublicKey) = (key.publicKeyPacket.key as ECPublicBCPGKey).curveOID.id

    private fun binding(sub: PGPPublicKey): PGPSignature =
        sub.signatures.asSequence().filterIsInstance<PGPSignature>().first { it.signatureType == PGPSignature.SUBKEY_BINDING }

    private val oids = mapOf(
        KeyAlgorithm.ECDSA_NIST_P256 to "1.2.840.10045.3.1.7",
        KeyAlgorithm.ECDSA_NIST_P384 to "1.3.132.0.34",
        KeyAlgorithm.ECDSA_NIST_P521 to "1.3.132.0.35",
        KeyAlgorithm.ECDSA_BRAINPOOL_P256 to "1.3.36.3.3.2.8.1.1.7",
        KeyAlgorithm.ECDSA_BRAINPOOL_P384 to "1.3.36.3.3.2.8.1.1.11",
        KeyAlgorithm.ECDSA_BRAINPOOL_P512 to "1.3.36.3.3.2.8.1.1.13",
        KeyAlgorithm.ECDSA_SECP256K1 to "1.3.132.0.10"
    )

    @Test
    fun `every curve's sign, authenticate and encrypt subkey is added with the right shape`() {
        val base = keyPair(KeyAlgorithm.ED25519_CV25519, PASS)
        for (curve in KeyAlgorithm.generatableEcdsa) {
            for (cap in ClassicalSubkeyGen.Capability.entries) {
                val type = ClassicalSubkeyType.ecdsa(curve, cap)!!
                val ring = ClassicalSubkeyGen.addSubkey(base, type, PASS)
                val sub = added(base, ring)
                val what = "$type"
                assertEquals(what, 4, sub.version)
                assertEquals(what, oids.getValue(curve), curveOid(sub))
                val flags = binding(sub).hashedSubPackets.keyFlags
                when (cap) {
                    ClassicalSubkeyGen.Capability.SIGN -> {
                        assertEquals(what, PublicKeyAlgorithmTags.ECDSA, sub.algorithm)
                        assertEquals(what, 0x02, flags)
                        // The back-signature uses a hash as long as the curve.
                        val back = binding(sub).hashedSubPackets.embeddedSignatures[0]
                        assertEquals(what, EcCurveOid.signatureHash(sub, HashAlgorithmTags.SHA256), back.hashAlgorithm)
                    }
                    ClassicalSubkeyGen.Capability.AUTHENTICATE -> {
                        assertEquals(what, PublicKeyAlgorithmTags.ECDSA, sub.algorithm)
                        assertEquals(what, 0x20, flags)
                    }
                    ClassicalSubkeyGen.Capability.ENCRYPT -> {
                        assertEquals(what, PublicKeyAlgorithmTags.ECDH, sub.algorithm)
                        assertEquals(what, 0x0C, flags)
                        val kdf = sub.publicKeyPacket.key as ECDHPublicBCPGKey
                        assertEquals(what, EcdsaKeygen.curveFor(curve)!!.hashAlgorithm, kdf.hashAlgorithm.toInt() and 0xFF)
                    }
                }
                // Protected with the key's passphrase.
                assertTrue(what, ring.getSecretKey(sub.keyID).s2KUsage.toInt() != 0)
            }
        }
    }

    @Test
    fun `an ECDSA signing subkey added to a brainpool key signs documents that verify`() {
        val base = keyPair(KeyAlgorithm.ECDSA_BRAINPOOL_P384, PASS)
        val ring = ClassicalSubkeyGen.addSubkey(base, ClassicalSubkeyType.ECDSA_BP384_SIGN, PASS)
        val sub = added(base, ring)
        val data = "signed by an added brainpool subkey".toByteArray()
        val sig = SigningService.shared.signDetached(data = data, secretKeyRing = ring, passphrase = PASS, armor = false, signingKeyId = sub.keyID)
        val result = VerifyService.shared.verifyDetached(sig, data, listOf(pubOf(ring)))
        assertTrue("$result", result is VerificationResult.Verified)
        assertEquals(String.format("%016X", sub.keyID), (result as VerificationResult.Verified).signerKeyID)
    }

    @Test
    fun `an ECDH encryption subkey added to an Ed25519 key decrypts`() {
        for (curve in listOf(KeyAlgorithm.ECDSA_NIST_P521, KeyAlgorithm.ECDSA_SECP256K1)) {
            val base = keyPair(KeyAlgorithm.ED25519_CV25519, null)
            var ring = ClassicalSubkeyGen.addSubkey(base, ClassicalSubkeyType.ecdsa(curve, ClassicalSubkeyGen.Capability.ENCRYPT)!!, null)
            // Only the new subkey can decrypt: the Cv25519 one is removed.
            val cv = base.publicKeys.asSequence().first { !it.isMasterKey }
            ring = ClassicalSubkeyGen.removeSubkey(ring, cv.keyID)
            val text = "to an added ECDH $curve subkey".toByteArray()
            val ct = svc.encrypt(data = text, recipientPublicKeys = listOf(pubOf(ring)), armor = false)
            val out = svc.decrypt(ct, listOf(ring), null)
            assertArrayEquals(text, out.data)
            assertEquals(pubOf(ring).publicKeys.asSequence().single { !it.isMasterKey }.keyID, out.decryptingKeyIdRaw)
        }
    }

    @Test
    fun `an Authenticate subkey on a NIST curve signs for SSH, on brainpool it is kept for a card`() {
        for (curve in listOf(KeyAlgorithm.ECDSA_NIST_P256, KeyAlgorithm.ECDSA_NIST_P384, KeyAlgorithm.ECDSA_NIST_P521)) {
            val base = keyPair(curve, null)
            val ring = ClassicalSubkeyGen.addSubkey(base, ClassicalSubkeyGen.sshAuthTypeFor(curve), null)
            val sub = SshAuth.authSubkey(pubOf(ring).encoded)
            assertNotNull("$curve auth subkey for SSH", sub)
            val m = SshAuth.material(sub!!.publicBody)
            assertTrue("$curve", m is SshAuth.Material.Ecdsa)
            assertEquals(added(base, ring).keyID, sub.keyId)
        }
        val bp = keyPair(KeyAlgorithm.ECDSA_BRAINPOOL_P384, null)
        val withAuth = ClassicalSubkeyGen.addSubkey(bp, ClassicalSubkeyType.ECDSA_BP384_AUTH, null)
        assertEquals(0x20, binding(added(bp, withAuth)).hashedSubPackets.keyFlags)
        assertNull("SSH has no brainpool key type", SshAuth.authSubkey(pubOf(withAuth).encoded))
    }

    @Test
    fun `a composed v4 key with a brainpool encryption subkey encrypts and decrypts`() {
        val key = svc.assembleGranularV4(
            "Composed <composed@example.test>", includeDefaultEncryptionSubkey = false,
            subkeys = listOf(
                GranularSubkeySpec(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDH_BP512_ENCRYPT), null),
                GranularSubkeySpec(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_BP512_AUTH), null)
            ),
            passphrase = PASS
        )
        val pub = key.publicRing!!
        val subs = pub.publicKeys.asSequence().filter { !it.isMasterKey }.toList()
        assertEquals(2, subs.size)
        assertTrue(subs.all { curveOid(it) == oids.getValue(KeyAlgorithm.ECDSA_BRAINPOOL_P512) })
        val secret = PGPSecretKeyRing(ByteArrayInputStream(key.secret), JcaKeyFingerprintCalculator())
        val text = "to a composed brainpool subkey".toByteArray()
        val ct = svc.encrypt(data = text, recipientPublicKeys = listOf(pub), armor = true)
        val out = svc.decrypt(ct, listOf(secret), PASS)
        assertArrayEquals(text, out.data)
        assertEquals(subs.single { it.algorithm == PublicKeyAlgorithmTags.ECDH }.keyID, out.decryptingKeyIdRaw)
    }
}
