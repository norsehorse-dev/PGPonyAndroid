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

    // ── 4.8.0 RC11 (#109): the composer on the picked primary ─────────

    @Test
    fun `a composed NIST P-256 key with ECDSA auth and ECDH encrypt subkeys round-trips`() {
        val key = svc.assembleGranularV4(
            "P256 <p256@example.test>", includeDefaultEncryptionSubkey = false,
            subkeys = listOf(
                GranularSubkeySpec(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_P256_AUTH), null),
                GranularSubkeySpec(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDH_P256_ENCRYPT), null)
            ),
            passphrase = PASS,
            primary = KeyAlgorithm.ECDSA_NIST_P256
        )
        val pub = key.publicRing!!
        val p256 = oids.getValue(KeyAlgorithm.ECDSA_NIST_P256)
        assertEquals(PublicKeyAlgorithmTags.ECDSA, pub.publicKey.algorithm)
        assertEquals(p256, curveOid(pub.publicKey))
        assertEquals(KeyAlgorithm.ECDSA_NIST_P256, svc.detectAlgorithm(pub.publicKey, pub))
        val subs = pub.publicKeys.asSequence().filter { !it.isMasterKey }.toList()
        assertEquals("the default ECDH subkey is left out, the two composed ones are there", 2, subs.size)
        assertTrue(subs.all { curveOid(it) == p256 })
        val auth = subs.single { it.algorithm == PublicKeyAlgorithmTags.ECDSA }
        assertEquals(0x20, binding(auth).hashedSubPackets.keyFlags)
        assertEquals(auth.keyID, SshAuth.authSubkey(pub.encoded)!!.keyId)

        val secret = PGPSecretKeyRing(ByteArrayInputStream(key.secret), JcaKeyFingerprintCalculator())
        val text = "to a composed NIST P-256 key".toByteArray()
        val ct = svc.encrypt(data = text, recipientPublicKeys = listOf(pub), armor = true)
        val out = svc.decrypt(ct, listOf(secret), PASS)
        assertArrayEquals(text, out.data)
        assertEquals(subs.single { it.algorithm == PublicKeyAlgorithmTags.ECDH }.keyID, out.decryptingKeyIdRaw)

        val sig = SigningService.shared.signDetached(data = text, secretKeyRing = secret, passphrase = PASS, armor = false)
        val verified = VerifyService.shared.verifyDetached(sig, text, listOf(pub))
        assertTrue("$verified", verified is VerificationResult.Verified)
    }

    @Test
    fun `a composed RSA key keeps its RSA encryption subkey when asked`() {
        val key = svc.assembleGranularV4(
            "RSA <rsa@example.test>", includeDefaultEncryptionSubkey = true,
            subkeys = listOf(GranularSubkeySpec(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_BP256_AUTH), null)),
            passphrase = null,
            primary = KeyAlgorithm.RSA_2048
        )
        val pub = key.publicRing!!
        assertEquals(PublicKeyAlgorithmTags.RSA_GENERAL, pub.publicKey.algorithm)
        val subs = pub.publicKeys.asSequence().filter { !it.isMasterKey }.toList()
        assertTrue("the default RSA encryption subkey", subs.any { it.algorithm == PublicKeyAlgorithmTags.RSA_GENERAL && it.isEncryptionKey })
        assertTrue("the brainpool auth subkey", subs.any { it.algorithm == PublicKeyAlgorithmTags.ECDSA })
    }

    @Test
    fun `an RSA or ECDSA primary refuses an ML-KEM-768 subkey`() {
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            svc.assembleGranularV4(
                "No <no@example.test>", includeDefaultEncryptionSubkey = true,
                subkeys = listOf(GranularSubkeySpec(AddSubkeyChoice.PqEncryption(com.pgpony.android.crypto.pqc.CompositeSuite.IETF_768), null)),
                passphrase = null,
                primary = KeyAlgorithm.ECDSA_NIST_P256
            )
        }
    }

    @Test
    fun `the authentication subkey switch gives a brainpool key a brainpool AUT subkey, or Ed25519 for SSH`() {
        val base = keyPair(KeyAlgorithm.ECDSA_BRAINPOOL_P384, PASS)
        val same = ClassicalSubkeyGen.addSubkey(base, ClassicalSubkeyGen.authTypeFor(KeyAlgorithm.ECDSA_BRAINPOOL_P384), PASS)
        val aut = added(base, same)
        assertEquals(PublicKeyAlgorithmTags.ECDSA, aut.algorithm)
        assertEquals(oids.getValue(KeyAlgorithm.ECDSA_BRAINPOOL_P384), curveOid(aut))
        assertEquals(0x20, binding(aut).hashedSubPackets.keyFlags)

        val forSsh = ClassicalSubkeyGen.addSubkey(base, ClassicalSubkeyGen.authTypeFor(KeyAlgorithm.ECDSA_BRAINPOOL_P384, forSsh = true), PASS)
        val ed = added(base, forSsh)
        assertEquals(PublicKeyAlgorithmTags.EDDSA_LEGACY, ed.algorithm)
        assertEquals(0x20, binding(ed).hashedSubPackets.keyFlags)
        assertNotNull("Ed25519 is usable over SSH", SshAuth.authSubkey(pubOf(forSsh).encoded))
    }

    // ── 4.8.0 RC11 (#109): a certify-only primary for a security key ──

    @Test
    fun `a composed certify-only brainpool key gets a signing subkey, signs, takes subkeys and moves S, E and A to a card`() {
        val key = svc.assembleGranularV4(
            "Card <card@example.test>", includeDefaultEncryptionSubkey = true,
            subkeys = listOf(GranularSubkeySpec(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_BP384_AUTH), null)),
            passphrase = PASS,
            primary = KeyAlgorithm.ECDSA_BRAINPOOL_P384,
            certifyOnly = true
        )
        val pub = key.publicRing!!
        val certification = pub.publicKey.signatures.asSequence().filterIsInstance<PGPSignature>()
            .first { it.signatureType == PGPSignature.POSITIVE_CERTIFICATION }
        assertEquals("the primary certifies only", 0x01, certification.hashedSubPackets.keyFlags)
        val subs = pub.publicKeys.asSequence().filter { !it.isMasterKey }.toList()
        val bp384 = oids.getValue(KeyAlgorithm.ECDSA_BRAINPOOL_P384)
        assertTrue(subs.all { curveOid(it) == bp384 })
        val flags = subs.associateWith { binding(it).hashedSubPackets.keyFlags }
        val sign = subs.single { flags[it] == 0x02 }
        val enc = subs.single { flags[it] == 0x0C }
        val auth = subs.single { flags[it] == 0x20 }
        assertEquals("the added signing subkey is the primary's type", PublicKeyAlgorithmTags.ECDSA, sign.algorithm)

        // Signing uses the subkey, not the certify-only primary.
        val secret = PGPSecretKeyRing(ByteArrayInputStream(key.secret), JcaKeyFingerprintCalculator())
        val data = "signed by the subkey of a certify-only key".toByteArray()
        val sig = SigningService.shared.signDetached(data = data, secretKeyRing = secret, passphrase = PASS, armor = false)
        val verified = VerifyService.shared.verifyDetached(sig, data, listOf(pub))
        assertTrue("$verified", verified is VerificationResult.Verified)
        assertEquals(String.format("%016X", sign.keyID), (verified as VerificationResult.Verified).signerKeyID)

        // Add subkey works: the certify-only primary binds a new subkey.
        val more = ClassicalSubkeyGen.addSubkey(secret, ClassicalSubkeyType.ECDSA_BP384_SIGN, PASS)
        assertEquals(subs.size + 1, more.publicKeys.asSequence().count { !it.isMasterKey })

        // keytocard: each of S, E and A is movable and fits its own slot.
        fun movable(k: PGPPublicKey) = com.pgpony.android.crypto.card.KeyToCard.eligibility(k)
            as com.pgpony.android.crypto.card.KeyToCard.Eligibility.Movable
        assertTrue(com.pgpony.android.crypto.card.KeyToCard.fitsSlot(movable(sign).kind,
            com.pgpony.android.crypto.card.CardSlot.SIGNATURE, canSign = true, canEncrypt = false, canAuthenticate = false))
        assertTrue(com.pgpony.android.crypto.card.KeyToCard.fitsSlot(movable(enc).kind,
            com.pgpony.android.crypto.card.CardSlot.DECRYPTION, canSign = false, canEncrypt = true, canAuthenticate = false))
        assertTrue(com.pgpony.android.crypto.card.KeyToCard.fitsSlot(movable(auth).kind,
            com.pgpony.android.crypto.card.CardSlot.AUTHENTICATION, canSign = false, canEncrypt = false, canAuthenticate = true))
    }

    @Test
    fun `plain Generate still makes a primary that signs and certifies`() {
        val ring = keyPair(KeyAlgorithm.ECDSA_BRAINPOOL_P384, null)
        val certification = ring.publicKey.signatures.asSequence().filterIsInstance<PGPSignature>()
            .first { it.signatureType == PGPSignature.POSITIVE_CERTIFICATION }
        assertEquals(0x03, certification.hashedSubPackets.keyFlags)
    }
}
