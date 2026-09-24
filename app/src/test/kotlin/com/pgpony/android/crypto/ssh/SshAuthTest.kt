// SshAuthTest.kt
// PGPony Android, 4.6.0 (item 16): SSH authentication with an OpenPGP
// authentication subkey. The subkey is found from the certificate, encoded in
// OpenSSH form, and its signatures verify under the SSH public key, for
// Ed25519 (v4 legacy and v6), RSA (all three SSH hash choices), ECDSA on the
// NIST curves, an Ed25519 auth subkey on a composite ML-DSA key, and the card
// path (INTERNAL AUTHENTICATE input and output). These blobs were also checked
// against OpenSSH (ssh-keygen -Y verify) during development.

package com.pgpony.android.crypto.ssh

import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.V6SubkeyGen
import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositePrimaryKeyGen
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.encodings.PKCS1Encoding
import org.bouncycastle.crypto.engines.RSABlindedEngine
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECNamedDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.RSADigestSigner
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

class SshAuthTest {

    private val svc = PGPCryptoService.shared
    private val challenge = "session-id and userauth request".toByteArray()

    private fun sec(b: ByteArray) = PGPSecretKeyRing(b, JcaKeyFingerprintCalculator())
    private fun pubOf(r: PGPSecretKeyRing) = PGPPublicKeyRing(r.publicKeys.asSequence().toList()).encoded

    private fun withAuth(alg: KeyAlgorithm, type: ClassicalSubkeyGen.ClassicalSubkeyType, pass: String? = null): PGPSecretKeyRing {
        val k = svc.generateKeyPair("T", "t@example.org", alg, pass, null)
        return ClassicalSubkeyGen.addSubkey(sec(k.privateKeyData), type, pass)
    }

    private class Found(val m: SshAuth.Material, val keyId: Long)

    private fun find(cert: ByteArray): Found {
        val sub = SshAuth.authSubkey(cert)
        assertNotNull("auth subkey", sub)
        return Found(SshAuth.material(sub!!.publicBody)!!, sub.keyId)
    }

    private fun unlock(ring: PGPSecretKeyRing, keyId: Long, pass: String? = null) =
        (SshSigningKey.unlock(ring, keyId, pass) as SshSigningKey.Unlock.Ok).key

    /** Verify an SSH signature blob under the SSH public key blob, independently. */
    private fun verify(m: SshAuth.Material, blob: ByteArray, data: ByteArray): String {
        val (type, sig) = SshAuth.parseSignatureBlob(blob)
        val pub = SshWire.Reader(SshAuth.publicBlob(m))
        val keyType = String(pub.string())
        val ok = when (m) {
            is SshAuth.Material.Ed25519 -> {
                assertEquals("ssh-ed25519", keyType)
                Ed25519Signer().run {
                    init(false, Ed25519PublicKeyParameters(pub.string(), 0))
                    update(data, 0, data.size)
                    verifySignature(sig)
                }
            }
            is SshAuth.Material.Rsa -> {
                val e = BigInteger(pub.string()); val n = BigInteger(pub.string())
                val digest = when (type) {
                    "ssh-rsa" -> SHA1Digest()
                    "rsa-sha2-256" -> SHA256Digest()
                    else -> SHA512Digest()
                }
                assertEquals((n.bitLength() + 7) / 8, sig.size)
                RSADigestSigner(digest).run {
                    init(false, RSAKeyParameters(false, n, e))
                    update(data, 0, data.size)
                    verifySignature(sig)
                }
            }
            is SshAuth.Material.Ecdsa -> {
                assertEquals(keyType, type)
                assertEquals(m.curve.sshName, String(pub.string()))
                val q = pub.string()
                val oid = ASN1ObjectIdentifier(m.curve.oid)
                val x9 = ECNamedCurveTable.getByOID(oid)
                val params = ECPublicKeyParameters(x9.curve.decodePoint(q), ECNamedDomainParameters(oid, x9))
                val rs = SshWire.Reader(sig)
                val r = BigInteger(rs.string()); val s = BigInteger(rs.string())
                val d = when (m.curve) {
                    SshAuth.Curve.P256 -> SHA256Digest()
                    SshAuth.Curve.P384 -> SHA384Digest()
                    SshAuth.Curve.P521 -> SHA512Digest()
                }
                val h = ByteArray(d.digestSize).also { d.update(data, 0, data.size); d.doFinal(it, 0) }
                ECDSASigner().run { init(false, params); verifySignature(h, r, s) }
            }
        }
        assertTrue("signature verifies", ok)
        return type
    }

    @Test
    fun `v4 Ed25519 auth subkey signs and encodes for OpenSSH`() {
        val ring = withAuth(KeyAlgorithm.ED25519_CV25519, ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH)
        val f = find(pubOf(ring))
        assertTrue(f.m is SshAuth.Material.Ed25519)
        val line = SshAuth.authorizedKeysLine(f.m, "t@example.org")
        assertTrue(line.startsWith("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"))
        assertTrue(line.endsWith(" t@example.org"))
        assertTrue(SshAuth.sshFingerprint(f.m).startsWith("SHA256:"))
        val blob = SshAuth.sign(f.m, unlock(ring, f.keyId), challenge, SshAuth.HASH_SHA1)
        assertEquals("ssh-ed25519", verify(f.m, blob, challenge))
    }

    @Test
    fun `v6 Ed25519 auth subkey`() {
        val k = svc.generateKeyPair("V", "v@example.org", KeyAlgorithm.V6_ED25519, null, null)
        val ring = V6SubkeyGen.addSubkey(sec(k.privateKeyData), V6SubkeyGen.V6SubkeyType.ED25519_AUTH, null, null)
        val f = find(pubOf(ring))
        assertEquals("ssh-ed25519", verify(f.m, SshAuth.sign(f.m, unlock(ring, f.keyId), challenge, 0), challenge))
    }

    @Test
    fun `RSA auth subkey signs with each SSH hash`() {
        val ring = withAuth(KeyAlgorithm.RSA_2048, ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_AUTH)
        val f = find(pubOf(ring))
        assertTrue(f.m is SshAuth.Material.Rsa)
        assertTrue(SshAuth.authorizedKeysLine(f.m, "").startsWith("ssh-rsa AAAAB3NzaC1yc2EAAAA"))
        val key = unlock(ring, f.keyId)
        assertEquals("ssh-rsa", verify(f.m, SshAuth.sign(f.m, key, challenge, SshAuth.HASH_SHA1), challenge))
        assertEquals("rsa-sha2-256", verify(f.m, SshAuth.sign(f.m, key, challenge, SshAuth.HASH_SHA256), challenge))
        assertEquals("rsa-sha2-512", verify(f.m, SshAuth.sign(f.m, key, challenge, SshAuth.HASH_SHA512), challenge))
    }

    @Test(expected = SshAuth.UnsupportedHash::class)
    fun `RSA refuses a hash SSH does not use`() {
        val ring = withAuth(KeyAlgorithm.RSA_2048, ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_AUTH)
        val f = find(pubOf(ring))
        SshAuth.sign(f.m, unlock(ring, f.keyId), challenge, 3)
    }

    private fun ecdsaRing(oid: String): PGPSecretKeyRing {
        fun pair(): BcPGPKeyPair {
            val o = ASN1ObjectIdentifier(oid)
            val g = ECKeyPairGenerator()
            g.init(ECKeyGenerationParameters(ECNamedDomainParameters(o, ECNamedCurveTable.getByOID(o)), SecureRandom()))
            return BcPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, g.generateKeyPair(), Date())
        }
        val primary = pair()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, primary, "E <e@example.org>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, 0x03) }.generate(), null,
            BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.ECDSA, HashAlgorithmTags.SHA256), null
        )
        gen.addSubKey(pair(), PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, 0x20) }.generate(), null)
        return gen.generateSecretKeyRing()
    }

    @Test
    fun `ECDSA auth subkeys on the NIST curves`() {
        for ((oid, name) in listOf(
            "1.2.840.10045.3.1.7" to "ecdsa-sha2-nistp256",
            "1.3.132.0.34" to "ecdsa-sha2-nistp384",
            "1.3.132.0.35" to "ecdsa-sha2-nistp521"
        )) {
            val ring = ecdsaRing(oid)
            val f = find(pubOf(ring))
            assertEquals(name, f.m.sshType)
            assertEquals(name, verify(f.m, SshAuth.sign(f.m, unlock(ring, f.keyId), challenge, 0), challenge))
            val (spki, alg) = SshAuth.subjectPublicKeyInfo(f.m)
            assertEquals(SshAuth.API_ECDSA, alg)
            assertTrue(PublicKeyFactory.createKey(spki) is ECPublicKeyParameters)
        }
    }

    /** A P-256 key whose subkeys carry [subkeyFlags], oldest first. */
    private fun ringWithSubkeys(vararg subkeyFlags: Int): PGPSecretKeyRing {
        val oid = ASN1ObjectIdentifier("1.2.840.10045.3.1.7")
        val start = System.currentTimeMillis() - 60_000L
        fun pair(at: Long): BcPGPKeyPair {
            val g = ECKeyPairGenerator()
            g.init(ECKeyGenerationParameters(ECNamedDomainParameters(oid, ECNamedCurveTable.getByOID(oid)), SecureRandom()))
            return BcPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, g.generateKeyPair(), Date(at))
        }
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, pair(start), "F <f@example.org>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, 0x01) }.generate(), null,
            BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.ECDSA, HashAlgorithmTags.SHA256), null
        )
        subkeyFlags.forEachIndexed { i, flags ->
            gen.addSubKey(pair(start + (i + 1) * 1000L), PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, flags) }.generate(), null)
        }
        return gen.generateSecretKeyRing()
    }

    private fun flagsOf(cert: ByteArray): Int? = SshAuth.authSubkey(cert)?.keyFlags

    @Test
    fun `a dedicated Authenticate subkey is chosen`() {
        val cert = pubOf(ringWithSubkeys(0x20))
        assertEquals(0x20, flagsOf(cert))
        assertTrue(!SshAuth.onlyDualUseAuthSubkeys(cert))
    }

    @Test
    fun `an auth subkey that can also sign or certify is refused`() {
        for (flags in listOf(0x22, 0x21, 0x23)) {
            val cert = pubOf(ringWithSubkeys(flags))
            assertNull("flags $flags", SshAuth.authSubkey(cert))
            assertTrue("flags $flags", SshAuth.onlyDualUseAuthSubkeys(cert))
        }
    }

    @Test
    fun `a dedicated auth subkey wins over a newer dual-use one`() {
        val cert = pubOf(ringWithSubkeys(0x20, 0x22))
        assertEquals(0x20, flagsOf(cert))
        val reversed = pubOf(ringWithSubkeys(0x22, 0x20))
        assertEquals(0x20, flagsOf(reversed))
    }

    @Test
    fun `a key without an auth subkey has none`() {
        val k = svc.generateKeyPair("N", "n@example.org", KeyAlgorithm.ED25519_CV25519, null, null)
        assertNull(SshAuth.authSubkey(k.publicKeyData))
        // A signing subkey is not an authentication subkey.
        val signOnly = ClassicalSubkeyGen.addSubkey(sec(k.privateKeyData), ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN, null)
        assertNull(SshAuth.authSubkey(pubOf(signOnly)))
    }

    @Test
    fun `an expired auth subkey is not offered and the newest live one wins`() {
        val k = svc.generateKeyPair("X", "x@example.org", KeyAlgorithm.ED25519_CV25519, null, null)
        val expiring = ClassicalSubkeyGen.addSubkey(
            sec(k.privateKeyData), ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH, null, expirationSeconds = 3600
        )
        val cert = pubOf(expiring)
        assertNotNull(SshAuth.authSubkey(cert))
        assertNull(SshAuth.authSubkey(cert, nowMs = System.currentTimeMillis() + 2 * 3600_000L))
        val second = ClassicalSubkeyGen.addSubkey(
            expiring, ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_AUTH, null,
            creationTime = Date(System.currentTimeMillis() + 1000)
        )
        assertTrue(SshAuth.material(SshAuth.authSubkey(pubOf(second))!!.publicBody) is SshAuth.Material.Rsa)
    }

    @Test
    fun `a protected auth subkey asks for its passphrase`() {
        val ring = withAuth(KeyAlgorithm.ED25519_CV25519, ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH, pass = "correct horse")
        val f = find(pubOf(ring))
        assertTrue(SshSigningKey.unlock(ring, f.keyId, null) is SshSigningKey.Unlock.NeedsPassphrase)
        assertTrue(SshSigningKey.unlock(ring, f.keyId, "wrong") is SshSigningKey.Unlock.WrongPassphrase)
        val key = unlock(ring, f.keyId, "correct horse")
        verify(f.m, SshAuth.sign(f.m, key, challenge, 0), challenge)
    }

    @Test
    fun `Ed25519 auth subkey on a composite ML-DSA key`() {
        val raw = CompositePrimaryKeyGen.assemble("Q <q@example.org>", CompositeSignSuite.MLDSA65_ED25519)
        assertNull(SshAuth.authSubkey(CompositeKeyFacade.publicRingOf(raw)))
        val withAuth = CompositePrimaryKeyGen.addClassicalSubkey(raw, ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH)
        val f = find(CompositeKeyFacade.publicRingOf(withAuth))
        val carrier = CompositeKeyFacade.classicalAuthRing(withAuth)!!
        assertEquals("ssh-ed25519", verify(f.m, SshAuth.sign(f.m, unlock(carrier, f.keyId), challenge, 0), challenge))
    }

    @Test
    fun `card path builds the same signatures`() {
        // Ed25519: the card signs the message itself (PureEdDSA).
        val ed = withAuth(KeyAlgorithm.ED25519_CV25519, ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH)
        val fe = find(pubOf(ed))
        val edKey = unlock(ed, fe.keyId) as Ed25519PrivateKeyParameters
        val edInput = SshAuth.cardInput(fe.m, challenge, 0)
        val edRaw = Ed25519Signer().run { init(true, edKey); update(edInput, 0, edInput.size); generateSignature() }
        verify(fe.m, SshAuth.blobFromCard(fe.m, edRaw, 0), challenge)

        // RSA: the card pads the DigestInfo (PKCS#1 v1.5) and runs the key.
        val rsa = withAuth(KeyAlgorithm.RSA_2048, ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_AUTH)
        val fr = find(pubOf(rsa))
        val rsaKey = unlock(rsa, fr.keyId)
        for (hash in listOf(SshAuth.HASH_SHA1, SshAuth.HASH_SHA256, SshAuth.HASH_SHA512)) {
            val input = SshAuth.cardInput(fr.m, challenge, hash)
            val raw = PKCS1Encoding(RSABlindedEngine()).run { init(true, rsaKey); processBlock(input, 0, input.size) }
            verify(fr.m, SshAuth.blobFromCard(fr.m, raw, hash), challenge)
        }
    }

    @Test
    fun `keygen adds an RSA auth subkey to an RSA key and Ed25519 to others`() {
        assertEquals(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_AUTH, ClassicalSubkeyGen.sshAuthTypeFor(KeyAlgorithm.RSA_2048))
        assertEquals(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_AUTH, ClassicalSubkeyGen.sshAuthTypeFor(KeyAlgorithm.RSA_4096))
        assertEquals(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH, ClassicalSubkeyGen.sshAuthTypeFor(KeyAlgorithm.ED25519_CV25519))
        assertEquals(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH, ClassicalSubkeyGen.sshAuthTypeFor(KeyAlgorithm.V6_ED25519))
        val ring = withAuth(KeyAlgorithm.RSA_2048, ClassicalSubkeyGen.sshAuthTypeFor(KeyAlgorithm.RSA_2048))
        val f = find(pubOf(ring))
        assertTrue(f.m is SshAuth.Material.Rsa)
        assertEquals("rsa-sha2-512", verify(f.m, SshAuth.sign(f.m, unlock(ring, f.keyId), challenge, SshAuth.HASH_SHA512), challenge))
    }

    @Test
    fun `wire mpint follows RFC 4251`() {
        fun enc(v: BigInteger) = SshWire().apply { mpint(v) }.bytes().joinToString("") { "%02x".format(it) }
        assertEquals("00000000", enc(BigInteger.ZERO))
        assertEquals("000000020080", enc(BigInteger.valueOf(0x80)))
        assertEquals("000000017f", enc(BigInteger.valueOf(0x7f)))
    }
}
