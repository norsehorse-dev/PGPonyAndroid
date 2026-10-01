// SignerIdentityA2Test.kt
// The signer of a verified signature is the exact key that verified it, by
// fingerprint (SOP-3, LOCAL-IPC-1, GAP-3); a data signature's own expiration
// is enforced (ENGINE-7); a certificate whose primary algorithm has no
// verifier vouches for no subkey (ENGINE-8); and only a verified key
// revocation is reported for a fetched copy (KEYSTORE-8).

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.RSAPublicBCPGKey
import org.bouncycastle.bcpg.sig.RevocationReasonTags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.util.encoders.Hex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

class SignerIdentityA2Test {

    private val svc = PGPCryptoService.shared
    private val data = "signed release notes".toByteArray()

    private fun gen(alg: KeyAlgorithm = KeyAlgorithm.ED25519_CV25519): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val g = svc.generateKeyPair("Signer", "signer@example.test", alg, null)
        return PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator()) to
            PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
    }

    private fun hex(fp: ByteArray) = Hex.toHexString(fp).uppercase()

    /** A detached signature by [sec]'s primary with a custom hashed and unhashed area. */
    private fun sign(
        sec: PGPSecretKeyRing,
        created: Date = Date(),
        expirySeconds: Long = 0,
        unhashedIssuer: Long? = null
    ): PGPSignature {
        val key = sec.secretKey
        val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(key.publicKey.algorithm, HashAlgorithmTags.SHA256), key.publicKey)
        gen.init(PGPSignature.BINARY_DOCUMENT, SecretKeyUnlock.extract(key, null))
        val h = PGPSignatureSubpacketGenerator()
        h.setSignatureCreationTime(false, created)
        if (expirySeconds > 0) h.setSignatureExpirationTime(false, expirySeconds)
        gen.setHashedSubpackets(h.generate())
        gen.update(data)
        val sig = gen.generate()
        return if (unhashedIssuer == null) sig else withUnhashedIssuer(sig, unhashedIssuer)
    }

    /** [sig] (v4) re-encoded with an unhashed area holding only IssuerKeyID([id]). */
    private fun withUnhashedIssuer(sig: PGPSignature, id: Long): PGPSignature {
        val pkt = CertificateBindings.packets(sig.encoded).first()
        val b = pkt.body
        val hLen = ((b[4].toInt() and 0xFF) shl 8) or (b[5].toInt() and 0xFF)
        val uAt = 6 + hLen
        val uLen = ((b[uAt].toInt() and 0xFF) shl 8) or (b[uAt + 1].toInt() and 0xFF)
        val issuer = byteArrayOf(9, 16) + ByteArray(8) { i -> (id ushr (56 - 8 * i)).toByte() }
        val body = b.copyOfRange(0, uAt) + byteArrayOf(0, issuer.size.toByte()) + issuer + b.copyOfRange(uAt + 2 + uLen, b.size)
        val list = org.bouncycastle.openpgp.bc.BcPGPObjectFactory(CertificateBindings.frame(2, body)).nextObject()
            as org.bouncycastle.openpgp.PGPSignatureList
        return list[0]
    }

    @Test
    fun `LOCAL-IPC-1 the reported key ID is the key that verified, not the issuer subpacket`() {
        val (aSec, aPub) = gen()
        val (_, bPub) = gen()
        val sig = sign(aSec, unhashedIssuer = bPub.publicKey.keyID)
        assertEquals("precondition: the signature names B", bPub.publicKey.keyID, sig.keyID)
        val r = VerifyService.shared.verifyDetached(sig.encoded, data, listOf(bPub, aPub))
        r as VerificationResult.Verified
        assertEquals(String.format("%016X", aPub.publicKey.keyID), r.signerKeyID)
        assertEquals(hex(aPub.publicKey.fingerprint), r.signingKeyFingerprint)
        assertEquals(hex(aPub.publicKey.fingerprint), r.signerFingerprint)
    }

    @Test
    fun `ENGINE-7 an expired data signature is not verified`() {
        val (sec, pub) = gen()
        val old = sign(sec, created = Date(System.currentTimeMillis() - 2 * 3600_000L), expirySeconds = 60)
        val r = VerifyService.shared.verifyDetached(old.encoded, data, listOf(pub))
        r as VerificationResult.Invalid
        assertEquals(SignerStatus.EXPIRED_SIGNATURE, r.signerStatus)
        assertEquals(hex(pub.publicKey.fingerprint), r.signingKeyFingerprint)
        assertTrue(SignaturePolicy.isExpired(old))
        assertEquals(SignerStatus.EXPIRED_SIGNATURE, SignerEvaluator.evaluate(old, pub.publicKey, listOf(pub)))
        // The streaming verifier grades it the same.
        val rs = VerifyService.shared.verifyDetachedStream(old.encoded, ByteArrayInputStream(data), listOf(pub))
        assertEquals(SignerStatus.EXPIRED_SIGNATURE, (rs as VerificationResult.Invalid).signerStatus)
        // A signature whose expiration is still ahead verifies.
        val live = sign(sec, created = Date(), expirySeconds = 3600)
        assertTrue(VerifyService.shared.verifyDetached(live.encoded, data, listOf(pub)) is VerificationResult.Verified)
    }

    /** A v3 RSA key whose key ID equals [target] (the low 64 bits of its modulus). */
    private fun v3KeyWithId(target: Long): PGPPublicKey {
        val rnd = SecureRandom()
        val two64 = BigInteger.ONE.shiftLeft(64)
        val t = BigInteger(java.lang.Long.toUnsignedString(target))
        while (true) {
            val p = BigInteger.probablePrime(512, rnd)
            val q0 = t.multiply(p.modInverse(two64)).mod(two64)
            for (i in 0 until 4000) {
                val q = BigInteger(448, rnd).shiftLeft(64).add(q0).setBit(511)
                if (!q.isProbablePrime(30)) continue
                val n = p.multiply(q)
                val pkt = PublicKeyPacket(3, PublicKeyAlgorithmTags.RSA_GENERAL, Date(), RSAPublicBCPGKey(n, BigInteger.valueOf(65537)))
                return PGPPublicKey(pkt, BcKeyFingerprintCalculator())
            }
        }
    }

    @Test
    fun `SOP-3 grading matches by fingerprint, so a key sharing the key ID gets nothing`() {
        var victim: PGPPublicKeyRing
        do { victim = gen().second } while (victim.publicKey.keyID and 1L == 0L)
        val impostor = v3KeyWithId(victim.publicKey.keyID)
        assertEquals("precondition: same key ID", victim.publicKey.keyID, impostor.keyID)
        assertNotEquals(hex(victim.publicKey.fingerprint), hex(impostor.fingerprint))
        // A lookup by key ID vouches for the impostor; by key it does not.
        assertEquals(SignerStatus.VERIFIED, SignerEvaluator.evaluate(impostor.keyID, Date(), listOf(victim)))
        assertEquals(SignerStatus.UNKNOWN_SIGNER, SignerEvaluator.evaluateKey(impostor, Date(), listOf(victim)))
        assertNull(SignerEvaluator.signerRing(impostor, listOf(victim)))
        assertNull(SignerEvaluator.validSignerView(impostor, listOf(victim)))
        assertEquals(SignerStatus.VERIFIED, SignerEvaluator.evaluateKey(victim.publicKey, Date(), listOf(victim)))
    }

    /** A certificate whose primary is Elgamal (no verifier here) carrying [extra] packets. */
    private fun elgamalCert(extra: ByteArray, revocation: PGPSignature? = null): PGPPublicKeyRing {
        val rnd = SecureRandom()
        val p = BigInteger.probablePrime(512, rnd)
        val pkt = PublicKeyPacket(4, PublicKeyAlgorithmTags.ELGAMAL_GENERAL, Date(), ElGamalPublicBCPGKey(p, BigInteger.TWO, BigInteger(500, rnd)))
        val primary = PGPPublicKey(pkt, BcKeyFingerprintCalculator())
        val out = ByteArrayOutputStream()
        primary.encode(out)
        if (revocation != null) out.write(revocation.encoded)
        out.write(extra)
        return PGPPublicKeyRing(ByteArrayInputStream(out.toByteArray()), BcKeyFingerprintCalculator())
    }

    @Test
    fun `ENGINE-8 an unverifiable primary cannot claim another certificate's signing subkey`() {
        val (vSec, vPub) = gen(KeyAlgorithm.V6_ED25519)
        val signSub = vPub.publicKeys.asSequence().first { !it.isMasterKey && it.algorithm == PublicKeyAlgorithmTags.Ed25519 }
        val copied = ByteArrayOutputStream().also { signSub.encode(it) }.toByteArray()
        val attacker = elgamalCert(copied)
        assertNotNull("precondition: the copied subkey is on the attacker ring", attacker.getPublicKey(signSub.fingerprint))
        val report = CertificateBindings.analyze(attacker)!!
        assertTrue(!report.supported)
        val subHex = hex(signSub.fingerprint)
        assertTrue(!report.isValidSignerKey(subHex))
        assertTrue(!report.isUsableEncryptionKey(subHex, System.currentTimeMillis()))
        assertEquals(CertificateBindings.SignerValidity.UNBOUND, report.signerValidityAt(subHex, System.currentTimeMillis()))

        val sigBytes = SigningService.shared.signDetached(data, vSec, armor = false)
        val alone = VerifyService.shared.verifyDetached(sigBytes, data, listOf(attacker))
        assertTrue(alone !is VerificationResult.Verified)
        val both = VerifyService.shared.verifyDetached(sigBytes, data, listOf(attacker, vPub))
        both as VerificationResult.Verified
        assertEquals(hex(vPub.publicKey.fingerprint), both.signerFingerprint)
        assertEquals(subHex, both.signingKeyFingerprint)

        // Encryption selection never picks a subkey off such a certificate.
        val view = CertificateBindings.verified(attacker)
        assertTrue(!SignerEvaluator.isUsableEncryptionKey(view, attacker.getPublicKey(signSub.fingerprint)))
    }

    private fun keyRevocation(sec: PGPSecretKeyRing): PGPSignature {
        val key = sec.secretKey
        val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(key.publicKey.algorithm, HashAlgorithmTags.SHA256), key.publicKey)
        gen.init(PGPSignature.KEY_REVOCATION, SecretKeyUnlock.extract(key, null))
        val h = PGPSignatureSubpacketGenerator()
        h.setSignatureCreationTime(false, Date())
        h.setRevocationReason(false, RevocationReasonTags.KEY_COMPROMISED, "lost")
        h.setIssuerFingerprint(false, key.publicKey)
        gen.setHashedSubpackets(h.generate())
        return gen.generateCertification(key.publicKey)
    }

    @Test
    fun `KEYSTORE-8 only a verified key revocation is reported`() {
        val (sec, pub) = gen()
        val rev = keyRevocation(sec)
        val revokedRing = PGPPublicKeyRing.insertPublicKey(pub, PGPPublicKey.addCertification(pub.publicKey, rev))
        val found = CertificateBindings.verifiedKeyRevocation(revokedRing)
        assertNotNull(found)
        assertEquals(RevocationReasonTags.KEY_COMPROMISED.toInt(), found!!.reason)
        assertNull(CertificateBindings.verifiedKeyRevocation(pub))

        // Someone else's revocation pasted onto the key does not verify.
        val (otherSec, _) = gen()
        val foreign = keyRevocation(otherSec)
        val forged = PGPPublicKeyRing.insertPublicKey(pub, PGPPublicKey.addCertification(pub.publicKey, foreign))
        assertNull(CertificateBindings.verifiedKeyRevocation(forged))

        // A primary this app cannot verify never yields a revocation.
        val elg = elgamalCert(ByteArray(0), revocation = foreign)
        assertTrue(elg.publicKey.signatures.asSequence().any { (it as PGPSignature).signatureType == PGPSignature.KEY_REVOCATION })
        assertNull(CertificateBindings.verifiedKeyRevocation(elg))
    }

    @Test
    fun `GAP-3 decrypt reports the fingerprints of the key that verified`() {
        val (sec, pub) = gen(KeyAlgorithm.V6_ED25519)
        val ct = svc.encrypt(data, listOf(pub), signingSecretKey = sec, passphrase = null, armor = false)
        val r = svc.decrypt(ct, listOf(sec), null, verificationKeys = listOf(pub))
        assertEquals(SignerStatus.VERIFIED, r.signerStatus)
        val signKey = pub.publicKeys.asSequence().first { !it.isMasterKey && it.algorithm == PublicKeyAlgorithmTags.Ed25519 }
        assertEquals(hex(signKey.fingerprint), r.signingKeyFingerprint)
        assertEquals(hex(pub.publicKey.fingerprint), r.signerPrimaryFingerprint)
        val sr = svc.decryptStream(ByteArrayInputStream(ct), ByteArrayOutputStream(), listOf(sec), null, verificationKeys = listOf(pub))
        assertEquals(hex(signKey.fingerprint), sr.signingKeyFingerprint)
        assertEquals(hex(pub.publicKey.fingerprint), sr.signerPrimaryFingerprint)
        // Without the signer's key nothing is claimed.
        val unknown = svc.decrypt(ct, listOf(sec), null, verificationKeys = emptyList())
        assertNull(unknown.signingKeyFingerprint)
    }
}
