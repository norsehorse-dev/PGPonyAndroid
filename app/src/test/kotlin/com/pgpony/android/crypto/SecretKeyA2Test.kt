// SecretKeyA2Test.kt
// Secret-key handling: the Argon2 guard on every unlock path (ENGINE-9), the
// "every secret is passphrase protected" check (PAIRING-IMPL-6), and the
// proof that a secret-key block really belongs to a stored certificate
// (KEYSTORE-4).

package com.pgpony.android.crypto

import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositePrimaryKeyGen
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.ssh.SshSigningKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

class SecretKeyA2Test {

    private val svc = PGPCryptoService.shared
    private val pw = "correct horse battery staple"

    private fun gen(alg: KeyAlgorithm = KeyAlgorithm.ED25519_CV25519, pass: String? = null): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val g = svc.generateKeyPair("Owner", "owner@example.test", alg, pass)
        return PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator()) to
            PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
    }

    // ── ENGINE-9 ─────────────────────────────────────────────────────────

    /** [ring] with every Argon2 S2K's memory exponent set to [exp]. */
    private fun withArgon2Memory(ring: PGPSecretKeyRing, exp: Int): ByteArray {
        val bytes = ring.encoded
        for (k in ring.secretKeys) {
            val s2k = k.s2K ?: continue
            if (s2k.type != org.bouncycastle.bcpg.S2K.ARGON_2) continue
            val salt = s2k.iv
            var at = -1
            for (i in 0..bytes.size - salt.size) {
                if (bytes.copyOfRange(i, i + salt.size).contentEquals(salt)) { at = i; break }
            }
            assertTrue("salt found", at >= 0)
            // Salt, then passes, parallelism, memory exponent.
            bytes[at + salt.size + 2] = exp.toByte()
        }
        return bytes
    }

    /** [plain] with every secret key protected by AEAD (OCB) and Argon2 under [pass]. */
    private fun argon2Protected(plain: PGPSecretKeyRing, pass: String): PGPSecretKeyRing {
        var ring = plain
        for (k in plain.secretKeys) {
            val enc = org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder(
                org.bouncycastle.bcpg.AEADAlgorithmTags.OCB,
                org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256,
                org.bouncycastle.bcpg.S2K.Argon2Params.memoryConstrainedParameters()
            ).build(pass.toCharArray(), k.publicKey.publicKeyPacket)
            ring = PGPSecretKeyRing.insertSecretKey(ring, PGPSecretKey.copyWithNewPassword(k, null, enc))
        }
        return ring
    }

    @Test
    fun `ENGINE-9 an oversized Argon2 secret key is refused before the KDF on every unlock path`() {
        val sec = argon2Protected(gen(KeyAlgorithm.V6_ED25519).first, pw)
        assertTrue("precondition: Argon2", sec.secretKey.s2K.type == org.bouncycastle.bcpg.S2K.ARGON_2)
        val bad = PGPSecretKeyRing(ByteArrayInputStream(withArgon2Memory(sec, 30)), JcaKeyFingerprintCalculator())
        assertEquals(30, bad.secretKey.s2K.memorySizeExponent)

        for (k in bad.secretKeys) {
            try {
                SecretKeyUnlock.extract(k, pw.toCharArray())
                fail("extract must refuse")
            } catch (e: PGPCryptoError.ResourceLimitExceeded) {
            }
            // The decryptor alone refuses too, when Bouncy Castle drives it.
            try {
                k.extractPrivateKey(SecretKeyUnlock.decryptor(pw.toCharArray()))
                fail("decryptor must refuse")
            } catch (e: Exception) {
                assertNotNull(argon2PolicyCause(e))
            }
        }
        try {
            SigningService.shared.signDetached("x".toByteArray(), bad, pw)
            fail("signing must refuse")
        } catch (e: PGPCryptoError.ResourceLimitExceeded) {
        }
        val subId = bad.secretKeys.asSequence().first { !it.isMasterKey }.keyID
        assertTrue(SshSigningKey.unlock(bad, subId, pw) is SshSigningKey.Unlock.Missing)
        try {
            KeyPolicy.requireAcceptableProtection(bad)
            fail("import policy must refuse")
        } catch (e: KeyPolicy.RefusedProtection) {
        }
        try {
            svc.importKeyData(bad.encoded)
            fail("import must refuse")
        } catch (e: PGPCryptoError.ImportFailed) {
        }
        // The untouched key still unlocks and imports.
        for (k in sec.secretKeys) assertNotNull(SecretKeyUnlock.extract(k, pw.toCharArray()))
        KeyPolicy.requireAcceptableProtection(sec)
    }

    // ── PAIRING-IMPL-6 ───────────────────────────────────────────────────

    /** [unprotected] with only its primary protected under [pass]. */
    private fun primaryOnlyProtected(unprotected: PGPSecretKeyRing, pass: String): PGPSecretKeyRing {
        val enc = S2kPolicy.v4EncryptorBuilder().build(pass.toCharArray())
        val p = PGPSecretKey.copyWithNewPassword(unprotected.secretKey, null, enc)
        return PGPSecretKeyRing.insertSecretKey(unprotected, p)
    }

    /** [ring] with its primary reduced to a GNU stub (offline primary). */
    private fun offlinePrimary(ring: PGPSecretKeyRing): ByteArray {
        val pkts = CertificateBindings.packets(ring.encoded)
        val out = ByteArrayOutputStream()
        out.write(CertificateBindings.frame(6, CertificateBindings.publicPart(pkts[0].tag, pkts[0].body)!!))
        for (p in pkts.drop(1)) out.write(CertificateBindings.frame(p.tag, p.body))
        return CertificateBindings.stubStrippedPrimary(out.toByteArray())
    }

    @Test
    fun `PAIRING-IMPL-6 every secret packet must be protected`() {
        val (plain, _) = gen()
        val (prot, _) = gen(pass = pw)
        assertFalse(SecretKeyCheck.isFullyPassphraseProtected(plain))
        assertTrue(SecretKeyCheck.isFullyPassphraseProtected(prot))

        val mixed = primaryOnlyProtected(plain, pw)
        assertTrue("the old primary-only test says protected", svc.isPassphraseProtected(mixed))
        assertFalse(SecretKeyCheck.isFullyPassphraseProtected(mixed))

        val stubPlain = offlinePrimary(plain)
        val stubRing = PGPSecretKeyRing(ByteArrayInputStream(stubPlain), JcaKeyFingerprintCalculator())
        assertTrue("precondition: primary is a stub", stubRing.secretKey.isPrivateKeyEmpty)
        assertTrue("the old primary-only test says protected", svc.isPassphraseProtected(stubRing))
        assertFalse(SecretKeyCheck.isFullyPassphraseProtected(stubPlain))
        assertTrue(SecretKeyCheck.isFullyPassphraseProtected(offlinePrimary(prot)))
        assertEquals(SecretKeyCheck.Protection.STUB, CertificateBindings.packets(stubPlain).first().let {
            SecretKeyCheck.protectionOf(it.tag, it.body)
        })

        // v6 (AEAD + Argon2) keys.
        assertTrue(SecretKeyCheck.isFullyPassphraseProtected(gen(KeyAlgorithm.V6_ED25519, pw).first))
        assertFalse(SecretKeyCheck.isFullyPassphraseProtected(gen(KeyAlgorithm.V6_ED25519).first))
        // A public certificate holds nothing secret.
        assertTrue(SecretKeyCheck.isFullyPassphraseProtected(gen().second.encoded))
    }

    @Test
    fun `PAIRING-IMPL-6 composite keys count every component`() {
        val raw = CompositePrimaryKeyGen.assemble("PQ <pq@example.test>", CompositeSignSuite.MLDSA65_ED25519, SecureRandom())
        assertFalse(SecretKeyCheck.isFullyPassphraseProtected(raw))
        val prot = CompositeKeyFacade.reprotect(raw, null, pw.toCharArray())
        assertTrue(SecretKeyCheck.isFullyPassphraseProtected(prot))
        // Protected primary next to the unprotected ML-KEM subkey of the original.
        val pp = CertificateBindings.packets(prot)
        val rp = CertificateBindings.packets(raw)
        val out = ByteArrayOutputStream()
        for ((i, p) in pp.withIndex()) {
            val use = if (p.tag == 7) rp[i] else p
            out.write(CertificateBindings.frame(use.tag, use.body))
        }
        val mixed = out.toByteArray()
        assertTrue("the old primary-only test says protected", CompositeKeyFacade.isProtected(mixed))
        assertFalse(SecretKeyCheck.isFullyPassphraseProtected(mixed))
    }

    // ── KEYSTORE-4 ───────────────────────────────────────────────────────

    /** [pub]'s certificate with its primary turned into a secret packet holding [secretTail]. */
    private fun junkSecret(pub: PGPPublicKeyRing, secretTail: ByteArray): ByteArray {
        val pkts = CertificateBindings.packets(pub.encoded)
        val out = ByteArrayOutputStream()
        out.write(CertificateBindings.frame(5, pkts[0].body + secretTail))
        for (p in pkts.drop(1)) {
            if (p.tag == 14) break
            out.write(CertificateBindings.frame(p.tag, p.body))
        }
        return out.toByteArray()
    }

    @Test
    fun `KEYSTORE-4 a genuine secret proves itself`() {
        val (plain, plainPub) = gen()
        assertEquals(SecretKeyCheck.SecretMatch.OK, SecretKeyCheck.checkSecretForPublic(plain.encoded, plainPub.encoded))
        val (prot, protPub) = gen(pass = pw)
        assertEquals(SecretKeyCheck.SecretMatch.NEEDS_PASSPHRASE, SecretKeyCheck.checkSecretForPublic(prot.encoded, protPub.encoded))
        assertEquals(SecretKeyCheck.SecretMatch.OK, SecretKeyCheck.checkSecretForPublic(prot.encoded, protPub.encoded, pw.toCharArray()))
        assertEquals(
            SecretKeyCheck.SecretMatch.WRONG_PASSPHRASE,
            SecretKeyCheck.checkSecretForPublic(prot.encoded, protPub.encoded, "nope".toCharArray())
        )
        assertEquals(SecretKeyCheck.SecretMatch.PUBLIC_MISMATCH, SecretKeyCheck.checkSecretForPublic(plain.encoded, protPub.encoded))
        val (v6, v6Pub) = gen(KeyAlgorithm.V6_ED25519, pw)
        assertEquals(SecretKeyCheck.SecretMatch.OK, SecretKeyCheck.checkSecretForPublic(v6.encoded, v6Pub.encoded, pw.toCharArray()))
        val (rsa, rsaPub) = gen(KeyAlgorithm.RSA_2048)
        assertEquals(SecretKeyCheck.SecretMatch.OK, SecretKeyCheck.checkSecretForPublic(rsa.encoded, rsaPub.encoded))
        // Armored input works too.
        assertEquals(
            SecretKeyCheck.SecretMatch.OK,
            SecretKeyCheck.checkSecretForPublic(svc.exportArmoredPrivateKey(plain).toByteArray(), plainPub.encoded)
        )
    }

    @Test
    fun `KEYSTORE-4 a junk secret on a contact's public key is never accepted`() {
        val (_, pub) = gen()
        val rnd = SecureRandom()
        // Encrypted junk: S2K usage 254, AES-256, iterated SHA-256, random IV and data.
        val salt = ByteArray(8).also { rnd.nextBytes(it) }
        val encTail = byteArrayOf(0xFE.toByte(), 9, 3, 8) + salt + byteArrayOf(0x60) +
            ByteArray(16).also { rnd.nextBytes(it) } + ByteArray(54).also { rnd.nextBytes(it) }
        val encJunk = junkSecret(pub, encTail)
        assertEquals(SecretKeyCheck.SecretMatch.NEEDS_PASSPHRASE, SecretKeyCheck.checkSecretForPublic(encJunk, pub.encoded))
        assertEquals(
            SecretKeyCheck.SecretMatch.WRONG_PASSPHRASE,
            SecretKeyCheck.checkSecretForPublic(encJunk, pub.encoded, "anything".toCharArray())
        )
        assertTrue("structure alone passes the old check", svc.isPassphraseProtected(
            PGPSecretKeyRing(ByteArrayInputStream(encJunk), JcaKeyFingerprintCalculator())
        ))

        // Unprotected junk: a random EdDSA scalar.
        val scalar = ByteArray(32).also { rnd.nextBytes(it); it[0] = (it[0].toInt() or 0x80).toByte() }
        val mpi = byteArrayOf(0x01, 0x00) + scalar
        val sum = mpi.sumOf { it.toInt() and 0xFF } and 0xFFFF
        val plainTail = byteArrayOf(0) + mpi + byteArrayOf((sum shr 8).toByte(), sum.toByte())
        val plainJunk = junkSecret(pub, plainTail)
        val got = SecretKeyCheck.checkSecretForPublic(plainJunk, pub.encoded)
        assertTrue("got $got", got == SecretKeyCheck.SecretMatch.MATERIAL_MISMATCH || got == SecretKeyCheck.SecretMatch.UNREADABLE)

        // Stubs only: nothing to prove.
        val (sec, _) = gen()
        val stubOnly = CertificateBindings.packets(offlinePrimary(sec)).filter { it.tag != 7 && it.tag != 14 }
            .let { ps -> ByteArrayOutputStream().also { o -> ps.forEach { o.write(CertificateBindings.frame(it.tag, it.body)) } }.toByteArray() }
        assertEquals(
            SecretKeyCheck.SecretMatch.NO_SECRET,
            SecretKeyCheck.checkSecretForPublic(stubOnly, sec.encoded)
        )
    }

    @Test
    fun `KEYSTORE-4 composite secrets are proved by a signature`() {
        val raw = CompositePrimaryKeyGen.assemble("PQ <pq@example.test>", CompositeSignSuite.MLDSA65_ED25519, SecureRandom())
        val pub = CompositeKeyFacade.publicRingOf(raw)
        assertEquals(SecretKeyCheck.SecretMatch.OK, SecretKeyCheck.checkSecretForPublic(raw, pub))
        val prot = CompositeKeyFacade.reprotect(raw, null, pw.toCharArray())
        assertEquals(SecretKeyCheck.SecretMatch.NEEDS_PASSPHRASE, SecretKeyCheck.checkSecretForPublic(prot, pub))
        assertEquals(SecretKeyCheck.SecretMatch.OK, SecretKeyCheck.checkSecretForPublic(prot, pub, pw.toCharArray()))
        // The primary's secret replaced by random octets of the same length.
        val pkts = CertificateBindings.packets(raw)
        val p0 = pkts[0]
        val pubLen = CertificateBindings.publicPart(p0.tag, p0.body)!!.size
        val junkBody = p0.body.copyOf().also { b ->
            val r = ByteArray(b.size - pubLen - 1).also { SecureRandom().nextBytes(it) }
            r.copyInto(b, pubLen + 1)
        }
        val out = ByteArrayOutputStream()
        out.write(CertificateBindings.frame(p0.tag, junkBody))
        for (p in pkts.drop(1)) out.write(CertificateBindings.frame(p.tag, p.body))
        assertEquals(SecretKeyCheck.SecretMatch.MATERIAL_MISMATCH, SecretKeyCheck.checkSecretForPublic(out.toByteArray(), pub))
    }
}
