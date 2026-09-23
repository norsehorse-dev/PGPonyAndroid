// CertificateBindingsTest.kt
// PGPony Android, 4.6.0 (item 17.1)
//
// Binding-signature verification. Two halves:
//
//   * Nothing legitimate breaks: every key type the app generates, the
//     RFC 9580 / RFC 9980 / Sequoia / LibrePGP fixtures, and a GnuPG-made key
//     of every classical algorithm (RSA, DSA + Elgamal, NIST, brainpool,
//     secp256k1, Ed25519, Ed448, a SHA-1 key from 2015) analyse as fully bound,
//     with signing subkeys back-signed, and sanitize to the same components.
//   * Nothing unbound is used: a subkey grafted onto a real certificate (bound
//     by the wrong key, or carrying a garbage binding that claims the right
//     issuer) is never listed, stored or chosen as a recipient; a signing
//     subkey grafted onto another certificate without its back-signature does
//     not lend that certificate its name; a forged revocation is ignored.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

class CertificateBindingsTest {

    private val svc = PGPCryptoService.shared

    // ── helpers ──────────────────────────────────────────────────────

    private fun resource(path: String): ByteArray {
        val b = javaClass.getResourceAsStream(path)!!.use { it.readBytes() }
        val head = String(b, 0, minOf(b.size, 64), Charsets.ISO_8859_1)
        return if (head.contains("-----BEGIN")) ArmoredInputStream(ByteArrayInputStream(b)).readBytes() else b
    }

    private fun pub(raw: ByteArray) = PGPPublicKeyRing(raw, BcKeyFingerprintCalculator())

    private fun fp(k: org.bouncycastle.openpgp.PGPPublicKey) =
        org.bouncycastle.util.encoders.Hex.toHexString(k.fingerprint)

    private fun assertFullyBound(name: String, raw: ByteArray) {
        val r = CertificateBindings.analyze(raw)
        assertNotNull("$name: report", r)
        r!!
        assertTrue("$name: supported", r.supported)
        assertFalse("$name: not revoked", r.primaryRevoked)
        for (s in r.subkeys) assertTrue("$name: subkey ${s.fingerprintHex} bound", s.bound)
        val clean = CertificateBindings.sanitize(raw)
        val r2 = CertificateBindings.analyze(clean)!!
        assertEquals("$name: sanitize keeps every subkey", r.subkeys.map { it.fingerprintHex }, r2.subkeys.map { it.fingerprintHex })
        assertEquals("$name: sanitize keeps every User ID", r.certifiedUserIds, r2.certifiedUserIds)
        assertEquals("$name: sanitize is idempotent", clean.toList(), CertificateBindings.sanitize(clean).toList())
    }

    private fun ed25519Pair(algo: Int = PublicKeyAlgorithmTags.EDDSA_LEGACY): PGPKeyPair {
        val g = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
        g.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
        return BcPGPKeyPair(algo, g.generateKeyPair(), Date())
    }

    private fun x25519Pair(): PGPKeyPair {
        val g = org.bouncycastle.crypto.generators.X25519KeyPairGenerator()
        g.init(org.bouncycastle.crypto.params.X25519KeyGenerationParameters(SecureRandom()))
        return BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, g.generateKeyPair(), Date())
    }

    /** A v4 Ed25519 certify-only primary with an Ed25519 signing subkey (back-signed)
     *  and an X25519 encryption subkey, built directly with Bouncy Castle. */
    private fun v4KeyWithSigningSubkey(uid: String): PGPSecretKeyRing {
        val master = ed25519Pair()
        val signSub = ed25519Pair()
        val encSub = x25519Pair()
        val sha1 = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        val mh = PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.CERTIFY_OTHER) }
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, master, uid, sha1, mh.generate(), null,
            BcPGPContentSignerBuilder(master.publicKey.algorithm, HashAlgorithmTags.SHA256), null
        )
        val sh = PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.SIGN_DATA) }
        gen.addSubKey(
            signSub, sh.generate(), null,
            BcPGPContentSignerBuilder(signSub.publicKey.algorithm, HashAlgorithmTags.SHA256)
        )
        val eh = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        }
        gen.addSubKey(encSub, eh.generate(), null)
        return gen.generateSecretKeyRing()
    }

    /** A 0x18 made by [signerRing]'s primary over ([boundPrimary], [sub]). */
    private fun bindingBy(
        signerRing: PGPSecretKeyRing,
        boundPrimary: org.bouncycastle.openpgp.PGPPublicKey,
        sub: org.bouncycastle.openpgp.PGPPublicKey,
        flags: Int,
        claimIssuerFingerprint: ByteArray? = null
    ): PGPSignature {
        val sk = signerRing.secretKey
        val priv = sk.extractPrivateKey(null)
        val g = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey
        )
        g.init(PGPSignature.SUBKEY_BINDING, priv)
        val h = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, flags)
            setSignatureCreationTime(false, Date())
            if (claimIssuerFingerprint != null) setIssuerFingerprint(false, boundPrimary)
        }
        g.setHashedSubpackets(h.generate())
        return g.generateCertification(boundPrimary, sub)
    }

    /** Raw public subkey packet (tag 14) for [key]. */
    private fun subkeyPacket(ringBytes: ByteArray, keyId: Long): ByteArray {
        for (p in CertificateBindings.packets(ringBytes)) {
            if (p.tag != 14 && p.tag != 7) continue
            val body = CertificateBindings.publicPart(p.tag, p.body) ?: continue
            if (CertificateBindings.KeyBody(body).keyId == keyId) return CertificateBindings.frame(14, body)
        }
        error("subkey not found")
    }

    private fun recipientKeyIds(ciphertext: ByteArray): Set<Long> {
        val f = BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(ciphertext)))
        var o = f.nextObject()
        while (o != null && o !is PGPEncryptedDataList) o = f.nextObject()
        val list = o as PGPEncryptedDataList
        return (0 until list.size()).mapNotNull { (list[it] as? PGPPublicKeyEncryptedData)?.keyIdentifier?.keyId }.toSet()
    }

    // ── nothing legitimate breaks ───────────────────────────────────

    @Test
    fun `every generated key type is fully bound and survives sanitize`() {
        val types = listOf(
            KeyAlgorithm.RSA_2048, KeyAlgorithm.ED25519_CV25519, KeyAlgorithm.V6_ED25519,
            KeyAlgorithm.MLKEM768_X25519_V6, KeyAlgorithm.MLKEM1024_X448_V6,
            KeyAlgorithm.MLKEM768_X25519_LIBREPGP, KeyAlgorithm.MLKEM1024_X448_LIBREPGP
        )
        for (t in types) {
            val k = svc.generateKeyPair("Bound $t", "b@pgpony.app", t, null, null)
            assertFullyBound("$t public", k.publicKeyData)
            assertFullyBound("$t secret", k.privateKeyData)
        }
    }

    @Test
    fun `generated signing subkeys carry a verified back-signature`() {
        val k = svc.generateKeyPair("V6", "v6@pgpony.app", KeyAlgorithm.V6_ED25519, null, null)
        val r = CertificateBindings.analyze(k.publicKeyData)!!
        val signing = r.subkeys.filter { it.algorithm == 27 }
        assertTrue(signing.isNotEmpty())
        signing.forEach { assertTrue("Ed25519 signing subkey back-signed", it.backSigned) }
    }

    @Test
    fun `standard fixtures are fully bound`() {
        for (f in listOf(
            "/rfc9580/a3_cert.asc", "/rfc9580/a4_secret.asc", "/pqc/librepgp-clean-pub.asc",
            "/pqc/rfc9980-a2-v4-ed25519-mlkem768-pub.asc", "/pqc/rfc9980-a3-mldsa65-ed25519-cert.asc",
            "/pqc/rfc9580-pqc-sample-key.asc", "/pqc/gpg-bp384-ecdsa-pub.asc", "/pqc/sq-1024-sec.asc",
            "/pqc/sq-sec.pgp", "/keys/uid-selfsig-expiry-rsa.asc"
        )) assertFullyBound(f, resource(f))
    }

    @Test
    fun `GnuPG keys of every classical algorithm are fully bound with back-signed signing subkeys`() {
        val names = listOf(
            "rsa3072", "dsa2048", "nistp256", "nistp384", "nistp521", "brainpoolP256r1",
            "brainpoolP384r1", "brainpoolP512r1", "secp256k1", "ed25519", "ed448", "sha1-2015"
        )
        for (n in names) {
            val raw = resource("/keys/bindings/gpg-$n.pgp")
            assertFullyBound(n, raw)
            val r = CertificateBindings.analyze(raw)!!
            val signingAlgos = setOf(1, 17, 19, 22)
            // The last subkey of each multi-subkey fixture is the [S] subkey gpg added.
            if (r.subkeys.size >= 2) {
                val s = r.subkeys.last()
                assertTrue("$n: signing subkey algo", s.algorithm in signingAlgos)
                assertTrue("$n: signing subkey back-signed", s.backSigned)
            }
        }
    }

    @Test
    fun `a subkey revoked by its primary is reported revoked and never chosen`() {
        val raw = resource("/keys/bindings/gpg-ed25519-subrevoked.pgp")
        val r = CertificateBindings.analyze(raw)!!
        val enc = r.subkeys.first { it.algorithm == 18 }
        assertTrue(enc.revoked)
        assertTrue(svc.encryptionKeyOptions(pub(raw)).none { it.keyId == enc.keyId })
    }

    // ── nothing unbound is used ─────────────────────────────────────

    @Test
    fun `an encryption subkey bound by another key is dropped and never chosen`() {
        val victim = svc.generateKeyPair("Victim", "victim@pgpony.app", KeyAlgorithm.ED25519_CV25519, null, null)
        val victimPub = pub(victim.publicKeyData)
        val attacker = v4KeyWithSigningSubkey("Attacker <a@evil.example>")
        val attackerEnc = attacker.publicKeys.asSequence().last()
        val forged = bindingBy(attacker, victimPub.publicKey, attackerEnc, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        // A second graft: a garbage binding that claims the victim as issuer.
        val claimed = bindingBy(attacker, victimPub.publicKey, attackerEnc,
            KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE, claimIssuerFingerprint = victimPub.publicKey.fingerprint)
        for (sig in listOf(forged, claimed)) {
            // Attacker subkey placed FIRST so a naive "first encryption subkey" picks it.
            val victimPackets = CertificateBindings.packets(victim.publicKeyData)
            val doctored = ByteArrayOutputStream().apply {
                for (p in victimPackets.takeWhile { it.tag != 14 }) write(CertificateBindings.frame(p.tag, p.body))
                write(subkeyPacket(attacker.publicKey.let { PGPPublicKeyRing(attacker.publicKeys.asSequence().toList()).encoded }, attackerEnc.keyID))
                write(sig.encoded)
                for (p in victimPackets.dropWhile { it.tag != 14 }) write(CertificateBindings.frame(p.tag, p.body))
            }.toByteArray()

            val r = CertificateBindings.analyze(doctored)!!
            assertFalse("grafted subkey not bound", r.subkeyByFingerprint(fp(attackerEnc))?.bound ?: false)
            val clean = CertificateBindings.sanitize(doctored)
            assertNull("sanitize drops the grafted subkey", CertificateBindings.analyze(clean)!!.subkeyByFingerprint(fp(attackerEnc)))

            // Import (the path a key server, WKD or a shared file takes) drops it.
            val imported = svc.importKeyData(doctored).publicKeyRing!!
            assertNull(imported.getPublicKey(attackerEnc.keyID))

            // Even an unsanitized ring handed straight to encrypt never uses it.
            val raw = pub(doctored)
            assertNotNull("BC itself still parses the grafted subkey", raw.getPublicKey(attackerEnc.keyID))
            assertTrue(svc.encryptionKeyOptions(raw).none { it.keyId == attackerEnc.keyID })
            val ct = svc.encrypt("hello".toByteArray(), listOf(raw), armor = false)
            val ids = recipientKeyIds(ct)
            assertFalse("not encrypted to the attacker", attackerEnc.keyID in ids)
            val realEnc = victimPub.publicKeys.asSequence().first { !it.isMasterKey }.keyID
            assertTrue("encrypted to the real subkey", realEnc in ids)
        }
    }

    @Test
    fun `a grafted ML-KEM subkey on a v6 certificate is never chosen`() {
        val victim = svc.generateKeyPair("V", "v@pgpony.app", KeyAlgorithm.V6_ED25519, null, null)
        val attacker = svc.generateKeyPair("A", "a@evil.example", KeyAlgorithm.MLKEM768_X25519_V6, null, null)
        // Take the attacker's algo-35 subkey WITH the attacker's own binding and
        // append it to the victim certificate.
        val ap = CertificateBindings.packets(attacker.publicKeyData)
        val idx = ap.indexOfFirst { it.tag == 14 && (it.body[5].toInt() and 0xFF) == 35 }
        val graft = ByteArrayOutputStream().apply {
            write(CertificateBindings.frame(14, ap[idx].body))
            for (p in ap.drop(idx + 1).takeWhile { it.tag == 2 }) write(CertificateBindings.frame(2, p.body))
        }.toByteArray()
        val doctored = victim.publicKeyData + graft
        val raw = pub(doctored)
        val grafted = raw.publicKeys.asSequence().first { it.algorithm == 35 }
        assertFalse(CertificateBindings.analyze(doctored)!!.subkeyByFingerprint(fp(grafted))?.bound ?: false)
        assertTrue(svc.encryptionKeyOptions(raw).none { it.keyId == grafted.keyID })
        assertFalse("does not become a post-quantum recipient", svc.isPostQuantumRecipient(raw))
    }

    @Test
    fun `a composite primary ignores a grafted signer or encryption subkey`() {
        val host = resource("/pqc/sq-sec.pgp")          // ML-DSA-65 primary
        val donor = resource("/pqc/sq-1024-sec.asc")    // ML-DSA-87 primary
        val dp = CertificateBindings.packets(donor)
        val graft = ByteArrayOutputStream()
        // Every donor subkey with its (donor-made) bindings.
        var i = 0
        while (i < dp.size) {
            val p = dp[i]
            if (p.tag == 7 || p.tag == 14) {
                graft.write(CertificateBindings.frame(14, CertificateBindings.publicPart(p.tag, p.body)!!))
                var j = i + 1
                while (j < dp.size && dp[j].tag == 2) { graft.write(CertificateBindings.frame(2, dp[j].body)); j++ }
                i = j
            } else i++
        }
        val hostPub = CompositeKeyFacade.publicRingOf(host)
        val before = CompositeKeyFacade.parse(hostPub)
        val doctored = hostPub + graft.toByteArray()
        val after = CompositeKeyFacade.parse(doctored)
        assertEquals("no extra composite signer", before.compositeSigners.map { it.fingerprintHex }, after.compositeSigners.map { it.fingerprintHex })
        assertEquals("same encryption subkey", before.encryptionSubkey?.fingerprint?.toList(), after.encryptionSubkey?.fingerprint?.toList())
        // Lifting the ML-KEM subkey for encryption also picks the host's own.
        val lifted = CompositeKeyFacade.encryptionSubkeyRing(doctored)!!
        assertEquals(
            before.encryptionSubkey!!.fingerprint.toList(),
            lifted.publicKey.fingerprint.toList()
        )
    }

    @Test
    fun `a signing subkey grafted onto another certificate does not lend it its name`() {
        val victim = v4KeyWithSigningSubkey("Victim <v@pgpony.app>")
        val victimPub = PGPPublicKeyRing(victim.publicKeys.asSequence().toList())
        val victimSign = victim.secretKeys.asSequence().toList()[1]
        val attacker = v4KeyWithSigningSubkey("Attacker <a@evil.example>")
        val attackerPub = PGPPublicKeyRing(attacker.publicKeys.asSequence().toList())
        // The attacker CAN make a valid 0x18 over the victim's subkey; it cannot
        // make the 0x19 back-signature, which needs the victim's subkey secret.
        val binding = bindingBy(attacker, attackerPub.publicKey, victimSign.publicKey, KeyFlags.SIGN_DATA)
        val doctored = attackerPub.encoded + subkeyPacket(victimPub.encoded, victimSign.keyID) + binding.encoded
        val attackerDoctored = pub(doctored)
        val r = CertificateBindings.analyze(doctored)!!
        val st = r.subkeyByFingerprint(fp(victimSign.publicKey))!!
        assertTrue("attacker binding verifies", st.bound)
        assertFalse("no back-signature", st.backSigned)

        // The victim signs a document with the real subkey.
        val g = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(victimSign.publicKey.algorithm, HashAlgorithmTags.SHA256), victimSign.publicKey
        )
        g.init(PGPSignature.BINARY_DOCUMENT, victimSign.extractPrivateKey(null))
        g.update("pay 100".toByteArray())
        val sig = g.generate()
        sig.init(BcPGPContentVerifierBuilderProvider(), victimSign.publicKey)
        sig.update("pay 100".toByteArray())
        assertTrue(sig.verify())

        assertEquals(SignerStatus.UNBOUND_SIGNER, SignerEvaluator.evaluate(sig, listOf(attackerDoctored)))
        // With both certificates present, the signature is the victim's.
        assertEquals(SignerStatus.VERIFIED, SignerEvaluator.evaluate(sig, listOf(attackerDoctored, victimPub)))
        assertEquals(
            victimPub.publicKey.keyID,
            SignerEvaluator.signerRing(victimSign.keyID, listOf(attackerDoctored, victimPub))!!.publicKey.keyID
        )
    }

    @Test
    fun `a forged key revocation is ignored`() {
        val victim = svc.generateKeyPair("Victim", "victim@pgpony.app", KeyAlgorithm.ED25519_CV25519, null, null)
        val victimPub = pub(victim.publicKeyData)
        val attacker = v4KeyWithSigningSubkey("Attacker <a@evil.example>")
        val sk = attacker.secretKey
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey)
        g.init(PGPSignature.KEY_REVOCATION, sk.extractPrivateKey(null))
        g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date()); setIssuerFingerprint(false, victimPub.publicKey)
        }.generate())
        val rev = g.generateCertification(victimPub.publicKey)
        // Insert right after the primary key packet.
        val vp = CertificateBindings.packets(victim.publicKeyData)
        val doctored = CertificateBindings.frame(vp[0].tag, vp[0].body) + rev.encoded +
            vp.drop(1).fold(ByteArray(0)) { acc, p -> acc + CertificateBindings.frame(p.tag, p.body) }
        assertTrue("BC alone would call it revoked", pub(doctored).publicKey.hasRevocation())
        assertFalse(CertificateBindings.analyze(doctored)!!.primaryRevoked)
        assertFalse(svc.importKeyData(doctored).publicKeyRing!!.publicKey.hasRevocation())
        assertTrue("still encryptable", svc.encryptionKeyOptions(pub(doctored)).isNotEmpty())
    }

    @Test
    fun `a weak data signature is not graded verified`() {
        val k = v4KeyWithSigningSubkey("Signer <s@pgpony.app>")
        val pubRing = PGPPublicKeyRing(k.publicKeys.asSequence().toList())
        val sub = k.secretKeys.asSequence().toList()[1]
        fun signWith(hash: Int): PGPSignature {
            val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sub.publicKey.algorithm, hash), sub.publicKey)
            g.init(PGPSignature.BINARY_DOCUMENT, sub.extractPrivateKey(null))
            g.update("x".toByteArray())
            return g.generate()
        }
        assertEquals(SignerStatus.VERIFIED, SignerEvaluator.evaluate(signWith(HashAlgorithmTags.SHA256), listOf(pubRing)))
        assertEquals(SignerStatus.WEAK_SIGNATURE, SignerEvaluator.evaluate(signWith(HashAlgorithmTags.SHA1), listOf(pubRing)))
    }
}
