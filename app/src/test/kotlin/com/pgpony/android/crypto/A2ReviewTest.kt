// A2ReviewTest.kt
// Follow-up checks for the signer, key-proof and composite gate work:
//   * KEYSTORE-4: a secret block proves a stored contact only through a key
//     that the stored certificate itself carries (an offline primary stub
//     next to someone else's secret subkey proves nothing);
//   * SOP-3: the streaming verifier still finds the signer when another held
//     key with the same key ID cannot even take the signature;
//   * ENGINE-4: a detached composite block signed by several keys verifies
//     when any one of them is a held, valid signer.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.pqc.CompositeDocumentSigner
import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositePrimaryKeyGen
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSignerGate
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.RSAPublicBCPGKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.util.encoders.Hex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

class A2ReviewTest {

    private val svc = PGPCryptoService.shared
    private val data = "review data".toByteArray()

    private fun gen(alg: KeyAlgorithm = KeyAlgorithm.ED25519_CV25519): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val g = svc.generateKeyPair("Owner", "owner@example.test", alg, null)
        return PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator()) to
            PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
    }

    private fun write(out: ByteArrayOutputStream, p: CertificateBindings.Packet) =
        out.write(CertificateBindings.frame(p.tag, p.body))

    @Test
    fun `KEYSTORE-4 a stub primary next to a foreign secret subkey proves nothing`() {
        val (_, victimPub) = gen()
        val (attackerSec, _) = gen()
        // The victim's primary (public), User ID and self-signatures ...
        val out = ByteArrayOutputStream()
        val vp = CertificateBindings.packets(victimPub.encoded)
        for (p in vp) {
            if (p.tag == 14) break
            write(out, p)
        }
        // ... followed by the attacker's own secret subkey and its binding.
        val ap = CertificateBindings.packets(attackerSec.encoded)
        val subAt = ap.indexOfFirst { it.tag == 7 }
        assertTrue("precondition: attacker has a secret subkey", subAt > 0)
        for (p in ap.drop(subAt)) write(out, p)
        val grafted = CertificateBindings.stubStrippedPrimary(out.toByteArray())
        assertEquals(
            "precondition: the primary became a stub",
            SecretKeyCheck.Protection.STUB,
            CertificateBindings.packets(grafted).first().let { SecretKeyCheck.protectionOf(it.tag, it.body) }
        )
        val got = SecretKeyCheck.checkSecretForPublic(grafted, victimPub.encoded)
        assertNotEquals(SecretKeyCheck.SecretMatch.OK, got)
        assertEquals(SecretKeyCheck.SecretMatch.UNPROVEN, got)
    }

    @Test
    fun `KEYSTORE-4 an own key with an offline primary still proves itself`() {
        val (sec, pub) = gen()
        val pkts = CertificateBindings.packets(sec.encoded)
        val out = ByteArrayOutputStream()
        out.write(CertificateBindings.frame(6, CertificateBindings.publicPart(pkts[0].tag, pkts[0].body)!!))
        for (p in pkts.drop(1)) write(out, p)
        val offline = CertificateBindings.stubStrippedPrimary(out.toByteArray())
        assertEquals(SecretKeyCheck.SecretMatch.OK, SecretKeyCheck.checkSecretForPublic(offline, pub.encoded))
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
    fun `SOP-3 the streaming verifier is not stopped by a held key sharing the key ID`() {
        var sec: PGPSecretKeyRing
        var pub: PGPPublicKeyRing
        do { val g = gen(KeyAlgorithm.RSA_2048); sec = g.first; pub = g.second } while (pub.publicKey.keyID and 1L == 0L)
        val impostor = PGPPublicKeyRing(listOf(v3KeyWithId(pub.publicKey.keyID)))
        assertEquals("precondition: same key ID", pub.publicKey.keyID, impostor.publicKey.keyID)
        val sig = SigningService.shared.signDetached(data, sec, armor = false)
        val rings = listOf(impostor, pub)
        val r = VerifyService.shared.verifyDetachedStream(sig, ByteArrayInputStream(data), rings)
        r as VerificationResult.Verified
        assertEquals(Hex.toHexString(pub.publicKey.fingerprint).uppercase(), r.signerFingerprint)
        // The in-memory verifier agrees.
        assertTrue(VerifyService.shared.verifyDetached(sig, data, rings) is VerificationResult.Verified)
    }

    @Test
    fun `ENGINE-4 a composite block signed by several keys verifies with any held signer`() {
        val suite = CompositeSignSuite.MLDSA65_ED25519
        val rnd = SecureRandom()
        fun key(): Pair<ByteArray, CompositeKeyFacade.Info> {
            val raw = CompositePrimaryKeyGen.assemble("Signer <s@example.test>", suite, rnd, Date(System.currentTimeMillis() - 86_400_000L), null)
            return raw to CompositeKeyFacade.parse(raw)
        }
        val (rawA, infoA) = key()
        val (rawB, infoB) = key()
        val sigA = CompositeDocumentSigner.signDetached(suite, infoA.compositeSecret!!, infoA.fingerprint, data, random = rnd)
        val sigB = CompositeDocumentSigner.signDetached(suite, infoB.compositeSecret!!, infoB.fingerprint, data, random = rnd)
        // Only B is held; A's signature comes first in the block.
        val g = CompositeSignerGate.verifyDetached(listOf(rawB), sigA + sigB, data)
        assertEquals(SignerStatus.VERIFIED, g.status)
        assertEquals(Hex.toHexString(infoB.fingerprint).uppercase(), g.signingKeyFingerprint)
        // Neither held: unknown signer, never verified.
        val none = CompositeSignerGate.verifyDetached(emptyList(), sigA + sigB, data)
        assertEquals(SignerStatus.UNKNOWN_SIGNER, none.status)
        // A alone still verifies as before.
        assertEquals(SignerStatus.VERIFIED, CompositeSignerGate.verifyDetached(listOf(rawA), sigA, data).status)
    }
}
