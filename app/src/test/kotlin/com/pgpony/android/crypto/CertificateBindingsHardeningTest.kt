// CertificateBindingsHardeningTest.kt
// PGPony Android, 4.6.0 (item 17.1, second pass)
//
// Cases found in review of the first binding-verification pass:
//
//   * a forged signature that names some other key by fingerprint but the
//     certificate's primary by key id must not survive as a "third-party"
//     certification (Bouncy Castle would read it as a self-signature and take
//     its expiry and key flags);
//   * a v3 subkey whose (attacker-chosen) key id equals a real subkey's must
//     never inherit that subkey's binding;
//   * a certificate padded past any size ceiling must not skip the checks;
//   * an expired encryption subkey is never a recipient;
//   * junk self-signatures on a large attribute cannot make a check slow or
//     starve the subkey bindings of their verification budget.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

class CertificateBindingsHardeningTest {

    private val svc = PGPCryptoService.shared

    private fun res(p: String): ByteArray = javaClass.getResourceAsStream(p)!!.use { it.readBytes() }
    private fun ring(b: ByteArray) = PGPPublicKeyRing(b, BcKeyFingerprintCalculator())
    private fun sp(type: Int, body: ByteArray) = byteArrayOf((body.size + 1).toByte(), type.toByte()) + body
    private fun be32(n: Long) = byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())
    private fun be64(n: Long) = ByteArray(8) { (n ushr (56 - 8 * it)).toByte() }

    /** A garbage 0x13 carrying an expiry and Encrypt-only flags, attributed to
     *  another key by fingerprint and to [victimId] by key id. */
    private fun spoofedCert(victimId: Long, variant: Int): ByteArray {
        val now = System.currentTimeMillis() / 1000
        var hashed = sp(2, be32(now)) + sp(27, byteArrayOf(0x0C)) + sp(9, be32(1))
        val unhashed = sp(16, be64(victimId))
        hashed += if (variant == 0) sp(33, byteArrayOf(4) + ByteArray(20) { 7 }) else sp(16, be64(0x1122334455667788L))
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(4, 0x13, 22, 8)); out.write(hashed.size shr 8); out.write(hashed.size and 0xff); out.write(hashed)
        out.write(unhashed.size shr 8); out.write(unhashed.size and 0xff); out.write(unhashed)
        out.write(byteArrayOf(0, 0, 0, 8, 0xFF.toByte(), 0, 8, 0xFF.toByte()))
        return out.toByteArray()
    }

    @Test
    fun `a signature naming the primary by key id is treated as a self-signature and must verify`() {
        val raw = res("/keys/bindings/gpg-ed25519.pgp")
        val victim = ring(raw)
        val vid = victim.publicKey.keyID
        for (variant in 0..1) {
            val pk = CertificateBindings.packets(raw)
            val out = ByteArrayOutputStream()
            var inserted = false
            for ((i, p) in pk.withIndex()) {
                out.write(CertificateBindings.frame(p.tag, p.body))
                if (!inserted && p.tag == 2 && i > 0 && pk[i - 1].tag == 13) {
                    out.write(CertificateBindings.frame(2, spoofedCert(vid, variant))); inserted = true
                }
            }
            val tampered = out.toByteArray()
            val clean = ring(CertificateBindings.sanitize(tampered))
            val sigs = clean.publicKey.signatures.asSequence().toList()
            assertEquals("spoofed certification dropped", victim.publicKey.signatures.asSequence().count(), sigs.size)
            assertEquals(0L, clean.publicKey.validSeconds)
            assertEquals(SignerStatus.VERIFIED, SignerEvaluator.evaluate(vid, Date(), listOf(ring(tampered))))
            assertTrue(svc.encryptionKeyOptions(ring(tampered)).isNotEmpty())
            val merged = ring(CertificateMerge.merge(raw, tampered, isKeyPair = false))
            assertEquals(0L, merged.publicKey.validSeconds)
        }
    }

    private fun mpi(x: BigInteger): ByteArray {
        val b = x.toByteArray().let { if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        val bits = x.bitLength()
        return byteArrayOf((bits shr 8).toByte(), bits.toByte()) + b
    }

    /** A v3 RSA key packet body whose key id (low 64 bits of n) is [target]. */
    private fun v3KeyWithId(target: Long): ByteArray {
        val rnd = SecureRandom()
        val m64 = BigInteger.ONE.shiftLeft(64)
        val t = BigInteger.valueOf(target).mod(m64)
        while (true) {
            val p = BigInteger.probablePrime(512, rnd)
            val q0 = t.multiply(p.modInverse(m64)).mod(m64)
            for (i in 0 until 50000) {
                val c = BigInteger(448, rnd).shiftLeft(64).add(q0).setBit(511)
                if (c.isProbablePrime(20)) {
                    val n = p.multiply(c)
                    return ByteArrayOutputStream().apply {
                        write(3); write(byteArrayOf(0x60, 0, 0, 0)); write(0); write(0); write(1)
                        write(mpi(n)); write(mpi(BigInteger.valueOf(65537)))
                    }.toByteArray()
                }
            }
        }
    }

    @Test
    fun `a v3 subkey carrying a real subkey's key id is never a recipient`() {
        val raw = res("/keys/bindings/gpg-ed25519.pgp")
        val legit = ring(raw).publicKeys.asSequence().first { !it.isMasterKey && it.isEncryptionKey }
        // An RSA modulus is odd, so only an odd key id can be forged; this fixture's is.
        assertEquals(1L, legit.keyID and 1L)
        val v3 = CertificateBindings.frame(14, v3KeyWithId(legit.keyID))
        val pk = CertificateBindings.packets(raw)
        for (placeFirst in listOf(true, false)) {
            val out = ByteArrayOutputStream()
            var ins = false
            for (p in pk) {
                if (placeFirst && !ins && p.tag == 14) { out.write(v3); ins = true }
                out.write(CertificateBindings.frame(p.tag, p.body))
            }
            if (!placeFirst) out.write(v3)
            val tampered = out.toByteArray()
            assertFalse("sanitize drops the v3 subkey",
                CertificateBindings.packets(CertificateBindings.sanitize(tampered)).any { it.tag == 14 && it.body[0].toInt() == 3 })
            val r = ring(tampered)
            val chosen = svc.encryptionKeys(r)
            assertTrue(chosen.isNotEmpty())
            assertTrue("no v3 recipient", chosen.all { it.version >= 4 })
            val merged = CertificateMerge.merge(raw, tampered, isKeyPair = false)
            assertFalse(CertificateBindings.packets(merged).any { it.tag == 14 && it.body[0].toInt() == 3 })
        }
    }

    @Test
    fun `a certificate padded to many megabytes still gets every check`() {
        val victim = res("/keys/bindings/gpg-ed25519.pgp")
        val other = res("/keys/bindings/gpg-nistp256.pgp")
        val op = CertificateBindings.packets(other)
        val vp = CertificateBindings.packets(victim)
        val firstSub = vp.indexOfFirst { it.tag == 14 }
        val out = ByteArrayOutputStream()
        for (p in vp.take(firstSub)) out.write(CertificateBindings.frame(p.tag, p.body))
        val img = ByteArray(1900 * 1024)
        val attr = ByteArrayOutputStream().apply {
            val n = 1 + 16 + img.size
            write(255); write(n ushr 24); write(n ushr 16); write(n ushr 8); write(n); write(1)
            write(byteArrayOf(0x10, 0, 1, 1)); write(ByteArray(12)); write(img)
        }.toByteArray()
        repeat(5) { out.write(CertificateBindings.frame(17, attr)) }
        for (p in vp.drop(firstSub)) out.write(CertificateBindings.frame(p.tag, p.body))
        for (p in op.drop(op.indexOfFirst { it.tag == 14 })) out.write(CertificateBindings.frame(p.tag, p.body))
        val tampered = out.toByteArray()
        assertTrue(tampered.size > 9 * 1024 * 1024)
        val r = ring(tampered)
        val foreign = r.publicKeys.asSequence().last()
        assertTrue(svc.encryptionKeys(r).none { it.keyID == foreign.keyID })
        assertNull(SignerEvaluator.validSignerView(foreign.keyID, listOf(r)))
        assertNull(ring(CertificateBindings.sanitize(tampered)).getPublicKey(foreign.keyID))
    }

    @Test
    fun `an expired encryption subkey is never a recipient`() {
        val raw = res("/keys/bindings/gpg-expired-subkey.pgp")
        val report = CertificateBindings.analyze(raw)!!
        val subs = report.subkeys
        assertEquals(2, subs.size)
        val now = System.currentTimeMillis()
        val expired = subs.first { it.expiresAtMs != null }
        val live = subs.first { it.expiresAtMs == null }
        assertFalse(report.isUsableEncryptionKey(expired.fingerprintHex, now))
        assertTrue(report.isUsableEncryptionKey(live.fingerprintHex, now))
        val options = svc.encryptionKeyOptions(ring(raw)).map { it.keyId }
        assertEquals(listOf(live.keyId), options)
    }

    @Test
    fun `junk signatures on a large attribute neither stall the check nor starve the subkeys`() {
        val v = res("/keys/bindings/gpg-ed25519.pgp")
        val fpr = ring(v).publicKey.fingerprint
        val vp = CertificateBindings.packets(v)
        val fs = vp.indexOfFirst { it.tag == 14 }
        val out = ByteArrayOutputStream()
        vp.take(fs).forEach { out.write(CertificateBindings.frame(it.tag, it.body)) }
        val img = ByteArray(1900 * 1024)
        val n = 1 + 16 + img.size
        val ua = ByteArrayOutputStream().apply {
            write(255); write(n ushr 24); write(n ushr 16); write(n ushr 8); write(n); write(1)
            write(byteArrayOf(0x10, 0, 1, 1)); write(ByteArray(12)); write(img)
        }.toByteArray()
        out.write(CertificateBindings.frame(17, ua))
        val hashed = sp(2, byteArrayOf(0x60, 0, 0, 0)) + sp(33, byteArrayOf(4) + fpr)
        val junk = ByteArrayOutputStream().apply {
            write(byteArrayOf(4, 0x13, 22, 8, 0, hashed.size.toByte())); write(hashed)
            write(byteArrayOf(0, 0, 0, 0)); write(byteArrayOf(0, 8, 0xFF.toByte(), 0, 8, 0xFF.toByte()))
        }.toByteArray()
        repeat(2000) { out.write(CertificateBindings.frame(2, junk)) }
        vp.drop(fs).forEach { out.write(CertificateBindings.frame(it.tag, it.body)) }
        val t = out.toByteArray()
        val start = System.nanoTime()
        val (_, report) = CertificateBindings.sanitizeAndAnalyze(t)
        val ms = (System.nanoTime() - start) / 1_000_000
        assertTrue("took $ms ms", ms < 5_000)
        val r = report!!
        assertEquals(2, r.subkeys.size)
        assertTrue("real subkeys still bound", r.subkeys.all { it.bound })
    }

}
