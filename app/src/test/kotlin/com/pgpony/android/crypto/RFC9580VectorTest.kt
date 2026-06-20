// RFC9580VectorTest.kt
// PGPony Android
//
// V6-7: regression-locks PGPony's v6 *consume* paths against the canonical
// RFC 9580 Appendix A test vectors, exercised through PGPony's own
// VerifyService / PGPCryptoService (not raw BouncyCastle).
//
// The vector files are deliberately NOT embedded in source. Transcribing ~200
// lines of base64 ASCII armor by hand risks byte errors that would make these
// tests worse than nothing. Instead they live (verbatim, from rfc-editor.org)
// in src/test/resources/rfc9580/, populated by tools/fetch_rfc9580_vectors.sh.
// Each test skips via Assume when its vector is absent, so CI stays green
// before the fetch and locks the v6 paths once the vectors are present.
//
//   a3_cert.asc       A.3    Sample Version 6 Certificate
//   a4_secret.asc     A.4    Sample Version 6 Secret Key (unlocked)
//   a6_cleartext.asc  A.6    Sample Cleartext Signed Message
//   a7_inline.asc     A.7    Sample Inline-Signed Message
//   a8_encrypted.asc  A.8.5  Complete X25519-AEAD-OCB Encrypted Packet Sequence
//
// These assertions intentionally avoid hardcoded constants (fingerprints,
// plaintext). The real interop proof is structural: PGPony parses the canonical
// v6 cert as v6, verifies the canonical signatures *against that cert* (which
// only works if key-ID/fingerprint resolution is correct), and decrypts the
// canonical SEIPDv2/X25519 message without error.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class RFC9580VectorTest {

    private fun vector(name: String): ByteArray? =
        javaClass.getResourceAsStream("/rfc9580/$name")?.use { it.readBytes() }

    // RFC vectors are ASCII-armored; getDecoderStream auto-detects armor (and
    // passes binary through), which the raw ring constructors do not do.
    private fun cert(bytes: ByteArray): PGPPublicKeyRing =
        PGPPublicKeyRing(PGPUtil.getDecoderStream(ByteArrayInputStream(bytes)), JcaKeyFingerprintCalculator())

    private fun secret(bytes: ByteArray): PGPSecretKeyRing =
        PGPSecretKeyRing(PGPUtil.getDecoderStream(ByteArrayInputStream(bytes)), JcaKeyFingerprintCalculator())

    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }

    @Test
    fun `A3 sample v6 certificate parses as a v6 key`() {
        val bytes = vector("a3_cert.asc")
        assumeTrue("a3_cert.asc absent — run tools/fetch_rfc9580_vectors.sh", bytes != null)
        val primary = cert(bytes!!).publicKey
        assertEquals("primary key version", 6, primary.version)
        assertEquals("v6 fingerprint is 32 bytes", 64, hex(primary.fingerprint).length)
    }

    @Test
    fun `A6 cleartext-signed message verifies against the A3 cert`() {
        val sig = vector("a6_cleartext.asc")
        val c = vector("a3_cert.asc")
        assumeTrue("a6_cleartext.asc / a3_cert.asc absent — run the fetch script", sig != null && c != null)
        val result = VerifyService.shared.verifyClearSigned(String(sig!!), listOf(cert(c!!)))
        assertTrue("expected Verified, got $result", result is VerificationResult.Verified)
    }

    @Test
    fun `A7 inline-signed message verifies against the A3 cert`() {
        val msg = vector("a7_inline.asc")
        val c = vector("a3_cert.asc")
        assumeTrue("a7_inline.asc / a3_cert.asc absent — run the fetch script", msg != null && c != null)
        val result = PGPCryptoService.shared.verify(msg!!, listOf(cert(c!!)))
        assertTrue("expected a valid signature", result.isValid)
    }

    @Test
    fun `A8 X25519-AEAD-OCB message decrypts with the A4 secret key`() {
        val ct = vector("a8_encrypted.asc")
        val sk = vector("a4_secret.asc")
        assumeTrue("a8_encrypted.asc / a4_secret.asc absent — run the fetch script", ct != null && sk != null)
        val result = PGPCryptoService.shared.decrypt(ct!!, listOf(secret(sk!!)), passphrase = null)
        assertTrue("decrypted plaintext should be non-empty", result.data.isNotEmpty())
    }
}
