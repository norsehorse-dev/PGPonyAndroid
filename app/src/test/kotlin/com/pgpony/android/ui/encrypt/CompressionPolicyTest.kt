// CompressionPolicyTest.kt
// PGPony Android 4.8.0 (#104): the ZLIB decision for streamed file encrypt,
// and that a file over the limit, compressed because the Settings switch is
// on, still decrypts to the same bytes.

package com.pgpony.android.ui.encrypt

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CompressionPolicyTest {

    private val svc = PGPCryptoService.shared

    // ── The decision ───────────────────────────────────────────────────

    @Test
    fun `switch off keeps the 16 MB rule`() {
        assertEquals(16L * 1024 * 1024, COMPRESSION_LIMIT)
        assertTrue(CompressionPolicy.shouldCompress(0L, compressLargeFiles = false))
        assertTrue(CompressionPolicy.shouldCompress(1024L, compressLargeFiles = false))
        assertTrue(CompressionPolicy.shouldCompress(COMPRESSION_LIMIT, compressLargeFiles = false))
        assertFalse(CompressionPolicy.shouldCompress(COMPRESSION_LIMIT + 1, compressLargeFiles = false))
        assertFalse(CompressionPolicy.shouldCompress(2L * 1024 * 1024 * 1024, compressLargeFiles = false))
    }

    @Test
    fun `switch on compresses every size`() {
        assertTrue(CompressionPolicy.shouldCompress(0L, compressLargeFiles = true))
        assertTrue(CompressionPolicy.shouldCompress(COMPRESSION_LIMIT, compressLargeFiles = true))
        assertTrue(CompressionPolicy.shouldCompress(COMPRESSION_LIMIT + 1, compressLargeFiles = true))
        assertTrue(CompressionPolicy.shouldCompress(50L * 1024 * 1024 * 1024, compressLargeFiles = true))
    }

    @Test
    fun `an unknown size compresses only with the switch on`() {
        assertFalse(CompressionPolicy.shouldCompress(-1L, compressLargeFiles = false))
        assertTrue(CompressionPolicy.shouldCompress(-1L, compressLargeFiles = true))
    }

    @Test
    fun `the limit is injectable`() {
        assertTrue(CompressionPolicy.shouldCompress(100L, compressLargeFiles = false, limit = 100L))
        assertFalse(CompressionPolicy.shouldCompress(101L, compressLargeFiles = false, limit = 100L))
        assertTrue(CompressionPolicy.shouldCompress(101L, compressLargeFiles = true, limit = 100L))
    }

    // ── Round trips ────────────────────────────────────────────────────

    private fun keys(alg: KeyAlgorithm): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val g = svc.generateKeyPair("Squash", "squash@pgpony.app", alg, null)
        return PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator()) to
            PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
    }

    /** CSV-like rows, like the export behind #104: compressible, but not one
     *  repeated byte, so a lost or doubled chunk shows as a mismatch. */
    private fun csv(minBytes: Int): ByteArray {
        val out = ByteArrayOutputStream(minBytes + 128)
        var i = 0
        while (out.size() < minBytes) {
            out.write("$i,${(i * 7919L) % 100003},item-${i % 37},2026-11-${1 + i % 28}\n".toByteArray())
            i++
        }
        return out.toByteArray()
    }

    private fun encrypt(plain: ByteArray, pub: PGPPublicKeyRing, compress: Boolean): ByteArray {
        val out = ByteArrayOutputStream()
        svc.encryptStream(
            input = ByteArrayInputStream(plain),
            output = out,
            recipientPublicKeys = listOf(pub),
            filename = "export.csv",
            armor = false,
            enableCompression = compress
        )
        return out.toByteArray()
    }

    private fun decrypt(ct: ByteArray, sec: PGPSecretKeyRing): ByteArray {
        val out = ByteArrayOutputStream()
        svc.decryptStream(
            input = ByteArrayInputStream(ct),
            output = out,
            secretKeyRings = listOf(sec),
            passphrase = null
        )
        return out.toByteArray()
    }

    @Test
    fun `a stream over 16 MB with the switch on is compressed and decrypts to the same bytes`() {
        val (sec, pub) = keys(KeyAlgorithm.ED25519_CV25519)
        val plain = csv(COMPRESSION_LIMIT.toInt() + 512 * 1024)
        val size = plain.size.toLong()
        assertFalse(CompressionPolicy.shouldCompress(size, compressLargeFiles = false))
        val compress = CompressionPolicy.shouldCompress(size, compressLargeFiles = true)
        assertTrue(compress)

        val ct = encrypt(plain, pub, compress)
        // ZLIB ran: the rows shrink to well under half. Without it the
        // ciphertext is a little larger than the plaintext.
        assertTrue("ciphertext ${ct.size} of $size", ct.size < plain.size / 2)
        assertArrayEquals(plain, decrypt(ct, sec))
    }

    @Test
    fun `switch off past an injected limit leaves the stream uncompressed`() {
        val (sec, pub) = keys(KeyAlgorithm.ED25519_CV25519)
        val plain = csv(256 * 1024)
        val compress = CompressionPolicy.shouldCompress(plain.size.toLong(), compressLargeFiles = false, limit = 64L * 1024)
        assertFalse(compress)
        val ct = encrypt(plain, pub, compress)
        assertTrue("ciphertext ${ct.size} of ${plain.size}", ct.size > plain.size)
        assertArrayEquals(plain, decrypt(ct, sec))
    }

    @Test
    fun `switch on past an injected limit compresses a SEIPDv2 stream too`() {
        val (sec, pub) = keys(KeyAlgorithm.V6_ED25519)
        val plain = csv(256 * 1024)
        val compress = CompressionPolicy.shouldCompress(plain.size.toLong(), compressLargeFiles = true, limit = 64L * 1024)
        assertTrue(compress)
        val ct = encrypt(plain, pub, compress)
        assertTrue("ciphertext ${ct.size} of ${plain.size}", ct.size < plain.size / 2)
        assertArrayEquals(plain, decrypt(ct, sec))
    }
}
