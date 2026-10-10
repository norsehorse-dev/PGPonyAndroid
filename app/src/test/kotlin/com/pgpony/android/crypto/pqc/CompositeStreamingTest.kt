// CompositeStreamingTest.kt
// PGPony Android 4.7.0 (item 23, #73): composite ML-DSA signatures made and
// checked over streamed content. Streamed output must verify with the
// buffered verifier, and the streaming reader must agree with it.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

class CompositeStreamingTest {

    private val suite = CompositeSignSuite.MLDSA65_ED25519
    private val rnd = SecureRandom()
    private val fingerprint = ByteArray(32) { (it * 7).toByte() }

    private fun freshKeypair(): Pair<ByteArray, ByteArray> {
        val edSecret = ByteArray(suite.eddsa.secretLen).also { rnd.nextBytes(it) }
        val mldsaSeed = ByteArray(suite.mldsa.seedLen).also { rnd.nextBytes(it) }
        val edPublic = Ed25519PrivateKeyParameters(edSecret, 0).generatePublicKey().encoded
        val mldsaPublic = MLDSAPrivateKeyParameters(suite.mldsa.params, mldsaSeed).publicKeyParameters.encoded
        return suite.join(edSecret, mldsaSeed) to suite.join(edPublic, mldsaPublic)
    }

    /** OPS + partial-length literal + signature, as PGPCryptoService.encryptStream writes it. */
    private fun streamedMessage(sec: ByteArray, data: ByteArray, name: String?, compress: Boolean): ByteArray {
        val out = ByteArrayOutputStream()
        val comp = if (compress) PGPCompressedDataGenerator(PGPCompressedData.ZLIB) else null
        val target = comp?.open(out) ?: out
        val inline = CompositeDocumentSigner.InlineStream(suite, sec, fingerprint, Date(), rnd)
        target.write(inline.onePassPacket())
        val lit = PGPLiteralDataGenerator()
        val litOut = lit.open(
            target, if (name != null) PGPLiteralData.BINARY else PGPLiteralData.UTF8,
            name ?: "", Date(), ByteArray(1 shl 16)
        )
        var off = 0
        while (off < data.size) {
            val n = minOf(7_919, data.size - off)
            litOut.write(data, off, n)
            inline.update(data, off, n)
            off += n
        }
        litOut.close()
        lit.close()
        target.write(inline.signaturePacket())
        comp?.close()
        return out.toByteArray()
    }

    private fun readStreamed(message: ByteArray): Pair<CompositeInlineStreamReader.Result, ByteArray> {
        val sink = ByteArrayOutputStream()
        val r = CompositeInlineStreamReader.read(ByteArrayInputStream(message)) { b, o, l -> sink.write(b, o, l) }
        return r to sink.toByteArray()
    }

    private fun digestVerifies(pub: ByteArray, r: CompositeInlineStreamReader.Result): Boolean =
        r.signatures.any { part ->
            val digest = part.digest ?: return@any false
            val parsed = CompositeSigPacket.parse(part.signatureBody)
            CompositeSigVerifier.verify(suite, pub, parsed.signature, digest)
        }

    @Test
    fun `the incremental hasher matches the one-shot digest`() {
        val data = ByteArray(200_003).also { rnd.nextBytes(it) }
        val salt = ByteArray(16).also { rnd.nextBytes(it) }
        val hashed = CompositeSigPacket.hashedArea(1_700_000_000, fingerprint)
        val oneShot = CompositeSigHash.v6DocumentDigest(8, salt, data, 0, suite.algId, hashed)
        val h = CompositeSigHash.V6DocumentHasher(8, salt)
        var off = 0
        while (off < data.size) { val n = minOf(4_096, data.size - off); h.update(data, off, n); off += n }
        assertArrayEquals(oneShot, h.finish(0, suite.algId, hashed))
        assertArrayEquals("finish leaves the hasher reusable", oneShot, h.finish(0, suite.algId, hashed))
    }

    @Test
    fun `a streamed inline message verifies with the buffered verifier`() {
        val (sec, pub) = freshKeypair()
        val data = ByteArray(300_000).also { rnd.nextBytes(it) }
        for (compress in listOf(false, true)) {
            val message = streamedMessage(sec, data, "photo.jpg", compress)
            val result = CompositeDocumentVerifier.verifyInline(pub, message)
            assertTrue("compress=$compress", result.valid)
            assertArrayEquals(data, result.content)
        }
    }

    @Test
    fun `the streaming reader recovers content, name and a verifying digest`() {
        val (sec, pub) = freshKeypair()
        val data = ByteArray(300_000).also { rnd.nextBytes(it) }
        for (compress in listOf(false, true)) {
            val (r, content) = readStreamed(streamedMessage(sec, data, "photo.jpg", compress))
            assertArrayEquals(data, content)
            assertEquals("photo.jpg", r.filename)
            assertEquals(data.size.toLong(), r.bytesWritten)
            assertTrue("compress=$compress", digestVerifies(pub, r))
        }
        val (r, content) = readStreamed(CompositeDocumentSigner.signInline(suite, sec, fingerprint, data, "a.bin", random = rnd))
        assertArrayEquals(data, content)
        assertTrue("a buffered signInline message reads the same way", digestVerifies(pub, r))
    }

    @Test
    fun `altered content does not verify`() {
        val (sec, pub) = freshKeypair()
        val data = ByteArray(100_000).also { rnd.nextBytes(it) }
        val message = streamedMessage(sec, data, "x.bin", compress = false)
        message[message.size / 2] = (message[message.size / 2].toInt() xor 0x01).toByte()
        val (r, _) = readStreamed(message)
        assertFalse(digestVerifies(pub, r))
    }

    @Test
    fun `text hashing canonicalizes line endings across chunk boundaries`() {
        val text = "one\ntwo\r\nthree\rfour\r\n\rend"
        val salt = ByteArray(16).also { rnd.nextBytes(it) }
        val hashed = CompositeSigPacket.hashedArea(1_700_000_000, fingerprint)
        val expected = CompositeSigHash.v6DocumentDigest(8, salt, CompositeSigPacket.canonicalizeText(text), 1, suite.algId, hashed)
        val bytes = text.toByteArray()
        for (chunk in 1..bytes.size) {
            val h = CompositeInlineStreamReader.ContentHasher(CompositeSigHash.V6DocumentHasher(8, salt), text = true)
            var off = 0
            while (off < bytes.size) { val n = minOf(chunk, bytes.size - off); h.update(bytes, off, n); off += n }
            assertArrayEquals("chunk=$chunk", expected, h.finish(1, suite.algId, hashed))
        }
    }

    @Test
    fun `a streamed detached signature verifies`() {
        val (sec, pub) = freshKeypair()
        val data = ByteArray(250_000).also { rnd.nextBytes(it) }
        val sig = CompositeDocumentSigner.signDetachedStream(suite, sec, fingerprint, ByteArrayInputStream(data), armor = false)
        assertTrue(CompositeDocumentVerifier.verifyDetached(pub, sig, data).valid)
        val armored = CompositeDocumentSigner.signDetachedStream(suite, sec, fingerprint, ByteArrayInputStream(data), armor = true)
        assertNotNull(String(armored, Charsets.UTF_8).takeIf { it.contains("BEGIN PGP SIGNATURE") })
        assertTrue(CompositeDocumentVerifier.verifyDetachedArmored(pub, String(armored, Charsets.UTF_8), data).valid)
    }
}
