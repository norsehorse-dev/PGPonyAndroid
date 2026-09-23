// DecompressionBombTest.kt
// PGPony Android, 4.6.0 (item 17.5)
//
// The composite inline pre-check inflates a leading Compressed Data packet on
// every decrypted message and on pasted signed text. It must stop at the same
// in-memory cap as the rest of the decrypt path instead of exhausting memory.
// (This is also the dedicated bomb regression test the 4.5.0 item 11 plan
// asked for.)

package com.pgpony.android.crypto

import com.pgpony.android.crypto.pqc.CompositeDocumentVerifier
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.Deflater

class DecompressionBombTest {

    /** New-format packet header (tag, definite length). */
    private fun pkt(tag: Int, body: ByteArray): ByteArray {
        val n = body.size
        val hdr = when {
            n < 192 -> byteArrayOf(n.toByte())
            n < 8384 -> {
                val v = n - 192
                byteArrayOf(((v shr 8) + 192).toByte(), (v and 0xFF).toByte())
            }
            else -> byteArrayOf(
                0xFF.toByte(),
                (n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()
            )
        }
        return byteArrayOf((0xC0 or tag).toByte()) + hdr + body
    }

    /**
     * A Compressed Data packet (tag 8, algo 1 = ZIP / raw DEFLATE) whose inner
     * stream is a Literal Data packet of [expandedBytes] zeros. The Deflater is
     * fed in 1 MiB chunks so this builder's own peak memory is the ~KB of
     * compressed output, never the expanded plaintext.
     */
    private fun zipBomb(expandedBytes: Long): ByteArray {
        val litBody = 6L + expandedBytes // format 'b' + nameLen 1 + name 'x' + 4 date + data
        // Literal header only; body streamed straight into the Deflater.
        val litHdr = byteArrayOf(
            (0xC0 or 11).toByte(), 0xFF.toByte(),
            (litBody ushr 24).toByte(), (litBody ushr 16).toByte(),
            (litBody ushr 8).toByte(), litBody.toByte(),
            'b'.code.toByte(), 1, 'x'.code.toByte(), 0, 0, 0, 0
        )
        val def = Deflater(Deflater.BEST_COMPRESSION, /* nowrap = */ true)
        val comp = ByteArrayOutputStream()
        val outBuf = ByteArray(1 shl 16)
        fun drain() { while (!def.needsInput()) { val n = def.deflate(outBuf); if (n > 0) comp.write(outBuf, 0, n) } }
        def.setInput(litHdr); drain()
        val zeros = ByteArray(1 shl 20)
        var remaining = expandedBytes
        while (remaining > 0) {
            val n = minOf(remaining, zeros.size.toLong()).toInt()
            def.setInput(zeros, 0, n); drain()
            remaining -= n
        }
        def.finish()
        while (!def.finished()) { val n = def.deflate(outBuf); if (n > 0) comp.write(outBuf, 0, n) }
        def.end()
        return pkt(8, byteArrayOf(1) + comp.toByteArray()) // 1 = ZIP
    }

    @Test
    fun `decompress of a zip bomb fails closed instead of exhausting memory`() {
        // Inflates to ~512 MiB, four times the 128 MiB in-memory cap.
        val bomb = zipBomb(512L * 1024 * 1024)
        assertThrows(PGPCryptoError.ResourceLimitExceeded::class.java) {
            CompositeDocumentVerifier.decompress(bomb)
        }
    }
}
