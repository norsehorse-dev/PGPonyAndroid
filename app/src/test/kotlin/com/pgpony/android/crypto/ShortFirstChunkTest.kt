// ShortFirstChunkTest.kt
// PGPony Android, 4.8.0 (item 4g, #110): a signed message whose first partial
// chunk is under 512 octets.
//
// Go's OpenPGP code writes partial-length packets whose first chunk is smaller
// than the 512 octets RFC 9580 4.2.1.4 asks writers for. Bouncy Castle and
// GnuPG read them; PGPony refused them as malformed. The message here is a
// PGPony inline signature whose compressed data packet is re-framed with a
// 64-octet first partial chunk, the shape #110 had, and it has to verify.

package com.pgpony.android.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.Random

class ShortFirstChunkTest {

    private val svc = PGPCryptoService.shared

    /** [message]'s first packet re-framed as a new-format packet whose first partial chunk is [firstChunk] octets. */
    private fun reframe(message: ByteArray, firstChunk: Int): ByteArray {
        var i = 0
        val c = message[i++].toInt() and 0xFF
        require(c and 0x80 != 0)
        val tag: Int
        val len: Int
        if (c and 0x40 != 0) {
            tag = c and 0x3F
            val l0 = message[i++].toInt() and 0xFF
            len = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (message[i++].toInt() and 0xFF) + 192
                l0 == 255 -> be32(message, i).also { i += 4 }
                else -> error("already partial")
            }
        } else {
            tag = (c shr 2) and 0x0F
            len = when (c and 0x03) {
                0 -> message[i++].toInt() and 0xFF
                1 -> (((message[i].toInt() and 0xFF) shl 8) or (message[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> be32(message, i).also { i += 4 }
                else -> message.size - i
            }
        }
        val body = message.copyOfRange(i, i + len)
        require(body.size > firstChunk && Integer.bitCount(firstChunk) == 1)
        val out = ByteArrayOutputStream()
        out.write(0xC0 or tag)
        out.write(224 + Integer.numberOfTrailingZeros(firstChunk))
        out.write(body, 0, firstChunk)
        val rest = body.size - firstChunk
        out.write(255)
        out.write(byteArrayOf((rest ushr 24).toByte(), (rest ushr 16).toByte(), (rest ushr 8).toByte(), rest.toByte()))
        out.write(body, firstChunk, rest)
        out.write(message, i + len, message.size - i - len)
        return out.toByteArray()
    }

    private fun be32(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    @Test
    fun `an inline signature with a 64-octet first partial chunk verifies`() {
        val gen = svc.generateKeyPair("Chunk", "chunk@example.test", KeyAlgorithm.ED25519_CV25519, passphrase = null)
        val secret = svc.importKeyData(gen.privateKeyData).secretKeyRing!!
        val public = svc.importKeyData(gen.publicKeyData).publicKeyRing!!
        val data = ByteArray(4000).also { Random(110).nextBytes(it) }

        val signed = svc.sign(data, secret, "", detached = false, armor = false)
        val shortFirst = reframe(signed, 64)
        assertEquals("the outer packet now starts with a 64-octet partial chunk", 224 + 6, shortFirst[1].toInt() and 0xFF)

        val result = svc.decrypt(shortFirst, emptyList(), null, verificationKeys = listOf(public))
        assertArrayEquals("the content reads", data, result.data)
        assertTrue("the signature verifies", result.signatureVerified)
    }
}
