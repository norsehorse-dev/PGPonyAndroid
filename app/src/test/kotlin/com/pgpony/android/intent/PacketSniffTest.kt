// PacketSniffTest.kt
// PGPony Android 4.6.3 (#67): shared files are routed by their packets, so a
// PNG or JPEG is never taken for a detached signature and an encrypted
// message opens to Decrypt even when its recipients cannot be listed.

package com.pgpony.android.intent

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketSniffTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    /** A new-format packet with [tag] and [body]. */
    private fun packet(tag: Int, body: ByteArray): ByteArray {
        require(body.size < 192)
        return bytes(0xC0 or tag, body.size) + body
    }

    /** An old-format packet with [tag] and a one-octet length. */
    private fun oldPacket(tag: Int, body: ByteArray): ByteArray {
        require(body.size < 256)
        return bytes(0x80 or (tag shl 2), body.size) + body
    }

    private fun sigBody(version: Int = 4) = ByteArray(40) { if (it == 0) version.toByte() else 7 }

    private val png = bytes(0x89, 'P'.code, 'N'.code, 'G'.code, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D) +
        ByteArray(200) { 1 }
    private val jpeg = bytes(0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10) + ByteArray(200) { 2 }
    private val pdf = "%PDF-1.7\n".toByteArray() + ByteArray(200) { 3 }
    private val zip = bytes('P'.code, 'K'.code, 3, 4) + ByteArray(200) { 4 }

    @Test
    fun imagesAndDocuments_areNeverSignaturesOrMessages() {
        for (f in listOf(png, jpeg, pdf, zip)) {
            assertFalse(PacketSniff.isDetachedSignature(f))
            assertFalse(PacketSniff.looksLikeEncryptedMessage(f))
        }
    }

    @Test
    fun aPngWithoutItsMagic_stillFailsTheWalk() {
        // 0x89 is an old-format tag-2 header with a two-octet length; the
        // length it claims does not end at the end of the file.
        val headerOnly = bytes(0x89, 0x50, 0x4E) + ByteArray(100) { 4 }
        assertFalse(PacketSniff.isDetachedSignature(headerOnly))
    }

    @Test
    fun binaryDetachedSignatures_areRecognized() {
        assertTrue(PacketSniff.isDetachedSignature(packet(2, sigBody(4))))
        assertTrue(PacketSniff.isDetachedSignature(oldPacket(2, sigBody(4))))
        assertTrue(PacketSniff.isDetachedSignature(packet(2, sigBody(6)) + packet(2, sigBody(4))))
    }

    @Test
    fun aSignatureFollowedByAnythingElse_isNotDetached() {
        assertFalse(PacketSniff.isDetachedSignature(packet(2, sigBody()) + packet(11, ByteArray(10))))
        assertFalse(PacketSniff.isDetachedSignature(packet(2, sigBody()) + bytes(0x00)))
        assertFalse(PacketSniff.isDetachedSignature(packet(2, sigBody(9))))
        assertFalse(PacketSniff.isDetachedSignature(ByteArray(0)))
    }

    @Test
    fun encryptedMessages_areRecognizedFromTheirSessionKeyPacket() {
        val pkeskV3 = packet(1, ByteArray(60) { if (it == 0) 3 else 9 })
        val pkeskV6 = packet(1, ByteArray(60) { if (it == 0) 6 else 9 })
        val skeskV4 = oldPacket(3, ByteArray(20) { if (it == 0) 4 else 9 })
        val body = packet(18, ByteArray(30) { 1 })
        assertTrue(PacketSniff.looksLikeEncryptedMessage(pkeskV3 + body))
        assertTrue(PacketSniff.looksLikeEncryptedMessage(pkeskV6 + body))
        assertTrue(PacketSniff.looksLikeEncryptedMessage(skeskV4 + body))
    }

    @Test
    fun keysAndSignedData_areNotEncryptedMessages() {
        assertFalse(PacketSniff.looksLikeEncryptedMessage(packet(6, ByteArray(50) { 4 })))
        assertFalse(PacketSniff.looksLikeEncryptedMessage(packet(4, ByteArray(13) { 3 })))
        assertFalse(PacketSniff.looksLikeEncryptedMessage(packet(2, sigBody())))
        assertFalse(PacketSniff.looksLikeEncryptedMessage(packet(1, ByteArray(60) { 2 })))
    }
}
