// ArmorExtractorBytesTest.kt
// PGPony Android, 4.8.0 (item 4d): a buffered file decrypt reads only the PGP
// MESSAGE block, so text around the armor in a .asc file is ignored.

package com.pgpony.android.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

class ArmorExtractorBytesTest {

    private val block = buildString {
        append("-----BEGIN PGP MESSAGE-----\n\n")
        append("hF4DAAAAAAAAAAASAQdA...base64...\n")
        append("=abcd\n")
        append("-----END PGP MESSAGE-----")
    }

    @Test
    fun `leading prose and a trailing signature line are stripped to the block`() {
        val input = "Here is the file you asked for.\n\n$block\n-- \nsig line\n".toByteArray()
        assertEquals("$block\n", String(ArmorExtractor.messageOnlyBytes(input), Charsets.US_ASCII))
    }

    @Test
    fun `a trailing row of dashes is stripped`() {
        val input = "$block\n-----\nfooter\n".toByteArray()
        assertEquals("$block\n", String(ArmorExtractor.messageOnlyBytes(input), Charsets.US_ASCII))
    }

    @Test
    fun `non UTF-8 text around the block is still stripped`() {
        val prefix = byteArrayOf(0xE9.toByte(), 0x0A)
        val input = prefix + "$block\n-- \n".toByteArray()
        assertEquals("$block\n", String(ArmorExtractor.messageOnlyBytes(input), Charsets.US_ASCII))
    }

    @Test
    fun `an armored message with nothing around it comes back unchanged`() {
        val input = "$block\n".toByteArray()
        assertSame(input, ArmorExtractor.messageOnlyBytes(input))
        val crlf = "$block\n".replace("\n", "\r\n").toByteArray()
        assertSame(crlf, ArmorExtractor.messageOnlyBytes(crlf))
    }

    @Test
    fun `binary input comes back unchanged`() {
        val input = ByteArray(512) { (it * 37 + 0x85).toByte() }
        assertSame(input, ArmorExtractor.messageOnlyBytes(input))
    }

    @Test
    fun `input with no complete block comes back unchanged`() {
        val truncated = "prose\n-----BEGIN PGP MESSAGE-----\n\nhF4DAAAA\n".toByteArray()
        assertSame(truncated, ArmorExtractor.messageOnlyBytes(truncated))
        val signed = "prose\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhi\n".toByteArray()
        assertSame(signed, ArmorExtractor.messageOnlyBytes(signed))
    }

    @Test
    fun `indexOfAscii finds a marker past the first 64 bytes`() {
        val text = "x".repeat(200) + "\n-----BEGIN PGP SIGNED MESSAGE-----\n"
        assertEquals(201, ArmorExtractor.indexOfAscii(text.toByteArray(), "-----BEGIN PGP"))
        assertEquals(-1, ArmorExtractor.indexOfAscii("short".toByteArray(), "-----BEGIN PGP"))
        assertEquals(-1, ArmorExtractor.indexOfAscii(ByteArray(0), "-----BEGIN PGP"))
    }

    @Test
    fun `an encrypted message with a trailing signature decrypts after the helper`() {
        val svc = PGPCryptoService.shared
        val key = svc.generateKeyPair("Armor", "armor@example.test", KeyAlgorithm.ED25519_CV25519, passphrase = null)
        val secret = svc.importKeyData(key.privateKeyData).secretKeyRing!!
        val pub = svc.importKeyData(key.publicKeyData).publicKeyRing!!

        val plain = "hello from a file".toByteArray()
        val armored = String(svc.encrypt(plain, listOf(pub), armor = true), Charsets.US_ASCII)
        val file = "Forwarded below.\n\n${armored.trimEnd()}\n-- \nsig\n-----\n".toByteArray()

        val result = svc.decrypt(ArmorExtractor.messageOnlyBytes(file), listOf(secret), null)
        assertArrayEquals(plain, result.data)
    }
}
