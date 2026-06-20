// Rfc6637Test.kt
// PGPony Android — HW Phase 3a tests

package com.pgpony.android.crypto.card

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.RFC3394WrapEngine
import org.bouncycastle.crypto.params.KeyParameter
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class Rfc6637Test {

    private val fp = ByteArray(20) { it.toByte() }

    @Test
    fun kdfParamLayout() {
        val param = Rfc6637.kdfParam(Rfc6637.CURVE25519_OID, 8, 7, fp)
        var i = 0
        assertEquals(10, param[i++].toInt() and 0xFF)                 // curve OID len
        assertArrayEquals(Rfc6637.CURVE25519_OID, param.copyOfRange(i, i + 10)); i += 10
        assertEquals(18, param[i++].toInt() and 0xFF)                 // ECDH algo
        assertEquals(0x03, param[i++].toInt() and 0xFF)
        assertEquals(0x01, param[i++].toInt() and 0xFF)
        assertEquals(8, param[i++].toInt() and 0xFF)                  // KDF hash
        assertEquals(7, param[i++].toInt() and 0xFF)                  // KEK algo
        assertArrayEquals(Rfc6637.ANONYMOUS_SENDER, param.copyOfRange(i, i + 20)); i += 20
        assertArrayEquals(fp, param.copyOfRange(i, i + 20)); i += 20
        assertEquals(i, param.size)
        assertEquals(20, Rfc6637.ANONYMOUS_SENDER.size)
    }

    @Test
    fun kdfInputHasCounterPrefix() {
        val secret = ByteArray(32) { 0x11 }
        val input = Rfc6637.kdfInput(secret, byteArrayOf(0x09))
        assertArrayEquals(byteArrayOf(0, 0, 0, 1), input.copyOfRange(0, 4))
        assertArrayEquals(secret, input.copyOfRange(4, 36))
        assertEquals(0x09, input[36].toInt() and 0xFF)
    }

    @Test
    fun kekTruncationByAlgo() {
        val secret = ByteArray(32) { 0x22 }
        val param = Rfc6637.kdfParam(Rfc6637.CURVE25519_OID, 8, 7, fp)
        assertEquals(16, Rfc6637.deriveKek(secret, param, 8, 7).size) // AES-128
        assertEquals(32, Rfc6637.deriveKek(secret, param, 8, 9).size) // AES-256
    }

    @Test
    fun aesKeyWrapRoundTrip() {
        val kek = ByteArray(16) { it.toByte() }
        val m = ByteArray(24) { (it * 7).toByte() }
        val engine = RFC3394WrapEngine(AESEngine.newInstance())
        engine.init(true, KeyParameter(kek))
        val wrapped = engine.wrap(m, 0, m.size)
        assertArrayEquals(m, Rfc6637.aesKeyUnwrap(kek, wrapped))
    }

    @Test
    fun stripPadRemovesPkcs5Pad() {
        val padded = byteArrayOf(1, 2, 3, 0x05, 0x05, 0x05, 0x05, 0x05)
        assertArrayEquals(byteArrayOf(1, 2, 3), Rfc6637.stripPad(padded))
    }

    @Test
    fun parseSessionKeyVerifiesChecksum() {
        val key = ByteArray(16) { 1 }   // sum = 16 = 0x0010
        val m = byteArrayOf(9) + key + byteArrayOf(0x00, 0x10)
        val sk = Rfc6637.parseSessionKey(m)
        assertEquals(9, sk.symAlgoId)
        assertArrayEquals(key, sk.key)
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseSessionKeyRejectsBadChecksum() {
        val key = ByteArray(16) { 1 }
        val m = byteArrayOf(9) + key + byteArrayOf(0x00, 0x00) // wrong checksum
        Rfc6637.parseSessionKey(m)
    }
}
