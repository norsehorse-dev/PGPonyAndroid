// CompositePrimaryKeyFlagsTest.kt
// PGPony Android, 4.8.0: Key Details had no Usage row on an ML-DSA key,
// because the row read the primary through Bouncy Castle, which cannot load
// an algo-30/31 primary. CompositeKeyFacade.primaryKeyFlags reads the flags
// from the packets instead; these pin it on generated keys of both suites,
// the RFC 9980 A.3 certificate, an sq-made certify-only primary, and against
// a third party's certification of the User ID.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ArmoredInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CompositePrimaryKeyFlagsTest {

    private val certifySign = 0x03

    @Test
    fun `a generated ML-DSA-65 key certifies and signs`() {
        val raw = CompositePrimaryKeyGen.assemble("Usage 65 <u65@pgpony.app>", CompositeSignSuite.MLDSA65_ED25519)
        assertEquals(certifySign, CompositeKeyFacade.primaryKeyFlags(raw))
    }

    @Test
    fun `a generated ML-DSA-87 key certifies and signs`() {
        val raw = CompositePrimaryKeyGen.assemble("Usage 87 <u87@pgpony.app>", CompositeSignSuite.MLDSA87_ED448)
        assertEquals(certifySign, CompositeKeyFacade.primaryKeyFlags(raw))
    }

    @Test
    fun `the RFC 9980 A_3 certificate certifies and signs`() {
        val asc = res("rfc9980-a3-mldsa65-ed25519-cert.asc")
        assumeTrue("pqc/rfc9980 A.3 vector absent", asc != null)
        assertEquals(certifySign, CompositeKeyFacade.primaryKeyFlags(dearmor(asc!!)))
    }

    @Test
    fun `an sq primary that only certifies says so`() {
        val raw = res("sq15-sec.pgp")
        assumeTrue("pqc/sq15-sec.pgp absent", raw != null)
        assertEquals(0x01, CompositeKeyFacade.primaryKeyFlags(raw!!))
    }

    @Test
    fun `a v4 key is not read`() {
        val asc = res("rfc9980-a2-v4-ed25519-mlkem768-pub.asc")
        assumeTrue("pqc/rfc9980 A.2 vector absent", asc != null)
        assertNull(CompositeKeyFacade.primaryKeyFlags(dearmor(asc!!)))
    }

    @Test
    fun `a newer certification by another key does not change the usage`() {
        val raw = CompositePrimaryKeyGen.assemble("Certified <c@pgpony.app>", CompositeSignSuite.MLDSA65_ED25519)
        val other = ByteArray(32) { 0xAA.toByte() }
        val withThirdParty = insertBeforeFirstSubkey(raw, fakeCert(issuer = other, keyFlags = 0x20))
        assertEquals(certifySign, CompositeKeyFacade.primaryKeyFlags(withThirdParty))
    }

    @Test
    fun `the newest self-signature wins`() {
        val raw = CompositePrimaryKeyGen.assemble("Renewed <r@pgpony.app>", CompositeSignSuite.MLDSA65_ED25519)
        val fp = CompositeKeyFacade.parse(raw).fingerprint
        val renewed = insertBeforeFirstSubkey(raw, fakeCert(issuer = fp, keyFlags = 0x01))
        assertEquals(0x01, CompositeKeyFacade.primaryKeyFlags(renewed))
    }

    // -- helpers --

    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    private fun dearmor(asc: ByteArray): ByteArray =
        ArmoredInputStream(ByteArrayInputStream(asc)).use { it.readBytes() }

    /** A v6 positive certification packet (0x13) dated well after any generated
     *  key, carrying only what the reader looks at. Its signature is not valid;
     *  the reader does not verify, as the Bouncy Castle path it replaces did not. */
    private fun fakeCert(issuer: ByteArray, keyFlags: Int): ByteArray {
        val hashed = ByteArrayOutputStream().apply {
            write(byteArrayOf(5, (0x80 or 2).toByte()) + uint32(0x7F000000))
            write(byteArrayOf(2, (0x80 or 27).toByte(), keyFlags.toByte()))
            write(byteArrayOf(34, 33, 6) + issuer)
        }.toByteArray()
        val body = byteArrayOf(6, 0x13, 30, 8) + uint32(hashed.size) + hashed + uint32(0) + byteArrayOf(0, 0)
        return byteArrayOf(0xC2.toByte(), 0xFF.toByte()) + uint32(body.size) + body
    }

    /** [raw] with [packet] inserted before its first subkey packet (tag 14 or 7). */
    private fun insertBeforeFirstSubkey(raw: ByteArray, packet: ByteArray): ByteArray {
        var i = 0
        while (i < raw.size) {
            val start = i
            val c = raw[i++].toInt() and 0xFF
            require(c and 0xC0 == 0xC0) { "new-format packets only" }
            val tag = c and 0x3F
            val l0 = raw[i++].toInt() and 0xFF
            val len = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (raw[i++].toInt() and 0xFF) + 192
                else -> uint32At(raw, i).also { i += 4 }
            }
            if (tag == 14 || tag == 7) {
                return raw.copyOfRange(0, start) + packet + raw.copyOfRange(start, raw.size)
            }
            i += len
        }
        error("no subkey in the generated key")
    }

    private fun uint32(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun uint32At(b: ByteArray, o: Int) =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)
}
