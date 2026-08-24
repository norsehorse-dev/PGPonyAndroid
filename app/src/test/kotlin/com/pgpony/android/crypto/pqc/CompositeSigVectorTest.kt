// CompositeSigVectorTest.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Byte-locks the composite verify path against the RFC 9980 Appendix A.3
// worked example: the sample ML-DSA-65+Ed25519 certificate (A.3.2) and the
// detached signature it makes over "Testing\n" (A.3.4). Both are the RFC's
// own octets, carried verbatim as test resources.
//
// This is the format proof for CompositeSigVerifier + CompositeSigHash with
// no gpg in the loop: parse the RFC's v6 public key packet for the composite
// public material, parse its v6 signature packet for the salt / hashed
// subpackets / composite signature value, rebuild the v6 dataDigest by hand
// (BouncyCastle throws on algorithm ids 30/31, so it will not build it for
// us), and require both component signatures to verify. A.3.4 is a text
// document signature (type 0x01), so the document is canonicalized to CRLF
// before hashing, exactly as RFC 9580 Section 5.2.4 requires.
//
// Resources (RFC 9980 Appendix A.3, verbatim):
//   pqc/rfc9980-a3-mldsa65-ed25519-cert.asc  - A.3.2 Transferable Public Key
//   pqc/rfc9980-a3-mldsa65-ed25519-sig.asc   - A.3.4 Detached Signature

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ArmoredInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class CompositeSigVectorTest {

    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    /** Strip ASCII armor to the raw packet octets. */
    private fun dearmor(asc: ByteArray): ByteArray =
        ArmoredInputStream(ByteArrayInputStream(asc)).use { it.readBytes() }

    private data class Packet(val tag: Int, val body: ByteArray)

    /** The first OpenPGP packet in [raw], which for these vectors is the one we want. */
    private fun firstPacket(raw: ByteArray): Packet {
        val octet0 = raw[0].toInt() and 0xFF
        require(octet0 and 0xC0 == 0xC0) {
            "expected an OpenPGP-format packet, got first octet 0x${octet0.toString(16)}"
        }
        val tag = octet0 and 0x3F
        var p = 1
        val l0 = raw[p++].toInt() and 0xFF
        val len = when {
            l0 < 192 -> l0
            l0 < 224 -> ((l0 - 192) shl 8) + (raw[p++].toInt() and 0xFF) + 192
            l0 == 255 -> beInt(raw, p).also { p += 4 }
            else -> throw IllegalStateException("partial body lengths are not used by these vectors")
        }
        return Packet(tag, raw.copyOfRange(p, p + len))
    }

    /**
     * The composite public key material from a v6 public key packet body:
     * version(1) | creationTime(4) | algorithm(1) | 4-octet material length |
     * material. For a composite key the material is EdDSA public || ML-DSA
     * public, which is what CompositeSignSuite.splitPublic then divides.
     */
    private fun v6CompositePublic(body: ByteArray): ByteArray {
        var q = 0
        val version = body[q++].toInt() and 0xFF
        require(version == 6) { "expected a v6 public key, got version $version" }
        q += 4 // creation time
        val algorithm = body[q++].toInt() and 0xFF
        require(algorithm == 30) { "expected composite algorithm 30, got $algorithm" }
        val materialLen = beInt(body, q); q += 4
        return body.copyOfRange(q, q + materialLen)
    }

    private data class V6Signature(
        val sigType: Int,
        val pubAlgo: Int,
        val hashAlgo: Int,
        val hashedSubpackets: ByteArray,
        val salt: ByteArray,
        val signature: ByteArray
    )

    /**
     * Parse a v6 signature packet body (RFC 9580 Section 5.2.3):
     * version(1) | type(1) | pubAlgo(1) | hashAlgo(1) |
     * 4-octet hashed-subpacket length | hashed subpackets |
     * 4-octet unhashed-subpacket length | unhashed subpackets |
     * left-16(2) | salt size(1) | salt | signature material.
     */
    private fun v6Signature(body: ByteArray): V6Signature {
        var q = 0
        val version = body[q++].toInt() and 0xFF
        require(version == 6) { "expected a v6 signature, got version $version" }
        val sigType = body[q++].toInt() and 0xFF
        val pubAlgo = body[q++].toInt() and 0xFF
        val hashAlgo = body[q++].toInt() and 0xFF
        val hashedLen = beInt(body, q); q += 4
        val hashed = body.copyOfRange(q, q + hashedLen); q += hashedLen
        val unhashedLen = beInt(body, q); q += 4
        q += unhashedLen
        q += 2 // left 16 bits of the signed hash
        val saltSize = body[q++].toInt() and 0xFF
        val salt = body.copyOfRange(q, q + saltSize); q += saltSize
        val signature = body.copyOfRange(q, body.size)
        return V6Signature(sigType, pubAlgo, hashAlgo, hashed, salt, signature)
    }

    private fun beInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or
            ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or
            (b[o + 3].toInt() and 0xFF)

    private data class Vector(
        val suite: CompositeSignSuite,
        val compositePublic: ByteArray,
        val sig: V6Signature,
        val digest: ByteArray
    )

    /** Parse the A.3 resources and rebuild the v6 dataDigest they signed. */
    private fun loadA3(): Vector? {
        val certAsc = res("rfc9980-a3-mldsa65-ed25519-cert.asc")
        val sigAsc = res("rfc9980-a3-mldsa65-ed25519-sig.asc")
        if (certAsc == null || sigAsc == null) return null

        val compositePublic = v6CompositePublic(firstPacket(dearmor(certAsc)).body)
        val sig = v6Signature(firstPacket(dearmor(sigAsc)).body)
        val suite = requireNotNull(CompositeSignSuite.forAlgId(sig.pubAlgo)) {
            "no composite signature suite for algorithm ${sig.pubAlgo}"
        }

        // A.3.4 is a text signature (type 0x01) over "Testing\n"; canonicalize
        // line endings to CRLF and encode UTF-8 before hashing.
        val document = "Testing\r\n".toByteArray(Charsets.UTF_8)
        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = sig.hashAlgo,
            salt = sig.salt,
            data = document,
            signatureType = sig.sigType,
            publicKeyAlgorithm = sig.pubAlgo,
            hashedSubpacketBody = sig.hashedSubpackets
        )
        return Vector(suite, compositePublic, sig, digest)
    }

    @Test
    fun `parses the A_3_2 composite certificate as ML-DSA-65 + Ed25519`() {
        val v = loadA3()
        assumeTrue("pqc/rfc9980 A.3 vectors absent", v != null)
        v!!
        assertEquals("composite algorithm id", CompositeSignSuite.MLDSA65_ED25519, v.suite)
        assertEquals(
            "composite public key length",
            v.suite.compositePubLen,
            v.compositePublic.size
        )
        assertEquals("composite signature length", v.suite.compositeSigLen, v.sig.signature.size)
        assertEquals("text document signature type", 0x01, v.sig.sigType)
        assertEquals("SHA-256 hash algorithm", 8, v.sig.hashAlgo)
    }

    @Test
    fun `verifies the RFC 9980 A_3_4 composite detached signature`() {
        val v = loadA3()
        assumeTrue("pqc/rfc9980 A.3 vectors absent", v != null)
        v!!
        assertTrue(
            "RFC 9980 A.3.4 composite signature must verify over the v6 dataDigest",
            CompositeSigVerifier.verify(v.suite, v.compositePublic, v.sig.signature, v.digest)
        )
    }

    @Test
    fun `rejects the A_3_4 signature over a different document`() {
        val v = loadA3()
        assumeTrue("pqc/rfc9980 A.3 vectors absent", v != null)
        v!!
        val wrongDigest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = v.sig.hashAlgo,
            salt = v.sig.salt,
            data = "Tampered\r\n".toByteArray(Charsets.UTF_8),
            signatureType = v.sig.sigType,
            publicKeyAlgorithm = v.sig.pubAlgo,
            hashedSubpacketBody = v.sig.hashedSubpackets
        )
        assertFalse(
            "a signature must not verify over the wrong document",
            CompositeSigVerifier.verify(v.suite, v.compositePublic, v.sig.signature, wrongDigest)
        )
    }

    @Test
    fun `rejects the A_3_4 signature when the ML-DSA half is corrupted`() {
        val v = loadA3()
        assumeTrue("pqc/rfc9980 A.3 vectors absent", v != null)
        v!!
        val corrupted = v.sig.signature.copyOf()
        val last = corrupted.size - 1 // trailing octet lives in the ML-DSA half
        corrupted[last] = (corrupted[last].toInt() xor 0x01).toByte()
        assertFalse(
            "a corrupted ML-DSA component must fail the composite",
            CompositeSigVerifier.verify(v.suite, v.compositePublic, corrupted, v.digest)
        )
    }

    @Test
    fun `rejects the A_3_4 signature when the EdDSA half is corrupted`() {
        val v = loadA3()
        assumeTrue("pqc/rfc9980 A.3 vectors absent", v != null)
        v!!
        val corrupted = v.sig.signature.copyOf()
        corrupted[0] = (corrupted[0].toInt() xor 0x01).toByte() // leading octet is EdDSA
        assertFalse(
            "a corrupted EdDSA component must fail the composite",
            CompositeSigVerifier.verify(v.suite, v.compositePublic, corrupted, v.digest)
        )
    }
}
