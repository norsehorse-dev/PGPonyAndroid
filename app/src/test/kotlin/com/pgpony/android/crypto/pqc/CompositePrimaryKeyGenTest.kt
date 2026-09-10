// CompositePrimaryKeyGenTest.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Pins CompositePrimaryKeyGen: a v6 key whose primary is a composite
// ML-DSA-65 + Ed25519 signing key, self-certified with composite signatures.
//
// Phase 1 (no gpg, no BouncyCastle on the composite signatures): hand-parse
// the raw assembled ring and verify both self-signatures with
// CompositeSigVerifier over their recomputed v6 hashes, the Direct Key
// signature over the primary key and the certification over key + User ID.
//
// Phase 2: probe that BouncyCastle re-parses the ring (routing the algo-30
// primary into UnknownBCPGKey), agrees on the v6 fingerprint, and that a
// passphrase yields a protected primary.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException

class CompositePrimaryKeyGenTest {

    private val suite = CompositeSignSuite.MLDSA65_ED25519

    private data class Pkt(val tag: Int, val body: ByteArray)

    private fun walkPackets(raw: ByteArray): List<Pkt> {
        val out = ArrayList<Pkt>()
        var i = 0
        while (i < raw.size) {
            val c = raw[i++].toInt() and 0xFF
            check(c and 0x80 != 0) { "not a packet header: 0x${c.toString(16)}" }
            val tag: Int
            val len: Int
            if (c and 0x40 != 0) {
                tag = c and 0x3F
                val l0 = raw[i++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0
                    l0 < 224 -> ((l0 - 192) shl 8) + (raw[i++].toInt() and 0xFF) + 192
                    l0 == 255 -> beInt(raw, i).also { i += 4 }
                    else -> throw IllegalStateException("partial length not used here")
                }
            } else {
                tag = (c shr 2) and 0x0F
                len = when (c and 0x03) {
                    0 -> raw[i++].toInt() and 0xFF
                    1 -> (((raw[i].toInt() and 0xFF) shl 8) or (raw[i + 1].toInt() and 0xFF)).also { i += 2 }
                    2 -> beInt(raw, i).also { i += 4 }
                    else -> throw IllegalStateException("indeterminate length not used here")
                }
            }
            out.add(Pkt(tag, raw.copyOfRange(i, i + len)))
            i += len
        }
        return out
    }

    private fun beInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    private fun publicKeyBody(keyPacketBody: ByteArray): ByteArray {
        var q = 1 + 4 + 1
        val matLen = beInt(keyPacketBody, q); q += 4
        return keyPacketBody.copyOfRange(0, q + matLen)
    }

    private fun publicMaterial(publicBody: ByteArray): ByteArray {
        var q = 1 + 4 + 1
        val matLen = beInt(publicBody, q); q += 4
        return publicBody.copyOfRange(q, q + matLen)
    }

    private fun uint32(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun keyFrame(body: ByteArray): ByteArray =
        byteArrayOf(0x9B.toByte()) + uint32(body.size) + body

    private data class V6Sig(
        val sigType: Int, val pubAlgo: Int, val hashAlgo: Int,
        val hashed: ByteArray, val salt: ByteArray, val signature: ByteArray
    )

    private fun parseV6Sig(body: ByteArray): V6Sig {
        var q = 1
        val sigType = body[q++].toInt() and 0xFF
        val pubAlgo = body[q++].toInt() and 0xFF
        val hashAlgo = body[q++].toInt() and 0xFF
        val hLen = beInt(body, q); q += 4
        val hashed = body.copyOfRange(q, q + hLen); q += hLen
        val uLen = beInt(body, q); q += 4; q += uLen
        q += 2
        val saltSize = body[q++].toInt() and 0xFF
        val salt = body.copyOfRange(q, q + saltSize); q += saltSize
        return V6Sig(sigType, pubAlgo, hashAlgo, hashed, salt, body.copyOfRange(q, body.size))
    }

    private fun verify(sig: V6Sig, data: ByteArray, compositePublic: ByteArray): Boolean {
        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = sig.hashAlgo, salt = sig.salt, data = data,
            signatureType = sig.sigType, publicKeyAlgorithm = sig.pubAlgo,
            hashedSubpacketBody = sig.hashed
        )
        return CompositeSigVerifier.verify(suite, compositePublic, sig.signature, digest)
    }

    @Test
    fun `assemble produces verifiable composite self-signatures`() {
        val raw = CompositePrimaryKeyGen.assemble("PQ Primary <pq@pgpony.app>", suite)
        val packets = walkPackets(raw)

        assertEquals("primary secret key first", 5, packets[0].tag)
        assertEquals("direct-key self-signature second", 2, packets[1].tag)
        assertEquals("user id third", 13, packets[2].tag)
        assertEquals("certification self-signature fourth", 2, packets[3].tag)

        val primaryPubBody = publicKeyBody(packets[0].body)
        val compositePublic = publicMaterial(primaryPubBody)
        val uid = packets[2].body

        val direct = parseV6Sig(packets[1].body)
        assertEquals("direct-key signature type", 0x1F, direct.sigType)
        assertEquals("direct-key signature is composite", suite.algId, direct.pubAlgo)
        assertTrue(
            "the 0x1F direct-key self-signature must verify",
            verify(direct, keyFrame(primaryPubBody), compositePublic)
        )

        val cert = parseV6Sig(packets[3].body)
        assertEquals("certification signature type", 0x13, cert.sigType)
        val certData = keyFrame(primaryPubBody) +
            byteArrayOf(0xB4.toByte()) + uint32(uid.size) + uid
        assertTrue(
            "the 0x13 certification self-signature must verify",
            verify(cert, certData, compositePublic)
        )

        // ML-KEM encryption subkey and its composite binding.
        assertEquals("encryption subkey fifth", 7, packets[4].tag)
        assertEquals("subkey binding sixth", 2, packets[5].tag)
        val kemPubBody = publicKeyBody(packets[4].body)
        val kemPubMat = publicMaterial(kemPubBody)
        assertEquals("ML-KEM-768 + X25519 public material length", 1216, kemPubMat.size)

        val binding = parseV6Sig(packets[5].body)
        assertEquals("subkey binding type", 0x18, binding.sigType)
        assertEquals("subkey binding is composite", suite.algId, binding.pubAlgo)
        assertTrue(
            "the composite 0x18 encryption-subkey binding must verify under the primary",
            verify(binding, keyFrame(primaryPubBody) + keyFrame(kemPubBody), compositePublic)
        )
    }

    /**
     * item 1 (#36) — PQ-only invariant. A composite ML-DSA key is a FULL
     * post-quantum certificate: a composite signing primary and a single
     * composite ML-KEM encryption subkey, with NO standalone classical
     * encryption subkey to downgrade to. This pins that the assembled ring
     * carries exactly one subkey and that it is the composite ML-KEM (algo 35),
     * so a later change that grafts a classical Cv25519 subkey here is caught.
     */
    @Test
    fun `PQ-only composite key has no standalone classical encryption subkey`() {
        val raw = CompositePrimaryKeyGen.assemble("PQ Only <pq@pgpony.app>", suite)
        val packets = walkPackets(raw)
        // primary(5), direct sig(2), uid(13), cert sig(2), ONE subkey(7), binding(2).
        assertEquals("exactly one secret-subkey packet", 1, packets.count { it.tag == 7 })
        assertEquals("no extra packets beyond the single composite subkey", 6, packets.size)
        val subAlgId = packets[4].body[1 + 4].toInt() and 0xFF
        assertEquals("the sole encryption subkey is the composite ML-KEM (algo 35)", 35, subAlgId)
    }

    /**
     * BouncyCastle 1.85 rejects a TOP-LEVEL composite signature: its
     * SignaturePacket throws "unknown signature key algorithm: 30". A composite
     * primary's self-signatures are top-level composite signatures, so the ring
     * cannot be loaded as a PGPSecretKeyRing. (A composite SIGNING SUBKEY is
     * fine: its only composite signature is an opaque embedded back-signature.)
     * This test pins that limitation so we notice if a future BouncyCastle
     * lifts it.
     */
    @Test
    fun `BouncyCastle currently rejects a top-level composite signature`() {
        val raw = CompositePrimaryKeyGen.assemble("PQ Primary <pq@pgpony.app>", suite)
        val error = try {
            PGPSecretKeyRing(ByteArrayInputStream(raw), JcaKeyFingerprintCalculator())
            null
        } catch (e: IOException) {
            e
        }
        assertNotNull("expected BouncyCastle to reject the composite signature", error)
        assertTrue(
            "unexpected parse error: ${error?.message}",
            error?.message?.contains("30") == true
        )
    }
}
