// CompositeAddUserIdTest.kt
// PGPony Android — 4.5.0 (item 4 / issue #55): composite ML-DSA multi-User-ID.
//
// Adds a second User ID to a composite ML-DSA primary and verifies its
// composite positive-certification (0x13) with CompositeSigVerifier, the same
// offline proof CompositePrimaryKeyGenTest uses for the first UID. No gpg, no
// BouncyCastle on the composite signature.

package com.pgpony.android.crypto.pqc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CompositeAddUserIdTest {

    private val suite = CompositeSignSuite.MLDSA65_ED25519

    private data class Pkt(val tag: Int, val body: ByteArray)

    private fun beInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    private fun uint32(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun keyFrame(body: ByteArray): ByteArray =
        byteArrayOf(0x9B.toByte()) + uint32(body.size) + body

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
    fun `addUserId appends a second verifiable composite certification`() {
        val ring = CompositePrimaryKeyGen.assemble("First <first@pgpony.app>")
        val updated = CompositePrimaryKeyGen.addUserId(ring, "Second <second@pgpony.app>")

        val info = CompositeKeyFacade.parse(updated)
        assertEquals(
            "both User IDs must be present, in order",
            listOf("First <first@pgpony.app>", "Second <second@pgpony.app>"),
            info.userIds
        )

        val packets = walkPackets(updated)
        val uidIdxs = packets.indices.filter { packets[it].tag == 13 }
        assertEquals("two User ID packets", 2, uidIdxs.size)
        val secondUid = packets[uidIdxs[1]]
        val secondCert = packets[uidIdxs[1] + 1]
        assertEquals("a signature must follow the second UID", 2, secondCert.tag)

        val primaryPubBody = publicKeyBody(packets[0].body)
        val compositePublic = publicMaterial(primaryPubBody)
        val certData = keyFrame(primaryPubBody) +
            byteArrayOf(0xB4.toByte()) + uint32(secondUid.body.size) + secondUid.body

        val sig = parseV6Sig(secondCert.body)
        assertEquals("positive certification type", 0x13, sig.sigType)
        assertEquals("certification is composite", suite.algId, sig.pubAlgo)
        assertTrue(
            "the added UID's composite certification must verify under the primary",
            verify(sig, certData, compositePublic)
        )
    }
}
