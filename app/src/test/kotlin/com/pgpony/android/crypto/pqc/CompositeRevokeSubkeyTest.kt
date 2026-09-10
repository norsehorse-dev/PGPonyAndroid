// CompositeRevokeSubkeyTest.kt
// PGPony Android — 4.5.0 (item 16 / issue #54): revoke a subkey of a composite
// ML-DSA primary.
//
// Revokes the ML-KEM encryption subkey of a composite primary and verifies its
// composite subkey-revocation (0x28) with CompositeSigVerifier, the same
// offline proof CompositeAddUserIdTest uses for a certification. No gpg, no
// BouncyCastle on the composite signature.

package com.pgpony.android.crypto.pqc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CompositeRevokeSubkeyTest {

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

    private fun subpacketBody(hashed: ByteArray, wantType: Int): ByteArray? {
        var i = 0
        while (i < hashed.size) {
            val l0 = hashed[i++].toInt() and 0xFF
            val len = when {
                l0 < 192 -> l0
                l0 < 255 -> ((l0 - 192) shl 8) + (hashed[i++].toInt() and 0xFF) + 192
                else -> beInt(hashed, i).also { i += 4 }
            }
            val type = hashed[i].toInt() and 0x7F
            if (type == wantType) return hashed.copyOfRange(i + 1, i + len)
            i += len
        }
        return null
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
    fun `revokeSubkey appends a verifiable composite subkey revocation`() {
        val ring = CompositePrimaryKeyGen.assemble("Revoker <revoke@pgpony.app>")
        val subFp = CompositeKeyFacade.parse(ring).encryptionSubkey!!.fingerprint

        val updated = CompositePrimaryKeyGen.revokeSubkey(
            ring, subFp, reasonCode = 3, reasonText = "retired"
        )

        val packets = walkPackets(updated)
        val subIdx = packets.indexOfFirst { it.tag == 7 }
        assertTrue("encryption subkey packet present", subIdx >= 0)

        // The revocation must be one of the signatures that follow the subkey.
        var revIdx = -1
        var k = subIdx + 1
        while (k < packets.size && packets[k].tag == 2) {
            if ((packets[k].body[1].toInt() and 0xFF) == 0x28) { revIdx = k; break }
            k++
        }
        assertTrue("a 0x28 subkey revocation must follow the subkey", revIdx >= 0)

        val primaryPubBody = publicKeyBody(packets[0].body)
        val subPubBody = publicKeyBody(packets[subIdx].body)
        val compositePublic = publicMaterial(primaryPubBody)
        val revokeData = keyFrame(primaryPubBody) + keyFrame(subPubBody)

        val sig = parseV6Sig(packets[revIdx].body)
        assertEquals("subkey revocation type", 0x28, sig.sigType)
        assertEquals("revocation is composite", suite.algId, sig.pubAlgo)

        val reason = subpacketBody(sig.hashed, 29)
        assertNotNull("reason-for-revocation subpacket present", reason)
        assertEquals("reason code", 3, reason!![0].toInt() and 0xFF)
        assertEquals("reason text", "retired", String(reason.copyOfRange(1, reason.size), Charsets.UTF_8))

        assertTrue(
            "the composite subkey revocation must verify under the primary",
            verify(sig, revokeData, compositePublic)
        )

        assertTrue(
            "the facade must report the subkey as revoked after revocation",
            CompositeKeyFacade.parse(updated).encryptionSubkey!!.isRevoked
        )
    }
}
