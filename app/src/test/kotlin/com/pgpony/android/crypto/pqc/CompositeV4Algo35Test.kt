// CompositeV4Algo35Test.kt
// PGPony Android — 4.5.0 (item 14 / #56): v4 ML-KEM-768+X25519 (algo 35) subkey.
//
// Grafts a v4 algo-35 encryption subkey onto a v4 Ed25519 primary and checks,
// offline, that the hand-rolled v4 subkey-binding signature is a valid Ed25519
// signature over the v4-framed (0x99 / 2-octet) hash of primary + subkey, and
// that the subkey fingerprint is the v4 SHA-1 form. This proves internal
// correctness; RFC 9980 Appendix A.2 interop (gpg 2.5.x / sq) is the on-device
// delivery check.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class CompositeV4Algo35Test {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"

    private data class Pkt(val tag: Int, val body: ByteArray)

    private fun walk(raw: ByteArray): List<Pkt> {
        val out = ArrayList<Pkt>()
        var i = 0
        while (i < raw.size) {
            val c = raw[i++].toInt() and 0xFF
            check(c and 0x80 != 0)
            val tag: Int; val len: Int
            if (c and 0x40 != 0) {
                tag = c and 0x3F
                val l0 = raw[i++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0
                    l0 < 224 -> ((l0 - 192) shl 8) + (raw[i++].toInt() and 0xFF) + 192
                    l0 == 255 -> beInt(raw, i).also { i += 4 }
                    else -> throw IllegalStateException("partial length")
                }
            } else {
                tag = (c shr 2) and 0x0F
                len = when (c and 0x03) {
                    0 -> raw[i++].toInt() and 0xFF
                    1 -> (((raw[i].toInt() and 0xFF) shl 8) or (raw[i + 1].toInt() and 0xFF)).also { i += 2 }
                    2 -> beInt(raw, i).also { i += 4 }
                    else -> throw IllegalStateException("indeterminate length")
                }
            }
            out.add(Pkt(tag, raw.copyOfRange(i, i + len)))
            i += len
        }
        return out
    }

    private fun beInt(b: ByteArray, o: Int) =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    /** Strip a new-format packet header, returning the body. */
    private fun packetBody(encoded: ByteArray): ByteArray = walk(encoded).first().body

    private fun v4Frame(body: ByteArray) =
        byteArrayOf(0x99.toByte(), ((body.size ushr 8) and 0xFF).toByte(), (body.size and 0xFF).toByte()) + body

    private fun mpiValue(b: ByteArray, off: Int): Pair<ByteArray, Int> {
        val bits = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
        val n = (bits + 7) / 8
        return b.copyOfRange(off + 2, off + 2 + n) to (off + 2 + n)
    }

    private fun leftPad32(v: ByteArray): ByteArray =
        if (v.size >= 32) v.copyOfRange(v.size - 32, v.size) else ByteArray(32 - v.size) + v

    @Test
    fun `v4 algo-35 subkey has a verifiable v4 binding and a SHA-1 fingerprint`() {
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "V4 Interop", email = "v4@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = pass
            ).privateKeyData
        ).secretKeyRing!!

        val raw = CompositeKeyGen.addV4Algo35Subkey(base, pass)
        val packets = walk(raw)

        // The appended v4 algo-35 secret subkey is the last tag-7 packet.
        val subPacket = packets.last { it.tag == 7 }
        assertEquals("v4 key packet version", 4, subPacket.body[0].toInt() and 0xFF)
        assertEquals("algorithm 35 (ML-KEM-768 + X25519)", 35, subPacket.body[1 + 4].toInt() and 0xFF)

        // v4 pub body: version(1) ctime(4) algo(1) + material(1216), no length field.
        val subPubBody = subPacket.body.copyOfRange(0, 6 + 1216)

        // v4 fingerprint = SHA-1 over 0x99 || 2-octet len || pub body (20 octets).
        val fp = MessageDigest.getInstance("SHA-1").digest(v4Frame(subPubBody))
        assertEquals("v4 fingerprint is SHA-1 (20 octets)", 20, fp.size)

        // The binding is the last signature packet.
        val bind = packets.last { it.tag == 2 }
        assertEquals("subkey binding type", 0x18, bind.body[1].toInt() and 0xFF)
        assertEquals("EdDSA-legacy signer", 22, bind.body[2].toInt() and 0xFF)
        assertEquals("SHA-256 hash", 8, bind.body[3].toInt() and 0xFF)

        var q = 4
        val hLen = ((bind.body[q].toInt() and 0xFF) shl 8) or (bind.body[q + 1].toInt() and 0xFF); q += 2
        val hashed = bind.body.copyOfRange(q, q + hLen); q += hLen
        val uLen = ((bind.body[q].toInt() and 0xFF) shl 8) or (bind.body[q + 1].toInt() and 0xFF); q += 2
        q += uLen
        q += 2 // left 16 bits of hash
        val (r, q2) = mpiValue(bind.body, q)
        val (sVal, _) = mpiValue(bind.body, q2)
        val sig64 = leftPad32(r) + leftPad32(sVal)

        // Recompute the v4 binding hash (0x99 / 2-octet framing on both keys).
        val primaryPubBody = packetBody(base.publicKey.encoded)
        val hashData = java.io.ByteArrayOutputStream().apply {
            write(v4Frame(primaryPubBody))
            write(v4Frame(subPubBody))
            write(4); write(0x18); write(22); write(8)
            write((hLen ushr 8) and 0xFF); write(hLen and 0xFF); write(hashed)
            write(4); write(0xFF)
            write(byteArrayOf(
                (((6 + hLen) ushr 24) and 0xFF).toByte(), (((6 + hLen) ushr 16) and 0xFF).toByte(),
                (((6 + hLen) ushr 8) and 0xFF).toByte(), ((6 + hLen) and 0xFF).toByte()
            ))
        }.toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(hashData)

        val edPub = BcPGPKeyConverter().getPublicKey(base.publicKey) as Ed25519PublicKeyParameters
        val verifier = Ed25519Signer().apply { init(false, edPub) }
        verifier.update(digest, 0, digest.size)
        assertTrue(
            "the v4 algo-35 subkey binding must verify under the Ed25519 primary",
            verifier.verifySignature(sig64)
        )
    }

    @Test
    fun `addV4Algo35SubkeyRings yields a matching public ring and the v4 primary fingerprint`() {
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "V4 Interop", email = "v4@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = pass
            ).privateKeyData
        ).secretKeyRing!!

        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base, pass)

        val pubPackets = walk(rings.publicRaw)
        val secPackets = walk(rings.secretRaw)
        // The public ring carries the algo-35 subkey as a PUBLIC subkey (tag 14),
        // never a secret one (tag 7); the secret ring is its mirror.
        assertEquals("public ring has no secret packets", 0, pubPackets.count { it.tag == 7 })
        assertTrue("secret ring carries the algo-35 secret subkey", secPackets.any { it.tag == 7 })

        val pubSub = pubPackets.last { it.tag == 14 }
        assertEquals("v4 key packet version", 4, pubSub.body[0].toInt() and 0xFF)
        assertEquals("algorithm 35", 35, pubSub.body[1 + 4].toInt() and 0xFF)
        assertEquals("v4 pub body: 6-octet header + 1216 material", 6 + 1216, pubSub.body.size)

        // Public and secret subkey share identical public material (the secret
        // body is that public body followed by usage/material/checksum).
        val secSub = secPackets.last { it.tag == 7 }
        val secPubPrefix = secSub.body.copyOfRange(0, 6 + 1216)
        assertTrue("secret subkey embeds the same public body", pubSub.body.contentEquals(secPubPrefix))

        val expected = base.publicKey.fingerprint.joinToString("") { "%02X".format(it) }
        assertEquals("primary fingerprint is the v4 primary SHA-1 hex", expected, rings.primaryFingerprintHex)
        assertEquals("SHA-1 fingerprint hex length", 40, rings.primaryFingerprintHex.length)
    }
}
