// CompositeSignSubkeyGenTest.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Pins CompositeSignSubkeyGen: adding a composite ML-DSA-65 + Ed25519 signing
// subkey to a real v6 Ed25519 primary. The subkey and both of its signatures
// are hand-emitted, so the test hand-parses the produced ring and verifies,
// with no gpg:
//
//   * the 0x18 subkey-binding signature (native Ed25519 by the primary) over
//     the v6 key-binding hash of primary || subkey, and
//   * the embedded 0x19 back-signature (composite, by the subkey itself) over
//     the same key-binding hash, through CompositeSigVerifier.
//
// It also checks that BouncyCastle re-parses the ring, sees a v6 algo-30
// signing subkey with the primary fingerprint unchanged, and that a protected
// primary yields a protected subkey.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class CompositeSignSubkeyGenTest {

    private val svc = PGPCryptoService.shared
    private val suite = CompositeSignSuite.MLDSA65_ED25519

    private fun v6Primary(passphrase: String?): PGPSecretKeyRing {
        val gen = svc.generateKeyPair(
            "Composite Sign", "csign@pgpony.app",
            KeyAlgorithm.V6_ED25519, passphrase = passphrase
        )
        return PGPSecretKeyRing(
            ByteArrayInputStream(gen.privateKeyData), JcaKeyFingerprintCalculator()
        )
    }

    private fun newSubkeyOf(before: PGPSecretKeyRing, after: PGPSecretKeyRing): List<PGPSecretKey> {
        val beforeIds = before.secretKeys.asSequence().map { it.keyID }.toSet()
        return after.secretKeys.asSequence().filter { it.keyID !in beforeIds }.toList()
    }

    // -- minimal packet reading, matching the emitter --

    private data class Pkt(val tag: Int, val body: ByteArray)

    private fun walkPackets(raw: ByteArray): List<Pkt> {
        val out = ArrayList<Pkt>()
        var i = 0
        while (i < raw.size) {
            val c = raw[i++].toInt() and 0xFF
            check(c and 0x80 != 0) { "not a packet header: 0x${c.toString(16)}" }
            val tag: Int
            val len: Int
            if (c and 0x40 != 0) { // new-format header
                tag = c and 0x3F
                val l0 = raw[i++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0
                    l0 < 224 -> ((l0 - 192) shl 8) + (raw[i++].toInt() and 0xFF) + 192
                    l0 == 255 -> beInt(raw, i).also { i += 4 }
                    else -> throw IllegalStateException("partial length not used here")
                }
            } else { // old-format header
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

    /** The v6 public key packet body (through the public material) from a key packet body. */
    private fun publicKeyBody(keyPacketBody: ByteArray): ByteArray {
        var q = 1 + 4 + 1 // version, creation time, algorithm
        val matLen = beInt(keyPacketBody, q); q += 4
        return keyPacketBody.copyOfRange(0, q + matLen)
    }

    private fun publicMaterial(publicBody: ByteArray): ByteArray {
        var q = 1 + 4 + 1
        val matLen = beInt(publicBody, q); q += 4
        return publicBody.copyOfRange(q, q + matLen)
    }

    private fun keyFrame(body: ByteArray): ByteArray =
        byteArrayOf(0x9B.toByte()) + byteArrayOf(
            (body.size ushr 24).toByte(), (body.size ushr 16).toByte(),
            (body.size ushr 8).toByte(), body.size.toByte()
        ) + body

    private data class V6Sig(
        val sigType: Int, val pubAlgo: Int, val hashAlgo: Int,
        val hashed: ByteArray, val salt: ByteArray, val signature: ByteArray
    )

    private fun parseV6Sig(body: ByteArray): V6Sig {
        var q = 1 // version
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

    /** Extract the body of the embedded signature subpacket (type 32) from a hashed area. */
    private fun embeddedSignature(hashed: ByteArray): ByteArray {
        var i = 0
        while (i < hashed.size) {
            val l0 = hashed[i++].toInt() and 0xFF
            val len = when {
                l0 < 192 -> l0
                l0 < 255 -> ((l0 - 192) shl 8) + (hashed[i++].toInt() and 0xFF) + 192
                else -> beInt(hashed, i).also { i += 4 }
            }
            val type = hashed[i].toInt() and 0x7F
            val body = hashed.copyOfRange(i + 1, i + len)
            if (type == 32) return body
            i += len
        }
        throw AssertionError("no embedded signature subpacket in the binding")
    }

    private fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val signer = Ed25519Signer().apply { init(false, Ed25519PublicKeyParameters(publicKey, 0)) }
        signer.update(message, 0, message.size)
        return signer.verifySignature(signature)
    }

    @Test
    fun `adds a composite signing subkey with verifiable binding and back-signature`() {
        val ring = v6Primary(passphrase = null)
        val primaryFp = ring.publicKey.fingerprint
        val updated = CompositeSignSubkeyGen.addCompositeSigningSubkey(ring, suite, passphrase = null)

        val added = newSubkeyOf(ring, updated)
        assertEquals("exactly one new subkey", 1, added.size)
        val sub = added.first()
        assertEquals("subkey must be v6", 6, sub.publicKey.version)
        assertEquals("subkey algorithm is composite 30", suite.algId, sub.publicKey.algorithm)
        assertTrue("a signing subkey is not an encryption key", !sub.publicKey.isEncryptionKey)
        assertTrue("primary fingerprint unchanged", primaryFp.contentEquals(updated.publicKey.fingerprint))

        // Round-trips through BC.
        val reparsed = PGPSecretKeyRing(
            ByteArrayInputStream(updated.encoded), JcaKeyFingerprintCalculator()
        )
        assertEquals(
            updated.secretKeys.asSequence().count(),
            reparsed.secretKeys.asSequence().count()
        )

        // Hand-verify both signatures from the emitted bytes.
        val packets = walkPackets(updated.encoded)
        val primaryBody = packets.first { it.tag == 5 }.body
        val subkeyBody = packets.last { it.tag == 7 }.body
        val bindingBody = packets.last { it.tag == 2 }.body

        val primaryPublicBody = publicKeyBody(primaryBody)
        val subkeyPublicBody = publicKeyBody(subkeyBody)
        val keyBindingData = keyFrame(primaryPublicBody) + keyFrame(subkeyPublicBody)

        val binding = parseV6Sig(bindingBody)
        assertEquals("binding is a subkey-binding signature", 0x18, binding.sigType)
        val bindingDigest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = binding.hashAlgo, salt = binding.salt, data = keyBindingData,
            signatureType = binding.sigType, publicKeyAlgorithm = binding.pubAlgo,
            hashedSubpacketBody = binding.hashed
        )
        val primaryEd = publicMaterial(primaryPublicBody)
        assertTrue(
            "the 0x18 binding must verify under the primary Ed25519 key",
            ed25519Verify(primaryEd, bindingDigest, binding.signature)
        )

        val back = parseV6Sig(embeddedSignature(binding.hashed))
        assertEquals("embedded back-signature is a primary-key-binding signature", 0x19, back.sigType)
        assertEquals("back-signature is composite", suite.algId, back.pubAlgo)
        val backDigest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = back.hashAlgo, salt = back.salt, data = keyBindingData,
            signatureType = back.sigType, publicKeyAlgorithm = back.pubAlgo,
            hashedSubpacketBody = back.hashed
        )
        val subComposite = publicMaterial(subkeyPublicBody)
        assertTrue(
            "the 0x19 back-signature must verify under the composite subkey",
            CompositeSigVerifier.verify(suite, subComposite, back.signature, backDigest)
        )
    }

    @Test
    fun `a composite signing subkey added to a protected key is itself protected`() {
        val pass = "correct horse"
        val ring = v6Primary(passphrase = pass)
        val updated = CompositeSignSubkeyGen.addCompositeSigningSubkey(ring, suite, passphrase = pass)
        val sub = newSubkeyOf(ring, updated).single()
        assertNotEquals("a new secret subkey must not be stored unprotected", 0, sub.s2KUsage)
    }
}
