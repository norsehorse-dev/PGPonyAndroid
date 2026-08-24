// CompositeSignerTest.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Pins CompositeSigner against RFC 9980 Appendix A.3 and round-trips it with
// CompositeSigVerifier. Two proofs, no gpg:
//
//   1. RFC parity. Signing the A.3.4 v6 dataDigest with the A.3.1 composite
//      secret must reproduce A.3.4's EdDSA half byte-for-byte (EdDSA is
//      deterministic, RFC 8032), and the full composite signature must verify
//      against the A.3.2 composite public key. This locks the EdDSA component
//      and the digest to the RFC's own octets.
//
//   2. Fresh round-trip. A freshly generated ML-DSA-65 + Ed25519 keypair signs
//      a digest that then verifies, and a tampered signature does not. This
//      exercises the ML-DSA half (hedged, so not byte-reproducible) end to end.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.SecureRandom

class CompositeSignerTest {

    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    private fun dearmor(asc: ByteArray): ByteArray =
        ArmoredInputStream(ByteArrayInputStream(asc)).use { it.readBytes() }

    private fun beInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    /** Body of the first OpenPGP-format packet in [raw]. */
    private fun firstBody(raw: ByteArray): ByteArray {
        var p = 1
        val l0 = raw[p++].toInt() and 0xFF
        val len = when {
            l0 < 192 -> l0
            l0 < 224 -> ((l0 - 192) shl 8) + (raw[p++].toInt() and 0xFF) + 192
            l0 == 255 -> beInt(raw, p).also { p += 4 }
            else -> throw IllegalStateException("partial length not used here")
        }
        return raw.copyOfRange(p, p + len)
    }

    /** Composite public material from a v6 public key packet body. */
    private fun compositePublic(body: ByteArray): ByteArray {
        var q = 1 + 4 // version + creation time
        q += 1 // algorithm
        val matLen = beInt(body, q); q += 4
        return body.copyOfRange(q, q + matLen)
    }

    /** Composite secret material from an unprotected v6 secret key packet body. */
    private fun compositeSecret(body: ByteArray, secretLen: Int): ByteArray {
        var q = 1 + 4 + 1 // version, creation time, algorithm
        val matLen = beInt(body, q); q += 4
        q += matLen // public material
        val usage = body[q++].toInt() and 0xFF
        check(usage == 0) { "expected an unprotected sample secret key, s2k usage $usage" }
        return body.copyOfRange(q, q + secretLen)
    }

    private data class SigFields(
        val sigType: Int, val pubAlgo: Int, val hashAlgo: Int,
        val hashed: ByteArray, val salt: ByteArray, val signature: ByteArray
    )

    private fun sigFields(body: ByteArray): SigFields {
        var q = 1 // version
        val sigType = body[q++].toInt() and 0xFF
        val pubAlgo = body[q++].toInt() and 0xFF
        val hashAlgo = body[q++].toInt() and 0xFF
        val hLen = beInt(body, q); q += 4
        val hashed = body.copyOfRange(q, q + hLen); q += hLen
        val uLen = beInt(body, q); q += 4; q += uLen
        q += 2 // left 16 bits
        val saltSize = body[q++].toInt() and 0xFF
        val salt = body.copyOfRange(q, q + saltSize); q += saltSize
        return SigFields(sigType, pubAlgo, hashAlgo, hashed, salt, body.copyOfRange(q, body.size))
    }

    @Test
    fun `reproduces the RFC 9980 A_3_4 EdDSA half and verifies the composite`() {
        val secAsc = res("rfc9980-a3-mldsa65-ed25519-sec.asc")
        val certAsc = res("rfc9980-a3-mldsa65-ed25519-cert.asc")
        val sigAsc = res("rfc9980-a3-mldsa65-ed25519-sig.asc")
        assumeTrue("pqc/rfc9980 A.3 vectors absent", secAsc != null && certAsc != null && sigAsc != null)

        val suite = CompositeSignSuite.MLDSA65_ED25519
        val secret = compositeSecret(firstBody(dearmor(secAsc!!)), suite.compositeSecretLen)
        val public = compositePublic(firstBody(dearmor(certAsc!!)))
        val ref = sigFields(firstBody(dearmor(sigAsc!!)))

        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = ref.hashAlgo,
            salt = ref.salt,
            data = "Testing\r\n".toByteArray(Charsets.UTF_8),
            signatureType = ref.sigType,
            publicKeyAlgorithm = ref.pubAlgo,
            hashedSubpacketBody = ref.hashed
        )

        val produced = CompositeSigner.sign(suite, secret, digest)

        val (producedEddsa, _) = suite.splitSignature(produced)
        val (refEddsa, _) = suite.splitSignature(ref.signature)
        assertArrayEquals(
            "CompositeSigner must reproduce the RFC A.3.4 deterministic EdDSA half",
            refEddsa, producedEddsa
        )
        assertTrue(
            "the freshly produced composite signature must verify against A.3.2",
            CompositeSigVerifier.verify(suite, public, produced, digest)
        )
    }

    @Test
    fun `signs and verifies a freshly generated composite keypair`() {
        val suite = CompositeSignSuite.MLDSA65_ED25519
        val rnd = SecureRandom()

        val edSecret = ByteArray(suite.eddsa.secretLen).also { rnd.nextBytes(it) }
        val mldsaSeed = ByteArray(suite.mldsa.seedLen).also { rnd.nextBytes(it) }
        val edPublic = Ed25519PrivateKeyParameters(edSecret, 0).generatePublicKey().encoded
        val mldsaPublic = MLDSAPrivateKeyParameters(suite.mldsa.params, mldsaSeed)
            .publicKeyParameters.encoded

        val compositeSecret = suite.join(edSecret, mldsaSeed)
        val compositePublic = suite.join(edPublic, mldsaPublic)

        // A plausible v6 digest input; the value only needs to be well-formed.
        val salt = ByteArray(16).also { rnd.nextBytes(it) }
        val hashed = byteArrayOf(0x00, 0x00, 0x00, 0x00)
        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = 8,
            salt = salt,
            data = "round trip\n".toByteArray(Charsets.UTF_8),
            signatureType = 0x00,
            publicKeyAlgorithm = suite.algId,
            hashedSubpacketBody = hashed
        )

        val sig = CompositeSigner.sign(suite, compositeSecret, digest, rnd)
        assertTrue(
            "a freshly signed composite must verify",
            CompositeSigVerifier.verify(suite, compositePublic, sig, digest)
        )

        val tampered = sig.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        assertFalse(
            "a tampered composite must not verify",
            CompositeSigVerifier.verify(suite, compositePublic, tampered, digest)
        )
    }
}
