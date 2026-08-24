// CompositeDocumentSignaturesTest.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Round-trips CompositeDocumentSigner against CompositeDocumentVerifier for the
// three signing forms (detached, cleartext, inline), and verifies the RFC 9980
// Appendix A.3.4 detached signature through the verifier's public entry point.

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

class CompositeDocumentSignaturesTest {

    private val suite = CompositeSignSuite.MLDSA65_ED25519
    private val rnd = SecureRandom()

    private fun freshKeypair(): Pair<ByteArray, ByteArray> {
        val edSecret = ByteArray(suite.eddsa.secretLen).also { rnd.nextBytes(it) }
        val mldsaSeed = ByteArray(suite.mldsa.seedLen).also { rnd.nextBytes(it) }
        val edPublic = Ed25519PrivateKeyParameters(edSecret, 0).generatePublicKey().encoded
        val mldsaPublic = MLDSAPrivateKeyParameters(suite.mldsa.params, mldsaSeed)
            .publicKeyParameters.encoded
        return suite.join(edSecret, mldsaSeed) to suite.join(edPublic, mldsaPublic)
    }

    private val fingerprint = ByteArray(32) { it.toByte() }

    @Test
    fun `detached signature round-trips and rejects tampering`() {
        val (sec, pub) = freshKeypair()
        val data = "the quick brown pony".toByteArray()
        val sig = CompositeDocumentSigner.signDetached(suite, sec, fingerprint, data, random = rnd)

        assertTrue(
            "detached signature must verify",
            CompositeDocumentVerifier.verifyDetached(pub, sig, data).valid
        )
        assertFalse(
            "detached signature must fail over altered data",
            CompositeDocumentVerifier.verifyDetached(pub, sig, "tampered".toByteArray()).valid
        )
        assertTrue("detached packet is recognized as composite", CompositeDocumentVerifier.isCompositeSignature(sig))
    }

    @Test
    fun `armored detached signature round-trips`() {
        val (sec, pub) = freshKeypair()
        val data = ByteArray(500).also { rnd.nextBytes(it) }
        val armored = CompositeDocumentSigner.signDetachedArmored(suite, sec, fingerprint, data, random = rnd)
        assertTrue(armored.contains("-----BEGIN PGP SIGNATURE-----"))
        assertTrue(
            "armored detached signature must verify",
            CompositeDocumentVerifier.verifyDetachedArmored(pub, armored, data).valid
        )
    }

    @Test
    fun `cleartext signed message round-trips`() {
        val (sec, pub) = freshKeypair()
        val text = "Dear world,\n-dash at line start\ntrailing spaces here   \nlast line"
        val message = CompositeDocumentSigner.signCleartext(suite, sec, fingerprint, text, random = rnd)

        assertTrue(message.startsWith("-----BEGIN PGP SIGNED MESSAGE-----"))
        val result = CompositeDocumentVerifier.verifyCleartext(pub, message)
        assertTrue("cleartext signature must verify", result.valid)
    }

    @Test
    fun `inline one-pass message round-trips and returns the content`() {
        val (sec, pub) = freshKeypair()
        val data = "one-pass composite payload".toByteArray()
        val message = CompositeDocumentSigner.signInline(suite, sec, fingerprint, data, random = rnd)

        assertTrue("inline packet is recognized as composite", CompositeDocumentVerifier.isCompositeSignature(message))
        val result = CompositeDocumentVerifier.verifyInline(pub, message)
        assertTrue("inline signature must verify", result.valid)
        assertArrayEquals("literal content must be recovered", data, result.content)
    }

    @Test
    fun `a classical signature packet is not misdetected as composite`() {
        // A minimal v6 tag-2 body with Ed25519 (27) at the algorithm offset.
        val body = byteArrayOf(6, 0x00, 27, 8, 0, 0, 0, 0)
        val fake = CompositeSigPacket.packet(2, body)
        assertFalse(CompositeDocumentVerifier.isCompositeSignature(fake))
    }

    @Test
    fun `verifies the RFC 9980 A_3_4 detached signature through the verifier`() {
        val certAsc = res("rfc9980-a3-mldsa65-ed25519-cert.asc")
        val sigAsc = res("rfc9980-a3-mldsa65-ed25519-sig.asc")
        assumeTrue("pqc/rfc9980 A.3 vectors absent", certAsc != null && sigAsc != null)

        val compositePublic = compositePublicOf(dearmor(certAsc!!))
        val sigPacket = dearmor(sigAsc!!)
        // A.3.4 is a text signature over "Testing\n"; the verifier canonicalizes.
        val result = CompositeDocumentVerifier.verifyDetached(
            compositePublic, sigPacket, "Testing\n".toByteArray(Charsets.UTF_8)
        )
        assertTrue("RFC 9980 A.3.4 must verify through CompositeDocumentVerifier", result.valid)
    }

    // -- helpers --

    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    private fun dearmor(asc: ByteArray): ByteArray =
        ArmoredInputStream(ByteArrayInputStream(asc)).use { it.readBytes() }

    private fun compositePublicOf(certBytes: ByteArray): ByteArray {
        val (_, body) = CompositeSigPacket.firstPacket(certBytes)
        var q = 1 + 4 + 1
        val matLen = CompositeSigPacket.beInt(body, q); q += 4
        return body.copyOfRange(q, q + matLen)
    }
}
