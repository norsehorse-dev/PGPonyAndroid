// VerifyServiceTest.kt
// PGPony Android — Phase A3
//
// Coverage:
//   • detectInputType across all four input shapes (encrypted, clear-signed,
//     detached, garbage)
//   • verifyClearSigned end-to-end roundtrip: sign with SigningService,
//     verify with VerifyService — green Verified result
//   • verifyClearSigned UnknownSigner case: sign with a key not present
//     in the supplied rings, get a yellow UnknownSigner with the claimed
//     fingerprint populated
//   • verifyClearSigned Invalid case: tamper with the signed text after
//     signing, get a red Invalid result
//   • verifyClearSigned parse-failure: malformed input returns Invalid
//     without crashing
//   • verifyDetached roundtrip: same shape for the detached flow that A10
//     will eventually surface
//
// We generate test keys via PGPCryptoService.generateKeyPair so the
// crypto stack is shared with the rest of the app — these aren't
// reaching past production code paths.

package com.pgpony.android.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.security.Security

class VerifyServiceTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun installBouncyCastle() {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        private val crypto by lazy { PGPCryptoService.shared }

        // Alice and Bob — two independent key rings. Alice is "the user's
        // own key" (in the local keyring); Bob is "a stranger" whose key
        // is NOT in the user's keyring (drives the UnknownSigner case).
        private val alice by lazy { generateKey("Alice", "alice@example.com") }
        private val bob   by lazy { generateKey("Bob",   "bob@example.com") }

        private data class TestKey(
            val secRing: PGPSecretKeyRing,
            val pubRing: PGPPublicKeyRing
        )

        private fun generateKey(name: String, email: String): TestKey {
            val gen = crypto.generateKeyPair(
                name = name,
                email = email,
                algorithm = KeyAlgorithm.ED25519_CV25519,
                passphrase = null
            )
            val sec = crypto.importKeyData(gen.privateKeyData).secretKeyRing
                ?: error("Generated key should expose a secret key ring")
            val pub = crypto.importKeyData(gen.publicKeyData).publicKeyRing
                ?: error("Generated key should expose a public key ring")
            return TestKey(sec, pub)
        }
    }

    private val verifier get() = VerifyService.shared
    private val signer   get() = SigningService.shared

    // ── detectInputType ───────────────────────────────────────────────

    @Test
    fun detectInputTypeRecognizesClearSigned() {
        val signed = signer.signClear("hello", alice.secRing)
        assertEquals(SignedInputType.CLEAR_SIGNED, verifier.detectInputType(signed))
    }

    @Test
    fun detectInputTypeRecognizesDetachedSignature() {
        val sigBytes = signer.signDetached("hello".toByteArray(), alice.secRing)
        val sigText = String(sigBytes, Charsets.UTF_8)
        assertEquals(SignedInputType.DETACHED_SIGNATURE, verifier.detectInputType(sigText))
    }

    @Test
    fun detectInputTypeRecognizesEncryptedMessage() {
        // Synthesize the marker rather than performing a real encrypt —
        // we're testing classification, not the encrypt pipeline.
        val fakeEncrypted = """
            -----BEGIN PGP MESSAGE-----
            
            (some base64 here)
            -----END PGP MESSAGE-----
        """.trimIndent()
        assertEquals(SignedInputType.ENCRYPTED, verifier.detectInputType(fakeEncrypted))
    }

    @Test
    fun detectInputTypeReturnsUnknownForGarbage() {
        assertEquals(SignedInputType.UNKNOWN, verifier.detectInputType(""))
        assertEquals(SignedInputType.UNKNOWN, verifier.detectInputType("just some prose"))
        assertEquals(SignedInputType.UNKNOWN, verifier.detectInputType("https://example.com/"))
    }

    @Test
    fun detectInputTypePrefersClearSignedOverDetachedWhenBothMarkersPresent() {
        // Clear-signed messages contain BOTH BEGIN PGP SIGNED MESSAGE
        // AND BEGIN PGP SIGNATURE — must classify as CLEAR_SIGNED, not
        // mistakenly as DETACHED_SIGNATURE.
        val signed = signer.signClear("hello", alice.secRing)
        assertTrue(signed.contains("-----BEGIN PGP SIGNED MESSAGE-----"))
        assertTrue(signed.contains("-----BEGIN PGP SIGNATURE-----"))
        assertEquals(SignedInputType.CLEAR_SIGNED, verifier.detectInputType(signed))
    }

    // ── verifyClearSigned — Verified path ─────────────────────────────

    @Test
    fun verifyClearSignedReturnsVerifiedForOwnKey() {
        val message = "Hello, this is signed by Alice."
        val signed = signer.signClear(message, alice.secRing)

        val result = verifier.verifyClearSigned(signed, listOf(alice.pubRing))
        assertTrue("Expected Verified, got $result", result is VerificationResult.Verified)
        val v = result as VerificationResult.Verified

        assertEquals("Alice", v.signerName)
        assertEquals("alice@example.com", v.signerEmail)
        assertEquals(message, v.signedContent)
        assertTrue("Fingerprint should be 40 hex chars (v4)", v.signerFingerprint.length == 40)
        assertTrue("Key ID should be 16 hex chars", v.signerKeyID.length == 16)
    }

    @Test
    fun verifyClearSignedPreservesMultilineContent() {
        val message = "Line one\nLine two with    trailing  whitespace\n-Dash-leading line\nFinal"
        val signed = signer.signClear(message, alice.secRing)

        val result = verifier.verifyClearSigned(signed, listOf(alice.pubRing))
        assertTrue(result is VerificationResult.Verified)
        val v = result as VerificationResult.Verified

        // Content should round-trip exactly — line endings normalized by
        // ClearSignedParser to LF, but characters preserved.
        assertEquals(message, v.signedContent)
    }

    @Test
    fun verifyClearSignedHandlesContentEndingInBlankLine() {
        // RFC 9580 §7.1: a trailing blank line is signed content; only the
        // single line terminator before the signature is excluded. Regression
        // for the double-strip bug (parser strip + canonicalize drop) that
        // deleted the blank line from the hash, making such messages — PGPony's
        // own included — fail to verify. Mirrors the shape of RFC 9580 A.6.
        val message = "Shopping list:\n\n- tofu\n- noodles\n\n"
        val signed = signer.signClear(message, alice.secRing)

        val result = verifier.verifyClearSigned(signed, listOf(alice.pubRing))
        assertTrue("Expected Verified, got $result", result is VerificationResult.Verified)
    }

    // ── verifyClearSigned — UnknownSigner path ────────────────────────

    @Test
    fun verifyClearSignedReturnsUnknownSignerWhenKeyNotInRings() {
        // Bob signs, but only Alice's pubRing is in the keyring list.
        val message = "Signed by Bob, but you don't know Bob."
        val signed = signer.signClear(message, bob.secRing)

        val result = verifier.verifyClearSigned(signed, listOf(alice.pubRing))
        assertTrue("Expected UnknownSigner, got $result", result is VerificationResult.UnknownSigner)
        val u = result as VerificationResult.UnknownSigner

        assertEquals(message, u.signedContent)
        assertTrue("Key ID should be 16 hex chars", u.signerKeyID.length == 16)
        assertNotNull(
            "Claimed fingerprint should be populated from issuer-fingerprint subpacket",
            u.claimedFingerprint
        )
        assertEquals(
            "Claimed fingerprint should be 40 hex chars (v4)",
            40,
            u.claimedFingerprint!!.length
        )
    }

    @Test
    fun verifyClearSignedUnknownSignerFingerprintMatchesActualBobsKey() {
        val signed = signer.signClear("data", bob.secRing)
        val result = verifier.verifyClearSigned(signed, listOf(alice.pubRing))
            as VerificationResult.UnknownSigner

        val bobFingerprint = bob.pubRing.publicKey.fingerprint
            .joinToString("") { "%02X".format(it) }
        assertEquals(
            "Claimed fingerprint must match Bob's actual primary key fingerprint",
            bobFingerprint,
            result.claimedFingerprint
        )
    }

    // ── verifyClearSigned — Invalid paths ─────────────────────────────

    @Test
    fun verifyClearSignedReturnsInvalidWhenContentTampered() {
        val signed = signer.signClear("Original signed content", alice.secRing)
        // Replace one character of the cleartext while keeping the signature
        // block intact. Verification should fail.
        val tampered = signed.replace("Original signed content", "Original signed CONTENT")

        val result = verifier.verifyClearSigned(tampered, listOf(alice.pubRing))
        assertTrue("Expected Invalid, got $result", result is VerificationResult.Invalid)
    }

    @Test
    fun verifyClearSignedReturnsInvalidForMalformedInput() {
        val result = verifier.verifyClearSigned(
            armored = "not a clear-signed message",
            publicKeyRings = listOf(alice.pubRing)
        )
        assertTrue(result is VerificationResult.Invalid)
        val inv = result as VerificationResult.Invalid
        assertNull(inv.signerKeyID)
    }

    @Test
    fun verifyClearSignedReturnsInvalidForTruncatedSignatureBlock() {
        val signed = signer.signClear("hello", alice.secRing)
        // Strip the END marker — should fail parsing.
        val truncated = signed.substringBefore("-----END PGP SIGNATURE-----")
        val result = verifier.verifyClearSigned(truncated, listOf(alice.pubRing))
        assertTrue(result is VerificationResult.Invalid)
    }

    // ── verifyDetached — Verified + UnknownSigner paths ───────────────

    @Test
    fun verifyDetachedReturnsVerifiedForMatchingSignature() {
        val data = "Hello, world".toByteArray()
        val sig = signer.signDetached(data, alice.secRing, armor = true)
        val sigText = String(sig, Charsets.UTF_8)

        val result = verifier.verifyDetached(sigText, data, listOf(alice.pubRing))
        assertTrue("Expected Verified, got $result", result is VerificationResult.Verified)
        val v = result as VerificationResult.Verified
        assertEquals("Alice", v.signerName)
        assertEquals("alice@example.com", v.signerEmail)
    }

    @Test
    fun verifyDetachedReturnsInvalidWhenDataDoesntMatch() {
        val data = "Hello, world".toByteArray()
        val sig = signer.signDetached(data, alice.secRing, armor = true)
        val sigText = String(sig, Charsets.UTF_8)

        // Different bytes — verification should fail.
        val result = verifier.verifyDetached(
            sigText,
            "Different bytes".toByteArray(),
            listOf(alice.pubRing)
        )
        assertTrue("Expected Invalid, got $result", result is VerificationResult.Invalid)
    }

    @Test
    fun verifyDetachedReturnsUnknownSignerWhenSignerNotInRings() {
        val data = "Signed by Bob".toByteArray()
        val sig = signer.signDetached(data, bob.secRing, armor = true)
        val sigText = String(sig, Charsets.UTF_8)

        val result = verifier.verifyDetached(sigText, data, listOf(alice.pubRing))
        assertTrue("Expected UnknownSigner, got $result", result is VerificationResult.UnknownSigner)
        val u = result as VerificationResult.UnknownSigner
        assertNotNull(u.claimedFingerprint)
    }

    // ── ClearSignedParser smoke ───────────────────────────────────────

    @Test
    fun clearSignedParserExtractsCorrectHashAlgorithm() {
        val signed = signer.signClear("hello", alice.secRing)
        val parsed = ClearSignedParser.parse(signed)
        assertNotNull(parsed)
        assertEquals("SHA256", parsed!!.hashAlgorithmName)
    }

    @Test
    fun clearSignedParserReturnsNullForNonClearSignedInput() {
        assertNull(ClearSignedParser.parse("not a clear-signed message"))
        assertNull(ClearSignedParser.parse(""))
    }

    @Test
    fun clearSignedParserStripsDashEscapes() {
        // Sign content that triggers dash-escaping, then verify the
        // parser un-escapes correctly.
        val original = "-Line starting with a dash\nNormal line"
        val signed = signer.signClear(original, alice.secRing)
        // Sanity: dash-escape was applied on the wire.
        assertTrue(signed.contains("- -Line starting with a dash"))
        // After parse, dash-escape is gone — we get the original back.
        val parsed = ClearSignedParser.parse(signed)!!
        assertEquals(original, parsed.cleartext)
    }

    // ── Phase A3: binary .sig overload (verifyDetached(ByteArray, …)) ──────

    @Test
    fun verifyDetachedBytesReturnsVerifiedForBinarySig() {
        val data = "release artifact contents".toByteArray()
        // Binary detached signature (.sig), armor = false.
        val sigBytes = signer.signDetached(data, alice.secRing, armor = false)
        val result = verifier.verifyDetached(sigBytes, data, listOf(alice.pubRing))
        assertTrue("Expected Verified, got $result", result is VerificationResult.Verified)
        assertEquals("Alice", (result as VerificationResult.Verified).signerName)
    }

    @Test
    fun verifyDetachedBytesAlsoHandlesArmoredSigBytes() {
        val data = "armored .asc bytes through the binary overload".toByteArray()
        // Armored .asc bytes fed to the byte overload — the sniffer should
        // detect the armor header and parse it the same way.
        val ascBytes = signer.signDetached(data, alice.secRing, armor = true)
        val result = verifier.verifyDetached(ascBytes, data, listOf(alice.pubRing))
        assertTrue("Expected Verified, got $result", result is VerificationResult.Verified)
    }

    @Test
    fun verifyDetachedBytesReturnsInvalidForTamperedData() {
        val data = "original download".toByteArray()
        val sigBytes = signer.signDetached(data, alice.secRing, armor = false)
        val result = verifier.verifyDetached(
            sigBytes,
            "tampered download".toByteArray(),
            listOf(alice.pubRing),
        )
        assertTrue("Expected Invalid, got $result", result is VerificationResult.Invalid)
    }

    @Test
    fun verifyDetachedBytesReturnsUnknownSignerWhenSignerNotInRings() {
        val data = "signed by bob, only alice in rings".toByteArray()
        val sigBytes = signer.signDetached(data, bob.secRing, armor = false)
        val result = verifier.verifyDetached(sigBytes, data, listOf(alice.pubRing))
        assertTrue("Expected UnknownSigner, got $result", result is VerificationResult.UnknownSigner)
        assertNotNull((result as VerificationResult.UnknownSigner).claimedFingerprint)
    }
}
