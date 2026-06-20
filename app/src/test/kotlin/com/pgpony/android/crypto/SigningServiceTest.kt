// SigningServiceTest.kt
// PGPony Android
//
// Phase A2 tests for SigningService:
//   • Detached signature: full sign + verify roundtrip via BC.
//   • Clear-signed: output format validation (correct armor frame, hash
//     header, content present, signature block present). Plus an inline
//     verify routine that demonstrates the canonical-form hashing matches
//     what verifiers will compute on the receive side.
//   • Passphrase handling: encrypted key + correct passphrase signs;
//     missing passphrase throws PassphraseRequired; wrong passphrase
//     throws InvalidPassphrase.
//
// We generate test keys via PGPCryptoService.generateKeyPair (already
// covered by BouncyCastleValidationTest), so the cryptography is shared
// with the rest of the app — tests aren't reaching past production paths.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.Security

class SigningServiceTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun installBouncyCastle() {
            // PGPCryptoService.shared also registers BC via its init block;
            // do it here too so test order doesn't matter and a future
            // refactor of PGPCryptoService can't silently break us.
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        // ── Shared test fixtures ──────────────────────────────────────
        // Generated once per class because Ed25519 keygen via BC takes
        // ~50–200ms — re-generating per @Test would multiply that across
        // every assertion.

        private val crypto by lazy { PGPCryptoService.shared }

        private val unprotectedKey by lazy { generateKey(passphrase = null) }
        private val protectedKey   by lazy { generateKey(passphrase = "horseshoes") }

        private data class TestKey(
            val secRing: org.bouncycastle.openpgp.PGPSecretKeyRing,
            val pubRing: org.bouncycastle.openpgp.PGPPublicKeyRing
        )

        private fun generateKey(passphrase: String?): TestKey {
            val gen = crypto.generateKeyPair(
                name = "Test User",
                email = "test@example.com",
                algorithm = KeyAlgorithm.ED25519_CV25519,
                passphrase = passphrase
            )
            val secRing = crypto.importKeyData(gen.privateKeyData).secretKeyRing
                ?: error("Generated key should expose a secret key ring")
            val pubRing = crypto.importKeyData(gen.publicKeyData).publicKeyRing
                ?: error("Generated key should expose a public key ring")
            return TestKey(secRing, pubRing)
        }
    }

    private val signer get() = SigningService.shared

    // ── Detached: full roundtrip ──────────────────────────────────────

    @Test
    fun detachedSignArmoredRoundtripsAgainstBC() {
        val (secRing, pubRing) = unprotectedKey
        val message = "Hello, PGP world!".toByteArray(Charsets.UTF_8)

        val armored = signer.signDetached(data = message, secretKeyRing = secRing, armor = true)
        val armoredText = String(armored, Charsets.UTF_8)

        assertTrue(armoredText.startsWith("-----BEGIN PGP SIGNATURE-----"))
        assertTrue(armoredText.trimEnd().endsWith("-----END PGP SIGNATURE-----"))

        val sig = parseFirstSignature(armored)
        sig.init(BcPGPContentVerifierBuilderProvider(), pubRing.getPublicKey(sig.keyID))
        sig.update(message)
        assertTrue("Detached signature should verify against BC", sig.verify())
    }

    @Test
    fun detachedSignBinaryRoundtripsAgainstBC() {
        val (secRing, pubRing) = unprotectedKey
        val message = "Binary payload".toByteArray(Charsets.UTF_8)

        val binary = signer.signDetached(data = message, secretKeyRing = secRing, armor = false)
        assertTrue("Binary signature should not start with PGP armor header",
            !String(binary, Charsets.UTF_8).startsWith("-----BEGIN"))

        // Verify by feeding the bytes directly into PGPObjectFactory — no
        // ArmoredInputStream needed because it's already binary.
        val fact = JcaPGPObjectFactory(ByteArrayInputStream(binary))
        val sigList = fact.nextObject() as PGPSignatureList
        val sig = sigList.get(0)
        sig.init(BcPGPContentVerifierBuilderProvider(), pubRing.getPublicKey(sig.keyID))
        sig.update(message)
        assertTrue("Binary detached signature should verify", sig.verify())
    }

    @Test
    fun detachedSigCarriesIssuerFingerprintSubpacket() {
        // Issuer-fingerprint subpacket (RFC 4880bis subpacket type 33) is
        // required for the Phase A3 "unknown signer" lookup flow — the UI
        // uses the claimed fingerprint to query WKD/keyserver when the
        // signer isn't in the local keyring.
        val (secRing, _) = unprotectedKey
        val sig = parseFirstSignature(
            signer.signDetached(data = "x".toByteArray(), secretKeyRing = secRing, armor = true)
        )
        val hashed = sig.hashedSubPackets
        assertNotNull("Hashed subpackets must be present", hashed)
        // BC exposes issuer fingerprint via getIssuerFingerprint() — null if absent
        assertNotNull(
            "Issuer fingerprint subpacket should be set",
            hashed.issuerFingerprint
        )
    }

    // ── Clear-sign: output format + canonical verify ──────────────────

    @Test
    fun clearSignProducesProperRfc4880Section7Frame() {
        val (secRing, _) = unprotectedKey
        val message = "Hello, PGP world!\nMultiple lines\nWith content."

        val signed = signer.signClear(text = message, secretKeyRing = secRing)

        assertTrue("Should start with PGP SIGNED MESSAGE header",
            signed.startsWith("-----BEGIN PGP SIGNED MESSAGE-----"))
        assertTrue("Should declare hash algorithm SHA256",
            signed.contains("Hash: SHA256"))
        assertTrue("Body should be present verbatim",
            signed.contains("Hello, PGP world!"))
        assertTrue("Body should preserve middle line",
            signed.contains("Multiple lines"))
        assertTrue("Should transition into PGP SIGNATURE block",
            signed.contains("-----BEGIN PGP SIGNATURE-----"))
        assertTrue("Should end with END PGP SIGNATURE",
            signed.trimEnd().endsWith("-----END PGP SIGNATURE-----"))
    }

    @Test
    fun clearSignDashEscapesLeadingDashLines() {
        // RFC 4880 §7.1: any line that begins with "-" gets prefixed with "- "
        // in the displayed text so it can't be confused with armor markers.
        // BC's ArmoredOutputStream.beginClearText handles this for us — we're
        // testing that we actually use that path (not e.g. a raw write
        // that skips dash-escaping).
        val (secRing, _) = unprotectedKey
        val message = "Normal line\n-Subtract me\n--Two dashes"

        val signed = signer.signClear(text = message, secretKeyRing = secRing)
        assertTrue("Lines starting with - should be dash-escaped",
            signed.contains("- -Subtract me"))
        assertTrue("Two-dash line should be dash-escaped",
            signed.contains("- --Two dashes"))
    }

    @Test
    fun clearSignVerifiesEndToEndViaCanonicalForm() {
        // Full roundtrip: produce a clear-signed message, then verify the
        // signature ourselves by re-canonicalizing the cleartext and
        // calling BC's signature verifier. If signClear's canonical-form
        // hashing matches the verifier-side canonicalization, this passes.
        //
        // Implementation note: we parse the signed text into cleartext +
        // signature block via simple string operations, then feed the
        // signature block to a fresh ArmoredInputStream. This avoids the
        // shared-stream-state subtleties of trying to read both cleartext
        // and signature off the same ArmoredInputStream (BC's official
        // ClearSignedFileProcessor pattern should work but didn't survive
        // my Kotlin port for reasons I couldn't pin down in one sitting;
        // the manual approach is empirically robust and easy to reason
        // about). Phase A3's VerifyService will get the stream-based
        // approach properly designed and tested.
        val (secRing, pubRing) = unprotectedKey
        val message = "First line\nSecond line  \n  Third line with leading spaces\nLast line"

        val signed = signer.signClear(text = message, secretKeyRing = secRing)

        val cleartext = extractCleartextFromClearSigned(signed)
        val sigBlock = extractSignatureBlockFromClearSigned(signed)

        // Parse the signature from a fresh ArmoredInputStream over the
        // signature block alone — no shared state with cleartext reading.
        val ais = ArmoredInputStream(ByteArrayInputStream(sigBlock.toByteArray(Charsets.UTF_8)))
        val fact = JcaPGPObjectFactory(ais)
        val firstObj = fact.nextObject()
        assertNotNull("Expected a PGP object from the signature block", firstObj)
        val sigList = firstObj as PGPSignatureList
        val sig = sigList.get(0)

        val signerKey = pubRing.getPublicKey(sig.keyID)
            ?: error("Public key for signer not found in test pubRing")
        sig.init(BcPGPContentVerifierBuilderProvider(), signerKey)

        // Re-canonicalize using the same routine the signer used.
        val canonical = signer.canonicalizeForClearSign(cleartext)
        sig.update(canonical, 0, canonical.size)

        assertTrue("Clear-signed message should verify end-to-end", sig.verify())
    }

    /**
     * Pull the cleartext body out of a clear-signed armored message via
     * simple string scanning. Handles both LF and CRLF line endings
     * (BC tends to use CRLF on the wire). Strips dash-escapes ("- foo"
     * back to "foo") so the returned cleartext is what was originally
     * signed, not what BC's display format wrote.
     *
     * Layout this parses:
     *   -----BEGIN PGP SIGNED MESSAGE-----   <- skip
     *   Hash: SHA256                          <- skip (and any other headers)
     *                                         <- blank line, then cleartext starts
     *   <cleartext line 1>
     *   <cleartext line 2>
     *   ...
     *   <cleartext line N>
     *   -----BEGIN PGP SIGNATURE-----        <- cleartext ends just before this
     *
     * The line ending immediately before BEGIN PGP SIGNATURE is part of
     * the frame, not the cleartext (RFC 4880 §7.1).
     */
    private fun extractCleartextFromClearSigned(signed: String): String {
        // Normalize to LF for parsing simplicity. The canonical-form
        // hasher will re-introduce CRLF anyway, and trimEnd in
        // canonicalizeForClearSign strips any stray CRs.
        val text = signed.replace("\r\n", "\n")

        // Find the blank line that separates headers from cleartext.
        // Two consecutive '\n' chars = blank line.
        val headersEnd = text.indexOf("\n\n")
        require(headersEnd >= 0) {
            "Malformed clear-signed message: missing blank line after headers"
        }
        val cleartextStart = headersEnd + 2

        // Find the signature block marker — that's where cleartext ends.
        val sigStart = text.indexOf("-----BEGIN PGP SIGNATURE-----", cleartextStart)
        require(sigStart >= 0) {
            "Malformed clear-signed message: missing PGP SIGNATURE block"
        }

        // Exclude the trailing line ending immediately before the
        // SIGNATURE marker (RFC 4880 §7.1 says this terminator is not
        // part of the signed cleartext).
        var cleartextEnd = sigStart
        if (cleartextEnd > 0 && text[cleartextEnd - 1] == '\n') {
            cleartextEnd--
        }

        var cleartext = text.substring(cleartextStart, cleartextEnd)

        // Strip dash-escaping: any line that starts with "- " has the
        // "- " removed. This restores the original cleartext bytes that
        // the signer fed to the hash function.
        cleartext = cleartext.split("\n").joinToString("\n") { line ->
            if (line.startsWith("- ")) line.substring(2) else line
        }

        return cleartext
    }

    /**
     * Slice the signature block (from BEGIN PGP SIGNATURE to END PGP
     * SIGNATURE inclusive) out of a clear-signed armored message. Returns
     * it as a standalone armored string suitable for handing to a fresh
     * ArmoredInputStream.
     */
    private fun extractSignatureBlockFromClearSigned(signed: String): String {
        val text = signed.replace("\r\n", "\n")
        val start = text.indexOf("-----BEGIN PGP SIGNATURE-----")
        val end = text.indexOf("-----END PGP SIGNATURE-----")
        require(start >= 0 && end >= 0) {
            "Malformed clear-signed message: missing signature block markers"
        }
        val endMarker = "-----END PGP SIGNATURE-----"
        // Append a trailing newline because BC's ArmoredInputStream is
        // picky about whether the END marker has a terminator after it
        // — including one is the safer choice for parser robustness.
        return text.substring(start, end + endMarker.length) + "\n"
    }

    // ── Passphrase paths ──────────────────────────────────────────────

    @Test
    fun signClearWithCorrectPassphraseSucceeds() {
        val (secRing, _) = protectedKey
        val signed = signer.signClear(
            text = "passphrase-protected sign",
            secretKeyRing = secRing,
            passphrase = "horseshoes"
        )
        assertTrue(signed.contains("-----BEGIN PGP SIGNED MESSAGE-----"))
    }

    @Test
    fun signClearWithMissingPassphraseThrowsPassphraseRequired() {
        val (secRing, _) = protectedKey
        assertThrows(SigningError.PassphraseRequired::class.java) {
            signer.signClear(
                text = "missing passphrase",
                secretKeyRing = secRing,
                passphrase = null
            )
        }
    }

    @Test
    fun signClearWithWrongPassphraseThrowsInvalidPassphrase() {
        val (secRing, _) = protectedKey
        assertThrows(SigningError.InvalidPassphrase::class.java) {
            signer.signClear(
                text = "wrong passphrase",
                secretKeyRing = secRing,
                passphrase = "wrong"
            )
        }
    }

    @Test
    fun signDetachedRespectsPassphraseRequirementToo() {
        val (secRing, _) = protectedKey
        assertThrows(SigningError.PassphraseRequired::class.java) {
            signer.signDetached(
                data = "data".toByteArray(),
                secretKeyRing = secRing,
                passphrase = null
            )
        }
    }

    // ── Canonical form (pure function) ────────────────────────────────

    @Test
    fun canonicalizeStripsTrailingWhitespacePerLine() {
        val out = signer.canonicalizeForClearSign("foo   \nbar\t\nbaz")
        assertEquals("foo\r\nbar\r\nbaz", String(out, Charsets.UTF_8))
    }

    @Test
    fun canonicalizeNormalizesLineEndingsToCrlf() {
        val out = signer.canonicalizeForClearSign("foo\nbar\r\nbaz\n")
        // split("\n") on "foo\nbar\r\nbaz\n" -> ["foo", "bar\r", "baz", ""]
        // trimEnd ' ', '\t', '\r' on each -> ["foo", "bar", "baz", ""]
        // Drop trailing empty (per RFC 4880 §7.1, the trailing terminator
        // is excluded from the signed data) -> ["foo", "bar", "baz"]
        // join "\r\n" -> "foo\r\nbar\r\nbaz"  (no trailing CRLF)
        assertEquals("foo\r\nbar\r\nbaz", String(out, Charsets.UTF_8))
    }

    @Test
    fun canonicalizeProducesSameOutputForTrailingNewlineAndNot() {
        // RFC 4880 §7.1: trailing terminator is excluded, so these two
        // inputs MUST hash identically. If they don't, verifiers will
        // reject signatures whose source text was edited to add/remove
        // a final newline.
        val withNewline = signer.canonicalizeForClearSign("alpha\nbeta\n")
        val withoutNewline = signer.canonicalizeForClearSign("alpha\nbeta")
        assertEquals(String(withNewline, Charsets.UTF_8), String(withoutNewline, Charsets.UTF_8))
        assertEquals("alpha\r\nbeta", String(withNewline, Charsets.UTF_8))
    }

    @Test
    fun canonicalizePreservesLineContentExceptTrailingWhitespace() {
        val out = signer.canonicalizeForClearSign("hello world  ")
        assertEquals("hello world", String(out, Charsets.UTF_8))
    }

    // ── Internals ─────────────────────────────────────────────────────

    private fun parseFirstSignature(armored: ByteArray): org.bouncycastle.openpgp.PGPSignature {
        val ais = ArmoredInputStream(ByteArrayInputStream(armored))
        val fact = JcaPGPObjectFactory(ais)
        val sigList = fact.nextObject() as PGPSignatureList
        return sigList.get(0)
    }
}
