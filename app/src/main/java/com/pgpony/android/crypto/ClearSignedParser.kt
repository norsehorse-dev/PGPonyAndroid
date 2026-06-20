// ClearSignedParser.kt
// PGPony Android
//
// Internal utility for slicing clear-signed armored messages into their
// cleartext + signature-block parts via simple string scanning. Lives
// here (not inside SigningService or VerifyService) because both the
// production VerifyService and unit tests need the same parsing logic;
// keeping it in one place avoids drift between them.
//
// Why manual parsing instead of BC's ClearSignedFileProcessor pattern:
// the ArmoredInputStream lookahead approach BC recommends reuses the
// same stream for cleartext + signature, which makes the stream state
// fragile to subtle Kotlin↔Java boundary issues (Int vs Byte
// comparisons in EOL detection, lookAhead-byte-consumption semantics
// when isClearText flips). Manual string-based parsing has none of
// that complexity — armor markers are well-defined ASCII anchors that
// don't appear inside the signed content, so indexOf-based slicing is
// robust and easy to reason about.
//
// Added in Phase A3.

package com.pgpony.android.crypto

/**
 * Parsed components of a clear-signed armored message.
 */
internal data class ClearSignedComponents(
    /** Hash algorithm declared in the Hash: header (e.g., "SHA256"). */
    val hashAlgorithmName: String,
    /** The cleartext, with dash-escaping removed and trailing line terminator
     *  before the signature block stripped (per RFC 4880 §7.1). */
    val cleartext: String,
    /** The signature block as a standalone armored string suitable for
     *  feeding to a fresh ArmoredInputStream. */
    val signatureBlock: String
)

internal object ClearSignedParser {

    private const val BEGIN_MESSAGE = "-----BEGIN PGP SIGNED MESSAGE-----"
    private const val BEGIN_SIGNATURE = "-----BEGIN PGP SIGNATURE-----"
    private const val END_SIGNATURE = "-----END PGP SIGNATURE-----"

    /**
     * Decompose a clear-signed armored message into hash algorithm,
     * cleartext, and signature block. Returns null if the input is not
     * a well-formed clear-signed message (caller should check).
     *
     * Handles both LF and CRLF line endings — armor wire format is CRLF
     * but pasted input often comes in with LF only, and pre-normalizing
     * to LF lets the rest of the parser stay simple.
     */
    fun parse(signed: String): ClearSignedComponents? {
        // Normalize to LF. The canonical-form hasher will re-introduce
        // CRLF, and trimEnd in canonicalizeForClearSign strips any stray
        // CRs that slip through.
        val text = signed.replace("\r\n", "\n")

        // Must start with the BEGIN MESSAGE marker.
        val msgStart = text.indexOf(BEGIN_MESSAGE)
        if (msgStart < 0) return null

        // Headers run from after BEGIN MESSAGE through the first blank
        // line. The blank line is "\n\n" in the normalized form.
        val headersBlank = text.indexOf("\n\n", msgStart)
        if (headersBlank < 0) return null
        val cleartextStart = headersBlank + 2  // skip the two LFs

        // Extract the Hash: header value (defaults to SHA1 per legacy
        // RFC 4880, though every modern producer declares explicitly).
        val headerSection = text.substring(msgStart, headersBlank)
        val hashAlgorithmName = Regex("(?m)^Hash:\\s*(\\S+)")
            .find(headerSection)
            ?.groupValues?.get(1)
            ?: "SHA1"

        // Signature block starts at the next BEGIN PGP SIGNATURE marker.
        val sigStart = text.indexOf(BEGIN_SIGNATURE, cleartextStart)
        if (sigStart < 0) return null

        // Signature block ends at END PGP SIGNATURE marker, inclusive.
        val sigEnd = text.indexOf(END_SIGNATURE, sigStart)
        if (sigEnd < 0) return null
        val sigBlockEnd = sigEnd + END_SIGNATURE.length

        // Cleartext: from cleartextStart up to (but not including) the
        // line ending that immediately precedes the SIGNATURE marker.
        // RFC 4880 §7.1: that line terminator is not part of the signed
        // content. Strip a single trailing LF if present; the
        // canonicalize function will handle other cases robustly.
        var cleartextEnd = sigStart
        if (cleartextEnd > cleartextStart && text[cleartextEnd - 1] == '\n') {
            cleartextEnd--
        }
        var cleartext = text.substring(cleartextStart, cleartextEnd)

        // Strip dash-escaping: any line that starts with "- " has the
        // "- " removed. Restores the original signed bytes.
        cleartext = cleartext.split("\n").joinToString("\n") { line ->
            if (line.startsWith("- ")) line.substring(2) else line
        }

        // Signature block as a standalone armored string. Append a
        // trailing newline because some ArmoredInputStream parsers are
        // picky about the END marker having a line ending after it.
        val signatureBlock = text.substring(sigStart, sigBlockEnd) + "\n"

        return ClearSignedComponents(
            hashAlgorithmName = hashAlgorithmName,
            cleartext = cleartext,
            signatureBlock = signatureBlock
        )
    }

    /**
     * Quick predicate — does this text look like a clear-signed message?
     * Used by VerifyService.detectInputType before the more expensive
     * parse() call.
     */
    fun looksLikeClearSigned(text: String): Boolean =
        text.contains(BEGIN_MESSAGE)
}
