// Phase C — parses the decrypted plaintext of a `pass` entry into structured
// content. Convention: line 1 is the password; subsequent lines are freeform,
// often `key: value` metadata.
//
// Port of iOS Services/PassEntryParser.swift. Tolerant by design — never throws,
// never crashes:
// - Normalises CRLF/CR to LF and accepts a missing trailing newline.
// - Splits a `key: value` line on the FIRST colon only, so values may contain
//   further colons (e.g. `note: see 12:30`).
// - Keeps bare URL lines (e.g. `https://example.com`) as freeform rather than
//   misreading the scheme colon as a `key: value` separator.
// - Detects an `otpauth://` line and surfaces it read-only (no code generation).
// - Blank lines are dropped; unrecognised lines are preserved in extraLines.

package com.pgpony.android.crypto.pass

object PassEntryParser {

    // Match iOS `.whitespaces` (space + tab) rather than Kotlin's broader trim().
    private val WS = charArrayOf(' ', '\t')

    fun parse(text: String): PassEntryContent {
        val normalized = text
            .replace("\r\n", "\n")
            .replace("\r", "\n")
        val lines = normalized.split("\n")

        val password = lines.firstOrNull() ?: ""

        val fields = mutableListOf<PassField>()
        val extraLines = mutableListOf<String>()
        var otpauth: String? = null

        for (line in lines.drop(1)) {
            if (line.isEmpty()) continue

            if (line.lowercase().startsWith("otpauth://")) {
                if (otpauth == null) otpauth = line.trim(*WS)
                continue
            }

            val colon = line.indexOf(':')
            if (colon >= 0) {
                val valuePart = line.substring(colon + 1)        // untrimmed
                val key = line.substring(0, colon).trim(*WS)
                // A bare URL ("scheme://…") has "//" right after its first colon —
                // that's not a metadata separator, so treat the line as freeform.
                if (!valuePart.startsWith("//") && key.isNotEmpty()) {
                    fields.add(PassField(key, valuePart.trim(*WS)))
                    continue
                }
            }

            extraLines.add(line)
        }

        return PassEntryContent(
            password = password,
            fields = fields,
            otpauth = otpauth,
            extraLines = extraLines,
            raw = text
        )
    }
}
