// ArmorExtractor.kt
// PGPony Android — 4.5.0 (item 19 / #58): pull the OpenPGP armored block(s) out
// of noisy shared or pasted text.
//
// Sharing an on-screen text selection (open a key in a browser, select all,
// share) wraps the armored key in page text, and a strict parser rejects it.
// This finds every "-----BEGIN PGP <TYPE>-----...-----END PGP <TYPE>-----" block
// and ignores everything around them, so a key import works without hand-editing.
// A clean .asc is returned unchanged (its single block is the whole input).

package com.pgpony.android.crypto

object ArmorExtractor {

    /** One armored block; END must match BEGIN's type (backreference). */
    private val BLOCK = Regex(
        "-----BEGIN PGP ([A-Z0-9 ]+?)-----[\\s\\S]*?-----END PGP \\1-----"
    )

    data class Block(val type: String, val text: String)

    /** Every armored block in [input], in order. */
    fun blocks(input: String): List<Block> =
        BLOCK.findAll(input).map { Block(it.groupValues[1].trim(), it.value) }.toList()

    /**
     * The armored text to import from possibly-noisy [input]: the PGP KEY
     * blocks (public / private) concatenated, ignoring surrounding page text
     * and non-key blocks such as a detached signature. Falls back to every
     * armored block when none is a key block, and to null when [input] has no
     * armored block at all (the caller then reports "no key data").
     */
    fun extractForImport(input: String): String? {
        val all = blocks(input)
        if (all.isEmpty()) return null
        val keys = all.filter { it.type.endsWith("KEY BLOCK") }
        val chosen = if (keys.isNotEmpty()) keys else all
        return chosen.joinToString("\n\n") { it.text }
    }

    /**
     * 4.7.2 RC3: the first PGP MESSAGE block of [input], for decrypt. The decrypt reads the
     * armor to the end of the input, and after the END line Bouncy Castle's armor reader goes
     * on looking for another block: the first line starting with a dash is taken as its armor
     * header. A pasted email signature below the message (a row of dashes, or the "-- "
     * separator) therefore failed as a malformed message, and the same line above the BEGIN
     * line would too. Everything outside the BEGIN and END markers is dropped.
     *
     * [input] comes back unchanged when it holds no complete PGP MESSAGE block, so an
     * incomplete paste still reports as incomplete, and when the block is already all there
     * is, so an ordinary message reaches the parser byte for byte as before.
     */
    fun messageOnly(input: String): String {
        val block = blocks(input).firstOrNull { it.type == "MESSAGE" } ?: return input
        return if (input.trim() == block.text) input else block.text + "\n"
    }
}
