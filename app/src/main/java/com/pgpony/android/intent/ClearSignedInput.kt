// ClearSignedInput.kt
// PGPony Android
//
// Deciding whether input is a clear-signed message by searching for the
// "BEGIN PGP SIGNED MESSAGE" line anywhere in it lets an armor header value
// (a Comment, say) or text quoted inside another block steer the routing. The
// engine decides by the line that opens the input (PGPCryptoService treats
// input as clear-signed only when its first non-blank line is the clear-signed
// armor line). Callers that route input here follow the same idea: the first
// armor line ("-----BEGIN PGP ...") in the input decides, so leading prose
// before a clear-signed block (a mail body, a pasted note) still routes to
// verification, while a marker inside an armor header or inside the signed
// text (dash-escaped) never does.

package com.pgpony.android.intent

internal object ClearSignedInput {

    private const val BEGIN_SIGNED = "-----BEGIN PGP SIGNED MESSAGE-----"
    private const val ARMOR_PREFIX = "-----BEGIN PGP "

    /** True when the first armor line of [text] is the clear-signed armor line. */
    fun isClearSigned(text: String): Boolean =
        firstArmorLine(text) == BEGIN_SIGNED

    /** The first line of [text] that starts an armor block, trimmed, or null. */
    fun firstArmorLine(text: String): String? =
        text.lineSequence().map { it.trim() }.firstOrNull { it.startsWith(ARMOR_PREFIX) }
}
