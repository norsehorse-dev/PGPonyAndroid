// PairKeyProtection.kt
// PGPony Android 4.6.3 (pairing, 4.7.0 item 21): is every secret part of a key
// block under a passphrase? A key pair only travels protected
// (docs/PAIRING_PROTOCOL.md, section 6): the sender protects one that has no
// passphrase with a transfer passphrase, and the receiver refuses a block that
// carries any secret in the clear.
//
// The same reading as main's SecretKeyCheck.protectionOf, kept separate here so
// the 4.6.x branch does not carry the rest of that file.

package com.pgpony.android.ui.pair

import com.pgpony.android.crypto.CertificateBindings
import org.bouncycastle.bcpg.ArmoredInputStream
import java.io.ByteArrayInputStream

internal object PairKeyProtection {

    private const val TAG_SECRET_KEY = 5
    private const val TAG_SECRET_SUBKEY = 7
    private const val S2K_GNU = 101

    private enum class Protection { UNPROTECTED, PROTECTED, STUB }

    /** The protection of one secret key packet, or null when it cannot be read. */
    private fun protectionOf(tag: Int, body: ByteArray): Protection? = runCatching {
        if (tag != TAG_SECRET_KEY && tag != TAG_SECRET_SUBKEY) return@runCatching null
        val pub = CertificateBindings.publicPart(tag, body) ?: return@runCatching null
        var i = pub.size
        if (i >= body.size) return@runCatching null
        val version = body[0].toInt() and 0xFF
        val usage = body[i++].toInt() and 0xFF
        when (usage) {
            0 -> Protection.UNPROTECTED
            253, 254, 255 -> {
                val s2kType = if (version == 4) {
                    i += 1 // symmetric algorithm
                    if (usage == 253) i += 1 // AEAD algorithm
                    body[i].toInt() and 0xFF
                } else {
                    i += 1 // count of the following fields
                    i += 1 // symmetric algorithm
                    if (usage == 253) i += 1 // AEAD algorithm
                    if (version == 6) i += 1 // S2K specifier length (v6 only)
                    body[i].toInt() and 0xFF
                }
                if (s2kType == S2K_GNU) Protection.STUB else Protection.PROTECTED
            }
            else -> Protection.PROTECTED // a legacy cipher id (implicit S2K)
        }
    }.getOrNull()

    /**
     * True when every secret key packet in [raw] (binary or armored) that
     * carries material is protected by a passphrase. Stubs are skipped; a
     * packet that cannot be read counts as unprotected, and a block with no
     * readable secret packet is false.
     */
    fun isFullyPassphraseProtected(raw: ByteArray): Boolean {
        val bytes = binary(raw) ?: return false
        var sawSecret = false
        for (p in CertificateBindings.packets(bytes)) {
            if (p.tag != TAG_SECRET_KEY && p.tag != TAG_SECRET_SUBKEY) continue
            sawSecret = true
            when (protectionOf(p.tag, p.body)) {
                Protection.PROTECTED, Protection.STUB -> {}
                Protection.UNPROTECTED, null -> return false
            }
        }
        // Only ever asked about a key pair: a block in which no secret packet
        // could be read (the reader stops at a malformed header) is not proven.
        return sawSecret
    }

    private fun binary(raw: ByteArray): ByteArray? {
        val head = String(raw.copyOf(minOf(raw.size, 64)), Charsets.US_ASCII)
        if (!head.trimStart().startsWith("-----BEGIN PGP")) return raw
        return runCatching {
            ArmoredInputStream(ByteArrayInputStream(raw)).use { it.readBytes() }
        }.getOrNull()
    }
}
