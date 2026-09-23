// SharePayload.kt
// PGPony Android, 4.6.0 (item 6): what a shared piece of text actually holds,
// so the Quick Action offers only the actions that apply to it.
//
// A share can carry a public key, an encrypted message, a signed message
// (cleartext-signed, or an inline-signed PGP MESSAGE that is not encrypted),
// ordinary text, or a mix of these with text around the PGP block (an email
// body with a key pasted in, say). Each kind gets its own action; text around
// a PGP block can still be encrypted on its own.

package com.pgpony.android.ui.share

import com.pgpony.android.crypto.ArmorExtractor

data class SharePayload(
    /** The PUBLIC KEY BLOCK(s), joined, or null. */
    val publicKey: String?,
    /** The first encrypted PGP MESSAGE block, or null. */
    val encrypted: String?,
    /** The first signed-only block (SIGNED MESSAGE, or a PGP MESSAGE that is
     *  signed but not encrypted), or null. */
    val signed: String?,
    /** The text outside every PGP block, trimmed, or null when there is none. */
    val otherText: String?
) {
    val hasPgp: Boolean get() = publicKey != null || encrypted != null || signed != null

    companion object {
        private val ENCRYPTED_TAGS = setOf(1, 3, 9, 18, 20)

        /** A cleartext-signed message ends with a SIGNATURE block, not a
         *  SIGNED MESSAGE one, so it is matched on its own. */
        private val CLEARTEXT = Regex(
            "-----BEGIN PGP SIGNED MESSAGE-----[\\s\\S]*?-----END PGP SIGNATURE-----"
        )

        fun of(text: String): SharePayload {
            val cleartext = CLEARTEXT.findAll(text).map { it.value }.toList()
            var remaining = text
            for (c in cleartext) remaining = remaining.replace(c, "\n")
            val blocks = ArmorExtractor.blocks(remaining)
            val publicKeys = blocks.filter { it.type == "PUBLIC KEY BLOCK" }.map { it.text }
            var encrypted: String? = null
            var signed: String? = cleartext.firstOrNull()
            for (b in blocks) {
                when (b.type) {
                    "SIGNED MESSAGE" -> if (signed == null) signed = b.text
                    "MESSAGE" -> if (isEncrypted(b.text)) {
                        if (encrypted == null) encrypted = b.text
                    } else if (signed == null) {
                        signed = b.text
                    }
                }
            }
            var rest = remaining
            for (b in blocks) rest = rest.replace(b.text, "\n")
            val other = rest.trim().takeIf { it.isNotEmpty() }
            return SharePayload(
                publicKey = publicKeys.takeIf { it.isNotEmpty() }?.joinToString("\n\n"),
                encrypted = encrypted,
                signed = signed,
                otherText = other
            )
        }

        /**
         * True when an armored PGP MESSAGE starts with an encryption packet
         * (a PKESK / SKESK or encrypted data). A signed-only message starts
         * with a one-pass signature, a signature, compressed or literal data.
         * An unreadable block counts as encrypted, so it goes to Decrypt,
         * which reports what is wrong with it.
         */
        internal fun isEncrypted(armoredMessage: String): Boolean {
            val first = runCatching {
                org.bouncycastle.bcpg.ArmoredInputStream(armoredMessage.byteInputStream(Charsets.UTF_8)).use { it.read() }
            }.getOrNull() ?: return true
            if (first < 0 || first and 0x80 == 0) return true
            val tag = if (first and 0x40 != 0) first and 0x3F else (first shr 2) and 0x0F
            // A compressed top-level packet (tag 8) holds signed or plain
            // data; an encrypted message never starts with one.
            return tag in ENCRYPTED_TAGS
        }
    }
}
