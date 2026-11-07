// SshKeyForm.kt
// PGPony Android, 4.8.0 RC7 (item 1): the pure checks behind Settings > SSH
// keys (label, export passphrase, export file name), kept free of Android so
// the JVM tests cover them.

package com.pgpony.android.ui.settings

import com.pgpony.android.data.ssh.SshKeyStore

internal object SshKeyForm {

    /** The export file name when the label gives nothing usable: ssh-keygen's
     *  own default for this key type, with no extension, as ssh expects. */
    const val DEFAULT_FILE_NAME = "id_mldsa44_ed25519"

    /** Longest file name offered; the picker lets the user change it. */
    const val MAX_FILE_NAME = 64

    enum class PassphraseProblem { EMPTY, MISMATCH }

    /** The label as the store keeps it (one line, trimmed, capped). */
    fun cleanLabel(input: String): String = SshKeyStore.normalizeLabel(input)

    /** A new or renamed key needs a label: it is the comment on the public
     *  key line, which is how a server's authorized_keys tells keys apart. */
    fun isLabelUsable(input: String): Boolean = cleanLabel(input).isNotEmpty()

    /**
     * Why the export passphrase pair cannot be used, or null when it can.
     * An exported private key is always encrypted, so empty is refused.
     */
    fun passphraseProblem(passphrase: CharSequence, confirm: CharSequence): PassphraseProblem? = when {
        passphrase.isEmpty() -> PassphraseProblem.EMPTY
        !sameChars(passphrase, confirm) -> PassphraseProblem.MISMATCH
        else -> null
    }

    /**
     * The suggested name for an exported private key: the label made safe
     * for a file name (ASCII letters, digits, '-', '_' and '.', with every
     * other run of characters as one '_', no leading or trailing '.' or '_',
     * so never a hidden file), or [DEFAULT_FILE_NAME] when nothing is left.
     * No extension: ssh -i and ~/.ssh take the bare name.
     */
    fun exportFileName(label: String): String {
        val mapped = StringBuilder()
        for (c in label) {
            val keep = (c in 'a'..'z') || (c in 'A'..'Z') || (c in '0'..'9') || c == '-' || c == '_' || c == '.'
            if (keep) {
                mapped.append(c)
            } else if (mapped.isEmpty() || mapped[mapped.length - 1] != '_') {
                mapped.append('_')
            }
        }
        val safe = mapped.toString()
            .replace(Regex("_+"), "_")
            .trim('_', '.')
            .take(MAX_FILE_NAME)
            .trim('_', '.')
        return safe.ifEmpty { DEFAULT_FILE_NAME }
    }

    /**
     * A key type or cipher name read from a picked file, fit to show in a
     * message: the file decides these strings, so control characters go and
     * the length is capped.
     */
    fun displayToken(raw: String, max: Int = 64): String {
        val clean = raw.filter { !it.isISOControl() }.trim()
        return if (clean.length > max) clean.take(max).trimEnd() + "…" else clean
    }

    private fun sameChars(a: CharSequence, b: CharSequence): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }
}
