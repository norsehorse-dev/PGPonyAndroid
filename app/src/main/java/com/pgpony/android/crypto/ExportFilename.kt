// ExportFilename.kt
// PGPony Android: the file name a key export is offered under. Moved here from
// ui/keyring/KeyShareIntents.kt in 4.8.0 RC10 (move only) so PGPony Desktop
// vendors the same rule; KeyShareIntents.buildExportFilename calls it.

package com.pgpony.android.crypto

object ExportFilename {
    /**
     * Build a filesystem-safe export filename from an owner label +
     * short fingerprint + suffix. Centralized in A8.6 because all
     * three share helpers use the same pattern.
     *
     * Output shape: `{safe_owner}_{safe_fp}{suffix}.asc`
     * e.g.  `ffff_1AC7C311_public.asc`
     *       `Jane_Smith_ABCD9876_private.asc`
     *       `alex_DEAD1234_revocation.asc`
     */
    fun build(
        ownerLabel: String,
        shortFingerprint: String,
        suffix: String,
        // 4.8.0 (item 4h): the key's email, between the name and the key ID, so
        // keys under one name are told apart at a glance. Left out when blank or
        // when the label already is the email (a key with no name).
        email: String? = null
    ): String {
        val safeLabel = ownerLabel
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .take(40)
            .ifEmpty { "key" }
        val safeFp = shortFingerprint
            .replace(Regex("[^A-Za-z0-9]"), "")
            .ifEmpty { "unknown" }
        val safeEmail = email?.trim()
            ?.takeIf { it.isNotEmpty() && !it.equals(ownerLabel.trim(), ignoreCase = true) }
            ?.lowercase()
            ?.replace("@", "-")
            ?.replace(Regex("[^a-z0-9._-]"), "_")
            ?.take(64)
        val emailPart = if (safeEmail.isNullOrEmpty()) "" else "_$safeEmail"
        return "${safeLabel}${emailPart}_${safeFp}${suffix}.asc"
    }
}
