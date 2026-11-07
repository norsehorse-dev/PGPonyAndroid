// ShareFileActions.kt
// PGPony Android, 4.8.0 (#72, #67): what the Quick Action offers for one
// shared file that is not armored text, and what a detached signature made
// there is called.
//
// #72: a single shared file used to get Encrypt only, while several files
// already had Sign only on the package screen. It now gets Sign (a detached
// signature) next to Encrypt, and Encrypt can sign too (Sign as).
// #67: a keyring backup gets Restore, which opens the main app's Restore
// with the file, instead of Decrypt (a backup is sealed with its recovery
// code, not with a key, so Decrypt could never open it).
//
// Pure, so it is unit tested (ShareFileActionsTest).

package com.pgpony.android.ui.share

import com.pgpony.android.crypto.LiteralFilename
import com.pgpony.android.data.PGPKeyEntity

internal object ShareFileActions {

    enum class Action { RESTORE, DECRYPT, ENCRYPT, SIGN }

    /**
     * The actions for one shared file, in the order they are shown. A backup
     * gets Restore alone; an encrypted message gets Decrypt; any other file
     * gets Encrypt and Sign.
     */
    fun forFile(isBackup: Boolean, looksLikeMessage: Boolean): List<Action> = when {
        isBackup -> listOf(Action.RESTORE)
        looksLikeMessage -> listOf(Action.DECRYPT)
        else -> listOf(Action.ENCRYPT, Action.SIGN)
    }

    /**
     * The name of a detached signature over [input], as the Sign a file
     * sheet names it: the file's own name plus ".asc" (armored) or ".sig"
     * (binary), so `gpg --verify` finds the file next to it. The shared name
     * comes from another app, so it is reduced to a plain base name first,
     * as the multi-file Sign only does (FileBatchNaming.signatureName).
     */
    fun signatureName(input: String?, armor: Boolean): String =
        (LiteralFilename.sanitize(input) ?: "file") + (if (armor) ".asc" else ".sig")

    /**
     * The keys that can sign here: software key pairs that are not revoked.
     * A hardware key is left out, as on the Sign a file sheet
     * (signableFileKeys) and in the multi-file paths, because the Quick
     * Action has no card signing flow.
     */
    fun signers(keyPairs: List<PGPKeyEntity>): List<PGPKeyEntity> =
        keyPairs.filter { it.isKeyPair && !it.isCardBacked && !it.isRevoked }

    /** The signer to start with: the pinned default signer, then the key
     *  marked default, then the first, as the Encrypt screen picks it. */
    fun defaultSigner(signers: List<PGPKeyEntity>, defaultSignerFingerprint: String): PGPKeyEntity? =
        signers.firstOrNull { defaultSignerFingerprint.isNotEmpty() && it.fingerprint == defaultSignerFingerprint }
            ?: signers.firstOrNull { it.isDefault }
            ?: signers.firstOrNull()
}
