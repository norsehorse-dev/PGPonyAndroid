// ProcessText.kt
// PGPony Android, 4.8.0 (#103): encrypt or sign selected text from the text
// selection menu (ACTION_PROCESS_TEXT), as OpenKeychain does.
//
// Two menu entries, "Encrypt with PGPony" and "Sign with PGPony", are two
// activity-alias entries in the manifest pointing at ProcessTextActivity. The
// alias that was picked tells the activity which flow to run. In an editable
// field the selection is replaced with the result; in a read-only field (or
// when the result cannot be handed back) the result is shown in PGPony to copy
// or share.
//
// The decisions live here, free of Android types, so they run as JVM tests.

package com.pgpony.android.ui.share

object ProcessText {

    enum class Mode { ENCRYPT, SIGN }

    /** Intent.ACTION_PROCESS_TEXT, spelled out so this file needs no Android types. */
    const val ACTION_PROCESS_TEXT = "android.intent.action.PROCESS_TEXT"

    /** The activity-alias names in AndroidManifest.xml (relative to the namespace). */
    const val ALIAS_ENCRYPT = "com.pgpony.android.ui.share.ProcessTextEncrypt"
    const val ALIAS_SIGN = "com.pgpony.android.ui.share.ProcessTextSign"

    /**
     * The longest result handed back to the calling app. The result goes back
     * through a Binder transaction (about 1 MB for everything in flight, two
     * bytes per character in a Parcel), so a very long result is shown in
     * PGPony instead of failing with TransactionTooLargeException and losing
     * the work.
     */
    const val RESULT_LIMIT_CHARS = 256 * 1024

    /**
     * Which flow the menu entry asked for, from the intent's action and the
     * component it was sent to (the alias name, which an activity-alias keeps
     * on the intent). Null for anything that is not a PROCESS_TEXT request to
     * one of the two aliases.
     */
    fun modeFor(action: String?, componentClassName: String?): Mode? {
        if (action != ACTION_PROCESS_TEXT) return null
        return when (componentClassName) {
            ALIAS_ENCRYPT -> Mode.ENCRYPT
            ALIAS_SIGN -> Mode.SIGN
            else -> null
        }
    }

    /**
     * True when the result replaces the selection in the calling app: the
     * field is editable (EXTRA_PROCESS_TEXT_READONLY is false), the app
     * started us for a result (so it is waiting for one), and the result is
     * small enough to travel back. Otherwise PGPony shows the result.
     */
    fun returnsResult(readOnly: Boolean, hasCaller: Boolean, resultLength: Int): Boolean =
        !readOnly && hasCaller && resultLength <= RESULT_LIMIT_CHARS

    /**
     * True when the selection already holds a PGP block (an encrypted or
     * signed message, or a key). Such a selection goes to the Quick Action,
     * which offers Decrypt, Verify or Import for it, instead of being
     * encrypted or signed again.
     */
    fun isPgpSelection(text: String): Boolean =
        text.contains("-----BEGIN PGP ") && SharePayload.of(text).hasPgp
}
