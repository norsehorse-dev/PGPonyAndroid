// Phase C — data models for read-only `pass` (password-store) integration.
//
// A `pass` store is a directory tree of OpenPGP-encrypted `*.gpg` files. Each
// decrypted entry follows the convention: line 1 is the password, and the
// remaining lines are freeform metadata, conventionally `key: value`.
//
// Port of iOS Models/PassModels.swift. Android references the store in place via
// a Storage Access Framework tree URI (not a security-scoped bookmark), so it
// reflects whatever syncs from the desktop. Read-only in 3.0.

package com.pgpony.android.crypto.pass

/**
 * A persisted reference to an imported pass store. [treeUri] is a SAF tree URI
 * the app holds a persistable read permission for. [rootGpgIds] are the
 * recipients from the root `.gpg-id` (informational in read mode).
 */
data class PassStoreRef(
    val id: String,
    val displayName: String,
    val treeUri: String,
    val rootGpgIds: List<String> = emptyList()
)

/**
 * A node in the store tree, built from filenames only (never decrypts to
 * browse). Folders contain children; entries are `*.gpg` leaves (name without
 * the extension).
 */
sealed interface PassNode {
    val id: String
    val name: String

    data class Folder(
        val folderName: String,
        val path: String,
        val children: List<PassNode>
    ) : PassNode {
        override val id: String get() = "folder:$path"
        override val name: String get() = folderName
        val isFolder: Boolean get() = true
    }

    data class Entry(
        val entryName: String,
        val relativePath: String
    ) : PassNode {
        override val id: String get() = "entry:$relativePath"
        override val name: String get() = entryName
        val isFolder: Boolean get() = false
    }
}

/** One metadata line parsed from an entry, conventionally `key: value`. */
data class PassField(val key: String, val value: String)

/**
 * The decrypted + parsed content of a single entry. Held only while the entry
 * screen is on screen, then dropped.
 */
data class PassEntryContent(
    val password: String,        // line 1 by convention (may be empty)
    val fields: List<PassField>, // recognised `key: value` metadata lines
    val otpauth: String?,        // detected `otpauth://` URI — displayed, NOT generated in 3.0
    val extraLines: List<String>,// freeform lines that aren't `key: value`
    val raw: String              // full decrypted text (kept only while viewing)
)
