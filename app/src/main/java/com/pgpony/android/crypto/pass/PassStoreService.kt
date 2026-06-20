// Phase C0 — pass-store file access over the Storage Access Framework. The store
// is referenced in place via a persisted tree URI (DIVERGES from iOS security-
// scoped bookmarks), so it reflects whatever the user syncs in (Syncthing,
// Nextcloud, Drive, etc.). Read-only in 3.0; the tree is walked from filenames
// only and entries are decrypted lazily (C1/C2), never in bulk.

package com.pgpony.android.crypto.pass

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import java.util.UUID

class PassStoreService(private val context: Context) {

    /** Take a durable read permission on a tree URI returned by OpenDocumentTree. */
    fun persistPermission(treeUri: Uri) {
        context.contentResolver.takePersistableUriPermission(
            treeUri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION
        )
    }

    /** Build a store reference from a freshly-picked tree URI (reads the root .gpg-id). */
    fun buildRef(treeUri: Uri): PassStoreRef {
        val root = DocumentFile.fromTreeUri(context, treeUri)
        val name = root?.name?.takeIf { it.isNotBlank() } ?: "Password Store"
        val gpgIds = root?.let { readGpgId(it) } ?: emptyList()
        return PassStoreRef(
            id = UUID.randomUUID().toString(),
            displayName = name,
            treeUri = treeUri.toString(),
            rootGpgIds = gpgIds
        )
    }

    /** Resolve the store root; null if the folder is gone or the permission was revoked. */
    fun resolveRoot(ref: PassStoreRef): DocumentFile? {
        return try {
            val root = DocumentFile.fromTreeUri(context, Uri.parse(ref.treeUri))
            if (root != null && root.exists() && root.canRead()) root else null
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Walk the tree into a PassNode.Folder, built from filenames only (no
     * decryption). Dotfiles and `.git` are excluded; `*.gpg` files become entries
     * (name without the extension); subdirectories recurse. Folders and entries
     * are each sorted by name (case-insensitive), folders first.
     */
    fun walkTree(ref: PassStoreRef): PassNode.Folder? {
        val root = resolveRoot(ref) ?: return null
        return PassNode.Folder(
            folderName = ref.displayName,
            path = "",
            children = walkChildren(root, "")
        )
    }

    private fun walkChildren(dir: DocumentFile, prefix: String): List<PassNode> {
        val folders = mutableListOf<PassNode.Folder>()
        val entries = mutableListOf<PassNode.Entry>()
        for (child in dir.listFiles()) {
            val childName = child.name ?: continue
            if (childName.startsWith(".")) continue       // dotfiles + .git + .gpg-id*
            if (child.isDirectory) {
                val childPath = if (prefix.isEmpty()) childName else "$prefix/$childName"
                folders.add(
                    PassNode.Folder(
                        folderName = childName,
                        path = childPath,
                        children = walkChildren(child, childPath)
                    )
                )
            } else if (childName.endsWith(".gpg", ignoreCase = true)) {
                val entryName = childName.dropLast(4)      // strip ".gpg"
                val rel = if (prefix.isEmpty()) entryName else "$prefix/$entryName"
                entries.add(PassNode.Entry(entryName = entryName, relativePath = rel))
            }
        }
        folders.sortBy { it.folderName.lowercase() }
        entries.sortBy { it.entryName.lowercase() }
        return folders + entries
    }

    /**
     * Read the recipient ids from a `.gpg-id` file in [dir] (one id per non-empty
     * line). Informational in read mode; load-bearing only for writing (C3).
     */
    fun readGpgId(dir: DocumentFile): List<String> {
        val file = dir.findFile(".gpg-id") ?: return emptyList()
        if (!file.isFile) return emptyList()
        return try {
            context.contentResolver.openInputStream(file.uri)?.use { stream ->
                stream.readBytes().toString(Charsets.UTF_8)
                    .split("\n", "\r\n", "\r")
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
            } ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Read the raw bytes of an entry leaf (`<relativePath>.gpg`) for decryption.
     * Navigates the tree segment by segment via DocumentFile.findFile. Returns
     * null if the leaf is missing or unreadable (e.g. a cloud placeholder not yet
     * materialised).
     */
    fun readEntryBytes(ref: PassStoreRef, relativePath: String): ByteArray? {
        val root = resolveRoot(ref) ?: return null
        val segments = relativePath.split("/")
        var dir: DocumentFile = root
        for (i in 0 until segments.size - 1) {
            dir = dir.findFile(segments[i])?.takeIf { it.isDirectory } ?: return null
        }
        val leafName = segments.last() + ".gpg"
        val leaf = dir.findFile(leafName)?.takeIf { it.isFile } ?: return null
        return try {
            context.contentResolver.openInputStream(leaf.uri)?.use { it.readBytes() }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Find the nearest `.gpg-id` recipients for an entry path (the entry's own
     * folder, walking up to the root). Used for writing (C3); harmless to expose
     * now. Returns the root ids if no nested `.gpg-id` is found.
     */
    fun recipientsForEntry(ref: PassStoreRef, relativePath: String): List<String> {
        val root = resolveRoot(ref) ?: return ref.rootGpgIds
        val segments = relativePath.split("/").dropLast(1)
        // Walk from the deepest folder up to root, returning the first .gpg-id found.
        var dir: DocumentFile = root
        val chain = mutableListOf(root)
        for (seg in segments) {
            dir = dir.findFile(seg)?.takeIf { it.isDirectory } ?: break
            chain.add(dir)
        }
        for (d in chain.asReversed()) {
            val ids = readGpgId(d)
            if (ids.isNotEmpty()) return ids
        }
        return ref.rootGpgIds
    }
}
