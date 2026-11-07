// SshKeyBackup.kt
// PGPony Android, 4.8.0 RC7 (item 1): SSH-only keys in the encrypted backup.
//
// Additive entries in the backup's ustar archive, after the keys and before
// pgpony-settings.json:
//
//   ssh-keys/index.json        {"formatVersion":1,"keys":[{"fingerprint":"SHA256:...",
//                               "label":"...","createdAt":<epoch ms>,"file":"ssh-keys/<hex>.key"}]}
//   ssh-keys/<hex>.key         the key as an unencrypted OpenSSH private key file
//                              (openssh-key-v1, comment = label); <hex> is the
//                              hex SHA-256 of the public key blob
//
// The archive as a whole is encrypted with the recovery code, as for the
// OpenPGP keys, so a key file needs no passphrase of its own; and since it is
// a plain OpenSSH file, a user who opens the backup with gpg and tar can use
// it with ssh directly. Older PGPony versions (Android reads only keys/*.asc
// and the two JSON files it knows) and iOS (ignores unknown entries) skip
// these entries, so a backup with SSH keys still restores there, and an old
// backup without them restores here unchanged. pgpony-meta.json is not
// touched. Pure JVM code; BackupService calls it.

package com.pgpony.android.backup

import com.pgpony.android.data.ssh.SshKeyBackupItem
import com.pgpony.android.data.ssh.SshKeyStore
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.security.MessageDigest
import java.util.Base64

object SshKeyBackup {

    const val DIR = "ssh-keys/"
    const val INDEX_NAME = "ssh-keys/index.json"
    const val FORMAT_VERSION = 1
    private const val KEY_SUFFIX = ".key"

    /** The archive entries for [items]: the index first, then one key file each. Empty for no items. */
    fun entries(items: List<SshKeyBackupItem>): List<UstarArchive.Entry> {
        if (items.isEmpty()) return emptyList()
        val files = ArrayList<UstarArchive.Entry>(items.size)
        val index = ArrayList<JsonObject>(items.size)
        val used = HashSet<String>()
        for (item in items) {
            val name = DIR + fileStem(item.fingerprint) + KEY_SUFFIX
            if (!used.add(name)) continue
            files.add(UstarArchive.Entry(name, item.keyFile))
            index.add(
                JsonObject(
                    mapOf(
                        "fingerprint" to JsonPrimitive(item.fingerprint),
                        "label" to JsonPrimitive(item.label),
                        "createdAt" to JsonPrimitive(item.createdAt),
                        "file" to JsonPrimitive(name)
                    )
                )
            )
        }
        val indexJson = JsonObject(
            mapOf(
                "formatVersion" to JsonPrimitive(FORMAT_VERSION),
                "keys" to JsonArray(index)
            )
        ).toString().toByteArray(Charsets.UTF_8)
        return listOf(UstarArchive.Entry(INDEX_NAME, indexJson)) + files
    }

    /**
     * The SSH key items in a restored archive. Labels and creation times come
     * from the index when it names the file; a key file the index does not
     * name (or a damaged index) still restores, with the file's comment as
     * label. Each file is taken once.
     */
    fun items(entries: List<UstarArchive.Entry>): List<SshKeyBackupItem> {
        val byFile = HashMap<String, JsonObject>()
        entries.firstOrNull { it.name == INDEX_NAME }?.let { idx ->
            runCatching {
                val o = Json.parseToJsonElement(String(idx.data, Charsets.UTF_8)).jsonObject
                for (k in o["keys"]?.jsonArray.orEmpty()) {
                    val ko = k.jsonObject
                    val file = ko["file"]?.jsonPrimitive?.contentOrNull ?: continue
                    byFile[file] = ko
                }
            }
        }
        val seen = HashSet<String>()
        return entries
            .filter { it.name.startsWith(DIR) && it.name.endsWith(KEY_SUFFIX) && seen.add(it.name) }
            .map { e ->
                val meta = byFile[e.name]
                SshKeyBackupItem(
                    fingerprint = meta?.get("fingerprint")?.jsonPrimitive?.contentOrNull ?: e.name,
                    label = meta?.get("label")?.jsonPrimitive?.contentOrNull ?: "",
                    createdAt = meta?.get("createdAt")?.jsonPrimitive?.longOrNull ?: 0L,
                    keyFile = e.data
                )
            }
    }

    /** "SHA256:<base64>" to the hex digest, so the file name is plain and fixed-length. */
    private fun fileStem(fingerprint: String): String {
        val digest = runCatching {
            val b64 = fingerprint.removePrefix("SHA256:")
            Base64.getDecoder().decode(b64 + "=".repeat((4 - b64.length % 4) % 4))
        }.getOrNull()?.takeIf { it.size == 32 }
            ?: MessageDigest.getInstance("SHA-256").digest(fingerprint.toByteArray(Charsets.UTF_8))
        return SshKeyStore.hex(digest)
    }
}
