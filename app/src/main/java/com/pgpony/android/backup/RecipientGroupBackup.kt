// RecipientGroupBackup.kt
// PGPony Android, 4.8.0 RC8 (item 4n): recipient groups in the encrypted backup.
//
// One additive entry in the backup's ustar archive, after the SSH keys and
// before pgpony-settings.json:
//
//   recipient-groups.json   {"formatVersion":1,"groups":[{"name":"Family",
//                            "createdAt":<epoch ms>,"members":["<fingerprint>",...]}]}
//
// Members are primary fingerprints, lowercase hex with no spaces, the same
// form as the keys/<fingerprint>.asc entries. Only members whose key is in the
// same backup are written, and a group left with none is not written.
//
// Older PGPony versions (Android 4.7.x reads only keys/*.asc and the two JSON
// files it knows, as with the RC7 ssh-keys/ entries) and iOS (ignores unknown
// entries) skip this entry, so a backup with groups still restores there; an
// old backup without it restores here unchanged. A reader takes the fields it
// knows and ignores the rest, so a later format version can add fields
// without breaking this one; iOS can read the same entry when it takes
// groups. pgpony-meta.json is not touched. Pure JVM code; BackupService and
// the full-backup pairing transfer (which sends the same backup) call it.

package com.pgpony.android.backup

import com.pgpony.android.data.groups.BackupGroup
import com.pgpony.android.data.groups.RecipientGroup
import com.pgpony.android.data.groups.RecipientGroups
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

object RecipientGroupBackup {

    const val ENTRY_NAME = "recipient-groups.json"
    const val FORMAT_VERSION = 1

    /**
     * The archive entry for [groups], keeping only members in
     * [backedUpFingerprints] (normalized or not). Null when no group has a
     * member left, so a backup without groups has no entry at all.
     */
    fun entry(groups: List<RecipientGroup>, backedUpFingerprints: Collection<String>): UstarArchive.Entry? {
        val inBackup = backedUpFingerprints.map(RecipientGroups::normalize).toSet()
        val out = ArrayList<JsonObject>()
        for (g in RecipientGroups.sortGroups(groups)) {
            val members = g.members.map(RecipientGroups::normalize).filter { it in inBackup }.distinct().sorted()
            if (members.isEmpty()) continue
            out.add(
                JsonObject(
                    mapOf(
                        "name" to JsonPrimitive(g.name),
                        "createdAt" to JsonPrimitive(g.createdAt),
                        "members" to JsonArray(members.map { JsonPrimitive(it) })
                    )
                )
            )
        }
        if (out.isEmpty()) return null
        val json = JsonObject(
            mapOf(
                "formatVersion" to JsonPrimitive(FORMAT_VERSION),
                "groups" to JsonArray(out)
            )
        ).toString().toByteArray(Charsets.UTF_8)
        return UstarArchive.Entry(ENTRY_NAME, json)
    }

    /**
     * The groups in a restored archive. Empty when there is no entry or it
     * cannot be read. A group without a usable name is skipped, and members
     * that are not fingerprints are dropped; whether a member's key is on this
     * device is decided at merge time (RecipientGroupStore.mergeFromBackup).
     */
    fun groups(entries: List<UstarArchive.Entry>): List<BackupGroup> {
        val entry = entries.firstOrNull { it.name == ENTRY_NAME } ?: return emptyList()
        val root = runCatching {
            Json.parseToJsonElement(String(entry.data, Charsets.UTF_8)).jsonObject
        }.getOrNull() ?: return emptyList()
        val list = runCatching { root["groups"]?.jsonArray }.getOrNull() ?: return emptyList()
        val out = ArrayList<BackupGroup>()
        for (element in list) {
            val o = runCatching { element.jsonObject }.getOrNull() ?: continue
            val name = runCatching { o["name"]?.jsonPrimitive?.contentOrNull }.getOrNull()
                ?.let(RecipientGroups::cleanName)
                ?.takeIf { it.isNotEmpty() && it.length <= RecipientGroups.NAME_MAX_LENGTH }
                ?: continue
            val createdAt = runCatching { o["createdAt"]?.jsonPrimitive?.longOrNull }.getOrNull() ?: 0L
            val members = runCatching { o["members"]?.jsonArray }.getOrNull().orEmpty()
                .mapNotNull { runCatching { it.jsonPrimitive.contentOrNull }.getOrNull() }
                .map(RecipientGroups::normalize)
                .filter(RecipientGroups::isFingerprint)
                .distinct()
            out.add(BackupGroup(name, createdAt, members))
        }
        return out
    }
}
