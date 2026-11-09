// RecipientGroups.kt
// PGPony Android, 4.8.0 RC8 (item 4n): recipient groups and the picker's order.
//
// The rules behind groups, free of Room, Compose and Android so the JVM tests
// can check them and PGPony Desktop can take them from the sync unchanged:
//
//   - how a member fingerprint is compared (lowercase hex, no spaces, the same
//     as KeyDeduplicationService.normalize),
//   - what a group name may be (trimmed, not blank, at most NAME_MAX_LENGTH,
//     unique ignoring case),
//   - the recipient picker's order: your own keys first, then everyone else A
//     to Z by name, the email when there is no name,
//   - which members of a group a pick adds and which it leaves out, and why,
//   - how a restored backup's groups merge into the ones on the device (by
//     name; the same name takes the union of members).
//
// A group is a named set of keys stored by primary fingerprint. A member whose
// key is in Recently Deleted stays a member but cannot be picked; a key
// deleted for good leaves every group (KeyRepository.purgeKey and deleteKey).

package com.pgpony.android.data.groups

import java.util.Locale

/** A group as the app uses it: [members] are normalized fingerprints, in no set order. */
data class RecipientGroup(
    val id: String,
    val name: String,
    val createdAt: Long,
    val members: List<String>
)

/** A group as a backup carries it (see backup/RecipientGroupBackup). */
data class BackupGroup(
    val name: String,
    val createdAt: Long,
    val members: List<String>
)

/** What a group pick needs to know about one member's key. */
data class GroupMemberFacts(
    val fingerprint: String,
    /** The name, else the email, else the short fingerprint. */
    val label: String,
    val revoked: Boolean = false,
    val expired: Boolean = false,
    /** A scanned security key stored without its public certificate. */
    val noCertificate: Boolean = false,
    /** In Recently Deleted. */
    val deleted: Boolean = false
)

/** Why a group pick left a member out. */
enum class LeftOutReason { REVOKED, EXPIRED, NO_CERTIFICATE, DELETED, NOT_IN_KEYRING }

data class LeftOutMember(val fingerprint: String, val label: String, val reason: LeftOutReason)

/** The outcome of picking a group: [usable] fingerprints in the picker's order. */
data class GroupPick(val usable: List<String>, val leftOut: List<LeftOutMember>)

/** Why a group name was refused. */
enum class GroupNameProblem { BLANK, TOO_LONG, TAKEN }

/** What a restore does with the backup's groups (see [RecipientGroups.planMerge]). */
data class GroupMergePlan(
    /** Groups whose name is new here, with the members this device knows. */
    val add: List<BackupGroup>,
    /** Existing group id to the members the backup adds to it. */
    val extend: Map<String, List<String>>,
    /** Names of existing groups the backup matched without adding anyone. */
    val unchanged: List<String>
)

object RecipientGroups {

    const val NAME_MAX_LENGTH = 64

    /** How fingerprints are stored and compared: lowercase, no whitespace. */
    fun normalize(fingerprint: String): String =
        fingerprint.lowercase(Locale.ROOT).filter { !it.isWhitespace() }

    /** A fingerprint a group may hold: 32 to 64 hex digits after [normalize]. */
    fun isFingerprint(normalized: String): Boolean =
        normalized.length in 32..64 && normalized.all { it in '0'..'9' || it in 'a'..'f' }

    /** The name as stored. */
    fun cleanName(name: String): String = name.trim()

    private fun nameKey(name: String): String = cleanName(name).lowercase(Locale.ROOT)

    /** Whether two names are the same group name (case and outer spaces ignored). */
    fun sameName(a: String, b: String): Boolean = nameKey(a) == nameKey(b)

    /**
     * The problem with [name] for a group, or null when it can be used. [existing]
     * are the groups already held; [exceptId] is the group being renamed, so
     * keeping its own name (or changing only its case) is allowed.
     */
    fun nameProblem(name: String, existing: List<RecipientGroup>, exceptId: String? = null): GroupNameProblem? {
        val clean = cleanName(name)
        if (clean.isEmpty()) return GroupNameProblem.BLANK
        if (clean.length > NAME_MAX_LENGTH) return GroupNameProblem.TOO_LONG
        if (existing.any { it.id != exceptId && sameName(it.name, clean) }) return GroupNameProblem.TAKEN
        return null
    }

    /** Groups A to Z by name, ignoring case. */
    fun sortGroups(groups: List<RecipientGroup>): List<RecipientGroup> =
        groups.sortedWith(compareBy<RecipientGroup> { nameKey(it.name) }.thenBy { it.createdAt })

    /**
     * The recipient picker's order: your own keys first, then everyone else,
     * each part A to Z by name, the email when there is no name, ignoring case.
     * Keys with neither sort by [userId], after the named ones; the fingerprint
     * breaks ties so the order never depends on the query.
     */
    fun <T> pickerOrder(
        items: List<T>,
        isOwn: (T) -> Boolean,
        name: (T) -> String,
        email: (T) -> String,
        userId: (T) -> String,
        fingerprint: (T) -> String
    ): List<T> {
        fun label(t: T): String = name(t).trim().ifEmpty { email(t).trim() }
        return items.sortedWith(
            compareBy<T> { if (isOwn(it)) 0 else 1 }
                .thenBy { if (label(it).isEmpty()) 1 else 0 }
                .thenBy { label(it).ifEmpty { userId(it).trim() }.lowercase(Locale.ROOT) }
                .thenBy { email(it).trim().lowercase(Locale.ROOT) }
                .thenBy { normalize(fingerprint(it)) }
        )
    }

    /**
     * Picking [group]: the members that can be recipients, in the order of
     * [pickerOrder] (so the chips read like the list), and the ones left out
     * with why. [facts] holds the keyring's live and binned keys by normalized
     * fingerprint. A revoked key is named as revoked even when it is also
     * expired, and a binned key as deleted whatever else is true of it, since
     * restoring it is what brings it back.
     */
    fun resolve(group: RecipientGroup, facts: Map<String, GroupMemberFacts>, order: List<String>): GroupPick {
        val usable = ArrayList<String>()
        val leftOut = ArrayList<LeftOutMember>()
        for (member in group.members.map(::normalize).distinct()) {
            val f = facts[member]
            val reason = reasonFor(f)
            if (reason == null) usable.add(member)
            else leftOut.add(LeftOutMember(member, f?.label ?: shortFingerprint(member), reason))
        }
        val rank = order.map(::normalize).withIndex().associate { it.value to it.index }
        usable.sortBy { rank[it] ?: Int.MAX_VALUE }
        leftOut.sortBy { it.label.lowercase(Locale.ROOT) }
        return GroupPick(usable, leftOut)
    }

    /**
     * Why a member with these [facts] cannot be picked now, or null when it can.
     * Null facts: the key is not in the keyring at all.
     */
    fun reasonFor(facts: GroupMemberFacts?): LeftOutReason? = when {
        facts == null -> LeftOutReason.NOT_IN_KEYRING
        facts.deleted -> LeftOutReason.DELETED
        facts.revoked -> LeftOutReason.REVOKED
        facts.noCertificate -> LeftOutReason.NO_CERTIFICATE
        facts.expired -> LeftOutReason.EXPIRED
        else -> null
    }

    /** The last 8 hex digits, uppercased, as a stand-in label for an unknown key. */
    fun shortFingerprint(fingerprint: String): String = normalize(fingerprint).takeLast(8).uppercase(Locale.ROOT)

    /**
     * Merges a restored backup's [incoming] groups into the [existing] ones, by
     * name. Only members [known] on this device (its keyring, live or binned,
     * after the backup's keys were imported) are taken, so a group never points
     * at a key that is not here. A new name with no known member is not added.
     * Two groups of the same name in one backup count as one.
     */
    fun planMerge(
        existing: List<RecipientGroup>,
        incoming: List<BackupGroup>,
        known: (String) -> Boolean
    ): GroupMergePlan {
        // Fold the backup's own duplicates first, keeping the first spelling
        // and the earliest creation time.
        val folded = LinkedHashMap<String, BackupGroup>()
        for (g in incoming) {
            val clean = cleanName(g.name)
            if (clean.isEmpty() || clean.length > NAME_MAX_LENGTH) continue
            val members = g.members.map(::normalize).filter { isFingerprint(it) && known(it) }
            val k = nameKey(clean)
            val prev = folded[k]
            folded[k] = if (prev == null) {
                BackupGroup(clean, g.createdAt, members.distinct())
            } else {
                BackupGroup(prev.name, minOf(prev.createdAt, g.createdAt), (prev.members + members).distinct())
            }
        }
        val add = ArrayList<BackupGroup>()
        val extend = LinkedHashMap<String, List<String>>()
        val unchanged = ArrayList<String>()
        for ((k, g) in folded) {
            val here = existing.firstOrNull { nameKey(it.name) == k }
            if (here == null) {
                if (g.members.isNotEmpty()) add.add(g)
                continue
            }
            val held = here.members.map(::normalize).toSet()
            val more = g.members.filter { it !in held }
            if (more.isEmpty()) unchanged.add(here.name) else extend[here.id] = more
        }
        return GroupMergePlan(add, extend, unchanged)
    }
}
