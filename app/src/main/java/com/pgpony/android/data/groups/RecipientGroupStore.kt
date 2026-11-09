// RecipientGroupStore.kt
// PGPony Android, 4.8.0 RC8 (item 4n): reads and changes recipient groups.
//
// The one place the app touches the group tables (the Encrypt picker, the
// Groups screen, Key Details, the backup). No Android or Compose import, only
// the DAO interface, so the JVM tests run it against a map and PGPony Desktop
// can take it from the sync. Names are checked here (RecipientGroups.
// nameProblem), so no caller can store a blank, overlong or duplicate name.
//
// There are no transactions: every change is a few single statements, ordered
// so that an interrupted change never loses a member it did not mean to drop
// (setMembers adds before it removes; delete removes the members first, so a
// group row is never left pointing at members of a group that is gone).

package com.pgpony.android.data.groups

import java.util.UUID

/** A change refused because of the name. */
class GroupNameException(val problem: GroupNameProblem) : Exception(problem.name)

/** 4.8.0 RC8 (item 4n): a group change that failed in storage, not because of the name. */
class GroupSaveException(cause: Throwable) : Exception(cause)

/** How a restore's groups landed (names, for the restore report). */
data class GroupMergeReport(
    val added: List<String> = emptyList(),
    val merged: List<String> = emptyList(),
    val unchanged: List<String> = emptyList()
)

class RecipientGroupStore(
    private val dao: RecipientGroupDao,
    private val clock: () -> Long = System::currentTimeMillis,
    private val newId: () -> String = { UUID.randomUUID().toString() }
) {

    /** Every group with its members, A to Z by name. */
    suspend fun all(): List<RecipientGroup> {
        val byGroup = dao.members().groupBy({ it.groupId }, { it.fingerprint })
        return RecipientGroups.sortGroups(
            dao.groups().map { RecipientGroup(it.id, it.name, it.createdAt, byGroup[it.id].orEmpty()) }
        )
    }

    suspend fun get(id: String): RecipientGroup? = all().firstOrNull { it.id == id }

    /** The groups [fingerprint] is a member of, A to Z. */
    suspend fun groupsOf(fingerprint: String): List<RecipientGroup> {
        val fp = RecipientGroups.normalize(fingerprint)
        return all().filter { g -> g.members.any { it == fp } }
    }

    /** The problem with [name], or null when [create] or [rename] would take it. */
    suspend fun nameProblem(name: String, exceptId: String? = null): GroupNameProblem? =
        RecipientGroups.nameProblem(name, all(), exceptId)

    /**
     * A new group named [name] holding [fingerprints]. Throws
     * [GroupNameException] when the name cannot be used.
     */
    suspend fun create(name: String, fingerprints: Collection<String>): RecipientGroup {
        RecipientGroups.nameProblem(name, all())?.let { throw GroupNameException(it) }
        val group = RecipientGroupEntity(newId(), RecipientGroups.cleanName(name), clock())
        dao.upsertGroup(group)
        val members = cleanMembers(fingerprints)
        if (members.isNotEmpty()) dao.addMembers(members.map { RecipientGroupMemberEntity(group.id, it) })
        return RecipientGroup(group.id, group.name, group.createdAt, members)
    }

    /** Renames group [id]. Throws [GroupNameException] when the name cannot be used. */
    suspend fun rename(id: String, name: String) {
        val groups = all()
        val group = groups.firstOrNull { it.id == id } ?: return
        RecipientGroups.nameProblem(name, groups, exceptId = id)?.let { throw GroupNameException(it) }
        dao.upsertGroup(RecipientGroupEntity(group.id, RecipientGroups.cleanName(name), group.createdAt))
    }

    /** Makes [fingerprints] the members of group [id]. */
    suspend fun setMembers(id: String, fingerprints: Collection<String>) {
        val group = get(id) ?: return
        val want = cleanMembers(fingerprints)
        val have = group.members.toSet()
        val add = want.filter { it !in have }
        if (add.isNotEmpty()) dao.addMembers(add.map { RecipientGroupMemberEntity(id, it) })
        for (fp in have) if (fp !in want) dao.removeMember(id, fp)
    }

    suspend fun addMember(id: String, fingerprint: String) {
        if (get(id) == null) return
        val fp = cleanMembers(listOf(fingerprint))
        if (fp.isNotEmpty()) dao.addMembers(fp.map { RecipientGroupMemberEntity(id, it) })
    }

    suspend fun removeMember(id: String, fingerprint: String) {
        dao.removeMember(id, RecipientGroups.normalize(fingerprint))
    }

    suspend fun delete(id: String) {
        dao.removeAllMembers(id)
        dao.deleteGroup(id)
    }

    /** A key deleted for good: it leaves every group. */
    suspend fun forgetKey(fingerprint: String) {
        dao.removeFromAllGroups(RecipientGroups.normalize(fingerprint))
    }

    /**
     * Merges a restored backup's groups by name (RecipientGroups.planMerge).
     * [known] says whether a normalized fingerprint is in this keyring.
     */
    suspend fun mergeFromBackup(incoming: List<BackupGroup>, known: (String) -> Boolean): GroupMergeReport {
        if (incoming.isEmpty()) return GroupMergeReport()
        val existing = all()
        val plan = RecipientGroups.planMerge(existing, incoming, known)
        val added = ArrayList<String>()
        for (g in plan.add) {
            val entity = RecipientGroupEntity(newId(), g.name, if (g.createdAt > 0) g.createdAt else clock())
            dao.upsertGroup(entity)
            dao.addMembers(g.members.map { RecipientGroupMemberEntity(entity.id, it) })
            added.add(g.name)
        }
        val merged = ArrayList<String>()
        for ((id, more) in plan.extend) {
            dao.addMembers(more.map { RecipientGroupMemberEntity(id, it) })
            existing.firstOrNull { it.id == id }?.let { merged.add(it.name) }
        }
        return GroupMergeReport(added, merged, plan.unchanged)
    }

    private fun cleanMembers(fingerprints: Collection<String>): List<String> =
        fingerprints.map(RecipientGroups::normalize).filter { RecipientGroups.isFingerprint(it) }.distinct()
}
