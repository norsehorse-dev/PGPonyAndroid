// RecipientGroupStoreTest.kt
// PGPony Android, 4.8.0 RC8 (item 4n): RecipientGroupStore against an in-memory
// RecipientGroupDao: create, rename, members, delete, a key deleted for good
// leaving every group, and a restore merging groups by name.

package com.pgpony.android.data.groups

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class RecipientGroupStoreTest {

    /** The DAO's queries, on two maps. Matches the SQL in RecipientGroupEntity.kt. */
    private class MemoryDao : RecipientGroupDao {
        val groups = LinkedHashMap<String, RecipientGroupEntity>()
        val members = LinkedHashSet<RecipientGroupMemberEntity>()

        override suspend fun groups(): List<RecipientGroupEntity> = groups.values.toList()
        override suspend fun members(): List<RecipientGroupMemberEntity> = members.toList()
        override suspend fun upsertGroup(group: RecipientGroupEntity) { groups[group.id] = group }
        override suspend fun addMembers(rows: List<RecipientGroupMemberEntity>) { members.addAll(rows) }
        override suspend fun removeMember(groupId: String, fingerprint: String) {
            members.removeAll { it.groupId == groupId && it.fingerprint == fingerprint }
        }
        override suspend fun removeAllMembers(groupId: String) { members.removeAll { it.groupId == groupId } }
        override suspend fun deleteGroup(groupId: String) { groups.remove(groupId) }
        override suspend fun removeFromAllGroups(fingerprint: String) { members.removeAll { it.fingerprint == fingerprint } }
    }

    private fun fp(n: Int): String = n.toString(16).padStart(40, '0')

    private fun store(dao: MemoryDao): RecipientGroupStore {
        var next = 0
        return RecipientGroupStore(dao, clock = { 1_000L }, newId = { "id${next++}" })
    }

    @Test
    fun `create stores normalized members and refuses a taken name`() = runBlocking {
        val dao = MemoryDao()
        val s = store(dao)
        val g = s.create("  Family ", listOf(fp(1).uppercase(), " ${fp(2)} ", fp(1), "not a key"))
        assertEquals("Family", g.name)
        assertEquals(listOf(fp(1), fp(2)), g.members)
        try {
            s.create("FAMILY", listOf(fp(3)))
            fail("a taken name was accepted")
        } catch (e: GroupNameException) {
            assertEquals(GroupNameProblem.TAKEN, e.problem)
        }
        assertEquals(1, s.all().size)
    }

    @Test
    fun `all lists groups A to Z`() = runBlocking {
        val s = store(MemoryDao())
        s.create("work", listOf(fp(1)))
        s.create("Club", listOf(fp(1)))
        s.create("art", listOf(fp(1)))
        assertEquals(listOf("art", "Club", "work"), s.all().map { it.name })
    }

    @Test
    fun `rename keeps the members and checks the name`() = runBlocking {
        val s = store(MemoryDao())
        val a = s.create("A", listOf(fp(1)))
        s.create("B", listOf(fp(2)))
        s.rename(a.id, "Alpha")
        assertEquals("Alpha", s.get(a.id)?.name)
        assertEquals(listOf(fp(1)), s.get(a.id)?.members)
        try {
            s.rename(a.id, "b")
            fail("a taken name was accepted")
        } catch (e: GroupNameException) {
            assertEquals(GroupNameProblem.TAKEN, e.problem)
        }
    }

    @Test
    fun `setMembers adds and removes, addMember and removeMember change one`() = runBlocking {
        val s = store(MemoryDao())
        val g = s.create("G", listOf(fp(1), fp(2)))
        s.setMembers(g.id, listOf(fp(2), fp(3)))
        assertEquals(setOf(fp(2), fp(3)), s.get(g.id)?.members?.toSet())
        s.addMember(g.id, fp(4).uppercase())
        s.removeMember(g.id, fp(2))
        assertEquals(setOf(fp(3), fp(4)), s.get(g.id)?.members?.toSet())
        assertEquals(listOf("G"), s.groupsOf(fp(4).uppercase()).map { it.name })
    }

    @Test
    fun `delete removes the group and its members`() = runBlocking {
        val dao = MemoryDao()
        val s = store(dao)
        val g = s.create("G", listOf(fp(1)))
        s.delete(g.id)
        assertTrue(s.all().isEmpty())
        assertTrue(dao.members.isEmpty())
    }

    @Test
    fun `a key deleted for good leaves every group, the groups stay`() = runBlocking {
        val s = store(MemoryDao())
        s.create("A", listOf(fp(1), fp(2)))
        s.create("B", listOf(fp(1)))
        s.forgetKey(fp(1).uppercase())
        val all = s.all()
        assertEquals(2, all.size)
        assertEquals(listOf(fp(2)), all.first { it.name == "A" }.members)
        assertTrue(all.first { it.name == "B" }.members.isEmpty())
    }

    @Test
    fun `a restore adds new names, joins members of known names and reports both`() = runBlocking {
        val s = store(MemoryDao())
        s.create("Family", listOf(fp(1)))
        s.create("Work", listOf(fp(3)))
        val known = setOf(fp(1), fp(2), fp(3), fp(4))
        val report = s.mergeFromBackup(
            listOf(
                BackupGroup("family", 5L, listOf(fp(2))),
                BackupGroup("work", 5L, listOf(fp(3))),
                BackupGroup("Club", 7L, listOf(fp(4), fp(9))),
                BackupGroup("Nobody here", 7L, listOf(fp(9)))
            )
        ) { it in known }
        assertEquals(listOf("Club"), report.added)
        assertEquals(listOf("Family"), report.merged)
        assertEquals(listOf("Work"), report.unchanged)
        val all = s.all().associateBy { it.name }
        assertEquals(setOf(fp(1), fp(2)), all.getValue("Family").members.toSet())
        assertEquals(listOf(fp(4)), all.getValue("Club").members)
        assertEquals(7L, all.getValue("Club").createdAt)
        assertEquals(setOf("Club", "Family", "Work"), all.keys)
    }
}
