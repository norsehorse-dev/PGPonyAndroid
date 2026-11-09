// RecipientGroupsTest.kt
// PGPony Android, 4.8.0 RC8 (item 4n): the picker's order, group names, what a
// group pick adds and leaves out, and how a restore merges groups by name.

package com.pgpony.android.data.groups

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RecipientGroupsTest {

    private data class K(
        val fp: String,
        val name: String = "",
        val email: String = "",
        val own: Boolean = false,
        val uid: String = ""
    )

    private fun order(keys: List<K>): List<String> =
        RecipientGroups.pickerOrder(keys, { it.own }, { it.name }, { it.email }, { it.uid }, { it.fp }).map { it.fp }

    private fun fp(n: Int): String = n.toString(16).padStart(40, '0')

    @Test
    fun `own keys come first, then everyone else A to Z by name or email`() {
        val keys = listOf(
            K(fp(1), name = "zoe"),
            K(fp(2), name = "Mine B", own = true),
            K(fp(3), email = "carol@example.org"),
            K(fp(4), name = "Bob"),
            K(fp(5), name = "mine a", own = true),
            K(fp(6), name = "Alice")
        )
        assertEquals(listOf(fp(5), fp(2), fp(6), fp(4), fp(3), fp(1)), order(keys))
    }

    @Test
    fun `keys with no name and no email sort after the named ones, by user ID`() {
        val keys = listOf(K(fp(1), uid = "aaa"), K(fp(2), name = "Zed"), K(fp(3), uid = "bbb"))
        assertEquals(listOf(fp(2), fp(1), fp(3)), order(keys))
    }

    @Test
    fun `two keys with one name are told apart by email, then fingerprint, whatever the input order`() {
        val a = K(fp(9), name = "Sam", email = "b@example.org")
        val b = K(fp(8), name = "Sam", email = "a@example.org")
        val c = K(fp(7), name = "Sam", email = "a@example.org")
        assertEquals(listOf(fp(7), fp(8), fp(9)), order(listOf(a, b, c)))
        assertEquals(listOf(fp(7), fp(8), fp(9)), order(listOf(c, a, b)))
    }

    @Test
    fun `fingerprints compare lowercase without spaces`() {
        assertEquals("ab12cd34", RecipientGroups.normalize(" AB12 CD34 "))
        assertTrue(RecipientGroups.isFingerprint(fp(1)))
        assertTrue(RecipientGroups.isFingerprint("a".repeat(64)))
        assertTrue(!RecipientGroups.isFingerprint("xyz"))
        assertTrue(!RecipientGroups.isFingerprint("g".repeat(40)))
    }

    @Test
    fun `names are trimmed, not blank, not too long and unique ignoring case`() {
        val held = listOf(RecipientGroup("g1", "Family", 1L, emptyList()))
        assertEquals(GroupNameProblem.BLANK, RecipientGroups.nameProblem("   ", held))
        assertEquals(GroupNameProblem.TOO_LONG, RecipientGroups.nameProblem("x".repeat(65), held))
        assertNull(RecipientGroups.nameProblem("x".repeat(64), held))
        assertEquals(GroupNameProblem.TAKEN, RecipientGroups.nameProblem(" family ", held))
        assertNull(RecipientGroups.nameProblem("Work", held))
        // Renaming a group to its own name in another case is allowed.
        assertNull(RecipientGroups.nameProblem("FAMILY", held, exceptId = "g1"))
    }

    @Test
    fun `a pick adds usable keys in picker order and names the ones it left out`() {
        val group = RecipientGroup("g", "Team", 1L, listOf(fp(1), fp(2), fp(3), fp(4), fp(5), fp(6), fp(7)))
        val facts = mapOf(
            fp(1) to GroupMemberFacts(fp(1), "Bob"),
            fp(2) to GroupMemberFacts(fp(2), "Ann"),
            fp(3) to GroupMemberFacts(fp(3), "Rev", revoked = true, expired = true),
            fp(4) to GroupMemberFacts(fp(4), "Old", expired = true),
            fp(5) to GroupMemberFacts(fp(5), "Card", noCertificate = true),
            fp(6) to GroupMemberFacts(fp(6), "Binned", deleted = true)
            // fp(7) has no key here at all.
        )
        val pick = RecipientGroups.resolve(group, facts, order = listOf(fp(2), fp(1)))
        assertEquals(listOf(fp(2), fp(1)), pick.usable)
        val reasons = pick.leftOut.associate { it.fingerprint to it.reason }
        assertEquals(LeftOutReason.REVOKED, reasons[fp(3)])
        assertEquals(LeftOutReason.EXPIRED, reasons[fp(4)])
        assertEquals(LeftOutReason.NO_CERTIFICATE, reasons[fp(5)])
        assertEquals(LeftOutReason.DELETED, reasons[fp(6)])
        assertEquals(LeftOutReason.NOT_IN_KEYRING, reasons[fp(7)])
        assertEquals(RecipientGroups.shortFingerprint(fp(7)), pick.leftOut.first { it.fingerprint == fp(7) }.label)
    }

    @Test
    fun `restoring a binned key puts it back in the pick`() {
        val group = RecipientGroup("g", "Team", 1L, listOf(fp(1)))
        val binned = mapOf(fp(1) to GroupMemberFacts(fp(1), "Bob", deleted = true))
        assertEquals(emptyList<String>(), RecipientGroups.resolve(group, binned, emptyList()).usable)
        val restored = mapOf(fp(1) to GroupMemberFacts(fp(1), "Bob"))
        assertEquals(listOf(fp(1)), RecipientGroups.resolve(group, restored, emptyList()).usable)
    }

    @Test
    fun `a restore merges by name, joins members and skips keys this device lacks`() {
        val here = listOf(
            RecipientGroup("g1", "Family", 1L, listOf(fp(1))),
            RecipientGroup("g2", "Work", 1L, listOf(fp(3)))
        )
        val known = setOf(fp(1), fp(2), fp(3), fp(4))
        val incoming = listOf(
            BackupGroup("family", 5L, listOf(fp(1), fp(2), fp(9))),
            BackupGroup("Work", 5L, listOf(fp(3))),
            BackupGroup("Club", 7L, listOf(fp(4).uppercase(), fp(9))),
            BackupGroup("Gone", 8L, listOf(fp(9))),
            BackupGroup("  ", 8L, listOf(fp(1)))
        )
        val plan = RecipientGroups.planMerge(here, incoming) { it in known }
        assertEquals(mapOf("g1" to listOf(fp(2))), plan.extend)
        assertEquals(listOf("Work"), plan.unchanged)
        assertEquals(listOf(BackupGroup("Club", 7L, listOf(fp(4)))), plan.add)
    }

    @Test
    fun `two groups of one name in a backup count as one`() {
        val incoming = listOf(
            BackupGroup("Club", 9L, listOf(fp(1))),
            BackupGroup("club", 3L, listOf(fp(2), fp(1)))
        )
        val plan = RecipientGroups.planMerge(emptyList(), incoming) { true }
        assertEquals(listOf(BackupGroup("Club", 3L, listOf(fp(1), fp(2)))), plan.add)
    }
}
