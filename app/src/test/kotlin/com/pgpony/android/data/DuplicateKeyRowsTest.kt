// DuplicateKeyRowsTest.kt
// PGPony Android, 4.8.0 (item 4c): which row survives a fingerprint group and
// what it takes from the rows MIGRATION_12_13 deletes.

package com.pgpony.android.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DuplicateKeyRowsTest {

    private fun row(id: String, fp: String = "ab12cd34", vararg cols: Pair<String, Any?>): Map<String, Any?> =
        mapOf<String, Any?>(
            "id" to id, "fingerprint" to fp, "isKeyPair" to 0L, "isCardBacked" to 0L,
            "isDefault" to 0L, "trustLevel" to "UNKNOWN", "decryptUseCount" to 0L,
            "createdAt" to 1_000L, "deletedAt" to null, "notes" to null
        ) + cols

    @Test
    fun `groups only fingerprints held by two or more rows, case and spaces ignored`() {
        val rows = listOf(
            row("a", "AB12 CD34"), row("b", "ab12cd34"), row("c", "ffff0000")
        )
        val groups = DuplicateKeyRows.groups(rows)
        assertEquals(1, groups.size)
        assertEquals(setOf("a", "b"), groups.single().map { it["id"] }.toSet())
    }

    @Test
    fun `reimport after delete then restore keeps the key pair row and the notes`() {
        // The binned original: a key pair with a note and Verified trust.
        val original = row(
            "old", "ab12cd34", "isKeyPair" to 1L, "notes" to "work key",
            "trustLevel" to "VERIFIED", "deletedAt" to 5_000L, "decryptUseCount" to 7L
        )
        // The re-import: live, public only, no note.
        val reimport = row("new", "ab12cd34", "createdAt" to 6_000L, "armoredPublicKey" to "armor")
        val plan = DuplicateKeyRows.plan(listOf(reimport, original))
        assertEquals("old", plan.keeperId)
        assertEquals(listOf("new"), plan.deleteIds)
        assertTrue("the merged row is live", plan.changes.containsKey("deletedAt") && plan.changes["deletedAt"] == null)
        assertEquals("armor", plan.changes["armoredPublicKey"])
        assertFalse("the keeper's own note is unchanged", plan.changes.containsKey("notes"))
        assertFalse("Verified is already the highest trust in the group", plan.changes.containsKey("trustLevel"))
    }

    @Test
    fun `two live public rows keep one, with the higher trust, the default and both notes`() {
        val a = row("a", "ab12cd34", "notes" to "from mail", "trustLevel" to "UNVERIFIED", "contactId" to "c1")
        val b = row("b", "ab12cd34", "notes" to "met in person", "trustLevel" to "VERIFIED", "isDefault" to 1L)
        val plan = DuplicateKeyRows.plan(listOf(a, b))
        val keeper = plan.keeperId
        val other = if (keeper == "a") b else a
        assertEquals(listOf(other["id"]), plan.deleteIds)
        val merged = (if (keeper == "a") a else b) + plan.changes
        assertEquals("VERIFIED", merged["trustLevel"])
        assertEquals(1L, merged["isDefault"])
        assertEquals("c1", merged["contactId"])
        val notes = merged["notes"] as String
        assertTrue(notes.contains("from mail") && notes.contains("met in person"))
    }

    @Test
    fun `a binned group stays binned and a live row beats a binned one of equal standing`() {
        val binned = DuplicateKeyRows.plan(listOf(
            row("x", "ab12cd34", "deletedAt" to 10L), row("y", "ab12cd34", "deletedAt" to 20L)
        ))
        assertFalse(binned.changes.containsKey("deletedAt"))

        val mixed = DuplicateKeyRows.plan(listOf(row("binned", "ab12cd34", "deletedAt" to 10L), row("live")))
        assertEquals("live", mixed.keeperId)
    }

    @Test
    fun `card link, revocation and the latest timestamps carry over to the keeper`() {
        val pair = row("pair", "ab12cd34", "isKeyPair" to 1L, "lastBackedUpAt" to 100L)
        val card = row(
            "card", "ab12cd34", "isCardBacked" to 1L, "cardSerial" to "0A0B0C0D",
            "isRevoked" to 1L, "revokedAt" to 42L, "revocationReason" to "RETIRED",
            "lastBackedUpAt" to 300L, "lastUploadedAt" to 7L
        )
        val plan = DuplicateKeyRows.plan(listOf(card, pair))
        assertEquals("pair", plan.keeperId)
        assertEquals(1L, plan.changes["isCardBacked"])
        assertEquals("0A0B0C0D", plan.changes["cardSerial"])
        assertEquals(1L, plan.changes["isRevoked"])
        assertEquals("RETIRED", plan.changes["revocationReason"])
        assertEquals(300L, plan.changes["lastBackedUpAt"])
        assertEquals(7L, plan.changes["lastUploadedAt"])
    }

    @Test
    fun `a user import clears the Autocrypt mark, Don't use survives a merge`() {
        val auto = row("auto", "ab12cd34", "autocryptImportedAt" to 9L, "trustLevel" to "DONT_USE")
        val user = row("user", "ab12cd34", "contactId" to "c")
        val plan = DuplicateKeyRows.plan(listOf(auto, user))
        val merged = (if (plan.keeperId == "auto") auto else user) + plan.changes
        assertEquals(null, merged["autocryptImportedAt"])
        assertEquals("DONT_USE", merged["trustLevel"])
    }

    @Test
    fun `the keeper is chosen the same way whatever order the rows arrive in`() {
        val rows = listOf(row("a"), row("b"), row("c"))
        val keepers = listOf(rows, rows.reversed(), listOf(rows[1], rows[2], rows[0]))
            .map { DuplicateKeyRows.plan(it).keeperId }.toSet()
        assertEquals(1, keepers.size)
    }
}
