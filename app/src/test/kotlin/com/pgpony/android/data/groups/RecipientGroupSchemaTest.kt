// RecipientGroupSchemaTest.kt
// PGPony Android, 4.8.0 RC8 (item 4n): MIGRATION_13_14's SQL against the shape
// Room generates for RecipientGroupEntity and RecipientGroupMemberEntity. The
// project has no Room migration test harness (exportSchema = false, no
// room-testing), so this pins the statements; Room's own check when the
// database opens on the device is the final word.

package com.pgpony.android.data.groups

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RecipientGroupSchemaTest {

    @Test
    fun `the migration creates both tables, then the index`() {
        assertEquals(
            listOf(
                RecipientGroupSchema.CREATE_GROUPS,
                RecipientGroupSchema.CREATE_MEMBERS,
                RecipientGroupSchema.CREATE_MEMBERS_FINGERPRINT_INDEX
            ),
            RecipientGroupSchema.MIGRATION_13_14
        )
        // Re-running it (a migration retried after a crash) must not fail.
        RecipientGroupSchema.MIGRATION_13_14.forEach { assertTrue(it, it.contains("IF NOT EXISTS")) }
    }

    @Test
    fun `groups table matches RecipientGroupEntity`() {
        assertEquals(
            "CREATE TABLE IF NOT EXISTS `recipient_groups` (`id` TEXT NOT NULL, `name` TEXT NOT NULL, " +
                "`createdAt` INTEGER NOT NULL, PRIMARY KEY(`id`))",
            RecipientGroupSchema.CREATE_GROUPS
        )
    }

    @Test
    fun `members table matches RecipientGroupMemberEntity, primary key in declared order`() {
        assertEquals(
            "CREATE TABLE IF NOT EXISTS `recipient_group_members` (`groupId` TEXT NOT NULL, " +
                "`fingerprint` TEXT NOT NULL, PRIMARY KEY(`groupId`, `fingerprint`))",
            RecipientGroupSchema.CREATE_MEMBERS
        )
    }

    @Test
    fun `the index carries Room's default name for an index on fingerprint`() {
        assertEquals(
            "index_${RecipientGroupSchema.MEMBERS_TABLE}_fingerprint",
            RecipientGroupSchema.MEMBERS_FINGERPRINT_INDEX
        )
        assertTrue(
            RecipientGroupSchema.CREATE_MEMBERS_FINGERPRINT_INDEX.contains(
                "`${RecipientGroupSchema.MEMBERS_FINGERPRINT_INDEX}` ON `recipient_group_members` (`fingerprint`)"
            )
        )
    }
}
