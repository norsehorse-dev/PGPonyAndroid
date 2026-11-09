// RecipientGroupSchema.kt
// PGPony Android, 4.8.0 RC8 (item 4n): the SQL that MIGRATION_13_14 runs to add
// the two group tables. Kept here as plain strings, with no Android import, so
// a JVM test can hold them against the entities in RecipientGroupEntity.kt and
// PGPony Desktop can create the same tables from the sync.
//
// The statements mirror what Room generates from RecipientGroupEntity and
// RecipientGroupMemberEntity (column order, NOT NULL, primary keys and the
// default index name), since the database runs with exportSchema = false and
// Room checks the tables against the entities when it opens.

package com.pgpony.android.data.groups

object RecipientGroupSchema {

    const val GROUPS_TABLE = "recipient_groups"
    const val MEMBERS_TABLE = "recipient_group_members"

    /** Room's default name for the index on [MEMBERS_TABLE].fingerprint. */
    const val MEMBERS_FINGERPRINT_INDEX = "index_recipient_group_members_fingerprint"

    const val CREATE_GROUPS =
        "CREATE TABLE IF NOT EXISTS `recipient_groups` (" +
            "`id` TEXT NOT NULL, " +
            "`name` TEXT NOT NULL, " +
            "`createdAt` INTEGER NOT NULL, " +
            "PRIMARY KEY(`id`))"

    const val CREATE_MEMBERS =
        "CREATE TABLE IF NOT EXISTS `recipient_group_members` (" +
            "`groupId` TEXT NOT NULL, " +
            "`fingerprint` TEXT NOT NULL, " +
            "PRIMARY KEY(`groupId`, `fingerprint`))"

    const val CREATE_MEMBERS_FINGERPRINT_INDEX =
        "CREATE INDEX IF NOT EXISTS `index_recipient_group_members_fingerprint` " +
            "ON `recipient_group_members` (`fingerprint`)"

    /** In the order the migration runs them. */
    val MIGRATION_13_14: List<String> = listOf(CREATE_GROUPS, CREATE_MEMBERS, CREATE_MEMBERS_FINGERPRINT_INDEX)
}
