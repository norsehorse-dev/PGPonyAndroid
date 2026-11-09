// RecipientGroupEntity.kt
// PGPony Android, 4.8.0 RC8 (item 4n): the Room tables behind recipient groups.
//
//   recipient_groups         one row per group: id (UUID), name, createdAt
//   recipient_group_members  one row per member: groupId, fingerprint
//
// Members are stored by primary fingerprint, normalized by
// RecipientGroups.normalize (lowercase, no spaces), not by pgp_keys.id: a row
// id changes when a key is deleted and imported again, the fingerprint does
// not, and the backup and PGPony Desktop name keys by fingerprint too. No
// foreign keys: RecipientGroupStore removes a group's members itself, and
// KeyRepository removes a key from every group when it is deleted for good.
// Added by MIGRATION_13_14 (RoomMigrations.kt, SQL in RecipientGroupSchema).

package com.pgpony.android.data.groups

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query

@Entity(tableName = "recipient_groups")
data class RecipientGroupEntity(
    @PrimaryKey val id: String,
    val name: String,
    val createdAt: Long
)

@Entity(
    tableName = "recipient_group_members",
    primaryKeys = ["groupId", "fingerprint"],
    indices = [Index(value = ["fingerprint"])]
)
data class RecipientGroupMemberEntity(
    val groupId: String,
    val fingerprint: String
)

@Dao
interface RecipientGroupDao {
    @Query("SELECT * FROM recipient_groups")
    suspend fun groups(): List<RecipientGroupEntity>

    @Query("SELECT * FROM recipient_group_members")
    suspend fun members(): List<RecipientGroupMemberEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertGroup(group: RecipientGroupEntity)

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun addMembers(rows: List<RecipientGroupMemberEntity>)

    @Query("DELETE FROM recipient_group_members WHERE groupId = :groupId AND fingerprint = :fingerprint")
    suspend fun removeMember(groupId: String, fingerprint: String)

    @Query("DELETE FROM recipient_group_members WHERE groupId = :groupId")
    suspend fun removeAllMembers(groupId: String)

    @Query("DELETE FROM recipient_groups WHERE id = :groupId")
    suspend fun deleteGroup(groupId: String)

    /** A key deleted for good leaves every group. */
    @Query("DELETE FROM recipient_group_members WHERE fingerprint = :fingerprint")
    suspend fun removeFromAllGroups(fingerprint: String)
}
