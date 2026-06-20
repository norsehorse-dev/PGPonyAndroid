// PgpSubkeyEntity.kt
// PGPony Android
//
// Room entity for the subkey graph. One row per subkey under a primary
// PGPKeyEntity, plus one row for the primary key itself (so iteration
// always covers the full key ring).
//
// Mirrors iOS PGPSubkeyModel (SwiftData) introduced in v5.0 Phase 1.
// Cross-platform parity: the `capabilities` field uses the PGPony bit
// flag scheme (Certify=1, Sign=2, Encrypt=4, Authenticate=8) — see
// SubkeyCapability.kt for the wire-protocol mapping.
//
// Foreign key: primaryKeyId -> pgp_keys.id with ON DELETE CASCADE so
// deleting a primary key removes all its subkey rows automatically.
//
// Added in Phase A1 (Subkey Model Refactor).

package com.pgpony.android.data

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.TypeConverters
import com.pgpony.android.crypto.KeyAlgorithm

@Entity(
    tableName = "pgp_subkeys",
    foreignKeys = [
        ForeignKey(
            entity = PGPKeyEntity::class,
            parentColumns = ["id"],
            childColumns = ["primaryKeyId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index(value = ["primaryKeyId"]),
        Index(value = ["fingerprint"])
    ]
)
@TypeConverters(KeyAlgorithmConverter::class)
data class PgpSubkeyEntity(
    @PrimaryKey
    val id: String,                       // UUID string

    val primaryKeyId: String,             // FK -> pgp_keys.id (CASCADE)

    val fingerprint: String,              // 40/64 hex chars (v4/v6)
    val keyId: String,                    // 16 hex chars (long key ID)
    val algorithm: KeyAlgorithm,
    val creationTime: Long,               // epoch ms
    val expirationTime: Long? = null,     // epoch ms, null = never expires

    /**
     * PGPony capability bit-set. See SubkeyCapability.kt — values do
     * NOT match the OpenPGP wire-protocol KeyFlags numbers.
     */
    @ColumnInfo(defaultValue = "0")
    val capabilities: Int = 0,

    @ColumnInfo(defaultValue = "0")
    val isRevoked: Boolean = false,

    val revokedAt: Long? = null
) {
    val shortFingerprint: String
        get() = fingerprint.takeLast(8).uppercase()

    val formattedFingerprint: String
        get() = fingerprint.uppercase().chunked(4).joinToString(" ")

    val isExpired: Boolean
        get() = expirationTime?.let { it < System.currentTimeMillis() } ?: false
}

// ── DAO ────────────────────────────────────────────────────────────────

@Dao
interface PGPSubkeyDao {

    @Query("SELECT * FROM pgp_subkeys WHERE primaryKeyId = :primaryKeyId ORDER BY creationTime ASC")
    suspend fun getByPrimaryKeyId(primaryKeyId: String): List<PgpSubkeyEntity>

    @Query("SELECT * FROM pgp_subkeys WHERE fingerprint = :fingerprint LIMIT 1")
    suspend fun getByFingerprint(fingerprint: String): PgpSubkeyEntity?

    @Query("SELECT * FROM pgp_subkeys")
    suspend fun getAll(): List<PgpSubkeyEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(subkey: PgpSubkeyEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(subkeys: List<PgpSubkeyEntity>)

    @Delete
    suspend fun delete(subkey: PgpSubkeyEntity)

    @Query("DELETE FROM pgp_subkeys WHERE primaryKeyId = :primaryKeyId")
    suspend fun deleteByPrimaryKeyId(primaryKeyId: String)

    @Query("DELETE FROM pgp_subkeys")
    suspend fun deleteAll()

    @Query("SELECT COUNT(*) FROM pgp_subkeys WHERE primaryKeyId = :primaryKeyId")
    suspend fun countForPrimary(primaryKeyId: String): Int
}
