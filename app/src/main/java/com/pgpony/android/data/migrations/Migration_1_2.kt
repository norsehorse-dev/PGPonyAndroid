// Migration_1_2.kt
// PGPony Android
//
// Schema migration from database version 1 (v1.4.0 and earlier) to
// version 2 (Phase A1+). Adds the `pgp_subkeys` table and four new
// revocation columns on `pgp_keys`.
//
// Note this migration ONLY changes the schema. Populating subkey rows
// from existing key material is the SubkeyMigrationService's job — it
// runs after Room finishes opening the database because it needs
// EncryptedSharedPreferences (i.e. SecureKeyStore) which is not
// available inside a SupportSQLiteDatabase context.
//
// Added in Phase A1 (Subkey Model Refactor).

package com.pgpony.android.data.migrations

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {

        // ── Subkey table ──────────────────────────────────────────────
        //
        // Column ordering, NOT NULL constraints, and default values
        // mirror what Room would generate from the PgpSubkeyEntity
        // annotation. With `exportSchema = false`, Room verifies the
        // runtime schema at startup — column names and types must match,
        // but identifier quoting style (backticks vs none) is flexible.

        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS `pgp_subkeys` (
                `id` TEXT NOT NULL,
                `primaryKeyId` TEXT NOT NULL,
                `fingerprint` TEXT NOT NULL,
                `keyId` TEXT NOT NULL,
                `algorithm` TEXT NOT NULL,
                `creationTime` INTEGER NOT NULL,
                `expirationTime` INTEGER,
                `capabilities` INTEGER NOT NULL DEFAULT 0,
                `isRevoked` INTEGER NOT NULL DEFAULT 0,
                `revokedAt` INTEGER,
                PRIMARY KEY(`id`),
                FOREIGN KEY(`primaryKeyId`) REFERENCES `pgp_keys`(`id`) ON UPDATE NO ACTION ON DELETE CASCADE
            )
            """.trimIndent()
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS `index_pgp_subkeys_primaryKeyId` ON `pgp_subkeys` (`primaryKeyId`)")
        db.execSQL("CREATE INDEX IF NOT EXISTS `index_pgp_subkeys_fingerprint` ON `pgp_subkeys` (`fingerprint`)")

        // ── Revocation columns on pgp_keys ────────────────────────────
        //
        // All four are nullable / default-zero so existing rows stay
        // valid. The migration is non-destructive.

        db.execSQL("ALTER TABLE `pgp_keys` ADD COLUMN `isRevoked` INTEGER NOT NULL DEFAULT 0")
        db.execSQL("ALTER TABLE `pgp_keys` ADD COLUMN `revokedAt` INTEGER")
        db.execSQL("ALTER TABLE `pgp_keys` ADD COLUMN `revocationReasonValue` INTEGER")
        db.execSQL("ALTER TABLE `pgp_keys` ADD COLUMN `revocationCertificate` TEXT")
    }
}
