// RoomMigrations.kt
// PGPony Android
//
// The PGPDatabase migration chain, v1 → v7. Moved verbatim from the bottom
// of PGPKeyEntity.kt (Desktop D2a): the migrations are the only part of the
// schema file that touches SupportSQLiteDatabase — an Android-only API — and
// relocating them lets PGPonyDesktop vendor PGPKeyEntity.kt unmodified for
// its plain-JVM build. Same package, top-level vals, so PGPonyApp's
// addMigrations(...) references resolve unchanged. Zero behavior change.

package com.pgpony.android.data

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * Phase A6 — add revocation columns. ALTER TABLE is the right tool here:
 * all four new columns are nullable or have safe defaults so existing
 * rows pick up the right values without backfill.
 *
 * SQLite reminder: column types in ALTER TABLE clauses are loose hints —
 * Room enforces actual type matching at runtime via affinity. INTEGER for
 * Boolean (Kotlin's Long-backed) and Long, TEXT for nullable enum-name +
 * armored string.
 */
val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN isRevoked INTEGER NOT NULL DEFAULT 0")
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN revokedAt INTEGER")
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN revocationReason TEXT")
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN revocationCertificate TEXT")
    }
}

/**
 * HW Phase 0/1 — add hardware-key (OpenPGP card) backing columns.
 *
 * Same shape as MIGRATION_1_2: every new column is either nullable or
 * has a safe NOT NULL DEFAULT, so existing rows pick up correct values
 * without backfill. Column types match exactly what Room generates from
 * the entity — INTEGER NOT NULL DEFAULT 0 for the Boolean, TEXT (nullable)
 * for the serial/AID/manufacturer/fingerprint strings — so Room's
 * startup schema verification passes under exportSchema = false.
 */
val MIGRATION_2_3 = object : Migration(2, 3) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN isCardBacked INTEGER NOT NULL DEFAULT 0")
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN cardSerial TEXT")
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN cardAid TEXT")
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN cardManufacturer TEXT")
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN cardSigFingerprint TEXT")
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN cardDecFingerprint TEXT")
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN cardAuthFingerprint TEXT")
    }
}

/**
 * Phase AU-1 — add the decrypt usage counter that drives the "Decrypt With"
 * picker's most-used default.
 *
 * Same non-destructive shape as the earlier migrations: a single new column
 * with a safe NOT NULL DEFAULT, so existing rows pick up 0 without backfill
 * and Room's startup schema verification passes under exportSchema = false.
 * INTEGER affinity matches the entity's Kotlin Int.
 */
val MIGRATION_3_4 = object : Migration(3, 4) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN decryptUseCount INTEGER NOT NULL DEFAULT 0")
    }
}

/**
 * Phase 3.0.0-KS1 — add keyserver activity timestamps (Lukas request).
 *
 * Same non-destructive shape as the earlier migrations: two new nullable
 * columns, so existing rows pick up NULL ("Never" in the UI) without backfill
 * and Room's startup schema verification passes under exportSchema = false.
 * INTEGER affinity matches the entity's nullable Kotlin Long.
 */
val MIGRATION_4_5 = object : Migration(4, 5) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN lastUploadedAt INTEGER")
        db.execSQL("ALTER TABLE pgp_keys ADD COLUMN lastCheckedAt INTEGER")
    }
}

/**
 * 4.0.0 Succession Phase 1 — create the OpenPGP API provider's client
 * allow-list table. A brand-new table (no ALTER of pgp_keys), so the
 * migration cannot disturb existing rows. Column order, NOT NULL
 * constraints, and the TEXT primary key mirror exactly what Room
 * generates from ApiClientEntity, so the runtime schema verification
 * under exportSchema = false passes.
 */
val MIGRATION_5_6 = object : Migration(5, 6) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS `allowed_api_clients` (
                `packageName` TEXT NOT NULL,
                `signatureSha256` TEXT NOT NULL,
                `grantedAt` INTEGER NOT NULL,
                PRIMARY KEY(`packageName`)
            )
            """.trimIndent()
        )
    }
}

// 4.0.0 Phase 4 (Autocrypt) — the autocrypt_peers table.
val MIGRATION_6_7 = object : Migration(6, 7) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS `autocrypt_peers` (
                `identifier` TEXT NOT NULL,
                `lastSeen` INTEGER NOT NULL,
                `autocryptTimestamp` INTEGER NOT NULL,
                `autocryptKeyFingerprint` TEXT,
                `isMutual` INTEGER NOT NULL,
                `gossipTimestamp` INTEGER NOT NULL,
                `gossipKeyFingerprint` TEXT,
                PRIMARY KEY(`identifier`)
            )
            """.trimIndent()
        )
    }
}

// RC3 §N (#34) — per-key decryption fallbacks + backwards-compatible
// signing defaults. Both tables mirror their entities exactly
// (exportSchema=false → runtime schema verification, same as 6_7).
val MIGRATION_7_8 = object : Migration(7, 8) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS `fallback_keys` (
                `primaryFingerprint` TEXT NOT NULL,
                `fallbackFingerprint` TEXT NOT NULL,
                `position` INTEGER NOT NULL,
                PRIMARY KEY(`primaryFingerprint`, `fallbackFingerprint`)
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS `signing_defaults` (
                `fingerprint` TEXT NOT NULL,
                `pqcSignerFingerprint` TEXT,
                `classicalSignerFingerprint` TEXT,
                `signOnlySignerFingerprint` TEXT,
                PRIMARY KEY(`fingerprint`)
            )
            """.trimIndent()
        )
    }
}

// §5.6.1 (#36 part 1) recycle bin + §4.3 last-backed-up: two nullable
// columns on pgp_keys. Same additive shape as the earlier migrations.
val MIGRATION_8_9 = object : Migration(8, 9) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE `pgp_keys` ADD COLUMN `deletedAt` INTEGER")
        db.execSQL("ALTER TABLE `pgp_keys` ADD COLUMN `lastBackedUpAt` INTEGER")
    }
}

// 4.6.0 (item 17.4): Autocrypt-origin marker on pgp_keys. One nullable
// column, same additive shape as 8_9. Existing public-only rows that an
// Autocrypt peer record points at are marked as Autocrypt-origin, so a key
// planted through Autocrypt before this release does not keep counting as
// user-managed. Key pairs and card-backed keys (the user's own) are never marked; everything
// else reads as user-managed, and importing a key again clears the mark.
/** 4.6.0 (item 11): lastLocalEditAt, null for every existing row (no edit
 *  is known to be unpublished until the next one). */
val MIGRATION_10_11 = object : Migration(10, 11) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE `pgp_keys` ADD COLUMN `lastLocalEditAt` INTEGER")
    }
}

val MIGRATION_9_10 = object : Migration(9, 10) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE `pgp_keys` ADD COLUMN `autocryptImportedAt` INTEGER")
        db.execSQL(
            """
            UPDATE `pgp_keys` SET `autocryptImportedAt` = ${System.currentTimeMillis()}
            WHERE `isKeyPair` = 0 AND `isCardBacked` = 0 AND (
                lower(`fingerprint`) IN (SELECT lower(`autocryptKeyFingerprint`) FROM `autocrypt_peers`
                                         WHERE `autocryptKeyFingerprint` IS NOT NULL)
                OR lower(`fingerprint`) IN (SELECT lower(`gossipKeyFingerprint`) FROM `autocrypt_peers`
                                            WHERE `gossipKeyFingerprint` IS NOT NULL)
            )
            """.trimIndent()
        )
    }
}
