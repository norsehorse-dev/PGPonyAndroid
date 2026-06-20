// PGPKeyEntity.kt
// PGPony Android
//
// Room entity — Android equivalent of iOS PGPKeyModel (@Model).
// Stores key metadata in SQLite. Actual key material is stored
// in Android Keystore via SecureKeyStore.
//
// Phase A6: schema bumped from v1 to v2. New columns:
//   • isRevoked, revokedAt, revocationReason, revocationCertificate
// Migration v1→v2 declared at the bottom of this file; wired into the
// DB builder in PGPonyApp.kt.

package com.pgpony.android.data

import androidx.room.*
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.pgpony.android.crypto.KeyAlgorithm

// ── Trust Level ────────────────────────────────────────────────────────

enum class TrustLevel(val displayName: String, val colorName: String) {
    UNKNOWN("Unknown", "gray"),
    UNVERIFIED("Unverified", "yellow"),
    VERIFIED("Verified", "green"),
    ULTIMATE("Ultimate", "blue");

    // ── A15 preflight fix ──────────────────────────────────────────────
    //
    // KeyCard / KeyDetail / contacts UI calls trust.localizedName() in
    // places where they need the user-facing trust label. A13 string
    // extraction added the four R.string.trust_level_* entries but
    // never added the helper method on the enum, so every call site
    // failed to resolve. Add it here so existing call sites compile
    // and pick up the localized strings already defined in strings.xml.
    //
    // We resolve via PGPonyApp.instance.getString rather than taking a
    // Composable LocalContext so non-Composable code paths (e.g.
    // ViewModel formatters, snackbar messages) can use this too.
    fun localizedName(): String {
        val app = com.pgpony.android.PGPonyApp.instance
        return when (this) {
            UNKNOWN -> app.getString(com.pgpony.android.R.string.trust_level_unknown_name)
            UNVERIFIED -> app.getString(com.pgpony.android.R.string.trust_level_unverified_name)
            VERIFIED -> app.getString(com.pgpony.android.R.string.trust_level_verified_name)
            ULTIMATE -> app.getString(com.pgpony.android.R.string.trust_level_ultimate_name)
        }
    }

    fun localizedDescription(): String {
        val app = com.pgpony.android.PGPonyApp.instance
        return when (this) {
            UNKNOWN -> app.getString(com.pgpony.android.R.string.trust_level_unknown_description)
            UNVERIFIED -> app.getString(com.pgpony.android.R.string.trust_level_unverified_description)
            VERIFIED -> app.getString(com.pgpony.android.R.string.trust_level_verified_description)
            ULTIMATE -> app.getString(com.pgpony.android.R.string.trust_level_ultimate_description)
        }
    }
}

class TrustLevelConverter {
    @TypeConverter fun fromTrustLevel(value: TrustLevel): String = value.name
    @TypeConverter fun toTrustLevel(value: String): TrustLevel = TrustLevel.valueOf(value)
}

class KeyAlgorithmConverter {
    @TypeConverter fun fromAlgorithm(value: KeyAlgorithm): String = value.name
    @TypeConverter fun toAlgorithm(value: String): KeyAlgorithm = KeyAlgorithm.valueOf(value)
}

// ── Revocation Reason (Phase A6) ───────────────────────────────────────

/**
 * RFC 4880 §5.2.3.23 — Reason for Revocation subpacket values.
 *
 * Mirrors iOS RevocationReason (PGPKeyModel.swift). The integer
 * `rfcCode` is what gets packed into the revocation signature's
 * subpacket; the enum-name string is what gets stored in the Room
 * column via RevocationReasonConverter so we can change `rfcCode`
 * mapping later without DB migration churn.
 */
enum class RevocationReason(val rfcCode: Int, val displayName: String, val description: String) {
    NO_REASON(0, "No reason specified",
        "Don't share why — the certificate just declares the key revoked"),
    SUPERSEDED(1, "Superseded by new key",
        "You've moved to a different key; the old one is still trustworthy"),
    COMPROMISED(2, "Key compromised",
        "The private key may have been exposed — DO NOT trust anything signed after this date"),
    RETIRED(3, "Key retired",
        "The key is no longer used but the private key isn't compromised"),
    USER_ID_INVALID(32, "User ID no longer valid",
        "The email / name associated with the key has changed")
}

class RevocationReasonConverter {
    @TypeConverter
    fun fromRevocationReason(value: RevocationReason?): String? = value?.name

    @TypeConverter
    fun toRevocationReason(value: String?): RevocationReason? =
        value?.let { runCatching { RevocationReason.valueOf(it) }.getOrNull() }
}

// ── Entity ─────────────────────────────────────────────────────────────

@Entity(tableName = "pgp_keys")
@TypeConverters(
    TrustLevelConverter::class,
    KeyAlgorithmConverter::class,
    RevocationReasonConverter::class
)
data class PGPKeyEntity(
    @PrimaryKey
    val id: String,                    // UUID string

    val fingerprint: String,           // Hex fingerprint (40 chars for v4, 64 for v6)
    val userID: String,                // "Name <email@example.com>"
    val userName: String,              // Parsed name
    val userEmail: String,             // Parsed email
    val algorithm: KeyAlgorithm,       // RSA_2048, RSA_4096, ED25519_CV25519, etc.
    val isKeyPair: Boolean,            // Has private key?
    val trustLevel: TrustLevel = TrustLevel.UNKNOWN,
    val createdAt: Long,               // Epoch milliseconds
    val expiresAt: Long? = null,       // Epoch milliseconds or null
    val contactId: String? = null,     // Android contact URI
    val contactPhotoUri: String? = null,
    val contactName: String? = null,   // Cached contact display name
    val isSynced: Boolean = false,     // Google Drive backup synced
    val isDefault: Boolean = false,
    val notes: String? = null,
    val armoredPublicKey: String? = null, // Cached for QR/sharing
    val keyServerUploaded: Boolean = false,
    // ── Phase A6: Revocation ──
    /** Whether the user has applied a revocation certificate to this key.
     *  Revoked keys can still decrypt past messages (the secret is intact)
     *  but should not be used to sign new messages or be chosen as a new
     *  recipient — the encrypt-side ViewModels filter them out of
     *  `availableRecipients` and `availableSigningKeys`. */
    val isRevoked: Boolean = false,
    /** When the revocation was applied (epoch ms). Drives the "Revoked on
     *  {date}" line of the Revoked banner. */
    val revokedAt: Long? = null,
    /** RFC 4880 §5.2.3.23 reason the user chose. Null if revocation
     *  hasn't been applied yet OR if the pre-cached cert at key creation
     *  uses the default NO_REASON. */
    val revocationReason: RevocationReason? = null,
    /** Armored revocation certificate text. Two roles:
     *
     *  (a) **Pre-cached** — Phase A6 generates one of these at key
     *      creation time with reason=NO_REASON. Stored here so the user
     *      has it even if they later lose access to their passphrase
     *      (and so the post-revocation Export-cert flow has something
     *      to share without recomputing). isRevoked stays false in
     *      this state.
     *
     *  (b) **Applied** — when the user revokes through KeyDetailScreen,
     *      a fresh cert with the chosen reason is generated, applied
     *      to the public ring, and stored here, overwriting (a).
     *      isRevoked = true at this point. */
    val revocationCertificate: String? = null,
    // ── HW Phase 0/1: Hardware-key (OpenPGP card) backing ──────────────
    //
    // A card-backed key's private material lives on a physical OpenPGP
    // smart card (YubiKey 5 / Token2 PIN+ / Nitrokey 3) and is never
    // present in SecureKeyStore. These columns capture which card the
    // key belongs to and the fingerprints the card reports for each of
    // its three slots, so a later phase can match "is THIS the card for
    // THIS key" and route sign/decrypt to the card.
    //
    // Phase 1 imports a card as a read-only record (isKeyPair stays
    // false — no on-card crypto is wired yet). isCardBacked is the flag
    // the future routing branch keys off of. All columns default so the
    // v2→v3 migration is a clean, non-destructive ALTER TABLE.
    val isCardBacked: Boolean = false,
    /** 4-byte card serial as hex (from the AID), uppercased. */
    val cardSerial: String? = null,
    /** Full 16-byte Application Identifier as hex. */
    val cardAid: String? = null,
    /** Friendly manufacturer name parsed from the AID (e.g. "Yubico"). */
    val cardManufacturer: String? = null,
    /** SHA-1 (v4) fingerprint the card reports for its signature slot. */
    val cardSigFingerprint: String? = null,
    /** Fingerprint the card reports for its decryption slot. */
    val cardDecFingerprint: String? = null,
    /** Fingerprint the card reports for its authentication slot. */
    val cardAuthFingerprint: String? = null,
    // ── Phase AU-1: Decrypt picker usage ───────────────────────────────
    //
    // How many times this key has successfully decrypted a message. Drives
    // the Decrypt tab's "Decrypt With" picker default: with no message
    // loaded, the most-used key (card-backed first, then this count) is
    // pre-selected. Incremented on every successful decrypt — software or
    // card — via KeyRepository.incrementDecryptUseCount. Starts at 0, so
    // until there's history the default falls back to isDefault then name.
    val decryptUseCount: Int = 0,
    // ── Phase 3.0.0-KS1: Keyserver activity timestamps (Lukas request) ──
    //
    // Two epoch-millis stamps surfaced on the key detail screen under the
    // key-server section. Nullable so existing rows migrate cleanly with no
    // backfill; the UI shows "Never" until a value is set.
    /** When this key was last uploaded to a keyserver. Set by
     *  KeyRepository.markKeyServerUploaded. */
    val lastUploadedAt: Long? = null,
    /** When this key was last checked/refreshed against a keyserver. Set by
     *  KeyRepository.markKeyServerChecked. */
    val lastCheckedAt: Long? = null
) {
    // ── Computed Properties ─────────────────────────────────────────

    /**
     * Whether this is an RFC 9580 v6 key. v6 derives the key ID from the
     * LEADING bytes of the fingerprint (v4 uses the trailing bytes), so the
     * key-ID display properties below branch on this. See V6Fingerprint.
     */
    val isV6Key: Boolean
        get() = algorithm.isV6

    /**
     * The 8-byte (16 hex char) long key ID, version-aware:
     *   • v6 (RFC 9580): the LEADING 16 hex chars of the fingerprint.
     *   • v4 (RFC 4880): the TRAILING 16 hex chars.
     * Use this anywhere a key ID is shown or matched — never slice the
     * fingerprint directly, or v6 keys pick up the wrong end.
     */
    val longKeyId: String
        get() = (if (isV6Key) fingerprint.take(16) else fingerprint.takeLast(16)).uppercase()

    /**
     * Compact 8 hex char (4-byte) short key ID for tight UI rows. Same
     * version-aware end-selection as longKeyId; v4 behavior (takeLast)
     * is unchanged from before V6-1.
     */
    val shortFingerprint: String
        get() = (if (isV6Key) fingerprint.take(8) else fingerprint.takeLast(8)).uppercase()

    val formattedFingerprint: String
        get() = fingerprint.uppercase().chunked(4).joinToString(" ")

    val isExpired: Boolean
        get() = expiresAt?.let { it < System.currentTimeMillis() } ?: false

    val initials: String
        get() {
            val parts = userName.split(" ")
            return if (parts.size >= 2) {
                "${parts[0].take(1)}${parts[1].take(1)}".uppercase()
            } else {
                userName.take(2).uppercase()
            }
        }

    companion object {
        /**
         * Parse "Name <email@example.com>" into (name, email).
         * Matches iOS PGPKeyModel.parseUserID.
         */
        fun parseUserID(uid: String): Pair<String, String> {
            val regex = Regex("""^(.+?)\s*<(.+?)>$""")
            val match = regex.find(uid)
            if (match != null) {
                return Pair(
                    match.groupValues[1].trim(),
                    match.groupValues[2].trim()
                )
            }
            if (uid.contains("@")) return Pair("", uid.trim())
            return Pair(uid.trim(), "")
        }
    }
}

// ── DAO ────────────────────────────────────────────────────────────────

@Dao
interface PGPKeyDao {
    @Query("SELECT * FROM pgp_keys ORDER BY createdAt DESC")
    suspend fun getAllKeys(): List<PGPKeyEntity>

    @Query("SELECT * FROM pgp_keys WHERE isKeyPair = 1 ORDER BY createdAt DESC")
    suspend fun getKeyPairs(): List<PGPKeyEntity>

    @Query("SELECT * FROM pgp_keys WHERE fingerprint = :fingerprint LIMIT 1")
    suspend fun getByFingerprint(fingerprint: String): PGPKeyEntity?

    @Query("SELECT * FROM pgp_keys WHERE id = :id LIMIT 1")
    suspend fun getById(id: String): PGPKeyEntity?

    @Query("SELECT * FROM pgp_keys WHERE userEmail = :email")
    suspend fun getByEmail(email: String): List<PGPKeyEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(key: PGPKeyEntity)

    @Update
    suspend fun update(key: PGPKeyEntity)

    @Delete
    suspend fun delete(key: PGPKeyEntity)

    @Query("DELETE FROM pgp_keys WHERE id = :id")
    suspend fun deleteById(id: String)

    @Query("SELECT COUNT(*) FROM pgp_keys")
    suspend fun count(): Int

    @Query("SELECT * FROM pgp_keys WHERE isDefault = 1 LIMIT 1")
    suspend fun getDefaultKey(): PGPKeyEntity?

    /**
     * Phase AU-1 — bump the decrypt usage counter for the key with this
     * fingerprint. Used to drive the "Decrypt With" picker's most-used
     * default. A no-op if no row matches (e.g. a card key that isn't paired
     * as a row), so callers don't need to pre-check existence.
     */
    @Query("UPDATE pgp_keys SET decryptUseCount = decryptUseCount + 1 WHERE fingerprint = :fingerprint")
    suspend fun incrementDecryptUseCount(fingerprint: String)
}

// ── Database ──────────────────────────────────────────────────────────

@Database(entities = [PGPKeyEntity::class], version = 5, exportSchema = false)
@TypeConverters(
    TrustLevelConverter::class,
    KeyAlgorithmConverter::class,
    RevocationReasonConverter::class
)
abstract class PGPDatabase : RoomDatabase() {
    abstract fun keyDao(): PGPKeyDao
}

// ── Migrations ─────────────────────────────────────────────────────────

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
