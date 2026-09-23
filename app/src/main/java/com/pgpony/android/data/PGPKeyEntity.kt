// PGPKeyEntity.kt
// PGPony Android
//
// Room entity — Android equivalent of iOS PGPKeyModel (@Model).
// Stores key metadata in SQLite. Actual key material is stored
// in Android Keystore via SecureKeyStore.
//
// Phase A6: schema bumped from v1 to v2. New columns:
//   • isRevoked, revokedAt, revocationReason, revocationCertificate
// Migration v1→v2 declared in data/RoomMigrations.kt; wired into the
// DB builder in PGPonyApp.kt.

package com.pgpony.android.data

import androidx.room.*
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
    // ── Phase 3.0.0-KS1: Keyserver activity timestamps (lukascomer request) ──
    //
    // Two epoch-millis stamps surfaced on the key detail screen under the
    // key-server section. Nullable so existing rows migrate cleanly with no
    // backfill; the UI shows "Never" until a value is set.
    /** When this key was last uploaded to a keyserver. Set by
     *  KeyRepository.markKeyServerUploaded. */
    val lastUploadedAt: Long? = null,
    /** When this key was last checked/refreshed against a keyserver. Set by
     *  KeyRepository.markKeyServerChecked. */
    val lastCheckedAt: Long? = null,
    /** §5.6.1 (#36 part 1) recycle bin: when non-null, this key is soft-
     *  deleted (epoch ms of the delete). Live queries exclude these; the
     *  Recently Deleted view lists them; purge destroys them after the
     *  retention window. */
    val deletedAt: Long? = null,
    /** §4.3 delete-safeguard: when this key was last backed up / exported
     *  (epoch ms), so the delete sheet can say "in a backup from ..." versus
     *  "never backed up". Null = never. */
    val lastBackedUpAt: Long? = null,
    /** 4.6.0 (item 17.4): when non-null, this row was created by an Autocrypt
     *  header or gossip (OpenPGP API or PGPony's own mail ingest), not by the
     *  user. Such a key never joins a user-managed key for the same address as
     *  an extra provider recipient. Cleared when the user imports the key
     *  themselves. */
    val autocryptImportedAt: Long? = null,
    /** 4.6.0 (item 11): when this key was last changed here (User IDs,
     *  subkeys, expiry, notations, revocation). Newer than [lastUploadedAt] on
     *  a published key means the server copy is behind. */
    val lastLocalEditAt: Long? = null
) {
    /** 4.6.0 (item 1): the note's first non-blank line, shown as the key's
     *  label on the keyring list and under the Key Detail header. */
    val noteLabel: String?
        get() = notes?.lineSequence()?.map { it.trim() }?.firstOrNull { it.isNotEmpty() }

    /** 4.6.0 (item 20): what "the same identity" means when counting keys that
     *  share one: the email, else the whole User ID, case-insensitive. */
    val identityKey: String
        get() = (userEmail.ifBlank { userID }).trim().lowercase()

    /** 4.6.0 (item 11): published before, edited here since the last upload. */
    val hasUnpublishedChanges: Boolean
        get() {
            val edited = lastLocalEditAt ?: return false
            if (!keyServerUploaded) return false
            val uploaded = lastUploadedAt ?: return true
            return edited > uploaded
        }

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
            val bracketOnly = Regex("""^<(.+?)>$""").find(uid)
            if (bracketOnly != null) return Pair("", bracketOnly.groupValues[1].trim())
            if (uid.contains("@")) return Pair("", uid.trim())
            return Pair(uid.trim(), "")
        }

        /**
         * item 3 (#request): assemble a User ID from an optional name and
         * email. The inverse of parseUserID: "Name <email>" when both are
         * present, just the name when the email is blank, "<email>" when only
         * an email is given, and "" when neither is supplied (a UID-less v6
         * certificate). Callers that hardcoded "$name <$email>" route here so
         * a blank email no longer emits empty angle brackets.
         */
        fun composeUserID(name: String, email: String): String {
            val n = name.trim()
            val e = email.trim()
            return when {
                n.isNotEmpty() && e.isNotEmpty() -> "$n <$e>"
                n.isNotEmpty() -> n
                e.isNotEmpty() -> "<$e>"
                else -> ""
            }
        }
    }
}

// ── DAO ────────────────────────────────────────────────────────────────

@Dao
interface PGPKeyDao {
    @Query("SELECT * FROM pgp_keys WHERE deletedAt IS NULL ORDER BY createdAt DESC")
    suspend fun getAllKeys(): List<PGPKeyEntity>

    @Query("SELECT * FROM pgp_keys WHERE isKeyPair = 1 AND deletedAt IS NULL ORDER BY createdAt DESC")
    suspend fun getKeyPairs(): List<PGPKeyEntity>

    @Query("SELECT * FROM pgp_keys WHERE fingerprint = :fingerprint AND deletedAt IS NULL LIMIT 1")
    suspend fun getByFingerprint(fingerprint: String): PGPKeyEntity?

    @Query("SELECT * FROM pgp_keys WHERE id = :id AND deletedAt IS NULL LIMIT 1")
    suspend fun getById(id: String): PGPKeyEntity?

    @Query("SELECT * FROM pgp_keys WHERE userEmail = :email AND deletedAt IS NULL")
    suspend fun getByEmail(email: String): List<PGPKeyEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(key: PGPKeyEntity)

    @Update
    suspend fun update(key: PGPKeyEntity)

    @Delete
    suspend fun delete(key: PGPKeyEntity)

    @Query("DELETE FROM pgp_keys WHERE id = :id")
    suspend fun deleteById(id: String)

    @Query("SELECT COUNT(*) FROM pgp_keys WHERE deletedAt IS NULL")
    suspend fun count(): Int

    @Query("SELECT * FROM pgp_keys WHERE isDefault = 1 AND deletedAt IS NULL LIMIT 1")
    suspend fun getDefaultKey(): PGPKeyEntity?

    /**
     * Phase AU-1 — bump the decrypt usage counter for the key with this
     * fingerprint. Used to drive the "Decrypt With" picker's most-used
     * default. A no-op if no row matches (e.g. a card key that isn't paired
     * as a row), so callers don't need to pre-check existence.
     */
    @Query("UPDATE pgp_keys SET decryptUseCount = decryptUseCount + 1 WHERE fingerprint = :fingerprint")
    suspend fun incrementDecryptUseCount(fingerprint: String)

    // ── §5.6.1 (#36 part 1) recycle bin ──
    @Query("SELECT * FROM pgp_keys WHERE deletedAt IS NOT NULL ORDER BY deletedAt DESC")
    suspend fun getDeletedKeys(): List<PGPKeyEntity>

    @Query("SELECT * FROM pgp_keys WHERE id = :id AND deletedAt IS NOT NULL LIMIT 1")
    suspend fun getDeletedById(id: String): PGPKeyEntity?

    @Query("SELECT COUNT(*) FROM pgp_keys WHERE deletedAt IS NOT NULL")
    suspend fun deletedCount(): Int

    @Query("UPDATE pgp_keys SET deletedAt = :deletedAt, isDefault = 0 WHERE id = :id")
    suspend fun softDelete(id: String, deletedAt: Long)

    @Query("UPDATE pgp_keys SET deletedAt = NULL WHERE id = :id")
    suspend fun restoreFromBin(id: String)

    @Query("DELETE FROM pgp_keys WHERE id = :id AND deletedAt IS NOT NULL")
    suspend fun purgeById(id: String)

    // ── §4.3 last-backed-up ──
    @Query("UPDATE pgp_keys SET lastBackedUpAt = :ts WHERE fingerprint = :fingerprint")
    suspend fun setLastBackedUp(fingerprint: String, ts: Long)
}

// ── Database ──────────────────────────────────────────────────────────

// 4.0.0 Succession Phase 1: schema v5 → v6 adds the allowed_api_clients
// table (ApiClientEntity in data/ApiClientEntity.kt) backing the OpenPGP
// API provider's per-package, signature-pinned client allow-list.
// MIGRATION_5_6 declared in data/RoomMigrations.kt with the others.
// RC3 §N (#34) — schema v8 adds fallback_keys + signing_defaults
// (FallbackKeyEntity.kt), MIGRATION_7_8 in data/RoomMigrations.kt.
@Database(
    entities = [
        PGPKeyEntity::class, ApiClientEntity::class, AutocryptPeerEntity::class,
        FallbackKeyEntity::class, SigningDefaultsEntity::class
    ],
    version = 11,
    exportSchema = false
)
@TypeConverters(
    TrustLevelConverter::class,
    KeyAlgorithmConverter::class,
    RevocationReasonConverter::class
)
abstract class PGPDatabase : RoomDatabase() {
    abstract fun keyDao(): PGPKeyDao
    abstract fun apiClientDao(): ApiClientDao
    abstract fun autocryptPeerDao(): AutocryptPeerDao
    abstract fun fallbackKeyDao(): FallbackKeyDao
    abstract fun signingDefaultsDao(): SigningDefaultsDao
}
