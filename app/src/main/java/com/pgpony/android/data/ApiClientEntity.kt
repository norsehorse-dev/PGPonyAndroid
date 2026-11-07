// ApiClientEntity.kt
// PGPony Android — 4.0.0 Succession Phase 1 (OpenPGP API provider)
//
// Per-package allow-list for OpenPGP API client apps (Thunderbird for
// Android, K-9 Mail, Password Store, Conversations, …). Mirrors
// OpenKeychain's authorization model, which client apps assume: a
// client is identified by its package name AND the SHA-256 of its
// signing certificate. The signature pin is what makes the allow-list
// meaningful — a sideloaded impostor with a stolen package name gets
// SIGNATURE_MISMATCH, not access.
//
// Rows are written exclusively by the first-use consent flow
// (ApiConsentActivity → ApiClientAuthorizer.grant) and deleted from
// the Settings → Connected apps screen. There is no default-allow
// path anywhere (see §5 of the 4.0.0 plan: "Signature-pinned client
// authorization, no default-allow, and a revocation UI are
// non-negotiable").

package com.pgpony.android.data

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import com.pgpony.android.data.ssh.SshKeyStore

// ── Entity ─────────────────────────────────────────────────────────────

@Entity(tableName = "allowed_api_clients")
data class ApiClientEntity(
    /** The client app's package name, e.g. "net.thunderbird.android". */
    @PrimaryKey
    val packageName: String,

    /**
     * Lowercase hex SHA-256 of the client's signing certificate
     * (first signer, `GET_SIGNING_CERTIFICATES`). Checked on every
     * provider call; a mismatch is treated as a different app.
     */
    val signatureSha256: String,

    /** When the user granted access (epoch ms). Shown in Settings. */
    val grantedAt: Long,

    /**
     * 4.6.0: which provider services this app may use, a bitmask of
     * [SCOPE_OPENPGP] and [SCOPE_SSH]. Each is its own consent: an app
     * connected for SSH cannot encrypt, decrypt or sign messages, and a mail
     * client connected for OpenPGP cannot get SSH signatures. Rows from
     * before 4.6.0 are OpenPGP only (MIGRATION_11_12).
     */
    @ColumnInfo(defaultValue = "1")
    val scopes: Int = SCOPE_OPENPGP,

    /**
     * 4.6.0: the primary fingerprint (hex) of the key the user picked for this
     * app's SSH logins. SSH requests for any other key are refused. Cleared
     * with the SSH scope.
     *
     * 4.6.3 (#68): every key the user has approved for this app's SSH logins,
     * as uppercase hex fingerprints joined by [SSH_KEY_SEPARATOR]. A 4.6.0 to
     * 4.6.2 row holds one fingerprint, which reads as a set of one, so no
     * migration is needed. Read it through [sshKeyFingerprints].
     *
     * 4.8.0 RC7 (item 1): an SSH-only key is stored by its own id
     * ("ssh:SHA256:..." in base64, where case matters), as it is.
     */
    val sshKeyFingerprint: String? = null
) {
    fun has(scope: Int): Boolean = scopes and scope == scope

    /** 4.6.3 (#68): the approved SSH keys, in the order approved (see [normalizeSshKey]). */
    fun sshKeyFingerprints(): List<String> = parseSshKeys(sshKeyFingerprint)

    companion object {
        const val SCOPE_OPENPGP = 1
        const val SCOPE_SSH = 2

        /** Fingerprints are hex, so a comma never occurs inside one. 4.8.0
         *  RC7 (item 1): nor in an SSH-only key id (base64, ':' and "ssh"). */
        const val SSH_KEY_SEPARATOR = ","

        /**
         * 4.8.0 RC7 (item 1): one approved key as it is stored and compared.
         * An OpenPGP fingerprint is hex, so it is uppercased as before; an
         * SSH-only key id carries a base64 fingerprint, where uppercasing
         * would name another key, so it is kept as it is.
         */
        fun normalizeSshKey(key: String): String {
            val t = key.trim()
            return if (SshKeyStore.isSshKeyId(t)) t else t.uppercase()
        }

        /** 4.8.0 RC7 (item 1): true when [a] and [b] name the same approved key. */
        fun sameSshKey(a: String, b: String): Boolean = normalizeSshKey(a) == normalizeSshKey(b)

        fun parseSshKeys(stored: String?): List<String> =
            stored.orEmpty().split(SSH_KEY_SEPARATOR)
                .map { normalizeSshKey(it) }
                .filter { it.isNotEmpty() }
                .distinct()

        /** The column value for [keys], or null when there are none. */
        fun joinSshKeys(keys: List<String>): String? =
            keys.map { normalizeSshKey(it) }
                .filter { it.isNotEmpty() }
                .distinct()
                .takeIf { it.isNotEmpty() }
                ?.joinToString(SSH_KEY_SEPARATOR)
    }
}

// ── DAO ────────────────────────────────────────────────────────────────

@Dao
interface ApiClientDao {
    @Query("SELECT * FROM allowed_api_clients ORDER BY grantedAt DESC")
    suspend fun getAll(): List<ApiClientEntity>

    @Query("SELECT * FROM allowed_api_clients WHERE packageName = :packageName LIMIT 1")
    suspend fun getByPackage(packageName: String): ApiClientEntity?

    /**
     * REPLACE so re-consent after an app re-install (new signing key —
     * rare but real for debug↔release switches) simply overwrites the
     * stale pin once the user has explicitly re-approved.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(client: ApiClientEntity)

    @Query("DELETE FROM allowed_api_clients WHERE packageName = :packageName")
    suspend fun deleteByPackage(packageName: String)

    /** 4.6.0: set the scope bits and the SSH key binding of an existing row. */
    @Query(
        "UPDATE allowed_api_clients SET scopes = :scopes, sshKeyFingerprint = :sshKeyFingerprint " +
            "WHERE packageName = :packageName"
    )
    suspend fun updateAccess(packageName: String, scopes: Int, sshKeyFingerprint: String?)

    @Query("SELECT COUNT(*) FROM allowed_api_clients")
    suspend fun count(): Int
}
