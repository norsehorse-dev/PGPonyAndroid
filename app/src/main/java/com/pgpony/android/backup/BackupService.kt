// BackupService.kt
// PGPony Android — 4.0.0 Phase 3 (encrypted keyring backup)
//
// Export/restore the whole keyring as one passphrase-encrypted file that
// cross-restores with iOS PGPony 8.0.0 and standard OpenPGP tools. See
// BACKUP_FORMAT_4_0_0.md for the byte-level spec (reverse-engineered from
// a real iOS backup and validated against GNU tar + Python tarfile).
//
// Container: uncompressed ustar TAR — pgpony-meta.json first, then
// keys/<fingerprint>.asc per key, then an additive pgpony-settings.json
// (Android-only; iOS ignores unknown entries) — symmetric-sealed with
// AES-256 / SEIPDv1 (gpg -c style, no Argon2) and ASCII-armored with a
// `Comment: PGPony Backup v1` header.
//
// Restore is a MERGE: each key runs through the existing
// KeyRepository.importArmoredKeyDetailed, so a held secret is never
// overwritten and a public-only key is upgraded in place. Hardware/card
// keys export public-only (their secret can't leave the device) and so
// restore only their public half.

package com.pgpony.android.backup

import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.TrustLevel
import com.pgpony.android.data.repository.ImportResolution
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.keyserver.KeyServer
import com.pgpony.android.keyserver.KeyServerDirectory
import com.pgpony.android.network.HttpClientFactory
import com.pgpony.android.network.ProxyPrefs
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** A per-key line in the restore merge report. */
data class RestoredKey(val fingerprint: String, val label: String)

/** Plain-language outcome of a restore (mirrors iOS's merge report). */
data class MergeReport(
    val added: List<RestoredKey>,
    val upgraded: List<RestoredKey>,      // public-only → full key pair
    val updated: List<RestoredKey>,       // merged newer material / card pairing
    val unchanged: List<RestoredKey>,     // already up to date
    val failed: List<RestoredKey>,        // couldn't restore (parse/import error)
    val settingsApplied: Boolean,
    /** 4.6.0 (item 17.9): the backup's settings (proxy, key servers), NOT yet
     *  applied. The UI asks first and calls BackupService.applyBackupSettings
     *  only when the user agrees. */
    val pendingSettings: String? = null
) {
    val totalRestored: Int get() = added.size + upgraded.size + updated.size
}

/** Which app's backup a file is — drives code format + payload parsing. */
enum class BackupKind { PGPONY, OPENKEYCHAIN, UNKNOWN }

sealed class BackupError(message: String) : Exception(message) {
    /** File isn't an OpenPGP message / not a PGPony backup. */
    object NotABackup : BackupError("This file isn't a PGPony backup")
    /** Recovery code didn't decrypt the file. */
    object WrongCode : BackupError("That recovery code didn't unlock the backup")
    /** Decrypted but the archive is malformed. */
    class Corrupt(msg: String) : BackupError("The backup is damaged: $msg")
    /** Nothing to back up. */
    object EmptyKeyring : BackupError("There are no keys to back up")
}

class BackupService(
    private val repo: KeyRepository,
    private val crypto: PGPCryptoService = PGPCryptoService.shared
) {

    companion object {
        const val ARMOR_COMMENT = "PGPony Backup v1"
        const val FORMAT_VERSION = 1
        const val FILE_EXTENSION = "pgpony"

        private const val META_NAME = "pgpony-meta.json"
        private const val SETTINGS_NAME = "pgpony-settings.json"
        private const val KEYS_DIR = "keys/"
    }

    // ── Export ───────────────────────────────────────────────────────

    /**
     * Build an encrypted backup of the whole keyring, sealed with
     * [recoveryCanonical] (the normalized recovery-code string from
     * [CrockfordBase32]). Returns the armored `.pgpony` bytes.
     */
    suspend fun exportBackup(recoveryCanonical: String): ByteArray {
        val keys = repo.getAllKeys()
        if (keys.isEmpty()) throw BackupError.EmptyKeyring

        val entries = ArrayList<UstarArchive.Entry>()
        val metaKeys = JSONArray()
        // §4.3: fingerprints whose secret material this backup captured.
        val backedUpFps = ArrayList<String>()

        for (e in keys) {
            val fp = e.fingerprint.lowercase()
            // Card/hardware keys have no exportable secret → public-only.
            val wantSecret = e.isKeyPair && !e.isCardBacked
            val armored: String = (if (wantSecret) {
                repo.exportArmoredPrivateKey(fp) ?: repo.exportArmoredPublicKey(fp)
            } else {
                repo.exportArmoredPublicKey(fp)
            }) ?: continue // nothing exportable → skip

            val hasSecret = armored.contains("PRIVATE KEY BLOCK")
            if (hasSecret) backedUpFps.add(e.fingerprint)
            entries.add(
                UstarArchive.Entry("$KEYS_DIR$fp.asc", armored.toByteArray(Charsets.UTF_8))
            )
            metaKeys.put(JSONObject().apply {
                put("fingerprint", fp)
                put("userID", e.userID)
                put("algorithm", e.algorithm.displayName)
                put("hasSecret", hasSecret)
                put("trustLevel", e.trustLevel.displayName)
                if (e.userEmail.isNotBlank()) put("contactLink", e.userEmail)
                put("createdAt", iso(e.createdAt))
                e.expiresAt?.let { put("expiresAt", iso(it)) }
            })
        }

        if (metaKeys.length() == 0) throw BackupError.EmptyKeyring

        val meta = JSONObject().apply {
            put("appVersion", appVersion())
            put("platform", "android")
            put("createdAt", iso(System.currentTimeMillis()))
            put("formatVersion", FORMAT_VERSION)
            put("keys", metaKeys)
        }

        // Order: meta first, keys next, additive settings last.
        val ordered = ArrayList<UstarArchive.Entry>(entries.size + 2)
        ordered.add(UstarArchive.Entry(META_NAME, meta.toString(2).toByteArray(Charsets.UTF_8)))
        ordered.addAll(entries)
        runCatching { settingsJson() }.getOrNull()?.let {
            ordered.add(UstarArchive.Entry(SETTINGS_NAME, it.toByteArray(Charsets.UTF_8)))
        }

        val tar = UstarArchive.write(ordered)

        // Seal: symmetric AES-256 / SEIPDv1, iterated-salted S2K (no
        // Argon2) — matches the iOS container and `gpg -c` interop. Get
        // binary, then armor with the backup Comment header.
        val sealed = crypto.encryptSymmetric(
            data = tar,
            passphrase = recoveryCanonical,
            filename = null,
            armor = false,
            useAead = false,
            useArgon2 = false
        )
        // §4.3: the backup captured these keys' secret material.
        backedUpFps.forEach { repo.markBackedUp(it) }
        return armorMessage(sealed)
    }

    private fun armorMessage(binary: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).apply {
            setHeader("Version", null)
            setHeader("Comment", ARMOR_COMMENT)
            write(binary)
            close()
        }
        return out.toByteArray()
    }

    // ── Restore ──────────────────────────────────────────────────────

    /**
     * Decrypt and merge-import a backup. [enteredCode] is normalized
     * (hyphens stripped, Crockford typo mapping) before it's used as the
     * passphrase. Throws [BackupError] on a wrong code or damaged file;
     * per-key failures are collected in the returned report rather than
     * aborting the whole restore.
     */
    suspend fun restoreBackup(fileBytes: ByteArray, enteredCode: String): MergeReport {
        val text = fileBytes.toString(Charsets.UTF_8)
        if (!text.contains("BEGIN PGP MESSAGE")) throw BackupError.NotABackup

        val canonical = CrockfordBase32.normalize(enteredCode)

        val plaintext = try {
            crypto.decrypt(
                encryptedData = fileBytes,
                secretKeyRings = emptyList(),
                passphrase = canonical,
                verificationKeys = null
            ).data
        } catch (e: PGPCryptoError.InvalidPassphrase) {
            throw BackupError.WrongCode
        } catch (e: PGPCryptoError.IntegrityCheckFailed) {
            throw BackupError.Corrupt(e.message ?: "integrity check failed")
        } catch (e: Exception) {
            // A wrong passphrase on a SKESK usually surfaces as a generic
            // decryption failure ("bad session key"); treat unlabeled
            // decrypt failures as a wrong code rather than corruption.
            throw BackupError.WrongCode
        }

        val entries = try {
            UstarArchive.read(plaintext)
        } catch (e: Exception) {
            throw BackupError.Corrupt(e.message ?: "unreadable archive")
        }
        if (entries.isEmpty()) throw BackupError.Corrupt("empty archive")

        // Per-fingerprint metadata for trust reapplication.
        val metaByFp = HashMap<String, JSONObject>()
        entries.firstOrNull { it.name == META_NAME }?.let { m ->
            runCatching {
                val obj = JSONObject(String(m.data, Charsets.UTF_8))
                val arr = obj.optJSONArray("keys") ?: JSONArray()
                for (i in 0 until arr.length()) {
                    val k = arr.getJSONObject(i)
                    metaByFp[k.optString("fingerprint").lowercase()] = k
                }
            }
        }

        val added = ArrayList<RestoredKey>()
        val upgraded = ArrayList<RestoredKey>()
        val updated = ArrayList<RestoredKey>()
        val unchanged = ArrayList<RestoredKey>()
        val failed = ArrayList<RestoredKey>()

        val seenFingerprints = HashSet<String>()
        for (entry in entries) {
            if (!entry.name.startsWith(KEYS_DIR) || !entry.name.endsWith(".asc")) continue
            val fpFromName = entry.name.removePrefix(KEYS_DIR).removeSuffix(".asc").lowercase()
            // Defense-in-depth: never import the same key twice from one
            // archive, whatever produced it.
            if (!seenFingerprints.add(fpFromName)) continue
            val armored = String(entry.data, Charsets.UTF_8)
            try {
                val outcome = repo.importArmoredKeyDetailed(armored)
                val fp = outcome.entity.fingerprint.lowercase()
                val label = outcome.entity.userID.ifBlank { fp }
                val rk = RestoredKey(fp, label)
                when (outcome.resolution) {
                    ImportResolution.INSERTED -> added.add(rk)
                    ImportResolution.UPGRADED_TO_KEY_PAIR -> upgraded.add(rk)
                    ImportResolution.MERGED_NEW_MATERIAL,
                    ImportResolution.PAIRED_WITH_CARD -> updated.add(rk)
                    ImportResolution.ALREADY_IN_KEYRING -> unchanged.add(rk)
                }
                // 4.6.0 (item 17.9): trust levels are no longer taken from the
                // file. A crafted backup the user was talked into restoring
                // could otherwise mark an attacker's key as verified. Trust is
                // set by the user, in the app, after a fingerprint check.
            } catch (e: Exception) {
                val label = metaByFp[fpFromName]?.optString("userID")?.ifBlank { null } ?: fpFromName
                failed.add(RestoredKey(fpFromName, label))
            }
        }

        // 4.6.0 (item 17.9): settings are handed back, not applied. The user is
        // asked first (see applyBackupSettings), and even then a restore can
        // never turn a configured proxy off.
        val pendingSettings = entries.firstOrNull { it.name == SETTINGS_NAME }
            ?.let { String(it.data, Charsets.UTF_8) }
            ?.takeIf { hasApplicableSettings(it) }

        return MergeReport(added, upgraded, updated, unchanged, failed,
            settingsApplied = false, pendingSettings = pendingSettings)
    }

    // ── OpenKeychain migration (Succession) ──────────────────────────

    /**
     * Sniff a backup file's origin from its armor header. PGPony tags its
     * armor `Comment: PGPony Backup v1`; OpenKeychain writes a
     * `Passphrase-Format: numeric9x4` header. Used to pick the recovery-
     * code format and the payload parser.
     */
    fun detectKind(fileBytes: ByteArray): BackupKind {
        val head = String(fileBytes.copyOf(minOf(400, fileBytes.size)), Charsets.UTF_8)
        return when {
            head.contains("PGPony Backup", ignoreCase = true) -> BackupKind.PGPONY
            head.contains("Passphrase-Format", ignoreCase = true) ||
                head.contains("numeric", ignoreCase = true) -> BackupKind.OPENKEYCHAIN
            else -> BackupKind.UNKNOWN
        }
    }

    /**
     * OpenKeychain's backup code is `numeric9x4` — 36 digits shown as 9
     * groups of 4. The S2K passphrase is the code WITH its hyphens (the
     * opposite of PGPony's). Rebuild the canonical dashed form from just
     * the digits, so the code opens the file however the user types it.
     * Verified against a real OpenKeychain backup.
     */
    fun normalizeOpenKeychainCode(input: String): String =
        input.filter { it.isDigit() }.chunked(4).joinToString("-")

    /**
     * Decrypt and merge-import an OpenKeychain `.sec.pgp` backup. The
     * decrypted payload is one armor block holding many key rings, so it
     * runs through [PGPCryptoService.explodeToArmoredKeys] then the normal
     * per-key merge. Returns the same [MergeReport] shape as a PGPony
     * restore (no settings — OpenKeychain backups carry keys only).
     */
    suspend fun restoreOpenKeychainBackup(fileBytes: ByteArray, enteredCode: String): MergeReport {
        val passphrase = normalizeOpenKeychainCode(enteredCode)
        if (passphrase.isBlank()) throw BackupError.WrongCode

        val plaintext = try {
            crypto.decrypt(fileBytes, emptyList(), passphrase, null).data
        } catch (e: PGPCryptoError.InvalidPassphrase) {
            throw BackupError.WrongCode
        } catch (e: Exception) {
            throw BackupError.WrongCode
        }

        // The payload is one OR MORE armor blocks (OpenKeychain writes a
        // public block + a secret block), each possibly holding several
        // rings — importAllArmoredKeysDetailed splits blocks AND explodes
        // multi-ring blocks, so every key inside is merge-imported. Fall
        // back to raw-byte ring explosion if the payload isn't armored.
        val text = String(plaintext, Charsets.UTF_8)
        val outcomes = if (text.contains("BEGIN PGP")) {
            repo.importAllArmoredKeysDetailed(text)
        } else {
            crypto.explodeToArmoredKeys(plaintext).mapNotNull { ring ->
                runCatching { repo.importArmoredKeyDetailed(ring) }.getOrNull()
            }
        }
        if (outcomes.isEmpty()) throw BackupError.Corrupt("no keys found in backup")

        val added = ArrayList<RestoredKey>()
        val upgraded = ArrayList<RestoredKey>()
        val updated = ArrayList<RestoredKey>()
        val unchanged = ArrayList<RestoredKey>()
        for (outcome in outcomes) {
            val rk = RestoredKey(
                outcome.entity.fingerprint.lowercase(),
                outcome.entity.userID.ifBlank { outcome.entity.fingerprint }
            )
            when (outcome.resolution) {
                ImportResolution.INSERTED -> added.add(rk)
                ImportResolution.UPGRADED_TO_KEY_PAIR -> upgraded.add(rk)
                ImportResolution.MERGED_NEW_MATERIAL,
                ImportResolution.PAIRED_WITH_CARD -> updated.add(rk)
                ImportResolution.ALREADY_IN_KEYRING -> unchanged.add(rk)
            }
        }
        return MergeReport(added, upgraded, updated, unchanged, emptyList(), settingsApplied = false)
    }

    /** 4.6.0 (item 17.9): the user agreed; apply the backup's settings. */
    suspend fun applyBackupSettings(json: String): Boolean =
        runCatching { applySettings(json) }.getOrDefault(false)

    private fun hasApplicableSettings(json: String): Boolean = runCatching {
        val o = JSONObject(json)
        o.optJSONObject("proxy") != null || (o.optJSONArray("keyservers")?.length() ?: 0) > 0
    }.getOrDefault(false)

    // ── Settings (additive, Android-only) ────────────────────────────

    private suspend fun settingsJson(): String {
        val ctx = PGPonyApp.instance
        val cfg = ProxyPrefs.config(ctx)
        val proxy = JSONObject().apply {
            put("mode", cfg.mode)
            cfg.host?.let { put("customHost", it) }
            put("customPort", cfg.port)
            put("onionMirror", ProxyPrefs.onionMirror(ctx))
        }
        val servers = JSONArray()
        runCatching { KeyServerDirectory.get(ctx).readOnce() }.getOrDefault(emptyList())
            .forEach { servers.put(it.toJson()) }
        return JSONObject().apply {
            put("formatVersion", FORMAT_VERSION)
            put("proxy", proxy)
            put("keyservers", servers)
        }.toString(2)
    }

    /** @return true if any setting was applied. */
    private suspend fun applySettings(json: String): Boolean {
        val ctx = PGPonyApp.instance
        val obj = JSONObject(json)
        var applied = false

        obj.optJSONObject("proxy")?.let { p ->
            val mode = p.optString("mode", ProxyPrefs.MODE_OFF)
            val current = ProxyPrefs.config(ctx)
            // 4.6.0 (item 17.9): a restore never lowers protection. It cannot
            // turn a configured proxy off, cannot select Custom without a host
            // (which would leave no usable proxy), and cannot switch an Orbot
            // or Custom setup to anything else once one is in place.
            val downgrade = (current.enabled && mode == ProxyPrefs.MODE_OFF) ||
                (mode == ProxyPrefs.MODE_CUSTOM && p.optString("customHost", "").isBlank()) ||
                (current.enabled && mode != current.mode)
            if (downgrade) return@let
            if (mode == ProxyPrefs.MODE_CUSTOM) {
                ProxyPrefs.setCustom(
                    ctx,
                    p.optString("customHost", ""),
                    p.optInt("customPort", ProxyPrefs.ORBOT_PORT)
                )
            }
            ProxyPrefs.setMode(ctx, mode)
            ProxyPrefs.setOnionMirror(ctx, p.optBoolean("onionMirror", true))
            HttpClientFactory.invalidate()
            applied = true
        }

        obj.optJSONArray("keyservers")?.let { arr ->
            val list = ArrayList<KeyServer>(arr.length())
            for (i in 0 until arr.length()) {
                runCatching { KeyServer.fromJson(arr.getJSONObject(i)) }.getOrNull()?.let(list::add)
            }
            if (list.isNotEmpty()) {
                KeyServerDirectory.get(ctx).save(list)
                applied = true
            }
        }
        return applied
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private fun appVersion(): String = runCatching {
        val ctx = PGPonyApp.instance
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "unknown"
    }.getOrDefault("unknown")

    private fun iso(epochMs: Long): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date(epochMs))
    }
}
