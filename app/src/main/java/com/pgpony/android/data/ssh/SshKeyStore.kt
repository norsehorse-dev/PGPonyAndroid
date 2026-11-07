// SshKeyStore.kt
// PGPony Android, 4.8.0 RC7 (item 1): SSH-only ssh-mldsa44-ed25519 keys,
// held on the phone outside the OpenPGP keyring.
//
// This is the API the SSH provider and Settings use. It has no Android
// dependency: the protected storage sits behind [SshKeyVault], which the app
// backs with SecureKeyStore (SecureSshKeyVault) and the JVM tests with memory.
//
// Key ids. The SSH authentication API names a key by a string. OpenPGP keys use
// the primary fingerprint (hex) or a decimal key id there; an SSH-only key uses
// "ssh:" + its OpenSSH fingerprint, e.g. "ssh:SHA256:PwdCORll4fc1...". The
// prefix has letters outside hex and a colon, so it can never parse as an
// OpenPGP fingerprint or key id ([isSshKeyId] tells them apart).
//
// Storage. Per key: the 64 seed octets (secret) and a small JSON record (meta:
// label, creation time, public key). Both are sealed the same way as OpenPGP
// secret keys (per-key AES-256-GCM data key wrapped by the hardware Keystore
// key), under a storage name that is the hex SHA-256 of the public key blob.
// There is no passphrase on these keys, so, like a passphrase-less OpenPGP key,
// a Keystore wipe by the OS loses them; the app backup carries them.
//
// 4.8.0 RC7 (item 1): the id and the storage name both hash the public blob
// under MlDsaEd25519Ssh.KEY_TYPE, the OpenSSH 10.6 name, so they match what
// ssh-keygen 10.6 -l prints. A key imported from a 10.4 or 10.5 file (the old
// @openssh.com name) is stored under the new name. RC7 builds before the
// rename stored records under the old blob's hash; nothing was published with
// them, so they are not migrated: their record no longer matches its storage
// name, so list() leaves them out, backupItems() counts them as skipped, and
// an agent still holding such an id gets Unreadable. Clear All Data removes
// them.
//
// Every call does file I/O and, for generate/import/export/sign, real crypto
// (bcrypt_pbkdf on import/export): call it off the main thread. Nothing is
// cached in memory, so the provider process (:remote_api) and the app always
// see the same keys, and Clear All Data leaves nothing behind in either.

package com.pgpony.android.data.ssh

import com.pgpony.android.crypto.ssh.MlDsaEd25519Key
import com.pgpony.android.crypto.ssh.MlDsaEd25519Ssh
import com.pgpony.android.crypto.ssh.OpenSshKeyFile
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * Protected storage for SSH keys: two sealed blobs per key, addressed by a
 * storage name (64 lowercase hex). Implementations must be safe to call from
 * both app processes.
 */
interface SshKeyVault {
    /** Storage names of every stored key, readable or not. */
    fun names(): List<String>
    /** The key's 64 seed octets as a fresh array (the store wipes it after
     *  use), or null when missing or unreadable. */
    fun readSecret(name: String): ByteArray?
    /** The key's metadata record, or null when missing or unreadable. */
    fun readMeta(name: String): ByteArray?
    /** Store a new key (secret first, then meta, so a listed key is complete). */
    fun write(name: String, secret: ByteArray, meta: ByteArray)
    /** Replace the metadata of an existing key. */
    fun writeMeta(name: String, meta: ByteArray)
    fun delete(name: String)
    /** Remove every SSH key, readable or not. */
    fun deleteAll()
}

/** One SSH key as the UI and the provider see it. Holds no secret. */
class SshKeyEntry(
    /** "ssh:SHA256:..." (see [SshKeyStore.isSshKeyId]). */
    val id: String,
    /** The user's name for the key; also the comment in .pub lines and exports. May be empty. */
    val label: String,
    /** Creation (or first import) time, epoch milliseconds. */
    val createdAt: Long,
    /** "SHA256:..." as ssh-keygen -l prints it. */
    val fingerprint: String,
    private val publicKeyBytes: ByteArray
) {
    /** Always [MlDsaEd25519Ssh.KEY_TYPE] for now. */
    val keyType: String get() = MlDsaEd25519Ssh.KEY_TYPE

    /** The 1344-octet composite public key (a copy). */
    val publicKey: ByteArray get() = publicKeyBytes.copyOf()

    /** The SSH public key blob (what GET_SSH_PUBLIC_KEY encodes). */
    val publicBlob: ByteArray get() = MlDsaEd25519Ssh.publicBlob(publicKeyBytes)

    /** The authorized_keys line, with the label as comment. */
    val publicKeyLine: String get() = MlDsaEd25519Ssh.publicKeyLine(publicKeyBytes, label)

    override fun equals(other: Any?): Boolean =
        other is SshKeyEntry && other.id == id && other.label == label && other.createdAt == createdAt
    override fun hashCode(): Int = id.hashCode()
    override fun toString(): String = "SshKeyEntry($id, \"$label\")"
}

/** Why an SSH key operation failed. Messages are English, for logs; the UI maps the type. */
sealed class SshKeyError(message: String) : Exception(message) {
    /** The key file is passphrase-protected and no passphrase was given. */
    class PassphraseRequired : SshKeyError("This key file is protected by a passphrase")
    /** The passphrase did not open the key file. */
    class WrongPassphrase : SshKeyError("Wrong passphrase for this key file")
    /** The file holds another key type ([keyType], e.g. "ssh-ed25519"). */
    class WrongKeyType(val keyType: String) :
        SshKeyError("This file holds a $keyType key, not an ${MlDsaEd25519Ssh.KEY_TYPE} key")
    /** The file is encrypted in a way PGPony does not read ([detail]). */
    class UnsupportedEncryption(val detail: String) : SshKeyError("Unsupported key file encryption: $detail")
    /** Not an OpenSSH private key file, or a damaged one. */
    class Malformed(val reason: String) : SshKeyError("Not a readable OpenSSH private key: $reason")
    /** No SSH key with this id. */
    class NotFound(val id: String) : SshKeyError("No SSH key $id")
    /** The key is stored but its protected material can no longer be read
     *  (the OS dropped the Keystore key). Delete it and import it again. */
    class Unreadable(val id: String) : SshKeyError("SSH key $id can no longer be read on this device")
}

/** The result of [SshKeyStore.import]: the key, and whether it was new. */
class SshKeyImport(val entry: SshKeyEntry, val added: Boolean)

/** One key as the app backup carries it (see SshKeyBackup). */
class SshKeyBackupItem(
    val fingerprint: String,
    val label: String,
    val createdAt: Long,
    /** An unencrypted OpenSSH private key file (the backup itself is encrypted). */
    val keyFile: ByteArray
)

/**
 * What [SshKeyStore.backupItems] gives a backup: the keys it carries, and
 * how many stored keys could not be read and are left out.
 */
class SshKeyBackupSet(
    val items: List<SshKeyBackupItem>,
    /** 4.8.0 RC7 (item 1): stored keys whose record or seeds could not be
     *  read, so the backup does not carry them. The UI says so when above 0. */
    val skipped: Int
)

/** What a restore did with the backup's SSH keys, by id and label. */
class SshKeyRestoreReport(
    val added: List<SshKeyEntry>,
    val unchanged: List<SshKeyEntry>,
    /** Keys that could not be read from the backup (label or file name). */
    val failed: List<String>
)

class SshKeyStore(
    private val vault: SshKeyVault,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val rng: SecureRandom = SecureRandom()
) {

    companion object {
        /** Prefix of every SSH-only key id. */
        const val ID_PREFIX = "ssh:"

        /** Longest label kept; longer ones are cut. */
        const val MAX_LABEL_LENGTH = 200

        private const val META_VERSION = 1
        private val HEX64 = Regex("[0-9a-f]{64}")

        /** True when [id] names an SSH-only key, never an OpenPGP key. */
        fun isSshKeyId(id: String?): Boolean = id != null && id.startsWith(ID_PREFIX)

        /** The id for an OpenSSH fingerprint ("SHA256:..."). */
        fun idForFingerprint(fingerprint: String): String = ID_PREFIX + fingerprint

        /** The OpenSSH fingerprint inside [id], or null when [id] is not an SSH key id. */
        fun fingerprintOf(id: String): String? = if (isSshKeyId(id)) id.removePrefix(ID_PREFIX) else null

        /**
         * A label fit for an OpenSSH comment: one line, no control characters,
         * trimmed, at most [MAX_LABEL_LENGTH] characters.
         */
        fun normalizeLabel(label: String): String {
            val oneLine = label.map { c -> if (c == '\n' || c == '\r' || c == '\t') ' ' else c }
                .filter { c -> !c.isISOControl() }
                .joinToString("")
                .trim()
            return if (oneLine.length > MAX_LABEL_LENGTH) oneLine.take(MAX_LABEL_LENGTH).trim() else oneLine
        }

        /** The storage name for an id: the hex SHA-256 inside its fingerprint. */
        internal fun storageName(id: String): String? {
            val fp = fingerprintOf(id) ?: return null
            if (!fp.startsWith("SHA256:")) return null
            val digest = runCatching { Base64.getDecoder().decode(fp.removePrefix("SHA256:").let(::padBase64)) }
                .getOrNull() ?: return null
            if (digest.size != 32) return null
            return hex(digest)
        }

        private fun storageNameForPublicKey(publicKey: ByteArray): String =
            hex(MessageDigest.getInstance("SHA-256").digest(MlDsaEd25519Ssh.publicBlob(publicKey)))

        private fun padBase64(s: String): String = s + "=".repeat((4 - s.length % 4) % 4)

        /** Lowercase hex, independent of the default locale. */
        internal fun hex(b: ByteArray): String {
            val digits = "0123456789abcdef"
            val out = StringBuilder(b.size * 2)
            for (x in b) {
                out.append(digits[(x.toInt() shr 4) and 0x0F]).append(digits[x.toInt() and 0x0F])
            }
            return out.toString()
        }
    }

    private val lock = Any()

    // ── Reading ──────────────────────────────────────────────────────

    /** Every readable SSH key, oldest first. Keys whose material can no longer be read are left out. */
    fun list(): List<SshKeyEntry> =
        vault.names().filter { HEX64.matches(it) }.mapNotNull { entryFor(it) }.sortedBy { it.createdAt }

    /** The key [id], or null. */
    fun get(id: String): SshKeyEntry? = storageName(id)?.let { entryFor(it) }

    /** The authorized_keys line for [id] (label as comment), or null. */
    fun publicLine(id: String): String? = get(id)?.publicKeyLine

    // ── Creating ─────────────────────────────────────────────────────

    /** A new key from fresh random seeds, stored under [label]. */
    fun generate(label: String): SshKeyEntry {
        MlDsaEd25519Key.generate(rng).use { key -> return store(key, normalizeLabel(label), clock()) }
    }

    /**
     * Import an OpenSSH private key file (as ssh-keygen -t mldsa44-ed25519
     * writes it, with or without a passphrase). The label is [label] when
     * given, else the file's comment. A key already held is left as it is
     * (its label too) and returned with added = false.
     *
     * [shouldStore] is asked once the file is read (after bcrypt_pbkdf, which
     * cannot be interrupted); false stores nothing and throws
     * [java.util.concurrent.CancellationException]. 4.8.0 RC7 (item 1): the
     * import dialog's Cancel stays usable while the KDF runs, and a cancelled
     * import must not add the key once the KDF finishes.
     *
     * @throws SshKeyError.PassphraseRequired, SshKeyError.WrongPassphrase,
     *   SshKeyError.WrongKeyType, SshKeyError.UnsupportedEncryption,
     *   SshKeyError.Malformed
     */
    fun import(
        fileBytes: ByteArray,
        passphrase: CharArray? = null,
        label: String? = null,
        shouldStore: () -> Boolean = { true }
    ): SshKeyImport {
        val decoded = readFile(fileBytes, passphrase)
        decoded.key.use { key ->
            if (!shouldStore()) throw java.util.concurrent.CancellationException("SSH key import cancelled")
            synchronized(lock) {
                val name = storageNameForPublicKey(key.publicKey)
                entryFor(name)?.let { return SshKeyImport(it, added = false) }
                val entry = store(key, normalizeLabel(label ?: decoded.comment), clock())
                return SshKeyImport(entry, added = true)
            }
        }
    }

    /**
     * What a key file holds, read without a passphrase: lets the UI refuse
     * another key type, or encryption PGPony does not read
     * ([OpenSshKeyFile.Info.unsupportedEncryption]), or ask for the
     * passphrase before [import].
     * @throws SshKeyError.Malformed
     */
    fun inspectFile(fileBytes: ByteArray): OpenSshKeyFile.Info = try {
        OpenSshKeyFile.inspect(fileBytes)
    } catch (e: OpenSshKeyFile.ReadError) {
        throw mapReadError(e)
    }

    // ── Using ────────────────────────────────────────────────────────

    /**
     * [data] signed with key [id], as the full SSH signature blob
     * string("ssh-mldsa44-ed25519") + string(sig[2484]). The SSH
     * API's hash algorithm argument does not apply: the composite always
     * hashes with SHA-512.
     *
     * @throws SshKeyError.NotFound, SshKeyError.Unreadable
     */
    fun sign(id: String, data: ByteArray): ByteArray {
        val (entry, key) = loadKey(id)
        key.use {
            if (!it.publicKey.contentEquals(entry.publicKey)) throw SshKeyError.Unreadable(id)
            return it.sign(data, rng)
        }
    }

    /**
     * Key [id] as an OpenSSH private key file encrypted under [passphrase]
     * (aes256-ctr, bcrypt_pbkdf, as ssh-keygen writes by default), with the
     * label as comment. ssh, ssh-add and ssh-keygen 10.6 read it (10.4 and
     * 10.5 do not: they know only the old type name).
     *
     * @throws IllegalArgumentException when [passphrase] is empty
     * @throws SshKeyError.NotFound, SshKeyError.Unreadable
     */
    fun exportPrivate(id: String, passphrase: CharArray): String {
        require(passphrase.isNotEmpty()) { "A passphrase is required to export an SSH private key" }
        val (entry, key) = loadKey(id)
        key.use { return OpenSshKeyFile.write(it, entry.label, passphrase, rng = rng) }
    }

    // ── Changing ─────────────────────────────────────────────────────

    /** Give key [id] a new label. @throws SshKeyError.NotFound, SshKeyError.Unreadable */
    fun rename(id: String, label: String): SshKeyEntry {
        synchronized(lock) {
            val name = storageName(id) ?: throw SshKeyError.NotFound(id)
            val old = entryFor(name) ?: throw notFoundOrUnreadable(id, name)
            val updated = SshKeyEntry(old.id, normalizeLabel(label), old.createdAt, old.fingerprint, old.publicKey)
            vault.writeMeta(name, metaJson(updated))
            return updated
        }
    }

    /** Delete key [id]. Returns false when there was no such key. */
    fun delete(id: String): Boolean {
        synchronized(lock) {
            val name = storageName(id) ?: return false
            if (name !in vault.names()) return false
            vault.delete(name)
            return true
        }
    }

    /** Delete every SSH key (Clear All Data). */
    fun deleteAll() {
        synchronized(lock) { vault.deleteAll() }
    }

    // ── Backup ───────────────────────────────────────────────────────

    /**
     * Every readable key as the backup carries it, oldest first, and how many
     * stored keys could not be read (record or seeds) and are left out.
     *
     * 4.8.0 RC7 (item 1): a key that cannot be read is counted, not silently
     * dropped, so the backup screen can say the backup lacks it. A failure of
     * the store itself (listing the keys) is thrown: BackupService catches it
     * so the OpenPGP keys are still backed up, and reports the SSH keys as
     * skipped.
     */
    fun backupItems(): SshKeyBackupSet {
        val names = vault.names().filter { HEX64.matches(it) }
        val items = ArrayList<SshKeyBackupItem>(names.size)
        var skipped = 0
        for (name in names) {
            val item = try {
                val entry = entryFor(name) ?: throw SshKeyError.Unreadable(name)
                val (_, key) = loadKey(entry.id)
                key.use {
                    SshKeyBackupItem(
                        entry.fingerprint, entry.label, entry.createdAt,
                        OpenSshKeyFile.write(it, entry.label, null, rng = rng).toByteArray(Charsets.UTF_8)
                    )
                }
            } catch (e: Exception) {
                null
            }
            if (item == null) skipped++ else items.add(item)
        }
        return SshKeyBackupSet(items.sortedBy { it.createdAt }, skipped)
    }

    /**
     * Merge keys from a backup by fingerprint: a key not held is added with
     * the backup's label and creation time; a key already held is left as it
     * is. An item that does not read as this key type is reported as failed.
     *
     * 4.8.0 RC7 (item 1): each item is read and stored on its own, so one that
     * fails to store (the vault throws) is reported as failed and the rest are
     * still tried; the report never lists keys that were in fact added.
     */
    fun restoreItems(items: List<SshKeyBackupItem>): SshKeyRestoreReport {
        val added = ArrayList<SshKeyEntry>()
        val unchanged = ArrayList<SshKeyEntry>()
        val failed = ArrayList<String>()
        for (item in items) {
            val decoded = try {
                OpenSshKeyFile.read(item.keyFile, null)
            } catch (e: Exception) {
                failed.add(item.label.ifBlank { item.fingerprint })
                continue
            }
            decoded.key.use { key ->
                try {
                    synchronized(lock) {
                        val name = storageNameForPublicKey(key.publicKey)
                        val existing = entryFor(name)
                        if (existing != null) {
                            unchanged.add(existing)
                        } else {
                            val label = normalizeLabel(item.label.ifBlank { decoded.comment })
                            val createdAt = if (item.createdAt > 0) item.createdAt else clock()
                            added.add(store(key, label, createdAt))
                        }
                    }
                } catch (e: Exception) {
                    failed.add(item.label.ifBlank { item.fingerprint })
                }
            }
        }
        return SshKeyRestoreReport(added, unchanged, failed)
    }

    // ── Internals ────────────────────────────────────────────────────

    private fun store(key: MlDsaEd25519Key, label: String, createdAt: Long): SshKeyEntry {
        val fp = key.fingerprint
        val entry = SshKeyEntry(idForFingerprint(fp), label, createdAt, fp, key.publicKey)
        val name = storageNameForPublicKey(key.publicKey)
        val secret = key.privateBytes()
        try {
            vault.write(name, secret, metaJson(entry))
        } finally {
            secret.fill(0)
        }
        return entry
    }

    private fun loadKey(id: String): Pair<SshKeyEntry, MlDsaEd25519Key> {
        val name = storageName(id) ?: throw SshKeyError.NotFound(id)
        val entry = entryFor(name) ?: throw notFoundOrUnreadable(id, name)
        val secret = vault.readSecret(name) ?: throw SshKeyError.Unreadable(id)
        try {
            if (secret.size != MlDsaEd25519Ssh.PRIVATE_LEN) throw SshKeyError.Unreadable(id)
            return entry to MlDsaEd25519Key.fromPrivateBytes(secret)
        } finally {
            secret.fill(0)
        }
    }

    private fun notFoundOrUnreadable(id: String, name: String): SshKeyError =
        if (name in vault.names()) SshKeyError.Unreadable(id) else SshKeyError.NotFound(id)

    private fun entryFor(name: String): SshKeyEntry? {
        val raw = vault.readMeta(name) ?: return null
        return runCatching { parseMeta(raw) }.getOrNull()
            // The record must belong to the name it is stored under.
            ?.takeIf { storageNameForPublicKey(it.publicKey) == name }
    }

    private fun metaJson(e: SshKeyEntry): ByteArray = JsonObject(
        mapOf(
            "v" to JsonPrimitive(META_VERSION),
            "type" to JsonPrimitive(e.keyType),
            "label" to JsonPrimitive(e.label),
            "createdAt" to JsonPrimitive(e.createdAt),
            "publicKey" to JsonPrimitive(Base64.getEncoder().encodeToString(e.publicKey))
        )
    ).toString().toByteArray(Charsets.UTF_8)

    private fun parseMeta(raw: ByteArray): SshKeyEntry {
        val o = Json.parseToJsonElement(String(raw, Charsets.UTF_8)).jsonObject
        val v = o["v"]?.jsonPrimitive?.intOrNull ?: 0
        require(v in 1..META_VERSION) { "Unknown SSH key record version $v" }
        val type = o["type"]?.jsonPrimitive?.contentOrNull ?: ""
        require(MlDsaEd25519Ssh.isKeyType(type)) { "Unknown SSH key type $type" }
        val pk = Base64.getDecoder().decode(o["publicKey"]?.jsonPrimitive?.contentOrNull ?: "")
        require(pk.size == MlDsaEd25519Ssh.PUBLIC_LEN) { "Bad public key in SSH key record" }
        val fp = MlDsaEd25519Ssh.fingerprint(pk)
        return SshKeyEntry(
            id = idForFingerprint(fp),
            label = o["label"]?.jsonPrimitive?.contentOrNull ?: "",
            createdAt = o["createdAt"]?.jsonPrimitive?.longOrNull ?: 0L,
            fingerprint = fp,
            publicKeyBytes = pk
        )
    }

    private fun readFile(fileBytes: ByteArray, passphrase: CharArray?): OpenSshKeyFile.Decoded = try {
        OpenSshKeyFile.read(fileBytes, passphrase)
    } catch (e: OpenSshKeyFile.ReadError) {
        throw mapReadError(e)
    }

    private fun mapReadError(e: OpenSshKeyFile.ReadError): SshKeyError = when (e) {
        is OpenSshKeyFile.ReadError.PassphraseRequired -> SshKeyError.PassphraseRequired()
        is OpenSshKeyFile.ReadError.WrongPassphrase -> SshKeyError.WrongPassphrase()
        is OpenSshKeyFile.ReadError.UnsupportedKeyType -> SshKeyError.WrongKeyType(e.keyType)
        is OpenSshKeyFile.ReadError.UnsupportedEncryption -> SshKeyError.UnsupportedEncryption(e.detail)
        is OpenSshKeyFile.ReadError.Malformed -> SshKeyError.Malformed(e.reason)
    }
}
