// SecureKeyStore.kt
// PGPony Android
//
// Android equivalent of iOS KeychainService.swift.
//
// 4.5.3 (#57, from field reports): key material used to
// live in androidx.security.crypto EncryptedSharedPreferences (1.1.0-alpha06).
// That library wraps a Tink keyset (a second prefs file) with a hardware Android
// Keystore master key, is not multi-process safe, and PGPony opened it from BOTH
// the main process and the :remote_api provider process. On aggressive OEM ROMs
// (realme/ColorOS, Android 16 reported) the keyset or the keystore key gets
// invalidated, after which every value written under it silently stops
// decrypting while the Room metadata DB is untouched. A key still shows in the
// list and picker but its bytes can no longer be exported, encrypted to, or
// signed with, on every key at once regardless of algorithm. That produced the
// "could not export key material" reports and the "my key works for a couple of
// days then goes invalid" lockouts, with no crash and no reproduction on
// healthy hardware.
//
// Belt-and-suspenders design:
//   • Each key's material is encrypted with a per-key random data key (DEK),
//     AES-256-GCM, in app-private files under filesDir (multi-process safe, no
//     regenerable Tink keyset).
//   • The DEK is wrapped TWO ways and both wraps are stored:
//       – under a hardware Android Keystore key referenced by a stable alias
//         (the fast path, no user interaction), and
//       – under a PBKDF2-HMAC-SHA256 key derived from the key's own OpenPGP
//         passphrase, when it has one.
//   • Reads use the hardware wrap. If the OS has invalidated the hardware key,
//     a key that carries a passphrase is recovered by re-deriving the DEK from
//     that passphrase (recoverWithPassphrase), which then re-establishes a fresh
//     hardware wrap so future reads are fast again. A passphrase-less key has no
//     second factor, so a hardware wipe still loses it and the caller is told to
//     re-import.
//
// Existing 4.5.2-and-earlier installs migrate lazily and losslessly: a read that
// misses the new store falls back to the old EncryptedSharedPreferences and
// copies the value forward. Once the new store verifiably holds the value, the
// legacy copy of it is deleted (readWithMigration), so a later fallback cannot
// bring back a stale secret.
//
// Storage layout (per fingerprint, lowercased) under filesDir/secure_keystore_v2/:
//   <fp>.dek   DEK envelope (magic PKD2)
//   <fp>.pub   public blob,  AES-256-GCM under the DEK
//   <fp>.priv  private blob, AES-256-GCM under the DEK
// Sealed-blob bytes: [ivLen:1][iv][GCM ciphertext incl. 128-bit tag].

package com.pgpony.android.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileLock
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class SecureKeyStore(context: Context) {

    companion object {
        private const val TAG = "SecureKeyStore"

        private const val KEY_PREFIX_PUBLIC = "pgpony_key_"
        private const val KEY_SUFFIX_PUBLIC = "_public"
        private const val KEY_SUFFIX_PRIVATE = "_private"

        private const val STORE_DIR = "secure_keystore_v2"
        private const val HW_ALIAS = "pgpony_keystore_v2_hw"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128

        // DEK envelope.
        private val ENVELOPE_MAGIC = byteArrayOf('P'.code.toByte(), 'K'.code.toByte(), 'D'.code.toByte(), '2'.code.toByte())
        private const val ENVELOPE_VERSION = 1

        // PBKDF2 recovery-wrap parameters.
        private const val PBKDF2_ALGO = "PBKDF2WithHmacSHA256"
        private const val PBKDF2_ITERATIONS = 210_000
        private const val PBKDF2_SALT_LEN = 16
        private const val DEK_LEN = 32 // AES-256

        // Legacy store (read-only, for migration).
        private const val LEGACY_PREFS_FILE = "pgpony_secure_keys"

        @Volatile
        private var instance: SecureKeyStore? = null

        fun getInstance(context: Context): SecureKeyStore {
            return instance ?: synchronized(this) {
                instance ?: SecureKeyStore(context.applicationContext).also { instance = it }
            }
        }
    }

    private val appContext = context.applicationContext
    private val lock = Any()
    private val rng = SecureRandom()

    private val dir: File by lazy {
        File(appContext.filesDir, STORE_DIR).apply { if (!exists()) mkdirs() }
    }

    // Material that could not be read via hardware this session and has NO
    // passphrase recovery: genuinely lost, caller should prompt a re-import.
    @Volatile
    private var sawUnrecoverable = false

    // Material that failed the hardware read but CAN be recovered with its
    // passphrase.
    @Volatile
    private var sawRecoverable = false

    fun hasUnreadableMaterial(): Boolean = sawUnrecoverable
    fun hasRecoverableMaterial(): Boolean = sawRecoverable

    // Cross-process guard. The provider runs in :remote_api, so writes from
    // both processes are serialized on a lock file to keep a key's DEK envelope
    // and its blobs consistent (chiefly during the first-read migration).
    private val lockFile: File by lazy { File(dir, ".write.lock") }

    private inline fun <T> crossProcess(block: () -> T): T {
        synchronized(lock) {
            var raf: RandomAccessFile? = null
            var fl: FileLock? = null
            try {
                raf = RandomAccessFile(lockFile, "rw")
                fl = raf.channel.lock()
            } catch (e: Exception) {
                // File locking unavailable: fall back to the in-process lock we
                // already hold rather than failing the operation.
                Log.w(TAG, "Cross-process lock unavailable: ${e.message}")
                try { raf?.close() } catch (_: Exception) {}
                raf = null
                fl = null
            }
            try {
                return block()
            } finally {
                try { fl?.release() } catch (_: Exception) {}
                try { raf?.close() } catch (_: Exception) {}
            }
        }
    }

    // ── Legacy store (lazy, tolerant of its own breakage) ───────────────

    private val legacyPrefs: android.content.SharedPreferences? by lazy {
        try {
            val masterKey = androidx.security.crypto.MasterKey.Builder(appContext)
                .setKeyScheme(androidx.security.crypto.MasterKey.KeyScheme.AES256_GCM)
                .build()
            androidx.security.crypto.EncryptedSharedPreferences.create(
                appContext,
                LEGACY_PREFS_FILE,
                masterKey,
                androidx.security.crypto.EncryptedSharedPreferences
                    .PrefKeyEncryptionScheme.AES256_SIV,
                androidx.security.crypto.EncryptedSharedPreferences
                    .PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.w(TAG, "Legacy secure store unavailable for migration: ${e.message}")
            null
        }
    }

    private fun readLegacy(name: String): ByteArray? {
        val prefs = legacyPrefs ?: return null
        return try {
            prefs.getString(name, null)?.let { Base64.decode(it, Base64.NO_WRAP) }
        } catch (e: Exception) {
            Log.w(TAG, "Legacy read failed for $name: ${e.message}")
            null
        }
    }

    private fun deleteLegacy(name: String) {
        runCatching { legacyPrefs?.edit()?.remove(name)?.apply() }
    }

    // ── Hardware keystore key (stable alias) ────────────────────────────

    private fun loadHwKey(): SecretKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getKey(HW_ALIAS, null) as? SecretKey
    }

    private fun createHwKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                HW_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // No user-auth requirement: not invalidated by biometric or
                // lock-screen changes (only a genuine keystore wipe, which the
                // passphrase recovery below then covers).
                .build()
        )
        return generator.generateKey()
    }

    private fun getOrCreateHwKey(): SecretKey {
        loadHwKey()?.let { return it }
        synchronized(lock) {
            loadHwKey()?.let { return it }
            return createHwKey()
        }
    }

    /** The current hardware key if it can actually seal and open, else null. */
    private fun usableHwKey(): SecretKey? = try {
        loadHwKey()?.takeIf { k -> open(k, seal(k, ByteArray(1))).size == 1 }
    } catch (_: Exception) {
        null
    }

    // Delete and recreate the hardware key after an invalidation, so recovered
    // DEKs can be re-wrapped under a live key.
    private fun regenerateHwKey(): SecretKey {
        synchronized(lock) {
            try {
                val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                if (ks.containsAlias(HW_ALIAS)) ks.deleteEntry(HW_ALIAS)
            } catch (e: Exception) {
                Log.w(TAG, "Could not delete stale hardware key: ${e.message}")
            }
            return createHwKey()
        }
    }

    // ── AES-GCM seal/open helpers ───────────────────────────────────────

    private fun seal(key: SecretKey, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ct = cipher.doFinal(plain)
        return ByteArray(1 + iv.size + ct.size).also { out ->
            out[0] = iv.size.toByte()
            System.arraycopy(iv, 0, out, 1, iv.size)
            System.arraycopy(ct, 0, out, 1 + iv.size, ct.size)
        }
    }

    // Throws on a wrong/invalidated key (GCM tag failure).
    private fun open(key: SecretKey, sealed: ByteArray): ByteArray {
        require(sealed.size >= 2) { "sealed too short" }
        val ivLen = sealed[0].toInt()
        require(ivLen in 1..16 && sealed.size > 1 + ivLen) { "bad sealed length" }
        val iv = sealed.copyOfRange(1, 1 + ivLen)
        val ct = sealed.copyOfRange(1 + ivLen, sealed.size)
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ct)
    }

    private fun pbkdf2Key(passphrase: CharArray, salt: ByteArray, iterations: Int): SecretKey {
        val spec = PBEKeySpec(passphrase, salt, iterations, DEK_LEN * 8)
        try {
            val bytes = SecretKeyFactory.getInstance(PBKDF2_ALGO).generateSecret(spec).encoded
            return SecretKeySpec(bytes, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    // ── DEK envelope (de)serialization ──────────────────────────────────

    private class Envelope(
        val hwWrap: ByteArray,
        val pwPresent: Boolean,
        val salt: ByteArray?,
        val iterations: Int,
        val pwWrap: ByteArray?
    )

    private fun envelopeFile(fp: String) = File(dir, "$fp.dek")

    private fun readEnvelope(fp: String): Envelope? {
        val f = envelopeFile(fp)
        if (!f.exists()) return null
        return try {
            DataInputStream(ByteArrayInputStream(f.readBytes())).use { din ->
                val magic = ByteArray(4).also { din.readFully(it) }
                require(magic.contentEquals(ENVELOPE_MAGIC)) { "bad magic" }
                require(din.readByte().toInt() == ENVELOPE_VERSION) { "bad version" }
                val hwWrap = ByteArray(din.readInt()).also { din.readFully(it) }
                val pwPresent = din.readByte().toInt() != 0
                var salt: ByteArray? = null
                var iterations = 0
                var pwWrap: ByteArray? = null
                if (pwPresent) {
                    salt = ByteArray(din.readInt()).also { din.readFully(it) }
                    iterations = din.readInt()
                    pwWrap = ByteArray(din.readInt()).also { din.readFully(it) }
                }
                Envelope(hwWrap, pwPresent, salt, iterations, pwWrap)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Envelope for $fp is unreadable: ${e.message}")
            null
        }
    }

    private fun writeEnvelope(fp: String, env: Envelope) {
        val bytes = ByteArrayOutputStream().also { bos ->
            DataOutputStream(bos).use { dout ->
                dout.write(ENVELOPE_MAGIC)
                dout.writeByte(ENVELOPE_VERSION)
                dout.writeInt(env.hwWrap.size); dout.write(env.hwWrap)
                dout.writeByte(if (env.pwPresent) 1 else 0)
                if (env.pwPresent) {
                    dout.writeInt(env.salt!!.size); dout.write(env.salt)
                    dout.writeInt(env.iterations)
                    dout.writeInt(env.pwWrap!!.size); dout.write(env.pwWrap)
                }
            }
        }.toByteArray()
        atomicWrite(envelopeFile(fp), bytes)
    }

    // ── DEK acquisition ─────────────────────────────────────────────────

    // For writing new material: reuse the existing hardware-unwrappable DEK so
    // this key's other blob and any passphrase wrap stay valid; otherwise mint a
    // fresh DEK (the old material is being overwritten anyway).
    //
    // 4.6.0 (item 17.9): when the existing DEK is not hardware-readable but a
    // passphrase recovery wrap exists, do NOT mint a fresh DEK. Doing so
    // rewrote the envelope without the recovery wrap and orphaned this key's
    // other blob, so a background public-key refresh after a keystore wipe
    // could turn a recoverable private key into a lost one. Returns null
    // instead; the caller skips (public) or refuses (private) the write until
    // recoverWithPassphrase() has re-wrapped the DEK.
    private fun dekForWrite(fp: String): SecretKey? {
        val env = readEnvelope(fp)
        if (env != null) {
            try {
                val dek = open(getOrCreateHwKey(), env.hwWrap)
                return SecretKeySpec(dek, "AES")
            } catch (e: Exception) {
                if (env.pwPresent) {
                    sawRecoverable = true
                    Log.w(TAG, "DEK for $fp needs passphrase recovery before a rewrite")
                    return null
                }
                Log.w(TAG, "Existing DEK for $fp not hardware-readable, minting fresh: ${e.message}")
            }
        }
        val dekBytes = ByteArray(DEK_LEN).also { rng.nextBytes(it) }
        val hwWrap = seal(getOrCreateHwKey(), dekBytes)
        writeEnvelope(fp, Envelope(hwWrap, pwPresent = false, salt = null, iterations = 0, pwWrap = null))
        return SecretKeySpec(dekBytes, "AES")
    }

    // For reading: hardware path only. Returns null and sets the appropriate
    // session flag when the hardware key can no longer open the DEK.
    private fun dekForRead(fp: String): SecretKey? {
        val env = readEnvelope(fp) ?: return null
        val hw = loadHwKey()
        if (hw != null) {
            try {
                return SecretKeySpec(open(hw, env.hwWrap), "AES")
            } catch (e: Exception) {
                Log.w(TAG, "Hardware DEK unwrap failed for $fp: ${e.message}")
            }
        }
        if (env.pwPresent) sawRecoverable = true else sawUnrecoverable = true
        return null
    }

    // ── Files ───────────────────────────────────────────────────────────

    private fun atomicWrite(target: File, data: ByteArray) {
        synchronized(lock) {
            val tmp = File(target.parentFile, "${target.name}.tmp")
            tmp.writeBytes(data)
            if (!tmp.renameTo(target)) {
                target.delete()
                if (!tmp.renameTo(target)) {
                    target.writeBytes(tmp.readBytes())
                    tmp.delete()
                }
            }
        }
    }

    private fun blobFile(name: String) = File(dir, name)

    private fun writeBlob(fp: String, name: String, data: ByteArray) {
        crossProcess {
            val dek = dekForWrite(fp)
            if (dek == null) {
                // 4.6.0 (item 17.9): see dekForWrite. Public material can be
                // fetched again, so that write is skipped; private material is
                // refused so the caller surfaces it.
                if (name == pubName(fp)) return@crossProcess
                throw IllegalStateException("This key needs its passphrase to recover before it can be changed")
            }
            atomicWrite(blobFile(name), seal(dek, data))
        }
    }

    private fun readBlob(fp: String, name: String): ByteArray? {
        val f = blobFile(name)
        if (!f.exists()) return null
        val dek = dekForRead(fp) ?: return null
        return try {
            open(dek, f.readBytes())
        } catch (e: Exception) {
            Log.w(TAG, "Blob $name is undecryptable: ${e.message}")
            sawUnrecoverable = true
            null
        }
    }

    // fingerprint <-> blob-name plumbing (names kept for migration parity).
    private fun pubName(fp: String) = "$KEY_PREFIX_PUBLIC$fp$KEY_SUFFIX_PUBLIC"
    private fun privName(fp: String) = "$KEY_PREFIX_PUBLIC$fp$KEY_SUFFIX_PRIVATE"

    private fun readWithMigration(fp: String, name: String): ByteArray? {
        readBlob(fp, name)?.let { return it }
        val legacy = readLegacy(name) ?: return null
        try {
            writeBlob(fp, name, legacy)
            // 4.6.0 (item 17.9): once the new store verifiably holds the value,
            // drop the legacy copy, so a later fallback cannot resurrect a stale
            // secret or an old passphrase-protected form.
            if (readBlob(fp, name)?.contentEquals(legacy) == true) deleteLegacy(name)
        } catch (e: Exception) {
            Log.w(TAG, "Lazy migration write failed for $name: ${e.message}")
        }
        return legacy
    }

    // ── Public API (store/load surface unchanged) ───────────────────────

    fun storePublicKey(fingerprint: String, data: ByteArray) {
        val fp = fingerprint.lowercase()
        // 4.6.0 (item 17.1): every public certificate that reaches storage keeps
        // only the components its primary verifiably bound (and the signatures
        // that verify). A certificate whose primary cannot be evaluated, or data
        // that is not a certificate, is stored as given.
        val clean = runCatching { com.pgpony.android.crypto.CertificateBindings.sanitized(data) }.getOrDefault(data)
        writeBlob(fp, pubName(fp), clean)
    }

    fun storePrivateKey(fingerprint: String, data: ByteArray) {
        val fp = fingerprint.lowercase()
        writeBlob(fp, privName(fp), data)
    }

    fun loadPublicKey(fingerprint: String): ByteArray? {
        val fp = fingerprint.lowercase()
        return readWithMigration(fp, pubName(fp))
    }

    fun loadPrivateKey(fingerprint: String): ByteArray? {
        val fp = fingerprint.lowercase()
        return readWithMigration(fp, privName(fp))
    }

    fun deleteKeys(fingerprint: String) {
        synchronized(lock) {
            val fp = fingerprint.lowercase()
            blobFile(pubName(fp)).delete()
            blobFile(privName(fp)).delete()
            envelopeFile(fp).delete()
            legacyPrefs?.let { prefs ->
                try {
                    prefs.edit().remove(pubName(fp)).remove(privName(fp)).apply()
                } catch (_: Exception) { }
            }
        }
    }

    fun hasPublicKey(fingerprint: String): Boolean {
        val fp = fingerprint.lowercase()
        if (blobFile(pubName(fp)).exists()) return true
        return try { legacyPrefs?.contains(pubName(fp)) == true } catch (_: Exception) { false }
    }

    fun hasPrivateKey(fingerprint: String): Boolean {
        val fp = fingerprint.lowercase()
        if (blobFile(privName(fp)).exists()) return true
        return try { legacyPrefs?.contains(privName(fp)) == true } catch (_: Exception) { false }
    }

    // ── Passphrase recovery wrap ────────────────────────────────────────

    /**
     * Add or refresh the passphrase recovery wrap for [fingerprint], so the
     * key survives a hardware-keystore wipe. Call whenever the key's OpenPGP
     * passphrase is in hand (generation, passphrase change, a successful
     * unlock). No-op and returns false if the DEK can't currently be read via
     * hardware (nothing to wrap) or the key has no stored material yet.
     */
    fun attachRecoveryPassphrase(fingerprint: String, passphrase: CharArray): Boolean {
        if (passphrase.isEmpty()) return false
        return crossProcess {
            val fp = fingerprint.lowercase()
            val env = readEnvelope(fp) ?: return@crossProcess false
            val dekBytes = try {
                val hw = loadHwKey() ?: return@crossProcess false
                open(hw, env.hwWrap)
            } catch (e: Exception) {
                Log.w(TAG, "Cannot attach recovery passphrase for $fp (DEK unreadable): ${e.message}")
                return@crossProcess false
            }
            val salt = ByteArray(PBKDF2_SALT_LEN).also { rng.nextBytes(it) }
            val kek = pbkdf2Key(passphrase, salt, PBKDF2_ITERATIONS)
            val pwWrap = seal(kek, dekBytes)
            writeEnvelope(fp, Envelope(env.hwWrap, pwPresent = true, salt = salt, iterations = PBKDF2_ITERATIONS, pwWrap = pwWrap))
            true
        }
    }

    /**
     * Verified-unlock hook: make sure [fingerprint] has a passphrase recovery
     * wrap, given a passphrase already known good for the key. Cheap when the
     * wrap is already present (an envelope read plus one GCM open, no PBKDF2).
     * Only ever runs the attach path here, because a verified unlock means the
     * hardware wrap is currently readable; the recover path is reachable only
     * if this is somehow called while the hardware key is gone.
     */
    fun ensureRecoveryWrap(fingerprint: String, passphrase: CharArray): Boolean {
        if (passphrase.isEmpty()) return false
        val fp = fingerprint.lowercase()
        val env = readEnvelope(fp) ?: return false
        val hw = loadHwKey()
        if (hw != null) {
            val hwOk = try { open(hw, env.hwWrap); true } catch (_: Exception) { false }
            if (hwOk) {
                return if (env.pwPresent) true else attachRecoveryPassphrase(fp, passphrase)
            }
        }
        return recoverWithPassphrase(fp, passphrase)
    }

        /** Drop the recovery wrap (e.g. the user removed the key's passphrase). */
    fun clearRecoveryPassphrase(fingerprint: String) {
        crossProcess {
            val fp = fingerprint.lowercase()
            val env = readEnvelope(fp) ?: return@crossProcess
            if (!env.pwPresent) return@crossProcess
            writeEnvelope(fp, Envelope(env.hwWrap, pwPresent = false, salt = null, iterations = 0, pwWrap = null))
        }
    }

    /** True when [fingerprint]'s DEK can't be opened by hardware but a
     *  passphrase recovery wrap exists. */
    fun needsPassphraseRecovery(fingerprint: String): Boolean {
        val fp = fingerprint.lowercase()
        val env = readEnvelope(fp) ?: return false
        if (!env.pwPresent) return false
        val hw = loadHwKey() ?: return true
        return try { open(hw, env.hwWrap); false } catch (_: Exception) { true }
    }

    /**
     * Re-derive [fingerprint]'s DEK from [passphrase] after a hardware-key
     * wipe, then re-establish a fresh hardware wrap so subsequent reads are
     * fast again. Returns true on success, false on a wrong passphrase or when
     * no recovery wrap is present.
     */
    fun recoverWithPassphrase(fingerprint: String, passphrase: CharArray): Boolean {
        if (passphrase.isEmpty()) return false
        return crossProcess {
            val fp = fingerprint.lowercase()
            val env = readEnvelope(fp) ?: return@crossProcess false
            val salt = env.salt
            val pwWrap0 = env.pwWrap
            if (!env.pwPresent || salt == null || pwWrap0 == null) return@crossProcess false
            val dekBytes = try {
                val kek = pbkdf2Key(passphrase, salt, env.iterations)
                open(kek, pwWrap0)
            } catch (e: Exception) {
                return@crossProcess false
            }
            val hwWrap = try {
                // 4.6.0 (item 17.9): reuse the live hardware key when it works.
                // Deleting it (the old regenerate-every-time) invalidated every
                // key written or recovered since the wipe, and a passphrase-less
                // key among them was lost for good. Regenerate only when there is
                // no usable key.
                seal(usableHwKey() ?: regenerateHwKey(), dekBytes)
            } catch (e: Exception) {
                Log.w(TAG, "Could not re-wrap recovered DEK under hardware for $fp: ${e.message}")
                // Recovery still succeeded logically; keep the old hw wrap.
                env.hwWrap
            }
            writeEnvelope(fp, Envelope(hwWrap, pwPresent = true, salt = salt, iterations = env.iterations, pwWrap = pwWrap0))
            true
        }
    }
}
