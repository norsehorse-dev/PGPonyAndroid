// SecureKeyStore.kt
// PGPony Android
//
// Android equivalent of iOS KeychainService.swift.
// Uses Android Keystore (hardware-backed) for encrypting key material,
// and EncryptedSharedPreferences for storing the encrypted blobs.
//
// Key material is stored with the same naming convention as iOS:
//   "pgpony_key_{fingerprint}_public"
//   "pgpony_key_{fingerprint}_private"

package com.pgpony.android.data

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SecureKeyStore(context: Context) {

    companion object {
        private const val PREFS_FILE = "pgpony_secure_keys"
        private const val KEY_PREFIX_PUBLIC = "pgpony_key_"
        private const val KEY_SUFFIX_PUBLIC = "_public"
        private const val KEY_SUFFIX_PRIVATE = "_private"

        @Volatile
        private var instance: SecureKeyStore? = null

        fun getInstance(context: Context): SecureKeyStore {
            return instance ?: synchronized(this) {
                instance ?: SecureKeyStore(context.applicationContext).also { instance = it }
            }
        }
    }

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        PREFS_FILE,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    // ── Store ──────────────────────────────────────────────────────────

    fun storePublicKey(fingerprint: String, data: ByteArray) {
        val key = "${KEY_PREFIX_PUBLIC}${fingerprint.lowercase()}${KEY_SUFFIX_PUBLIC}"
        prefs.edit().putString(key, Base64.encodeToString(data, Base64.NO_WRAP)).apply()
    }

    fun storePrivateKey(fingerprint: String, data: ByteArray) {
        val key = "${KEY_PREFIX_PUBLIC}${fingerprint.lowercase()}${KEY_SUFFIX_PRIVATE}"
        prefs.edit().putString(key, Base64.encodeToString(data, Base64.NO_WRAP)).apply()
    }

    // ── Load ───────────────────────────────────────────────────────────

    fun loadPublicKey(fingerprint: String): ByteArray? {
        val key = "${KEY_PREFIX_PUBLIC}${fingerprint.lowercase()}${KEY_SUFFIX_PUBLIC}"
        return prefs.getString(key, null)?.let { Base64.decode(it, Base64.NO_WRAP) }
    }

    fun loadPrivateKey(fingerprint: String): ByteArray? {
        val key = "${KEY_PREFIX_PUBLIC}${fingerprint.lowercase()}${KEY_SUFFIX_PRIVATE}"
        return prefs.getString(key, null)?.let { Base64.decode(it, Base64.NO_WRAP) }
    }

    // ── Delete ─────────────────────────────────────────────────────────

    fun deleteKeys(fingerprint: String) {
        val pubKey = "${KEY_PREFIX_PUBLIC}${fingerprint.lowercase()}${KEY_SUFFIX_PUBLIC}"
        val privKey = "${KEY_PREFIX_PUBLIC}${fingerprint.lowercase()}${KEY_SUFFIX_PRIVATE}"
        prefs.edit().remove(pubKey).remove(privKey).apply()
    }

    // ── Query ──────────────────────────────────────────────────────────

    fun hasPublicKey(fingerprint: String): Boolean {
        val key = "${KEY_PREFIX_PUBLIC}${fingerprint.lowercase()}${KEY_SUFFIX_PUBLIC}"
        return prefs.contains(key)
    }

    fun hasPrivateKey(fingerprint: String): Boolean {
        val key = "${KEY_PREFIX_PUBLIC}${fingerprint.lowercase()}${KEY_SUFFIX_PRIVATE}"
        return prefs.contains(key)
    }
}
