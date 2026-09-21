// InAppPassphraseCache.kt
// PGPony Android — 4.3.0 RC4 §3 (#15) unify all three surfaces
//
// In-memory cache for passphrases entered at IN-APP prompts (Key Detail
// export/sign/change, the Sign tab, in-app decrypt), keyed by primary
// fingerprint. Before §3 these prompts cached nothing; now they honor the
// same SessionPolicy duration as the provider and card-PIN caches. Memory
// only, so process death clears it, matching the other two.

package com.pgpony.android.session

import android.os.SystemClock
import java.util.concurrent.ConcurrentHashMap

object InAppPassphraseCache {

    private data class Entry(val passphrase: String, val storedAt: Long)

    private val entries = ConcurrentHashMap<String, Entry>()

    private fun key(fingerprint: String) = fingerprint.lowercase()

    private fun remainingMsOf(entry: Entry): Long {
        if (SessionPolicy.isLifecycleHeld()) return Long.MAX_VALUE
        val expiresAt = entry.storedAt + SessionPolicy.durationSec() * 1000L
        return (expiresAt - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
    }

    // 4.5.3 (#57): fired when a passphrase is cached after a SUCCESSFUL in-app
    // unlock (decrypt/sign). PGPonyApp wires this to add the key's SecureKeyStore
    // recovery wrap on a background thread. Left null in tests/other processes.
    @Volatile
    var onVerifiedUnlock: ((fingerprint: String, passphrase: String) -> Unit)? = null

    fun put(fingerprint: String, passphrase: String) {
        entries[key(fingerprint)] = Entry(passphrase, SystemClock.elapsedRealtime())
        try { onVerifiedUnlock?.invoke(fingerprint, passphrase) } catch (_: Exception) {}
    }

    fun get(fingerprint: String): String? {
        val entry = entries[key(fingerprint)] ?: return null
        if (remainingMsOf(entry) <= 0L) {
            entries.remove(key(fingerprint))
            return null
        }
        return entry.passphrase
    }

    fun clear(fingerprint: String) {
        entries.remove(key(fingerprint))
    }

    fun clearAll() {
        entries.clear()
    }
}
