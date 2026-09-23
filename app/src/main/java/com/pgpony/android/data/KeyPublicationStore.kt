// KeyPublicationStore.kt
// PGPony Android, 4.6.0 (item 9): which key servers each key was published
// to, and when.
//
// The key row only knew "uploaded somewhere" (keyServerUploaded,
// lastUploadedAt), and only the Exchange upload set it. Key Detail's publish
// sheet now records every successful upload per server here, so an update
// can pre-select the servers used before and show when each last got a copy.

package com.pgpony.android.data

import android.content.Context
import com.pgpony.android.PGPonyApp
import org.json.JSONObject

object KeyPublicationStore {

    private const val PREFS = "pgpony_prefs"

    private fun key(fingerprint: String) = "published_to_${fingerprint.lowercase()}"

    private fun prefsOrNull() = runCatching {
        PGPonyApp.instance.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }.getOrNull()

    /** Server id to the epoch ms of the last successful upload of [fingerprint]. */
    fun servers(fingerprint: String): Map<String, Long> {
        val raw = prefsOrNull()?.getString(key(fingerprint), null) ?: return emptyMap()
        return runCatching {
            val o = JSONObject(raw)
            o.keys().asSequence().associateWith { o.getLong(it) }
        }.getOrDefault(emptyMap())
    }

    /** Record a successful upload of [fingerprint] to [serverId] at [atMs]. */
    fun record(fingerprint: String, serverId: String, atMs: Long = System.currentTimeMillis()) {
        val p = prefsOrNull() ?: return
        val o = JSONObject()
        servers(fingerprint).forEach { (id, t) -> o.put(id, t) }
        o.put(serverId, atMs)
        p.edit().putString(key(fingerprint), o.toString()).apply()
    }

    /** Forget every record for [fingerprint], e.g. when the key is purged. */
    fun clear(fingerprint: String) {
        prefsOrNull()?.edit()?.remove(key(fingerprint))?.apply()
    }
}
