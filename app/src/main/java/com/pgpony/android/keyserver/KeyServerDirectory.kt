// KeyServerDirectory.kt
// PGPony Android — 4.0.0 Phase 5a (multi-keyserver model)
//
// Replaces the single hardcoded keys.openpgp.org assumption with an
// ORDERED, user-editable list of key servers, persisted in DataStore
// (the ArmorCommentSettings pattern). Mirrors iOS 8.0.0 Phase C.
//
// v1 seeds two entries, both enabled:
//   1. keys.openpgp.org  — lookup PRIORITY. IETF/RFC-9580 Hagrid VKS,
//      verified-email model. Days-old keys.pgpony.app is still nearly
//      empty, so the mature server stays the default lookup source
//      (plan §1 constraint).
//   2. keys.pgpony.app   — first-party, co-default PUBLISH target.
//      Same VKS semantics, onion-reachable, accepts every key type.
//
// Lookup queries enabled servers IN ORDER and merges by fingerprint
// (KeyServerRepository); publish offers a per-server checkbox with
// both pre-checked (PublishSheet).
//
// R5 — per-server key-type compatibility: keys.openpgp.org (and any
// server flagged non-first-party VKS) is likely to reject anything
// that isn't RSA or v4 Ed25519 — v6, ML-KEM composites, LibrePGP. The
// mayNotAccept() capability check drives a non-coercive publish
// warning; keys.pgpony.app and user-added servers are never flagged.

package com.pgpony.android.keyserver

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.pgpony.android.crypto.KeyAlgorithm
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

private val Context.keyServerDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "keyserver_directory"
)

/**
 * One key server in the ordered directory.
 *
 * @param id        stable identifier (host for the seeds; a UUID for
 *                  user-added entries) — used as the DataStore key and
 *                  the per-(key,server) verification-status key.
 * @param label     user-facing name.
 * @param baseUrl   scheme + host, no trailing slash (e.g.
 *                  "https://keys.openpgp.org"). VKS/HKP paths are
 *                  appended by the repository.
 * @param isFirstParty  keys.pgpony.app — never flagged for key-type
 *                  compatibility (it accepts everything), and the
 *                  "maintained infrastructure" story.
 * @param lookupEnabled / publishEnabled  independent toggles; a server
 *                  can be lookup-only, publish-only, or both.
 * @param acceptsAllKeyTypes  when false, mayNotAccept() flags v6 / PQC /
 *                  LibrePGP for the R5 publish warning. True for the
 *                  first-party server and any user-added one (we don't
 *                  presume to know a custom server's limits).
 */
data class KeyServer(
    val id: String,
    val label: String,
    val baseUrl: String,
    val isFirstParty: Boolean,
    val lookupEnabled: Boolean,
    val publishEnabled: Boolean,
    val acceptsAllKeyTypes: Boolean
) {
    /**
     * R5: is this server likely to REJECT [algorithm]? A verified-email
     * VKS like keys.openpgp.org (RFC 9580, no PQC/LibrePGP, v6
     * unconfirmed) is flagged for anything that isn't RSA or v4
     * Ed25519. Servers that accept everything (first-party, custom)
     * never flag — the check relaxes as pgpony.app/keys.openpgp.org
     * confirm which types they take.
     */
    fun mayNotAccept(algorithm: KeyAlgorithm): Boolean {
        if (acceptsAllKeyTypes) return false
        return when (algorithm) {
            KeyAlgorithm.RSA_2048,
            KeyAlgorithm.RSA_4096,
            KeyAlgorithm.ED25519_CV25519 -> false
            else -> true // v6 variants (and future composite PQC) → flag
        }
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("label", label)
        put("baseUrl", baseUrl)
        put("isFirstParty", isFirstParty)
        put("lookupEnabled", lookupEnabled)
        put("publishEnabled", publishEnabled)
        put("acceptsAllKeyTypes", acceptsAllKeyTypes)
    }

    companion object {
        fun fromJson(o: JSONObject): KeyServer = KeyServer(
            id = o.getString("id"),
            label = o.getString("label"),
            baseUrl = o.getString("baseUrl"),
            isFirstParty = o.optBoolean("isFirstParty", false),
            lookupEnabled = o.optBoolean("lookupEnabled", true),
            publishEnabled = o.optBoolean("publishEnabled", true),
            acceptsAllKeyTypes = o.optBoolean("acceptsAllKeyTypes", true)
        )
    }
}

class KeyServerDirectory private constructor(private val appContext: Context) {

    companion object {
        const val ID_OPENPGP = "keys.openpgp.org"
        const val ID_PGPONY = "keys.pgpony.app"

        private val LIST_KEY = stringPreferencesKey("servers_json")

        /**
         * The seed list — order matters (lookup priority). Public so the
         * Settings "reset to defaults" and first-run both use it.
         */
        val DEFAULTS: List<KeyServer> = listOf(
            KeyServer(
                id = ID_OPENPGP,
                label = "keys.openpgp.org",
                baseUrl = "https://keys.openpgp.org",
                isFirstParty = false,
                lookupEnabled = true,
                publishEnabled = true,
                // Verified-email VKS, no PQC/LibrePGP, v6 unconfirmed → flag.
                acceptsAllKeyTypes = false
            ),
            KeyServer(
                id = ID_PGPONY,
                label = "keys.pgpony.app",
                baseUrl = "https://keys.pgpony.app",
                isFirstParty = true,
                lookupEnabled = true,
                publishEnabled = true,
                acceptsAllKeyTypes = true
            )
        )

        /** True for the two built-in seeds, which can be toggled/reordered
         *  but not removed (Reset to defaults restores them). */
        fun isSeed(id: String): Boolean = id == ID_OPENPGP || id == ID_PGPONY

        /**
         * item 6 (#55): validate and normalize a user-entered key server URL to
         * "scheme://host[:port]" (no path, no trailing slash). Defaults a missing
         * scheme to https. Returns null when the input is not a usable HKPS/HKP
         * base URL, which the Settings UI surfaces as an inline error.
         */
        fun normalizeBaseUrl(input: String): String? {
            val trimmed = input.trim()
            if (trimmed.isEmpty()) return null
            val withScheme =
                if (Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://").containsMatchIn(trimmed)) trimmed
                else "https://$trimmed"
            return try {
                val uri = java.net.URI(withScheme)
                val scheme = uri.scheme?.lowercase() ?: return null
                if (scheme != "https" && scheme != "http") return null
                val host = uri.host?.lowercase() ?: return null
                if (host.isBlank() || host.startsWith('.') || host.endsWith('.')) return null
                // Require a dotted host, unless an explicit port is given (allows
                // a self-hosted "localhost:11371" while rejecting bare typos).
                if (!host.contains('.') && uri.port <= 0) return null
                val port = if (uri.port > 0) ":${uri.port}" else ""
                "$scheme://$host$port"
            } catch (e: Exception) {
                null
            }
        }

        @Volatile
        private var instance: KeyServerDirectory? = null

        fun get(context: Context): KeyServerDirectory =
            instance ?: synchronized(this) {
                instance ?: KeyServerDirectory(context.applicationContext).also { instance = it }
            }
    }

    /** Observable ordered list; emits DEFAULTS until the user edits it. */
    val serversFlow: Flow<List<KeyServer>> =
        appContext.keyServerDataStore.data.map { prefs ->
            prefs[LIST_KEY]?.let { parse(it) } ?: DEFAULTS
        }

    suspend fun save(servers: List<KeyServer>) {
        val arr = JSONArray()
        servers.forEach { arr.put(it.toJson()) }
        appContext.keyServerDataStore.edit { it[LIST_KEY] = arr.toString() }
    }

    suspend fun setLookupEnabled(id: String, enabled: Boolean) =
        update { s -> if (s.id == id) s.copy(lookupEnabled = enabled) else s }

    suspend fun setPublishEnabled(id: String, enabled: Boolean) =
        update { s -> if (s.id == id) s.copy(publishEnabled = enabled) else s }

    /** Move [id] up (toward higher lookup priority) or down by one slot. */
    suspend fun move(id: String, up: Boolean) {
        val list = readOnce().toMutableList()
        val i = list.indexOfFirst { it.id == id }
        if (i < 0) return
        val j = if (up) i - 1 else i + 1
        if (j < 0 || j >= list.size) return
        val tmp = list[i]; list[i] = list[j]; list[j] = tmp
        save(list)
    }

    /**
     * item 6 (#55): add a user-defined key server. [baseUrl] is validated and
     * normalized via [normalizeBaseUrl]; an invalid URL returns null and nothing
     * is saved. A duplicate baseUrl returns the existing entry rather than adding
     * a second. New servers default to lookup + publish enabled and are assumed
     * to accept every key type (we do not presume a custom server's limits).
     */
    suspend fun addCustom(label: String, baseUrl: String): KeyServer? {
        val normalized = normalizeBaseUrl(baseUrl) ?: return null
        val existing = readOnce()
        existing.firstOrNull { it.baseUrl.equals(normalized, ignoreCase = true) }?.let { return it }
        val server = KeyServer(
            id = java.util.UUID.randomUUID().toString(),
            label = label.trim().ifBlank { normalized.substringAfter("://") },
            baseUrl = normalized,
            isFirstParty = false,
            lookupEnabled = true,
            publishEnabled = true,
            acceptsAllKeyTypes = true
        )
        save(existing + server)
        return server
    }

    /** item 6 (#55): remove a custom server. The two seeds are protected (toggle
     *  them off instead); a seed id is a no-op. */
    suspend fun remove(id: String) {
        if (isSeed(id)) return
        save(readOnce().filterNot { it.id == id })
    }

    suspend fun resetToDefaults() = save(DEFAULTS)

    private suspend fun update(transform: (KeyServer) -> KeyServer) {
        save(readOnce().map(transform))
    }

    /** Read the persisted list once (or DEFAULTS). Used by the
     *  repository and the background refresh worker. */
    suspend fun readOnce(): List<KeyServer> = serversFlow.first()

    private fun parse(json: String): List<KeyServer> = try {
        val arr = JSONArray(json)
        (0 until arr.length()).map { KeyServer.fromJson(arr.getJSONObject(it)) }
            .ifEmpty { DEFAULTS }
    } catch (e: Exception) {
        DEFAULTS
    }
}
