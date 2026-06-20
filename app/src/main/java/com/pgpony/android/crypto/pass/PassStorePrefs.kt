// Phase C0 — persistence for imported pass-store references. Stored as JSON in
// SharedPreferences, matching the app's existing settings-pref convention
// (DefaultRecipientPrefs et al). The list is small (a handful of stores), so a
// serialized blob is simpler than a Room table.

package com.pgpony.android.crypto.pass

import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

object PassStorePrefs {

    private const val KEY_STORES = "pass_stores_json"

    fun load(prefs: SharedPreferences): List<PassStoreRef> {
        val json = prefs.getString(KEY_STORES, null) ?: return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                val ids = o.optJSONArray("rootGpgIds")
                PassStoreRef(
                    id = o.getString("id"),
                    displayName = o.getString("displayName"),
                    treeUri = o.getString("treeUri"),
                    rootGpgIds = if (ids != null) (0 until ids.length()).map { ids.getString(it) } else emptyList()
                )
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun save(prefs: SharedPreferences, stores: List<PassStoreRef>) {
        val arr = JSONArray()
        for (s in stores) {
            arr.put(
                JSONObject().apply {
                    put("id", s.id)
                    put("displayName", s.displayName)
                    put("treeUri", s.treeUri)
                    put("rootGpgIds", JSONArray(s.rootGpgIds))
                }
            )
        }
        prefs.edit().putString(KEY_STORES, arr.toString()).apply()
    }

    /** Add or replace a store (matched by treeUri so re-importing the same folder updates in place). */
    fun upsert(prefs: SharedPreferences, ref: PassStoreRef): List<PassStoreRef> {
        val current = load(prefs).filterNot { it.treeUri == ref.treeUri }
        val updated = current + ref
        save(prefs, updated)
        return updated
    }

    fun remove(prefs: SharedPreferences, id: String): List<PassStoreRef> {
        val updated = load(prefs).filterNot { it.id == id }
        save(prefs, updated)
        return updated
    }
}
