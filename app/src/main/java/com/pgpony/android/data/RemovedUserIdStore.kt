// RemovedUserIdStore.kt
// PGPony Android — 4.5.1: tombstones for locally removed User IDs.
//
// Key servers are append-only: uploading a key with a User ID stripped does
// not remove it there, and a later refresh hands the UID back and overwrites
// the local copy, so a local remove would silently reappear. This store
// records the UIDs the user removed per key so the refresh merge can strip
// them again before storing (see KeyRepository.mergeFetchedPublicMaterial),
// making a local remove stick. To retire a UID for everyone, revoke it; that
// is a signature key servers accept and it survives refresh on its own.

package com.pgpony.android.data

import android.content.Context
import com.pgpony.android.PGPonyApp

object RemovedUserIdStore {

    private const val PREFS = "pgpony_prefs"

    private fun key(fingerprint: String) = "removed_uids_${fingerprint.lowercase()}"

    private fun prefsOrNull() = runCatching {
        PGPonyApp.instance.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }.getOrNull()

    /** UIDs the user has removed locally from [fingerprint]. */
    fun removed(fingerprint: String): Set<String> =
        prefsOrNull()?.getStringSet(key(fingerprint), emptySet())?.toSet() ?: emptySet()

    /** Record that [userId] was removed locally from [fingerprint]. */
    fun addRemoved(fingerprint: String, userId: String) {
        val p = prefsOrNull() ?: return
        val cur = p.getStringSet(key(fingerprint), emptySet())?.toMutableSet() ?: mutableSetOf()
        if (cur.add(userId)) p.edit().putStringSet(key(fingerprint), cur).apply()
    }

    /** Drop the tombstone for [userId], e.g. when it is deliberately re-added. */
    fun forget(fingerprint: String, userId: String) {
        val p = prefsOrNull() ?: return
        val cur = p.getStringSet(key(fingerprint), emptySet())?.toMutableSet() ?: return
        if (cur.remove(userId)) p.edit().putStringSet(key(fingerprint), cur).apply()
    }

    /** Clear every tombstone for [fingerprint], e.g. when the key is purged. */
    fun clear(fingerprint: String) {
        prefsOrNull()?.edit()?.remove(key(fingerprint))?.apply()
    }
}
