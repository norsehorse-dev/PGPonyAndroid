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

import com.pgpony.android.data.settings.SettingsStores

object RemovedUserIdStore {

    private const val PREFS = SettingsStores.APP_PREFS

    private fun key(fingerprint: String) = "removed_uids_${fingerprint.lowercase()}"

    private fun prefsOrNull() = SettingsStores.open(PREFS)

    /** UIDs the user has removed locally from [fingerprint]. */
    fun removed(fingerprint: String): Set<String> =
        prefsOrNull()?.getStringSet(key(fingerprint), emptySet()) ?: emptySet()

    /** Record that [userId] was removed locally from [fingerprint]. */
    fun addRemoved(fingerprint: String, userId: String) {
        val p = prefsOrNull() ?: return
        val cur = p.getStringSet(key(fingerprint), emptySet()).toMutableSet()
        if (cur.add(userId)) p.putStringSet(key(fingerprint), cur)
    }

    /** Drop the tombstone for [userId], e.g. when it is deliberately re-added. */
    fun forget(fingerprint: String, userId: String) {
        val p = prefsOrNull() ?: return
        val cur = p.getStringSet(key(fingerprint), emptySet()).toMutableSet()
        if (cur.remove(userId)) p.putStringSet(key(fingerprint), cur)
    }

    /** Clear every tombstone for [fingerprint], e.g. when the key is purged. */
    fun clear(fingerprint: String) {
        prefsOrNull()?.remove(key(fingerprint))
    }
}
