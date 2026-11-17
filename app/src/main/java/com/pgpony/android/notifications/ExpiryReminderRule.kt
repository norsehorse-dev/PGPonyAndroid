// ExpiryReminderRule.kt
// PGPony Android, 4.8.1 (#125): which keys get an expiry reminder.
//
// Reminders were scheduled for every key with an expiry date, a contact's
// public key included, and the notification reads "Your PGP key expires" with
// "Tap to renew". Only the user can renew their own key, so reminders are for
// key pairs and card-backed keys (PGPKeyEntity.isOwnKey) that are not revoked
// or in the bin. The receiver checks again when an alarm fires, so an alarm
// set before this release, or for a key whose expiry has moved since, posts
// nothing. Kept free of Android types for the unit tests.

package com.pgpony.android.notifications

import com.pgpony.android.data.PGPKeyEntity

object ExpiryReminderRule {

    private const val MILLIS_PER_DAY: Long = 24L * 60L * 60L * 1000L

    /** Whether [key] gets reminders at all. */
    fun remindsFor(key: PGPKeyEntity): Boolean =
        key.isOwnKey && !key.isRevoked && key.deletedAt == null && key.expiresAt != null

    /**
     * Whether the alarm for [daysBefore] that fires at [nowMs] should still
     * post for [key] (null when the key is gone). The alarm may run late in
     * Doze, so it counts as due up to a day after its time; a key whose
     * expiry moved later since the alarm was set is not due yet.
     */
    fun stillDue(key: PGPKeyEntity?, daysBefore: Int, nowMs: Long): Boolean {
        if (key == null || !remindsFor(key)) return false
        val dueAt = key.expiresAt!! - daysBefore * MILLIS_PER_DAY
        return nowMs >= dueAt - MILLIS_PER_DAY && nowMs <= dueAt + MILLIS_PER_DAY
    }
}
