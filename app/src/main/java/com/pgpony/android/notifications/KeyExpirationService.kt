// KeyExpirationService.kt
// PGPony Android — Phase A12
//
// Schedules local notifications for keys approaching expiration.
// Mirrors iOS Services/KeyExpirationService.swift functionally:
//
//   • 30 days before expiration: heads-up "Renew soon" reminder
//   • 7 days before expiration:  "Renew this week" follow-up
//   • 1 day before expiration:   "Renew tomorrow" urgent ping
//   • Day-of-expiration:         "Renew today" final ping
//
// Implementation differs significantly from iOS because Android's
// notification scheduling stack is a different shape:
//
//   • iOS uses UNUserNotificationCenter with UNCalendarNotificationTrigger,
//     which is a system-level scheduler — survives device reboot,
//     survives app process death. Android has no equivalent unified
//     API; we use AlarmManager for scheduled wake-ups + a
//     BroadcastReceiver to render the notification when the alarm
//     fires.
//
//   • Android alarms do NOT survive device reboot — they're cleared
//     by the kernel during the boot sequence. That's why
//     notifications/BootReceiver.kt listens for BOOT_COMPLETED and
//     re-invokes scheduleReminders on app boot.
//
//   • On API 31+ (Android 12) exact alarms require either the
//     SCHEDULE_EXACT_ALARM permission (a "normal" permission that
//     can be revoked by the system if abused) or USE_EXACT_ALARM
//     (API 33+, granted on install). For a low-frequency reminder
//     use case like this, inexact alarms (setWindow / setAndAllowWhileIdle)
//     are actually preferable — exact timing isn't valuable when
//     the user just needs to know "your key is expiring soon, no
//     specific hour-of-day matters". We use
//     setAndAllowWhileIdle which only escapes Doze mode but doesn't
//     require the exact-alarm permission. Notifications may fire
//     within ~15 minutes of the scheduled time on devices in Doze
//     mode; acceptable trade-off for a free permission story.
//
// Public surface:
//
//   • createNotificationChannel(context) — call from PGPonyApp.onCreate
//   • scheduleReminders(context, keys) — replaces the entire schedule
//     (cancels old + creates new)
//   • cancelAll(context, keys) — cancels every alarm for these keys
//   • REMINDER_INTERVALS_DAYS — public for tests / docs
//
// Threading:
//   All public methods are safe to call from Main or background.
//   AlarmManager / NotificationManager calls are synchronous and
//   thread-safe. Heavy operations (key fetch from the repository)
//   should happen on a background dispatcher before invoking
//   scheduleReminders — the service itself doesn't do that lifting.

package com.pgpony.android.notifications

import android.app.AlarmManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.getSystemService
import com.pgpony.android.data.PGPKeyEntity

object KeyExpirationService {

    // ── Constants ──────────────────────────────────────────────────────

    const val NOTIFICATION_CHANNEL_ID = "pgpony_key_expiration"

    // Phase A13 — channel name + description previously were `const val`
    // English strings. Now resolved via Context.getString() inside
    // createNotificationChannel() so the channel labels in
    // Settings → Apps → PGPony → Notifications localize properly.
    // The const val constants are removed because they can't reference
    // R.string.* at compile time (Android resources are runtime).

    /** Reminder offsets in days, mirroring iOS KeyExpirationService.scheduleForKey:66-70. */
    val REMINDER_INTERVALS_DAYS = intArrayOf(30, 7, 1, 0)

    // ── Channel setup ──────────────────────────────────────────────────

    /**
     * Idempotent notification channel registration. Required on
     * API 26+ before any notifications can fire. PGPony's minSdk is
     * 26 so the channel call is unconditional. Calling this multiple
     * times is safe — NotificationManager will update the channel's
     * metadata to match the latest call rather than create duplicates.
     */
    fun createNotificationChannel(context: Context) {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            context.getString(com.pgpony.android.R.string.key_expiration_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = context.getString(com.pgpony.android.R.string.key_expiration_channel_description)
            enableLights(true)
            enableVibration(true)
        }
        val nm = context.getSystemService<NotificationManager>() ?: return
        nm.createNotificationChannel(channel)
    }

    // ── Scheduling ─────────────────────────────────────────────────────

    /**
     * Replace the schedule with a fresh set of alarms for [keys] that
     * have a non-null [PGPKeyEntity.expiresAt] in the future. Cancels
     * any previously-scheduled alarms first so a re-call after a key
     * deletion or expiration date change leaves no stale alarms.
     *
     * Skips keys that have already expired (no point reminding about
     * the past). Skips reminder offsets that are already in the past
     * (e.g. a key expiring in 5 days only gets 1-day and day-of
     * alarms, not the 30-day or 7-day).
     *
     * Caller is responsible for the runtime POST_NOTIFICATIONS grant
     * on API 33+. If the grant is missing, AlarmManager.set still
     * succeeds but the eventual notification post in
     * [KeyExpirationReceiver] will be silently dropped by the
     * system. Settings UI surfaces a "Permission needed" inline
     * hint when applicable.
     */
    fun scheduleReminders(context: Context, keys: List<PGPKeyEntity>) {
        cancelAll(context, keys)

        val now = System.currentTimeMillis()
        val am = context.getSystemService<AlarmManager>() ?: return

        for (key in keys) {
            val expiresAt = key.expiresAt ?: continue
            if (expiresAt <= now) continue

            val displayName = if (key.userName.isBlank()) {
                context.getString(
                    com.pgpony.android.R.string.key_expiration_fallback_display_name_format,
                    key.fingerprint.takeLast(8).uppercase()
                )
            } else {
                key.userName
            }

            for (daysBefore in REMINDER_INTERVALS_DAYS) {
                val triggerAt = expiresAt - daysBefore * MILLIS_PER_DAY
                if (triggerAt <= now) continue  // already in the past

                val intent = Intent(context, KeyExpirationReceiver::class.java).apply {
                    action = KeyExpirationReceiver.ACTION_KEY_EXPIRING
                    putExtra(KeyExpirationReceiver.EXTRA_FINGERPRINT, key.fingerprint)
                    putExtra(KeyExpirationReceiver.EXTRA_DISPLAY_NAME, displayName)
                    putExtra(KeyExpirationReceiver.EXTRA_DAYS_BEFORE, daysBefore)
                }
                val pi = pendingIntentFor(context, key.fingerprint, daysBefore, intent, mutable = false)
                // setAndAllowWhileIdle: fires even in Doze mode, but
                // may be deferred up to ~15 minutes on idle devices.
                // Acceptable for "renew your key" — exact hour of
                // day doesn't matter for the user's task. Avoids
                // the SCHEDULE_EXACT_ALARM permission story.
                am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAt, pi)
            }
        }
    }

    /**
     * Cancel every alarm previously scheduled for [keys]. Used when
     * the user toggles reminders off, or before re-scheduling a fresh
     * batch. We compute the same (fingerprint, daysBefore) pairs as
     * scheduleReminders would, so the PendingIntent.requestCode
     * values match.
     *
     * Note: this does NOT cancel alarms for keys that were deleted
     * since the last schedule. If you call cancelAll(currentKeys)
     * after a key deletion, the deleted key's alarms persist until
     * they fire (at which point KeyExpirationReceiver checks the
     * repository and silently drops notifications for missing keys).
     * Robust but not pristine — see Receiver.kt for the second-pass
     * sanity check.
     */
    fun cancelAll(context: Context, keys: List<PGPKeyEntity>) {
        val am = context.getSystemService<AlarmManager>() ?: return
        for (key in keys) {
            for (daysBefore in REMINDER_INTERVALS_DAYS) {
                val intent = Intent(context, KeyExpirationReceiver::class.java).apply {
                    action = KeyExpirationReceiver.ACTION_KEY_EXPIRING
                }
                val pi = pendingIntentFor(context, key.fingerprint, daysBefore, intent, mutable = false)
                am.cancel(pi)
                pi.cancel()
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────

    private fun pendingIntentFor(
        context: Context,
        fingerprint: String,
        daysBefore: Int,
        intent: Intent,
        mutable: Boolean
    ): PendingIntent {
        // Deterministic request code so cancel-by-recompute works.
        // hashCode for the fingerprint string is stable across processes
        // (Java spec — same chars produce same hash) which is what
        // we need; the daysBefore offset is folded in via prime
        // multiplication to avoid collisions when two keys' fingerprints
        // happen to have similar hashes.
        val requestCode = fingerprint.hashCode() * 31 + daysBefore
        // FLAG_IMMUTABLE is API 23+ so always available given minSdk=26.
        // FLAG_MUTABLE is API 31+ — for the older window we just fall
        // through to the default mutability. In practice every
        // PendingIntent we build here is immutable; the `mutable`
        // parameter is here for future-proofing.
        val flagsBase = PendingIntent.FLAG_UPDATE_CURRENT
        val flags = when {
            !mutable -> flagsBase or PendingIntent.FLAG_IMMUTABLE
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                flagsBase or PendingIntent.FLAG_MUTABLE
            else -> flagsBase
        }
        return PendingIntent.getBroadcast(context, requestCode, intent, flags)
    }

    private const val MILLIS_PER_DAY: Long = 24L * 60L * 60L * 1000L

    /** Convenience for the Settings screen / about screen. Returns
     *  whether NotificationManagerCompat thinks app-wide notifications
     *  are currently enabled. On API 33+ this reflects the
     *  POST_NOTIFICATIONS runtime grant. On older APIs it reflects
     *  the per-app notification toggle in System Settings. */
    fun areNotificationsEnabled(context: Context): Boolean {
        return NotificationManagerCompat.from(context).areNotificationsEnabled()
    }
}
