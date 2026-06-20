// KeyExpirationReceiver.kt
// PGPony Android — Phase A12
//
// BroadcastReceiver invoked by AlarmManager when one of the alarms
// scheduled by KeyExpirationService fires. Builds and posts the
// notification that prompts the user to renew their key.
//
// Lifecycle:
//   • Receiver is short-lived (onReceive runs on Main thread,
//     ~10 seconds before the system kills it). The work here must
//     complete synchronously without blocking — and it does: building
//     a NotificationCompat.Builder and calling NotificationManager.notify
//     is fast.
//   • If the POST_NOTIFICATIONS permission is missing (API 33+) the
//     notify call silently drops. We don't try to request the
//     permission from here — runtime permission requests need a
//     foreground activity.
//   • If the channel hasn't been created yet (which shouldn't
//     happen — PGPonyApp.onCreate creates it on every launch) the
//     notify also silently drops. Defensive call to
//     createNotificationChannel ensures we don't hit that case.
//
// The Intent extras come from the original PendingIntent's Intent
// that KeyExpirationService scheduled, so we trust them — they're
// not coming from an external source.

package com.pgpony.android.notifications

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.pgpony.android.MainActivity
import com.pgpony.android.R

class KeyExpirationReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_KEY_EXPIRING) return

        val fingerprint = intent.getStringExtra(EXTRA_FINGERPRINT) ?: return
        val displayName = intent.getStringExtra(EXTRA_DISPLAY_NAME)
            ?: context.getString(R.string.key_expiration_notif_display_name_fallback)
        val daysBefore = intent.getIntExtra(EXTRA_DAYS_BEFORE, -1)
        if (daysBefore < 0) return

        // Defensive — ensures channel exists even if the app process
        // died between PGPonyApp.onCreate and this alarm firing.
        KeyExpirationService.createNotificationChannel(context)

        val title = context.getString(
            R.string.key_expiration_notif_title_format,
            labelForDays(context, daysBefore)
        )
        val body = context.getString(
            R.string.key_expiration_notif_body_format,
            displayName
        )

        // Tapping the notification opens MainActivity. We don't route
        // to a specific keyring detail screen because the deep-link
        // surface for that doesn't exist yet — MainActivity's default
        // tab (Keyring) shows the list with expiration warnings, so
        // the user lands in a useful place.
        val contentIntent = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            putExtra(EXTRA_FINGERPRINT, fingerprint)
        }
        val pi = PendingIntent.getActivity(
            context,
            fingerprint.hashCode(),
            contentIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notif = NotificationCompat.Builder(context, KeyExpirationService.NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentIntent(pi)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()

        // Notification ID derived from fingerprint+daysBefore so
        // re-firing the same alarm (after a cancel/re-schedule)
        // updates the existing notification rather than stacking.
        val notificationId = fingerprint.hashCode() * 31 + daysBefore
        try {
            NotificationManagerCompat.from(context).notify(notificationId, notif)
        } catch (e: SecurityException) {
            // Missing POST_NOTIFICATIONS on API 33+. Nothing we can
            // do from a BroadcastReceiver — user has to grant via
            // Settings → toggle off + on, which re-triggers the
            // permission request in MainActivity.
        }
    }

    /** Human phrase for the days-before offset. Matches iOS
     *  KeyExpirationService.scheduleForKey:66-71. */
    private fun labelForDays(context: Context, daysBefore: Int): String = when (daysBefore) {
        30 -> context.getString(R.string.key_expiration_label_in_30_days)
        7 -> context.getString(R.string.key_expiration_label_in_7_days)
        1 -> context.getString(R.string.key_expiration_label_tomorrow)
        0 -> context.getString(R.string.key_expiration_label_today)
        else -> context.getString(R.string.key_expiration_label_in_n_days_format, daysBefore)
    }

    companion object {
        const val ACTION_KEY_EXPIRING = "com.pgpony.android.action.KEY_EXPIRING"
        const val EXTRA_FINGERPRINT = "com.pgpony.android.extra.FINGERPRINT"
        const val EXTRA_DISPLAY_NAME = "com.pgpony.android.extra.DISPLAY_NAME"
        const val EXTRA_DAYS_BEFORE = "com.pgpony.android.extra.DAYS_BEFORE"
    }
}
