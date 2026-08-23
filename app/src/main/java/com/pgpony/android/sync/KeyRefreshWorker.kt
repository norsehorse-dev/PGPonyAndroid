// KeyRefreshWorker.kt
// PGPony Android — 4.0.0 Phase 5 (background keyserver refresh)
//
// Periodic WorkManager job: refresh stale held PUBLIC keys against
// every enabled lookup server in the Phase 5a directory, propagate
// revocations/expirations, and notify the user when a held key becomes
// revoked or expires upstream.
//
// Reuses the Phase 2 KeyRefreshService pipeline (verify → merge →
// revocation scan → lastCheckedAt stamp) — exactly the "so the worker
// reuses it" design. Multi-server (R2): for each stale key it fetches
// from each enabled server via MultiKeyServerService and runs the
// pipeline per copy, so a revocation published on ANY server is caught.
//
// Staleness: only keys not checked in the last 7 days are refreshed
// (OpenKeychain's cadence). Freshly-checked keys are skipped so a run
// interrupted partway resumes cheaply next period.

package com.pgpony.android.sync

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.pgpony.android.MainActivity
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.data.KeyRefreshResult
import com.pgpony.android.data.KeyRefreshService
import com.pgpony.android.keyserver.KeyServerDirectory
import com.pgpony.android.keyserver.MultiKeyServerService
import com.pgpony.android.notifications.KeyExpirationService

class KeyRefreshWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    companion object {
        private const val STALE_AFTER_MS = 7L * 24 * 60 * 60 * 1000 // 7 days
        // Notification ids for upstream-change alerts, offset from the
        // expiration-reminder id space to avoid collisions.
        private const val NOTIF_ID_BASE = 0x5A_0000
    }

    override suspend fun doWork(): Result {
        // RC1 offline switch: no keyserver refresh while offline.
        if (com.pgpony.android.network.OfflineMode.isEnabled()) return Result.success()
        val app = applicationContext as PGPonyApp
        val repo = app.keyRepository
        val refreshService = KeyRefreshService(repo)
        val service = MultiKeyServerService.shared

        // Enabled lookup servers, in order.
        val servers = KeyServerDirectory.get(applicationContext).readOnce()
            .filter { it.lookupEnabled }
        if (servers.isEmpty()) return Result.success()

        val now = System.currentTimeMillis()
        val keys = repo.getAllKeys().filter { entity ->
            // Refresh public keys that are stale and not already locally
            // revoked (a locally revoked key needs no upstream check).
            !entity.isRevoked &&
                (entity.lastCheckedAt == null || now - entity.lastCheckedAt!! > STALE_AFTER_MS)
        }
        if (keys.isEmpty()) return Result.success()

        var anyTransportSuccess = false

        for (entity in keys) {
            var current = repo.getByFingerprint(entity.fingerprint) ?: continue
            val wasRevoked = current.isRevoked
            val oldExpiry = current.expiresAt
            var becameRevoked = false

            for (server in servers) {
                val armored = try {
                    service.fetchByFingerprint(server, current.fingerprint)
                } catch (e: Exception) {
                    // Transport failure for this server — try the next.
                    continue
                }
                anyTransportSuccess = true
                if (armored.isNullOrBlank()) continue // not on this server

                when (val result = refreshService.processFetchedArmored(current, armored)) {
                    is KeyRefreshResult.RevokedUpstream -> {
                        current = result.entity
                        becameRevoked = true
                    }
                    is KeyRefreshResult.Merged -> current = result.entity
                    is KeyRefreshResult.UpToDate -> current = result.entity
                    is KeyRefreshResult.NotFound,
                    is KeyRefreshResult.Failed,
                    is KeyRefreshResult.FingerprintMismatch,
                    is KeyRefreshResult.KeyMissing -> { /* keep scanning */ }
                }
            }

            // Notify on a NEWLY detected revocation, or a NEW upstream
            // expiration that has already passed / moved earlier.
            if (becameRevoked && !wasRevoked) {
                notify(
                    id = NOTIF_ID_BASE + current.fingerprint.hashCode(),
                    title = applicationContext.getString(R.string.key_refresh_notif_revoked_title),
                    body = applicationContext.getString(
                        R.string.key_refresh_notif_revoked_body,
                        current.userName.ifEmpty { current.userEmail }
                    ),
                    fingerprint = current.fingerprint
                )
            } else if (!becameRevoked) {
                val newExpiry = current.expiresAt
                if (newExpiry != null && newExpiry != oldExpiry && newExpiry <= now) {
                    notify(
                        id = NOTIF_ID_BASE + 1 + current.fingerprint.hashCode(),
                        title = applicationContext.getString(R.string.key_refresh_notif_expired_title),
                        body = applicationContext.getString(
                            R.string.key_refresh_notif_expired_body,
                            current.userName.ifEmpty { current.userEmail }
                        ),
                        fingerprint = current.fingerprint
                    )
                }
            }
        }

        // If every server was unreachable for every key, ask WorkManager
        // to retry with backoff rather than reporting a clean success.
        return if (anyTransportSuccess || keys.isEmpty()) Result.success() else Result.retry()
    }

    private fun notify(id: Int, title: String, body: String, fingerprint: String) {
        val ctx = applicationContext
        if (!KeyExpirationService.areNotificationsEnabled(ctx)) return

        val tapIntent = Intent(ctx, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pending = PendingIntent.getActivity(
            ctx, id, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(
            ctx, KeyExpirationService.NOTIFICATION_CHANNEL_ID
        )
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()
        try {
            NotificationManagerCompat.from(ctx).notify(id, notification)
        } catch (e: SecurityException) {
            // POST_NOTIFICATIONS not granted — silently skip.
        }
    }
}
