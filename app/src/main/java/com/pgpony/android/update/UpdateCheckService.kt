// UpdateCheckService.kt
// PGPony Android — 4.3.0 RC3 §5.6.9 (email, Piotr Woronowicz)
//
// In-app update check for SIDELOADED builds only. Play and F-Droid installs
// update themselves; a build downloaded from GitHub (or an RC) has no update
// path and only learns of a release by hand. This closes that gap without a
// second flavor:
//
//   • One foss artifact. The api.github.com path lives in the binary but is
//     gated dormant on managed installs (isSideloaded() is false for F-Droid
//     and Play), so F-Droid users never reach it.
//   • Opt-in, OFF by default. The Settings toggle is even offered only on a
//     sideload.
//   • Notify-and-link only. It fetches the latest release's tag, compares it
//     to this build, and on a newer one posts a notification that opens the
//     release PAGE in a browser. It never downloads or installs an APK, so
//     F-Droid's "no downloading executable binaries without consent" rule is
//     not engaged at all.
//
// fdroiddata note: because the single foss binary can talk to GitHub (a
// non-free service), the listing most likely wants a NonFreeNet antifeature
// declared. Metadata only, not a blocker. Confirm the exact label with
// F-Droid before the build.

package com.pgpony.android.update

import com.pgpony.android.network.textCapped
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.getSystemService
import com.pgpony.android.BuildConfig
import com.pgpony.android.R
import com.pgpony.android.network.HttpClientFactory
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText

object UpdateCheckService {

    const val NOTIFICATION_CHANNEL_ID = "pgpony_updates"
    private const val NOTIFICATION_ID = 43900

    const val PREF_ENABLED = "update_check_enabled"      // opt-in, default OFF
    private const val PREF_LAST_CHECK = "update_check_last_ms"
    private const val PREFS = "pgpony_prefs"
    private const val MIN_INTERVAL_MS = 24L * 60 * 60 * 1000

    private const val OWNER_REPO = "norsehorse-dev/PGPonyAndroid"
    private const val RELEASES_API = "https://api.github.com/repos/$OWNER_REPO/releases/latest"
    private const val RELEASES_PAGE = "https://github.com/$OWNER_REPO/releases/latest"

    // Installers that ship their own updates; the checker stays dormant for
    // them. Everything else (a browser download, adb, an RC) is a sideload.
    private val MANAGED_INSTALLERS = setOf(
        "org.fdroid.fdroid", "org.fdroid.basic", "com.android.vending"
    )

    fun createNotificationChannel(context: Context) {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            context.getString(R.string.update_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply { description = context.getString(R.string.update_channel_description) }
        context.getSystemService<NotificationManager>()?.createNotificationChannel(channel)
    }

    /** True when this build was NOT installed by F-Droid or Play — a sideload
     *  with no automatic update path. A null installer (adb, some browsers)
     *  counts as a sideload. */
    fun isSideloaded(context: Context): Boolean {
        val installer = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager
                    .getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            }
        } catch (e: Exception) {
            null
        }
        return installer == null || installer !in MANAGED_INSTALLERS
    }

    fun isEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(PREF_ENABLED, false)

    fun setEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(PREF_ENABLED, enabled).apply()
    }

    /** Whether the setting should even be OFFERED. Only sideloads: on F-Droid
     *  and Play the store handles updates and the toggle stays hidden. */
    fun isEligible(context: Context): Boolean = isSideloaded(context)

    /**
     * Result of a manual check, so the Settings "Check now" action can tell
     * the user what happened without a notification.
     */
    sealed class CheckResult {
        data class UpdateAvailable(val version: String) : CheckResult()
        object UpToDate : CheckResult()
        object NotEligible : CheckResult()
        object Failed : CheckResult()
    }

    /**
     * Query the latest GitHub release and, when it is newer than this build,
     * post a notification pointing at the release page. No download, no
     * install. [force] bypasses the once-a-day throttle (the manual
     * "Check now"); the launch check leaves it false.
     */
    suspend fun checkForUpdate(context: Context, force: Boolean = false): CheckResult {
        // RC1 offline switch: no update check while offline.
        if (com.pgpony.android.network.OfflineMode.isEnabled()) return CheckResult.NotEligible
        if (!isSideloaded(context) || !isEnabled(context)) return CheckResult.NotEligible
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        if (!force && now - prefs.getLong(PREF_LAST_CHECK, 0L) < MIN_INTERVAL_MS) {
            return CheckResult.UpToDate
        }
        val body = try {
            HttpClientFactory.client(context).get(RELEASES_API) {
                header("Accept", "application/vnd.github+json")
            }.textCapped(com.pgpony.android.network.ResponseLimits.MAX_METADATA_RESPONSE_BYTES) // 4.6.0 (item 17.8)
        } catch (e: Exception) {
            return CheckResult.Failed
        }
        prefs.edit().putLong(PREF_LAST_CHECK, now).apply()
        val parsed = parseLatest(body) ?: return CheckResult.Failed
        val (tag, url) = parsed
        return if (isNewer(tag, BuildConfig.VERSION_NAME)) {
            postUpdateNotification(context, tag, url)
            CheckResult.UpdateAvailable(tag)
        } else {
            CheckResult.UpToDate
        }
    }

    private fun parseLatest(body: String): Pair<String, String>? = try {
        val json = org.json.JSONObject(body)
        val tag = json.optString("tag_name").removePrefix("v").trim()
        if (tag.isEmpty()) null
        else tag to json.optString("html_url").ifBlank { RELEASES_PAGE }
    } catch (e: Exception) {
        null
    }

    /** Numeric dot-part comparison (4.3.1 > 4.3.0). Any non-numeric part
     *  (a pre-release suffix, unexpected tag shape) is treated conservatively
     *  as not-newer so a malformed tag never nags. */
    internal fun isNewer(remote: String, current: String): Boolean {
        val r = remote.split('.').map { it.toIntOrNull() ?: return false }
        val c = current.split('.').map { it.toIntOrNull() ?: return false }
        val n = maxOf(r.size, c.size)
        for (i in 0 until n) {
            val rv = r.getOrElse(i) { 0 }
            val cv = c.getOrElse(i) { 0 }
            if (rv != cv) return rv > cv
        }
        return false
    }

    private fun postUpdateNotification(context: Context, version: String, url: String) {
        if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) return
        val viewIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
        val pi = PendingIntent.getActivity(
            context, 0, viewIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notif = NotificationCompat.Builder(context, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(context.getString(R.string.update_available_title))
            .setContentText(context.getString(R.string.update_available_text, version))
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        try {
            NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notif)
        } catch (e: SecurityException) {
            // POST_NOTIFICATIONS not granted (API 33+): nothing to surface.
        }
    }
}
