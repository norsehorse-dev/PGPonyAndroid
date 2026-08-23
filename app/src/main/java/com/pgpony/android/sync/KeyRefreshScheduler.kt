// KeyRefreshScheduler.kt
// PGPony Android — 4.0.0 Phase 5 (background keyserver refresh)
//
// Schedules / cancels the periodic KeyRefreshWorker via WorkManager.
// Reads the user's preferences (enable, Wi-Fi-only, interval) from the
// shared prefs the Settings "Key refresh" section writes, and encodes
// them as WorkManager constraints so the OS runs the refresh only when
// appropriate (Doze-friendly, battery-not-low, on the requested
// network). No foreground service.
//
// §6 Q4 default: enabled defaults to TRUE on the play flavor and FALSE
// on foss (F-Droid users expect no automatic network activity until
// they opt in). The default is applied in [isEnabled] so a fresh
// install schedules on play and stays quiet on foss.

package com.pgpony.android.sync

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.pgpony.android.BuildConfig
import java.util.concurrent.TimeUnit

object KeyRefreshScheduler {

    const val PREFS = "pgpony_prefs"
    const val KEY_ENABLED = "key_refresh_enabled"
    const val KEY_WIFI_ONLY = "key_refresh_wifi_only"
    const val KEY_INTERVAL_DAYS = "key_refresh_interval_days"

    private const val WORK_NAME = "pgpony_key_refresh"

    const val DEFAULT_INTERVAL_DAYS = 3
    const val DEFAULT_WIFI_ONLY = true

    /** §6 Q4 — play defaults ON, foss defaults OFF. */
    fun defaultEnabled(): Boolean = BuildConfig.FLAVOR == "play"

    fun isEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ENABLED, defaultEnabled())

    fun isWifiOnly(context: Context): Boolean =
        prefs(context).getBoolean(KEY_WIFI_ONLY, DEFAULT_WIFI_ONLY)

    fun intervalDays(context: Context): Int =
        prefs(context).getInt(KEY_INTERVAL_DAYS, DEFAULT_INTERVAL_DAYS)

    /**
     * Apply the current prefs: schedule the periodic worker when enabled,
     * cancel it when not. Idempotent — safe to call from onCreate and
     * after every settings change. Uses UPDATE so a changed interval /
     * network constraint takes effect without waiting out the old period.
     */
    fun apply(context: Context) {
        val wm = WorkManager.getInstance(context.applicationContext)
        // RC1 offline switch: offline mode cancels the periodic refresh too.
        if (!isEnabled(context) || com.pgpony.android.network.OfflineMode.isEnabled()) {
            wm.cancelUniqueWork(WORK_NAME)
            return
        }

        val networkType = if (isWifiOnly(context)) NetworkType.UNMETERED else NetworkType.CONNECTED
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(networkType)
            .setRequiresBatteryNotLow(true)
            .build()

        val request = PeriodicWorkRequestBuilder<KeyRefreshWorker>(
            intervalDays(context).toLong(), TimeUnit.DAYS
        )
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.HOURS)
            .build()

        wm.enqueueUniquePeriodicWork(
            WORK_NAME,
            // UPDATE keeps the same work but re-applies interval/constraints
            // when the user changes settings; no duplicate schedules.
            ExistingPeriodicWorkPolicy.UPDATE,
            request
        )
    }

    fun cancel(context: Context) {
        WorkManager.getInstance(context.applicationContext).cancelUniqueWork(WORK_NAME)
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
