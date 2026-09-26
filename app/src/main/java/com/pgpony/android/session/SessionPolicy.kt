// SessionPolicy.kt
// PGPony Android — 4.3.0 RC4 §3 (#15 deferred half) unified session policy
//
// ONE "how long a secret stays unlocked" duration that the provider
// passphrase cache, the card PIN cache, and the in-app passphrase prompts
// all read, so a user who sets "1 hour" gets it everywhere and the caches
// cannot disagree. Two lifecycle sentinels sit beside the timed durations:
//
//   DURATION_UNTIL_CLEARED (-1): held with no timer; cleared only on manual
//     Clear, wrong secret, invalidation, or process death.
//   DURATION_UNTIL_LOCKED (-2): held with no timer; ALSO cleared when the
//     phone locks (SessionLockReceiver, screen-off with a secure keyguard).

package com.pgpony.android.session

import android.content.Context
import com.pgpony.android.PGPonyApp

object SessionPolicy {

    private const val PREFS = "pgpony_prefs"
    const val KEY_DURATION_SEC = "session_cache_duration_sec"
    const val DEFAULT_DURATION_SEC = 300 // 5 minutes

    const val DURATION_UNTIL_CLEARED = -1
    const val DURATION_UNTIL_LOCKED = -2

    // 4.6.1 (#15): MODE_MULTI_PROCESS, like the provider's other shared
    // settings. The OpenPGP provider and its passphrase and PIN caches run in
    // the :remote_api process, whose MODE_PRIVATE instance caches the file on
    // first read and never sees a duration changed later in Settings; mail
    // apps then kept the 5-minute default. This mode re-reads the file on
    // each getSharedPreferences call, so every read here is current.
    @Suppress("DEPRECATION")
    private fun prefsOrNull() = runCatching {
        PGPonyApp.instance.getSharedPreferences(PREFS, Context.MODE_MULTI_PROCESS)
    }.getOrNull()

    fun durationSec(): Int =
        prefsOrNull()?.getInt(KEY_DURATION_SEC, DEFAULT_DURATION_SEC) ?: DEFAULT_DURATION_SEC

    fun setDurationSec(seconds: Int) {
        prefsOrNull()?.edit()?.putInt(KEY_DURATION_SEC, seconds)?.apply()
    }

    fun isUntilCleared(): Boolean = durationSec() == DURATION_UNTIL_CLEARED
    fun isUntilLocked(): Boolean = durationSec() == DURATION_UNTIL_LOCKED

    /** True under either lifecycle sentinel: a held secret has no timer and
     *  is cleared by an event (manual/lock) rather than by expiry. */
    fun isLifecycleHeld(): Boolean = isUntilCleared() || isUntilLocked()
}
