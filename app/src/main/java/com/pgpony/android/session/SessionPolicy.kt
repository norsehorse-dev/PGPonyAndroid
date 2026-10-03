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
//
// 4.6.3 (#15, reopened): the duration lives in its own small file
// (files/session_policy), written atomically and read straight from disk.
// 4.6.1 moved the pgpony_prefs read to MODE_MULTI_PROCESS, and mail apps still
// kept a passphrase for exactly the 5-minute default whatever was chosen, even
// after a force stop. SharedPreferences is not a cross-process store: each
// process keeps its own copy of the whole file in memory, and an apply() from
// one process writes that whole copy back, so a write made from a copy loaded
// before the duration changed puts back a file without it. A file that only this object writes, and that every read goes
// to, has no second copy to go stale. The pgpony_prefs value is still written,
// for a downgrade, and read once when the file does not exist yet.

package com.pgpony.android.session

import android.content.Context
import com.pgpony.android.PGPonyApp
import java.io.File

object SessionPolicy {

    private const val PREFS = "pgpony_prefs"
    const val KEY_DURATION_SEC = "session_cache_duration_sec"
    const val DEFAULT_DURATION_SEC = 300 // 5 minutes

    const val DURATION_UNTIL_CLEARED = -1
    const val DURATION_UNTIL_LOCKED = -2

    /** 4.6.3 (#15): the file both processes read; see the header. */
    const val POLICY_FILE = "session_policy"

    private fun contextOrNull(): Context? = runCatching { PGPonyApp.instance }.getOrNull()

    private fun policyFile(ctx: Context) = File(ctx.filesDir, POLICY_FILE)

    // Kept for the one-time read of a duration chosen before 4.6.3, and
    // written alongside the file so a downgrade keeps the user's choice.
    @Suppress("DEPRECATION")
    private fun prefsOrNull(ctx: Context) = runCatching {
        ctx.getSharedPreferences(PREFS, Context.MODE_MULTI_PROCESS)
    }.getOrNull()

    /** A stored value, or null when it is not one this policy offers. */
    fun parse(text: String?): Int? {
        val v = text?.trim()?.toIntOrNull() ?: return null
        return v.takeIf { it > 0 || it == DURATION_UNTIL_CLEARED || it == DURATION_UNTIL_LOCKED }
    }

    fun durationSec(): Int {
        val ctx = contextOrNull() ?: return DEFAULT_DURATION_SEC
        val fromFile = runCatching {
            val f = policyFile(ctx)
            if (f.isFile) parse(f.readText()) else null
        }.getOrNull()
        if (fromFile != null) return fromFile
        return prefsOrNull(ctx)?.getInt(KEY_DURATION_SEC, DEFAULT_DURATION_SEC)
            ?.let { parse(it.toString()) } ?: DEFAULT_DURATION_SEC
    }

    fun setDurationSec(seconds: Int) {
        val ctx = contextOrNull() ?: return
        val value = parse(seconds.toString()) ?: return
        runCatching {
            val target = policyFile(ctx)
            val tmp = File(ctx.filesDir, "$POLICY_FILE.tmp")
            tmp.writeText(value.toString())
            if (!tmp.renameTo(target)) {
                target.writeText(value.toString())
                tmp.delete()
            }
        }
        prefsOrNull(ctx)?.edit()?.putInt(KEY_DURATION_SEC, value)?.apply()
    }

    fun isUntilCleared(): Boolean = durationSec() == DURATION_UNTIL_CLEARED
    fun isUntilLocked(): Boolean = durationSec() == DURATION_UNTIL_LOCKED

    /** True under either lifecycle sentinel: a held secret has no timer and
     *  is cleared by an event (manual/lock) rather than by expiry. */
    fun isLifecycleHeld(): Boolean = isUntilCleared() || isUntilLocked()
}
