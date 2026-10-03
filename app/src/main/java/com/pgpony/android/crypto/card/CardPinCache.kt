// CardPinCache.kt
// PGPony Android — 3.1.0 Phase 7 (B1/B2)
//
// In-memory cache for the card USER PIN (PW1), so it isn't re-typed on
// every operation. Port of iOS 7.1.x CardPINCache. Properties:
//
//   • Memory only — the PIN never touches SharedPreferences, disk, or
//     logs. Killing the app clears it by construction.
//   • The user-chosen DURATION is the boundary (B2), not lifecycle
//     events: expiry is capturedAt + duration, checked on every read.
//   • 4.0.0 Phase 9 — "Until I clear it" (iOS parity superset): the
//     sentinel DURATION_UNTIL_CLEARED holds the PIN with no expiry.
//     Wrong-PIN clearing and process-death clearing are unchanged —
//     the sentinel only removes the TIMER, never the other exits.
//   • Duration changes apply to an already-held PIN immediately (the
//     7.1.x F-item): expiry is recomputed from the CURRENT preference
//     on every read, so shortening the duration can expire a held PIN
//     on the spot and lengthening extends it. Switching to the
//     sentinel holds the current PIN indefinitely; switching away
//     re-times it from the original capture instant.
//   • Wrong PIN clears the cache (wired at OpenPgpCardSession.verify,
//     the single chokepoint every operation passes through).
//   • Only PW1 (0x81 sign / 0x82 decrypt) is ever cached. The admin
//     PIN (PW3) is never cached and admin prompts are never prefilled.
//
// The enable flag (default OFF) and duration live in the app prefs;
// the PIN itself lives only in this object's field.

package com.pgpony.android.crypto.card

import android.content.Context
import com.pgpony.android.PGPonyApp
import com.pgpony.android.session.SessionPolicy

object CardPinCache {

    private const val PREFS = "pgpony_prefs"
    const val KEY_ENABLED = "card_pin_cache_enabled"
    const val KEY_DURATION_SEC = "card_pin_cache_duration_sec"
    const val DEFAULT_DURATION_SEC = 300 // 5 minutes

    /** 4.0.0 Phase 9 — sentinel duration for "Until I clear it" (iOS
     *  CardPINCache .untilCleared). A held PIN under this mode has no
     *  timer; it clears only on wrong PIN, manual Clear, toggle-off,
     *  or process death. */
    const val DURATION_UNTIL_CLEARED = -1

    @Volatile private var pin: String? = null
    @Volatile private var capturedAt: Long = 0L

    // Returns null when the app context isn't up yet (e.g. pure-JVM unit
    // tests, where PGPonyApp.instance is an uninitialized lateinit). In
    // production the singleton is always initialized, so behavior is
    // unchanged; when it's absent the cache simply reports disabled — the
    // safe default — instead of throwing.
    // 4.6.3 (#15): MODE_MULTI_PROCESS, so the provider process (:remote_api),
    // which holds the PIN for mail apps, sees the switch as Settings left it
    // rather than the copy it loaded when it started.
    @Suppress("DEPRECATION")
    private fun prefsOrNull() = runCatching {
        PGPonyApp.instance.getSharedPreferences(PREFS, Context.MODE_MULTI_PROCESS)
    }.getOrNull()

    fun isEnabled(): Boolean = prefsOrNull()?.getBoolean(KEY_ENABLED, false) ?: false

    // §3 (#15): unified — reads the single SessionPolicy duration.
    fun durationSec(): Int = SessionPolicy.durationSec()

    /** 4.0.0 Phase 9 — true when the duration preference is the
     *  "Until I clear it" sentinel. Settings uses this to show the
     *  held state instead of a countdown. */
    fun isUntilCleared(): Boolean = SessionPolicy.isUntilCleared()

    /** Remember a successfully-verified PW1. No-op when disabled. */
    fun remember(pinValue: String) {
        if (!isEnabled()) return
        pin = pinValue
        capturedAt = System.currentTimeMillis()
    }

    /**
     * The cached PIN, or null when disabled, empty, or expired. Expiry
     * is evaluated against the CURRENT duration preference (recompute-
     * on-read — see header).
     */
    fun retrieve(): String? {
        if (!isEnabled()) return null
        val held = pin ?: return null
        if (remainingMs() <= 0) {
            clear()
            return null
        }
        return held
    }

    /** Milliseconds until the held PIN expires; 0 when none is held.
     *  Under the "Until I clear it" sentinel a held PIN reports
     *  Long.MAX_VALUE, so retrieve() and isHolding() work unchanged
     *  while Settings branches on isUntilCleared() for display. */
    fun remainingMs(): Long {
        if (pin == null) return 0L
        if (SessionPolicy.isLifecycleHeld()) return Long.MAX_VALUE
        val expiresAt = capturedAt + durationSec() * 1000L
        return (expiresAt - System.currentTimeMillis()).coerceAtLeast(0L)
    }

    fun isHolding(): Boolean = pin != null && remainingMs() > 0

    /** Drop the held PIN (wrong PIN, user request, toggle off). */
    fun clear() {
        pin = null
        capturedAt = 0L
    }

    fun setEnabled(enabled: Boolean) {
        prefsOrNull()?.edit()?.putBoolean(KEY_ENABLED, enabled)?.apply()
        if (!enabled) clear()
    }

    fun setDurationSec(seconds: Int) {
        // §3 (#15): writes the single unified SessionPolicy duration.
        SessionPolicy.setDurationSec(seconds)
    }
}
