// ProviderWindowGuard.kt
// PGPony Android, 4.6.0 (item 17.7): window protection for the OpenPGP API's
// own screens (consent, passphrase, card PIN, key picker).
//
// These run in the :remote_api task, which MainActivity's Recents protection
// never covered, and ApiConsentActivity is the only gate that grants another
// app encrypt / decrypt / sign access. Each screen therefore:
//   * sets FLAG_SECURE, so a passphrase, PIN or the consent text cannot be
//     screenshotted, recorded, or shown in the Recents thumbnail;
//   * hides other apps' overlay windows on Android 12+ (HIDE_OVERLAY_WINDOWS);
//   * drops any touch that arrives while another window obscures it, on every
//     API level, so a tapjacking overlay cannot steal the "Allow" tap.

package com.pgpony.android.provider

import android.app.Activity
import android.os.Build
import android.view.MotionEvent
import android.view.WindowManager

internal object ProviderWindowGuard {

    fun harden(activity: Activity) {
        activity.window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            runCatching { activity.window.setHideOverlayWindows(true) }
        }
    }

    /** True when [ev] should be dropped because another window covers ours. */
    fun isObscured(ev: MotionEvent): Boolean {
        val obscured = MotionEvent.FLAG_WINDOW_IS_OBSCURED or
            (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED else 0)
        return (ev.flags and obscured) != 0
    }
}
