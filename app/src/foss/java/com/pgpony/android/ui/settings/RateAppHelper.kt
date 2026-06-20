// RateAppHelper.kt
// PGPony Android — FOSS distribution flavor
//
// The FOSS build (F-Droid / IzzyOnDroid / direct APK) ships with no Google
// Play dependencies, so there is no in-app review sheet. The Rate action
// instead opens the public listing in a Custom Tab.
//
// This file deliberately mirrors the public API of the play-flavor
// RateAppHelper (same package, same object name, same requestReview
// signature) so SettingsScreen.kt compiles unchanged in both flavors.
//
// Phase FD1 — F-Droid distribution split.

package com.pgpony.android.ui.settings

import android.app.Activity
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent

object RateAppHelper {

    // The F-Droid listing goes live once the app is published there. Until
    // the listing exists you may prefer to point this at the product site,
    // "https://pgpony.app", which is always reachable. Single-line swap.
    private const val LISTING_URL =
        "https://f-droid.org/packages/com.pgpony.android/"

    /**
     * FOSS-flavor "rate" action. There is no Play in-app review sheet in
     * this build, so we open the public listing in a Custom Tab and let the
     * user take it from there. Signature matches the play flavor exactly.
     */
    fun requestReview(activity: Activity) {
        try {
            CustomTabsIntent.Builder().build().launchUrl(
                activity,
                Uri.parse(LISTING_URL)
            )
        } catch (ignored: Exception) {
            // Nothing more we can do — caller should show a snackbar.
        }
    }
}
