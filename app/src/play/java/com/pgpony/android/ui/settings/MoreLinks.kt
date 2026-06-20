// MoreLinks.kt
// PGPony Android — play distribution flavor
//
// Flavor-specific "More from NorseHorse" outbound links. The play build
// points users at the Google Play listing for sibling apps. The foss build
// (F-Droid / IzzyOnDroid) points at the product website instead, so the
// FOSS APK contains no market:// or play.google.com references.
//
// Phase FD2 — F-Droid link hygiene.

package com.pgpony.android.ui.settings

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent

object MoreLinks {

    private const val AGEPONY_PKG = "com.agepony.app"

    /**
     * Open the AgePony listing. play flavor: the Play Store app via the
     * market:// scheme, falling back to the web listing in a Custom Tab,
     * then to onError if neither can be launched.
     */
    fun openAgePony(context: Context, onError: () -> Unit) {
        try {
            context.startActivity(
                Intent(
                    Intent.ACTION_VIEW,
                    Uri.parse("market://details?id=$AGEPONY_PKG")
                )
            )
        } catch (e: Exception) {
            try {
                CustomTabsIntent.Builder().build().launchUrl(
                    context,
                    Uri.parse("https://play.google.com/store/apps/details?id=$AGEPONY_PKG")
                )
            } catch (e2: Exception) {
                onError()
            }
        }
    }
}
