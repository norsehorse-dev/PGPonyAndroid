// MoreLinks.kt
// PGPony Android — foss distribution flavor
//
// FOSS counterpart to the play-flavor MoreLinks. Points the "More from
// NorseHorse" AgePony action at the product website instead of the Play
// Store, so the FOSS APK carries no market:// or play.google.com strings.
// Same package, same object, same openAgePony signature as the play
// flavor, so SettingsScreen compiles unchanged in both.
//
// Phase FD2 — F-Droid link hygiene.

package com.pgpony.android.ui.settings

import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent

object MoreLinks {

    private const val AGEPONY_URL = "https://agepony.com"

    /**
     * Open the AgePony website. foss flavor: a Custom Tab to the product
     * site, falling back to onError if it cannot be launched.
     */
    fun openAgePony(context: Context, onError: () -> Unit) {
        try {
            CustomTabsIntent.Builder().build().launchUrl(
                context,
                Uri.parse(AGEPONY_URL)
            )
        } catch (e: Exception) {
            onError()
        }
    }
}
