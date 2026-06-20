// RateAppHelper.kt
// PGPony Android
//
// Wraps Google Play's In-App Review API so the user can rate PGPony without
// leaving the app. If the in-app sheet can't be shown (Play Services missing,
// quota exceeded, etc.) we fall back to opening the Play Store listing.
//
// Added in Phase 1 (Tester Feedback Implementation Plan).

package com.pgpony.android.ui.settings

import android.app.Activity
import android.content.Intent
import android.net.Uri
import com.google.android.play.core.review.ReviewException
import com.google.android.play.core.review.ReviewManagerFactory

object RateAppHelper {

    /**
     * Request the Play In-App Review flow. Falls back to opening the
     * Play Store listing if the in-app sheet isn't available.
     */
    fun requestReview(activity: Activity) {
        val manager = ReviewManagerFactory.create(activity)
        val request = manager.requestReviewFlow()
        request.addOnCompleteListener { task ->
            if (task.isSuccessful) {
                try {
                    val flow = manager.launchReviewFlow(activity, task.result)
                    flow.addOnCompleteListener {
                        // Always succeeds from the user's perspective — Google
                        // does NOT tell us whether they actually rated.
                    }
                } catch (e: Exception) {
                    openPlayStoreFallback(activity)
                }
            } else {
                val cause = task.exception
                if (cause is ReviewException) {
                    openPlayStoreFallback(activity)
                } else {
                    openPlayStoreFallback(activity)
                }
            }
        }
    }

    /**
     * Open the PGPony listing on the Play Store app, or fall back to the
     * web Play Store URL if the Play Store app isn't installed.
     */
    private fun openPlayStoreFallback(activity: Activity) {
        val marketUri = Uri.parse("market://details?id=com.pgpony.android")
        val marketIntent = Intent(Intent.ACTION_VIEW, marketUri).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            activity.startActivity(marketIntent)
        } catch (e: Exception) {
            val webUri = Uri.parse(
                "https://play.google.com/store/apps/details?id=com.pgpony.android"
            )
            try {
                activity.startActivity(
                    Intent(Intent.ACTION_VIEW, webUri).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                )
            } catch (ignored: Exception) {
                // Nothing more we can do — caller should show a snackbar.
            }
        }
    }
}
