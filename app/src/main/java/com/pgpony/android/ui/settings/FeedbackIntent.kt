// FeedbackIntent.kt
// PGPony Android
//
// Launches the user's email client with a pre-filled "Send Feedback" message
// addressed to norsehorse@norsehor.se, including device + version info
// so reports are actionable without back-and-forth.
//
// Added in Phase 1 (Tester Feedback Implementation Plan).

package com.pgpony.android.ui.settings

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build

object FeedbackIntent {

    const val FEEDBACK_EMAIL = "norsehorse@norsehor.se"

    /**
     * Launches the user's preferred email client with a prefilled feedback
     * email. Returns true if an email client opened, false otherwise (so the
     * caller can show a snackbar offering to copy the address instead).
     */
    fun launch(context: Context, versionName: String): Boolean {
        val device = "${Build.MANUFACTURER} ${Build.MODEL}"
        val sdk = Build.VERSION.SDK_INT
        val release = Build.VERSION.RELEASE

        val bodyTemplate = """
            
            
            ---
            App version: $versionName
            Device: $device
            Android: $release (SDK $sdk)
        """.trimIndent()

        val uri = Uri.parse(
            "mailto:$FEEDBACK_EMAIL" +
                "?subject=" + Uri.encode("PGPony Android Feedback ($versionName)") +
                "&body=" + Uri.encode(bodyTemplate)
        )
        val intent = Intent(Intent.ACTION_SENDTO, uri).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return try {
            context.startActivity(intent)
            true
        } catch (e: Exception) {
            false
        }
    }
}
