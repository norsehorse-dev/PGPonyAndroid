// QrPartLimit.kt
// PGPony Android, 4.8.0 RC8 (#100): the sender's QR part limit and the
// too-large message's numbers.
//
// Settings > Long QR codes (off by default) raises the limit from 32 to 512
// parts. The receiver always accepts 512 (QrChunking.parse), so only the
// sending phone has the setting. Pure Kotlin; the view models read the
// preference and pass it in.

package com.pgpony.android.qr

object QrPartLimit {

    /** SharedPreferences key in "pgpony_prefs". */
    const val PREF_KEY = "qr_long_codes"

    /** The sender's part limit for the Long QR codes setting. */
    fun maxFrames(longCodes: Boolean): Int =
        if (longCodes) QrChunking.MAX_FRAMES_LONG else QrChunking.MAX_FRAMES

    /**
     * What the too-large message says about [text]: the parts it would need,
     * the limit in force, and whether turning on Long QR codes would fit it.
     */
    data class TooLarge(val partsNeeded: Int, val limit: Int, val longCodesWouldFit: Boolean)

    fun tooLarge(text: String, longCodes: Boolean): TooLarge {
        val needed = QrChunking.partsNeeded(text)
        return TooLarge(
            partsNeeded = needed,
            limit = maxFrames(longCodes),
            longCodesWouldFit = !longCodes && needed <= QrChunking.MAX_FRAMES_LONG
        )
    }
}
