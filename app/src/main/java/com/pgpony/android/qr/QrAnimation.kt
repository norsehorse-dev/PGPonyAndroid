// QrAnimation.kt
// PGPony Android — 4.3.0 RC3 §5.6.5 (#37, CertainBot)
//
// One source of truth for the animated multi-part QR cadence, shared by the
// Key Detail QR sheet and the Exchange tab so the two rotate in lockstep.

package com.pgpony.android.qr

object QrAnimation {
    // Keep the legacy cadence until physical-device measurements justify a new default.
    // PGPONY1 has no return channel; the sender cannot follow receiver progress.
    const val FRAME_INTERVAL_MS = 500L
    const val SLOW_FRAME_INTERVAL_MS = 1_000L
}
