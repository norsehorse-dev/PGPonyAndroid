// ClipboardService.kt
// PGPony Android — Phase A12
//
// Single chokepoint for clipboard writes that honors the user's
// "Auto-Clear Clipboard" setting. Mirrors iOS AppState.copyToClipboard
// (App/AppState.swift:138-154) plus startClipboardCountdown:156-169.
//
// What it does:
//
//   1. setPrimaryClip on the system ClipboardManager (label =
//      "PGPony" by default; callers can override for context, e.g.
//      "Decrypted message", "Fingerprint")
//   2. If `clipboard_auto_clear` is true in SharedPreferences, kick
//      off a coroutine that counts down for `clipboard_clear_seconds`
//      (defaults to 60) seconds, then sets the clip to empty so the
//      copied secret no longer lives in the pasteboard
//   3. Expose countdownSeconds as a StateFlow so result screens can
//      render "Clipboard will clear in Xs" inline, matching iOS's
//      Text("Clipboard will clear in \(Int(appState.clipboardCountdown))s")
//
// iOS divergences worth knowing:
//
//   • iOS 16+ has UIPasteboard.setItems(_:options:) with an
//     expirationDate option that lets the system itself clear the
//     pasteboard at a precise time — survives app death. Android has
//     no equivalent system API, so we do it in-process. If the user
//     kills the app (force-stop, OS reclaim) before the countdown
//     finishes, the clip is NOT cleared. This is a known Android
//     limitation; document in the user-visible Help screen if it
//     becomes a frequent ask. WorkManager could provide better
//     guarantees at the cost of a heavier setup.
//
//   • The countdown is best-effort UI feedback. Even on iOS where
//     the system clears the clip, the displayed countdown is
//     decremented by an in-app Timer that pauses on background.
//
// Threading: the scope uses Dispatchers.Main because the
// countdownSeconds StateFlow is consumed by Composables. Actual
// clipboard ops are cheap and synchronous on the calling thread
// (callers should be on Main already since copy is a UI action).
//
// Lifecycle: scoped to the Application process. Long-lived; one
// coroutine at a time; subsequent copies cancel the previous
// countdown (because the previous-copied content is no longer in the
// clipboard anyway — the new copy overwrote it).

package com.pgpony.android.ui.util

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

object ClipboardService {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var clearJob: Job? = null

    private val _countdownSeconds = MutableStateFlow(0)
    /** Live countdown in seconds. 0 when no auto-clear is in flight.
     *  Composables read this via collectAsState and render "Clipboard
     *  will clear in {value}s" when > 0. */
    val countdownSeconds: StateFlow<Int> = _countdownSeconds.asStateFlow()

    /**
     * Copy [text] to the system clipboard, then start the auto-clear
     * countdown if the user has the setting enabled. Idempotent in
     * the sense that calling repeatedly will cancel the previous
     * countdown and start a new one tied to the new content.
     *
     * [label] is what shows in the system clipboard preview (Android
     * 13+ shows a chip with this label). Defaults to "PGPony" so we
     * don't accidentally surface "Decrypted message" in a system
     * notification when the user is decrypting something private.
     * Callers can override when the leak risk is low (e.g.
     * "Fingerprint" for a 16-char hex string).
     */
    fun copyText(
        context: Context,
        text: String,
        label: String = "PGPony"
    ) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            ?: return  // Some test devices / restricted profiles return null; bail quietly
        cm.setPrimaryClip(ClipData.newPlainText(label, text))

        val prefs = context.getSharedPreferences(
            "pgpony_prefs",
            Context.MODE_PRIVATE
        )
        val autoClear = prefs.getBoolean("clipboard_auto_clear", true)
        if (autoClear) {
            val seconds = prefs.getInt("clipboard_clear_seconds", 60)
            startCountdown(cm, seconds)
        } else {
            // No countdown but also no leftover countdown from a
            // previous copy — clear the published value.
            cancelCountdown()
        }
    }

    private fun startCountdown(cm: ClipboardManager, seconds: Int) {
        clearJob?.cancel()
        _countdownSeconds.value = seconds
        clearJob = scope.launch {
            for (s in seconds downTo 1) {
                _countdownSeconds.value = s
                delay(1000)
            }
            _countdownSeconds.value = 0
            // Best-effort clear. We don't use ClipboardManager.clearPrimaryClip()
            // because it's API 28+ and PGPony's minSdk is 26. Empty ClipData
            // achieves the same outcome — the secret no longer lives in
            // the pasteboard — and works across the full version matrix.
            //
            // Wrap in try/catch because some OEM ROMs (notably older Huawei
            // builds) throw SecurityException on background clipboard
            // mutation. Quiet failure is acceptable since the worst case
            // is the user has to clear the clip manually.
            try {
                cm.setPrimaryClip(ClipData.newPlainText("", ""))
            } catch (e: Exception) {
                // best-effort — see comment above
            }
        }
    }

    /**
     * Cancel any in-flight countdown without altering the clipboard
     * contents. Used by [copyText] when the new copy's auto-clear
     * preference is off, and exposed publicly in case callers ever
     * need to stop the countdown without copying anything (e.g.
     * Settings → toggling off auto-clear while a countdown is live).
     */
    fun cancelCountdown() {
        clearJob?.cancel()
        clearJob = null
        _countdownSeconds.value = 0
    }
}
