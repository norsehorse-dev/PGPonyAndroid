// ShareTargetActivity.kt
// PGPony Android — Phase A15
//
// Standalone activity that handles incoming share/view intents
// without launching the full main app. Mirrors the iOS PGPonyAction
// extension target.
//
// Lifecycle:
//
//   1. onCreate fires from one of these intent triggers (declared in
//      AndroidManifest.xml):
//        • ACTION_SEND  text/plain — someone shared text to us
//        • ACTION_SEND  with EXTRA_STREAM — someone shared a file
//        • ACTION_VIEW  application/pgp-encrypted | application/pgp-keys
//        • ACTION_VIEW  file://*.pgp / .gpg / .asc
//        • ACTION_VIEW  content:// + pathPattern *.asc / *.pgp / *.gpg
//
//   2. We classify the intent via IntentHandler.classifyShareIntent()
//      into a ShareIntentContent. The classification is cheap (small
//      file read + a few string contains() calls) so it happens
//      synchronously on the main thread before the first frame.
//
//   3. ViewModel created with ShareTargetViewModel.factory() and
//      seeded via initialize(content). Initialize fires a background
//      coroutine to load the keyring from Room — the UI shows the
//      "no recipients / no key pairs" empty states briefly until
//      that load completes (typically <200ms).
//
//   4. UI renders inside PGPonyTheme so theme picker carries over
//      (light/dark/system mirrors MainActivity). The activity uses
//      the standard FILL theme — not a dialog, not a bottom sheet —
//      because the share flow can show 6+ rows of recipients which
//      would crowd a constrained surface. Floating dialog activities
//      look cute on first impression but degrade fast once content
//      grows.
//
//   5. finish() returns control to the source app. excludeFromRecents
//      is intentionally NOT set: the activity does appear in Recents
//      while it's running, but is a separate task entry from the main
//      app (taskAffinity=""), so dismissing it doesn't drag the main
//      app's task into focus.
//
// Note about onNewIntent: ShareTargetActivity is launchMode="singleTop"
// so a second share while one is already open will replace the
// existing flow rather than stacking. The ViewModel reset path
// (re-initialize) handles this.

package com.pgpony.android.ui.share

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.pgpony.android.PGPonyApp
import com.pgpony.android.PGPonyTheme
import com.pgpony.android.crypto.card.OpenPgpCardSession
import com.pgpony.android.intent.IntentHandler
import com.pgpony.android.intent.ShareIntentContent
import com.pgpony.android.nfc.OpenPgpCardReader

class ShareTargetActivity : AppCompatActivity() {

    private val vm: ShareTargetViewModel by viewModels {
        ShareTargetViewModel.factory(PGPonyApp.instance.keyRepository)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val content = IntentHandler.classifyShareIntent(intent, contentResolver)
        vm.initialize(content)

        setContent {
            PGPonyTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    ShareTargetScreen(
                        vm = vm,
                        onDismiss = { finish() },
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        // Reusing a single-top activity for a fresh share: reclassify
        // and reinitialize. The user is opting into a new task, so
        // any in-flight state from a prior share is discarded.
        setIntent(intent)
        val content = IntentHandler.classifyShareIntent(intent, contentResolver)
        vm.goBackToActionPicker()
        vm.initialize(content)
    }

    // ── HW Phase 3 — NFC OpenPGP-card reader (share-target card decrypt) ──
    //
    // The share flow runs in its own activity, and NFC reader mode binds to
    // the foreground activity, so it needs its own reader rather than
    // reaching into MainActivity. Mirrors MainActivity's small wrapper
    // (no biometric auto-lock here — the share activity has no lock gate).
    private var cardReader: OpenPgpCardReader? = null

    fun isNfcAvailable(): Boolean = OpenPgpCardReader.isNfcAvailable(this)

    fun isNfcEnabled(): Boolean = OpenPgpCardReader.isNfcEnabled(this)

    fun <T> startCardOperation(
        operation: (OpenPgpCardSession) -> T,
        onResult: (Result<T>) -> Unit
    ): Boolean {
        val reader = OpenPgpCardReader(this)
        cardReader = reader
        val started = reader.startOperation(operation, onResult)
        if (!started) cardReader = null
        return started
    }

    fun stopCardScan() {
        cardReader?.stop()
        cardReader = null
    }
}
