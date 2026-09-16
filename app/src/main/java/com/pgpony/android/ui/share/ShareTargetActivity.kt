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
import com.pgpony.android.saf.DocumentCreatorHost
import com.pgpony.android.saf.SafDocumentCreator

class ShareTargetActivity : AppCompatActivity(), DocumentCreatorHost {

    private val vm: ShareTargetViewModel by viewModels {
        ShareTargetViewModel.factory(PGPonyApp.instance.keyRepository)
    }

    // ── 3.1.0 Phase 1 Fix3 — detached-signature forward ────────────────
    //
    // The Quick Action has no verify flow, so a shared/opened detached
    // signature (armored or binary) dead-ended here: the picker offered
    // Encrypt/Decrypt, neither of which makes sense for a signature.
    // Instead of growing a verify phase in this activity, forward the
    // signature to MainActivity's Verify-a-file sheet — the same route
    // the main app's own intent handling uses — and finish. Signature
    // bytes ride as an extra (they're tiny; FORWARD_SIZE_LIMIT guards
    // the degenerate case, which falls through to the normal picker
    // rather than risking a TransactionTooLargeException).
    //
    // Returns true when the content was forwarded and this activity
    // should not render.
    private fun forwardDetachedSignatureIfNeeded(content: ShareIntentContent): Boolean {
        val file = content as? ShareIntentContent.PgpFile ?: return false
        if (!file.looksLikeDetachedSignature) return false
        // 4.0.4 — data is null only for a file too large to buffer, and
        // classifyLargeFileForShare never flags one of those as a
        // detached signature (it hands those back to the buffered path).
        // Belt and braces: no bytes means nothing to forward.
        val sigBytes = file.data ?: return false
        if (sigBytes.size > IntentHandler.FORWARD_SIZE_LIMIT) return false
        val forward = android.content.Intent(this, com.pgpony.android.MainActivity::class.java).apply {
            action = IntentHandler.ACTION_VERIFY_DETACHED
            putExtra(IntentHandler.EXTRA_SIGNATURE_BYTES, sigBytes)
            putExtra(IntentHandler.EXTRA_SIGNATURE_NAME, file.filename)
            // CLEAR_TOP + SINGLE_TOP: deliver to an existing MainActivity
            // via onNewIntent instead of stacking a second instance in
            // this activity's (affinity-less) task; NEW_TASK sends it to
            // the main app's own task when none is running.
            addFlags(
                android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                    android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP
            )
        }
        startActivity(forward)
        finish()
        return true
    }

    /** 4.5.1 (#58): the "Encrypt in PGPony" share entry is an alias of this
     *  activity. Launched through it, forward the shared text straight to the
     *  Encrypt screen as plaintext instead of classifying it. */
    private fun forwardEncryptTextIfNeeded(intent: android.content.Intent): Boolean {
        if (componentName.className != ENCRYPT_TEXT_ALIAS) return false
        if (intent.action != android.content.Intent.ACTION_SEND || intent.type != "text/plain") return false
        val text = intent.getStringExtra(android.content.Intent.EXTRA_TEXT)
        if (text.isNullOrBlank()) return false
        val forward = android.content.Intent(this, com.pgpony.android.MainActivity::class.java).apply {
            action = IntentHandler.ACTION_ENCRYPT_TEXT
            putExtra(IntentHandler.EXTRA_ENCRYPT_TEXT, text)
            addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        startActivity(forward)
        finish()
        return true
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (forwardEncryptTextIfNeeded(intent)) return
        val content = IntentHandler.classifyShareIntent(intent, contentResolver)
        // 3.1.0 Phase 1 Fix3 — detached signatures go to the main app's
        // verify sheet; skip rendering entirely when forwarded.
        if (forwardDetachedSignatureIfNeeded(content)) return
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
        if (forwardEncryptTextIfNeeded(intent)) return
        val content = IntentHandler.classifyShareIntent(intent, contentResolver)
        // 3.1.0 Phase 1 Fix3 — same forward as onCreate.
        if (forwardDetachedSignatureIfNeeded(content)) return
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
        // 4.1.0 USB Phase 2 — this activity has its OWN copy of
        // startCardOperation, so MainActivity's chokepoint does not cover it
        // and a card operation from the share sheet would have stayed
        // NFC-only.
        //
        // No broadcast receiver and no permission prompt here, deliberately.
        // The share activity is short-lived, and a system permission dialog on
        // top of a share sheet is a bad place to ask. If the grant already
        // exists, which it will after any use of the main app with the key
        // attached, use the wire; otherwise fall through to NFC.
        val usb = getSystemService(android.hardware.usb.UsbManager::class.java)
        val device = usb?.let {
            com.pgpony.android.usb.UsbCcidCardTransport.findReaders(it).firstOrNull()
        }
        if (usb != null && device != null && usb.hasPermission(device)) {
            com.pgpony.android.usb.UsbCardOperations.run(
                usb, device, operation, onResult = onResult
            )
            return true
        }

        val reader = OpenPgpCardReader(this)
        cardReader = reader
        val started = reader.startOperation(operation, onResult)
        if (!started) cardReader = null
        return started
    }

    /**
     * 4.0.5 — see MainActivity.endCardOperation. Reader mode deliberately
     * stays engaged after a card operation: disabling it while the card is
     * still against the phone hands the tag to the platform dispatcher,
     * which launches Yubico Authenticator (issue #7). This activity has no
     * auto-lock suppression to release, so there is nothing else to do
     * here, and reader mode is released when the activity pauses.
     */
    fun endCardOperation() {
        // Intentionally empty. Present so the shared call site in
        // ShareTargetScreen reads the same as the main app's.
    }

    fun stopCardScan() {
        cardReader?.stop()
        cardReader = null
    }

    // ── 4.1.0 Phase 7b — saving a result to disk (issue #13) ──────────
    //
    // The whole of what ScottishLemur was missing. Before this, every
    // result screen in the share target offered Copy, Share and Done,
    // because the only startDocumentCreator in the app was on MainActivity
    // and the ContextWrapper walk up to it returns null in here.
    //
    // No auto-lock hook: this activity has no lock gate (see the comment on
    // startCardOperation above), so the default no-op onBusy is right.

    private val documentCreator = SafDocumentCreator(REQ_DOCUMENT_CREATOR)

    override fun startDocumentCreator(
        mimeType: String,
        suggestedName: String,
        callback: (android.net.Uri?) -> Unit,
    ) {
        documentCreator.launch(this, mimeType, suggestedName, callback)
    }

    @Deprecated("Matches MainActivity's picker plumbing; see SafDocumentCreator.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        documentCreator.onActivityResult(requestCode, resultCode, data)
    }

    private companion object {
        /** Small enough for FragmentActivity's 0xFFFF0000 mask. */
        const val REQ_DOCUMENT_CREATOR = 1003
        const val ENCRYPT_TEXT_ALIAS = "com.pgpony.android.ui.share.EncryptTextShareAlias"
    }
}
