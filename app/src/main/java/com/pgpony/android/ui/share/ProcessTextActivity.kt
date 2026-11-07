// ProcessTextActivity.kt
// PGPony Android, 4.8.0 (#103): the text selection menu's "Encrypt with
// PGPony" and "Sign with PGPony" (ACTION_PROCESS_TEXT).
//
// Reached through two activity-alias entries (ProcessTextEncrypt and
// ProcessTextSign, see AndroidManifest.xml); ProcessText.modeFor reads which
// one from the intent. EXTRA_PROCESS_TEXT carries the selection and
// EXTRA_PROCESS_TEXT_READONLY says whether the field can take a result.
//
//   * Editable field: the result goes back with setResult(RESULT_OK) and the
//     app replaces the selection with it.
//   * Read-only field, no caller waiting, or a result too large to send back:
//     the result stays on screen with Copy, Save and Share.
//   * A selection that already holds a PGP block (a message, a signed
//     message or a key) goes to the Quick Action (ShareTargetActivity), which
//     offers Decrypt, Verify or Import for it.
//
// Same gates as the Quick Action: the app lock (and a PGPony PIN) covers the
// screen at entry and after the activity stops, Recents shows no snapshot on
// API 33+, and an empty keyring shows the Quick Action's "set up your first
// key" card. Not singleTop and no taskAffinity, unlike ShareTargetActivity:
// it runs in the calling app's task so the result reaches the caller.

package com.pgpony.android.ui.share

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.pgpony.android.PGPonyApp
import com.pgpony.android.PGPonyTheme
import com.pgpony.android.crypto.card.OpenPgpCardSession
import com.pgpony.android.nfc.OpenPgpCardReader
import com.pgpony.android.saf.DocumentCreatorHost
import com.pgpony.android.saf.SafDocumentCreator

class ProcessTextActivity : AppCompatActivity(), DocumentCreatorHost {

    private val vm: ProcessTextViewModel by viewModels {
        ProcessTextViewModel.factory(PGPonyApp.instance.keyRepository)
    }

    // 4.6.0 (item 17.7) and 4.7.0 (item 32), as in ShareTargetActivity.
    private var locked by mutableStateOf(false)
    private var pickerInFlight = false

    private fun lockEnabled(): Boolean = com.pgpony.android.lock.AppLock.isEnabled(this)

    private var readOnly = false

    override fun onStop() {
        super.onStop()
        if (!pickerInFlight && lockEnabled()) locked = true
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }

        val mode = ProcessText.modeFor(intent?.action, intent?.component?.className)
        val text = intent?.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString().orEmpty()
        readOnly = intent?.getBooleanExtra(Intent.EXTRA_PROCESS_TEXT_READONLY, false) ?: false
        if (mode == null || text.isBlank()) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }
        // A PGP block is read, not wrapped again: hand it to the Quick Action.
        // Nothing is shown here first, so the Quick Action's own lock covers it.
        if (ProcessText.isPgpSelection(text)) {
            startActivity(
                Intent(this, ShareTargetActivity::class.java).apply {
                    action = Intent.ACTION_SEND
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, text)
                }
            )
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        locked = lockEnabled()
        vm.initialize(mode, text)

        setContent {
            PGPonyTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    val state by vm.state.collectAsState()
                    val returns = state.phase == ProcessTextPhase.Result &&
                        ProcessText.returnsResult(readOnly, callingActivity != null, state.output.length)
                    // Editable field: the result replaces the selection. Never
                    // while the lock is up.
                    LaunchedEffect(returns, locked) {
                        if (returns && !locked) finishWithResult(state.output)
                    }
                    ProcessTextScreen(
                        vm = vm,
                        returningResult = returns,
                        onDismiss = {
                            setResult(Activity.RESULT_CANCELED)
                            finish()
                        },
                    )
                    if (locked) {
                        com.pgpony.android.ui.components.LockScreen(onUnlock = { locked = false })
                    }
                }
            }
        }
    }

    private fun finishWithResult(output: String) {
        setResult(Activity.RESULT_OK, Intent().putExtra(Intent.EXTRA_PROCESS_TEXT, output))
        finish()
    }

    // ── Card signing (NFC or a USB reader already granted) ──────────────
    //
    // Same plumbing as ShareTargetActivity: reader mode binds to the
    // foreground activity, so this activity needs its own reader.
    private var cardReader: OpenPgpCardReader? = null

    fun <T> startCardOperation(
        operation: (OpenPgpCardSession) -> T,
        onResult: (Result<T>) -> Unit
    ): Boolean {
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

    /** 4.0.5: reader mode stays engaged after an operation (#7); released on pause. */
    fun endCardOperation() {
        // Intentionally empty, as in ShareTargetActivity.
    }

    fun stopCardScan() {
        cardReader?.stop()
        cardReader = null
    }

    // ── Save (a read-only field's result) ─────────────────────────────

    private val documentCreator = SafDocumentCreator(REQ_DOCUMENT_CREATOR)

    override fun startDocumentCreator(
        mimeType: String,
        suggestedName: String,
        callback: (android.net.Uri?) -> Unit,
    ) {
        pickerInFlight = true
        documentCreator.launch(this, mimeType, suggestedName) { uri ->
            pickerInFlight = false
            callback(uri)
        }
    }

    @Deprecated("Matches MainActivity's picker plumbing; see SafDocumentCreator.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        documentCreator.onActivityResult(requestCode, resultCode, data)
    }

    private companion object {
        /** Small enough for FragmentActivity's 0xFFFF0000 mask. */
        const val REQ_DOCUMENT_CREATOR = 1004
    }
}
