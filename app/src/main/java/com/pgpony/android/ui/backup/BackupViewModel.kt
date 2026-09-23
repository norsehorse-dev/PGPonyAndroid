// BackupViewModel.kt
// PGPony Android — 4.0.0 Phase 3 (encrypted keyring backup UI)
//
// Drives the Settings backup/restore flow over BackupService:
//   • Back up: generate a recovery code → force the user to re-enter it
//     (so nobody saves a backup they can't open) → write the .pgpony file.
//   • Restore: read a picked .pgpony → enter the code → merge-import →
//     show a plain-language report.
//
// File I/O (SAF create/open) is done by the composable via MainActivity's
// document helpers; this VM only takes the resulting Uri + ContentResolver
// and runs the crypto/merge off the main thread.

package com.pgpony.android.ui.backup

import android.content.ContentResolver
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.backup.BackupError
import com.pgpony.android.backup.BackupKind
import com.pgpony.android.backup.BackupService
import com.pgpony.android.backup.CrockfordBase32
import com.pgpony.android.backup.MergeReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class BackupViewModel : ViewModel() {

    enum class Phase { Menu, ShowCode, EnterCode, BackupDone, RestoreDone }

    data class UiState(
        val phase: Phase = Phase.Menu,
        val working: Boolean = false,
        val error: String? = null,
        // Back up
        val recoveryGrouped: String? = null,   // the code to show, 4×6 hyphenated
        val confirmInput: String = "",
        val confirmMismatch: Boolean = false,
        // Restore
        val restoreCode: String = "",
        val okcBackup: Boolean = false,   // OpenKeychain backup (numeric code)
        val report: MergeReport? = null
    )

    private val service = BackupService(PGPonyApp.instance.keyRepository)

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    /** The canonical (normalized) form of the generated code — the S2K passphrase. */
    private var canonical: String = ""
    private var pendingRestoreBytes: ByteArray? = null

    // ── Back up ──────────────────────────────────────────────────────

    fun beginBackup() {
        val rec = CrockfordBase32.generate()
        canonical = rec.canonical
        _state.value = UiState(phase = Phase.ShowCode, recoveryGrouped = rec.grouped)
    }

    fun updateConfirm(text: String) {
        _state.value = _state.value.copy(confirmInput = text, confirmMismatch = false)
    }

    /** True when the re-entered code matches the generated one. */
    fun confirmMatches(): Boolean =
        canonical.isNotEmpty() &&
            CrockfordBase32.normalize(_state.value.confirmInput) == canonical

    fun flagConfirmMismatch() {
        _state.value = _state.value.copy(confirmMismatch = true)
    }

    /** A sensible default filename for the SAF create dialog. */
    fun suggestedFileName(dateStamp: String): String =
        "pgpony-backup-$dateStamp.${BackupService.FILE_EXTENSION}"

    /** Build the encrypted backup and write it to [uri]. */
    fun writeBackup(uri: Uri, resolver: ContentResolver) {
        if (!confirmMatches()) {
            flagConfirmMismatch(); return
        }
        if (_state.value.working) return
        // Flip `working` SYNCHRONOUSLY (before launch) so the button
        // disables on the first tap — otherwise a slow op looks
        // unresponsive and repeated taps queue duplicate passes.
        _state.value = _state.value.copy(working = true, error = null)
        viewModelScope.launch {
            try {
                val bytes = service.exportBackup(canonical)
                withContext(Dispatchers.IO) {
                    (resolver.openOutputStream(uri)
                        ?: throw IllegalStateException("Couldn't open the file for writing"))
                        .use { it.write(bytes); it.flush() }
                }
                _state.value = _state.value.copy(working = false, phase = Phase.BackupDone)
            } catch (e: BackupError) {
                _state.value = _state.value.copy(working = false, error = e.message)
            } catch (e: Exception) {
                _state.value = _state.value.copy(working = false, error = e.message ?: "Backup failed")
            }
        }
    }

    // ── Restore ──────────────────────────────────────────────────────

    /** Called once a backup file has been read into memory. */
    fun beginRestore(fileBytes: ByteArray) {
        pendingRestoreBytes = fileBytes
        val okc = service.detectKind(fileBytes) == BackupKind.OPENKEYCHAIN
        _state.value = UiState(phase = Phase.EnterCode, okcBackup = okc)
    }

    fun updateRestoreCode(text: String) {
        _state.value = _state.value.copy(restoreCode = text, error = null)
    }

    fun runRestore() {
        val bytes = pendingRestoreBytes ?: return
        if (_state.value.working) return
        // Flip `working` SYNCHRONOUSLY before launching so a second tap
        // (while the import is running) can't start a concurrent restore
        // pass — concurrent passes race the keyring dedup and insert the
        // same key multiple times.
        val okc = _state.value.okcBackup
        _state.value = _state.value.copy(working = true, error = null)
        viewModelScope.launch {
            try {
                val report = if (okc)
                    service.restoreOpenKeychainBackup(bytes, _state.value.restoreCode)
                else
                    service.restoreBackup(bytes, _state.value.restoreCode)
                _state.value = _state.value.copy(working = false, phase = Phase.RestoreDone, report = report)
            } catch (e: BackupError) {
                _state.value = _state.value.copy(working = false, error = e.message)
            } catch (e: Exception) {
                _state.value = _state.value.copy(working = false, error = e.message ?: "Restore failed")
            }
        }
    }

    /** 4.6.0 (item 17.9): the user chose to apply the restored backup's settings. */
    fun applyRestoredSettings() {
        val json = _state.value.report?.pendingSettings ?: return
        viewModelScope.launch {
            val ok = service.applyBackupSettings(json)
            _state.value = _state.value.copy(
                report = _state.value.report?.copy(settingsApplied = ok, pendingSettings = null)
            )
        }
    }

    /** 4.6.0 (item 17.9): the user declined; forget the restored settings. */
    fun skipRestoredSettings() {
        _state.value = _state.value.copy(report = _state.value.report?.copy(pendingSettings = null))
    }

    fun reset() {
        canonical = ""
        pendingRestoreBytes = null
        _state.value = UiState()
    }
}
