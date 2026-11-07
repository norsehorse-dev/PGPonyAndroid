// SshKeysViewModel.kt
// PGPony Android, 4.8.0 RC7 (item 1): drives Settings > SSH keys, the
// experimental ssh-mldsa44-ed25519 keys held outside the OpenPGP
// keyring (SshKeyStore). Every store call does file I/O and real crypto
// (bcrypt_pbkdf on import and export), so all of them run on Dispatchers.IO.
// Failures reach the screen as string resources, never exception text.

package com.pgpony.android.ui.settings

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.ssh.MlDsaEd25519Ssh
import com.pgpony.android.data.ssh.SshKeyEntry
import com.pgpony.android.data.ssh.SshKeyError
import com.pgpony.android.data.ssh.SshKeyStore
import com.pgpony.android.intent.DocumentBytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

class SshKeysViewModel : ViewModel() {

    /** A picked key file that is passphrase-protected and waits for it. */
    data class ImportPrompt(val wrongPassphrase: Boolean = false)

    data class UiState(
        /** False until the first list has been read, so no empty state flashes. */
        val loaded: Boolean = false,
        val loadFailed: Boolean = false,
        val keys: List<SshKeyEntry> = emptyList(),
        val working: Boolean = false,
        /** One snackbar line; the screen calls [consumeMessage] once shown. */
        val message: String? = null,
        val importPrompt: ImportPrompt? = null
    )

    companion object {
        /** A key file of this type is about 5 KB; anything past this is not one. */
        private const val MAX_KEY_FILE_BYTES = 256L * 1024
    }

    private val store: SshKeyStore get() = PGPonyApp.instance.sshKeyStore

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    /** The bytes of a protected key file while its passphrase is asked. Wiped after. */
    private var pendingImport: ByteArray? = null

    /** 4.8.0 RC7 (item 1): the passphrase import in flight, so Cancel can drop it. */
    private var importJob: Job? = null

    init {
        load()
    }

    fun load() {
        viewModelScope.launch { refresh() }
    }

    fun consumeMessage() {
        _state.value = _state.value.copy(message = null)
    }

    fun showMessage(text: String) {
        _state.value = _state.value.copy(message = text)
    }

    // ── Generate ─────────────────────────────────────────────────────

    fun generate(label: String) {
        if (!SshKeyForm.isLabelUsable(label) || !begin()) return
        viewModelScope.launch {
            val message = try {
                withContext(Dispatchers.IO) { store.generate(SshKeyForm.cleanLabel(label)) }
                str(R.string.ssh_keys_generated)
            } catch (e: Exception) {
                messageFor(e, R.string.ssh_keys_error_generate)
            }
            refresh()
            finish(message)
        }
    }

    // ── Import ───────────────────────────────────────────────────────

    /** Read a picked file and import it, or ask for its passphrase first. */
    fun importFrom(uri: Uri, resolver: ContentResolver) {
        if (!begin()) return
        viewModelScope.launch {
            val bytes = withContext(Dispatchers.IO) {
                runCatching { DocumentBytes.readDetailed(resolver, uri, MAX_KEY_FILE_BYTES).bytes }.getOrNull()
            }
            if (bytes == null || bytes.isEmpty()) {
                finish(str(R.string.ssh_keys_error_malformed))
                return@launch
            }
            val info = try {
                withContext(Dispatchers.IO) { store.inspectFile(bytes) }
            } catch (e: Exception) {
                bytes.fill(0)
                finish(messageFor(e, R.string.ssh_keys_error_malformed))
                return@launch
            }
            if (!MlDsaEd25519Ssh.isKeyType(info.keyType)) {
                bytes.fill(0)
                finish(str(R.string.ssh_keys_error_wrong_type, SshKeyForm.displayToken(info.keyType)))
                return@launch
            }
            // 4.8.0 RC7 (item 1): an unsupported cipher, or bcrypt rounds above
            // OpenSshKeyFile.MAX_ROUNDS, is refused here, before the passphrase
            // is asked and before any KDF runs.
            info.unsupportedEncryption?.let { detail ->
                bytes.fill(0)
                finish(messageFor(SshKeyError.UnsupportedEncryption(detail), R.string.ssh_keys_error_malformed))
                return@launch
            }
            if (info.encrypted) {
                discardPending()
                pendingImport = bytes
                _state.value = _state.value.copy(working = false, importPrompt = ImportPrompt())
                return@launch
            }
            runImport(bytes, null)
        }
    }

    /** The passphrase for the waiting key file. [passphrase] is wiped. */
    fun submitImportPassphrase(passphrase: CharArray) {
        val bytes = pendingImport
        if (bytes == null) {
            passphrase.fill('\u0000')
            _state.value = _state.value.copy(importPrompt = null)
            return
        }
        if (!begin()) {
            passphrase.fill('\u0000')
            return
        }
        importJob = viewModelScope.launch { runImport(bytes, passphrase) }
    }

    /**
     * 4.8.0 RC7 (item 1): Cancel works while bcrypt_pbkdf runs. The KDF itself
     * cannot be interrupted; it finishes on the IO thread, the key is not
     * stored, and runImport wipes the file bytes and the passphrase when it
     * ends. Until then the bytes stay untouched, so the running read never
     * sees them change.
     */
    fun cancelImport() {
        val job = importJob
        importJob = null
        if (job != null && job.isActive) {
            pendingImport = null
            job.cancel()
        } else {
            discardPending()
        }
        _state.value = _state.value.copy(working = false, importPrompt = null)
    }

    private suspend fun runImport(bytes: ByteArray, passphrase: CharArray?) {
        // 4.8.0 RC7 (item 1): the store checks isActive after the KDF, so a
        // cancelled import stores nothing; here it only wipes and leaves the
        // state as cancelImport set it.
        val result = try {
            withContext(Dispatchers.IO) { store.import(bytes, passphrase, shouldStore = { isActive }) }
        } catch (e: Exception) {
            if (!currentCoroutineContext().isActive) {
                bytes.fill(0)
                throw e
            }
            importFailed(bytes, e)
            return
        } finally {
            passphrase?.fill('\u0000')
        }
        bytes.fill(0)
        if (!currentCoroutineContext().isActive) return
        discardPending()
        refresh()
        _state.value = _state.value.copy(importPrompt = null)
        finish(str(if (result.added) R.string.ssh_keys_imported else R.string.ssh_keys_already_held))
    }

    private fun importFailed(bytes: ByteArray, e: Exception) {
        when (e) {
            is SshKeyError.WrongPassphrase -> {
                pendingImport = bytes
                _state.value = _state.value.copy(working = false, importPrompt = ImportPrompt(wrongPassphrase = true))
            }
            is SshKeyError.PassphraseRequired -> {
                pendingImport = bytes
                _state.value = _state.value.copy(working = false, importPrompt = ImportPrompt())
            }
            else -> {
                discardPending()
                bytes.fill(0)
                _state.value = _state.value.copy(importPrompt = null)
                finish(messageFor(e, R.string.ssh_keys_error_malformed))
            }
        }
    }

    private fun discardPending() {
        pendingImport?.fill(0)
        pendingImport = null
    }

    // ── Export ───────────────────────────────────────────────────────

    /**
     * Write key [id] to [uri] (a document the user just created) as an
     * OpenSSH key file encrypted under [passphrase], which is wiped. A failed
     * write removes the half-made document.
     */
    fun exportTo(id: String, passphrase: CharArray, uri: Uri, resolver: ContentResolver) {
        if (!begin()) {
            passphrase.fill('\u0000')
            return
        }
        viewModelScope.launch {
            val message = try {
                withContext(Dispatchers.IO) {
                    val text = store.exportPrivate(id, passphrase)
                    (resolver.openOutputStream(uri) ?: throw IOException("no output stream")).use { out ->
                        out.write(text.toByteArray(Charsets.UTF_8))
                        out.flush()
                    }
                }
                str(R.string.result_save_saved_note)
            } catch (e: Exception) {
                withContext(Dispatchers.IO) { runCatching { DocumentsContract.deleteDocument(resolver, uri) } }
                messageFor(e, R.string.result_save_failed_note)
            } finally {
                passphrase.fill('\u0000')
            }
            finish(message)
        }
    }

    // ── Rename and delete ────────────────────────────────────────────

    fun rename(id: String, label: String) {
        if (!SshKeyForm.isLabelUsable(label) || !begin()) return
        viewModelScope.launch {
            val message = try {
                withContext(Dispatchers.IO) { store.rename(id, SshKeyForm.cleanLabel(label)) }
                null
            } catch (e: Exception) {
                messageFor(e, R.string.ssh_keys_error_change)
            }
            refresh()
            finish(message)
        }
    }

    fun delete(id: String) {
        if (!begin()) return
        viewModelScope.launch {
            val message = try {
                withContext(Dispatchers.IO) { store.delete(id) }
                null
            } catch (e: Exception) {
                str(R.string.ssh_keys_error_change)
            }
            refresh()
            finish(message)
        }
    }

    override fun onCleared() {
        discardPending()
        super.onCleared()
    }

    // ── Internals ────────────────────────────────────────────────────

    /** Mark the screen busy; false when another operation is still running. */
    private fun begin(): Boolean {
        if (_state.value.working) return false
        _state.value = _state.value.copy(working = true)
        return true
    }

    private fun finish(message: String?) {
        _state.value = _state.value.copy(working = false, message = message ?: _state.value.message)
    }

    private suspend fun refresh() {
        val keys = withContext(Dispatchers.IO) { runCatching { store.list() } }
        _state.value = keys.fold(
            onSuccess = { _state.value.copy(loaded = true, loadFailed = false, keys = it) },
            onFailure = { _state.value.copy(loaded = true, loadFailed = true) }
        )
    }

    private fun messageFor(e: Throwable, fallback: Int): String = when (e) {
        is SshKeyError.WrongKeyType -> str(R.string.ssh_keys_error_wrong_type, SshKeyForm.displayToken(e.keyType))
        is SshKeyError.UnsupportedEncryption -> str(R.string.ssh_keys_error_encryption, SshKeyForm.displayToken(e.detail))
        is SshKeyError.Malformed -> str(R.string.ssh_keys_error_malformed)
        is SshKeyError.WrongPassphrase -> str(R.string.provider_passphrase_wrong)
        is SshKeyError.NotFound -> str(R.string.ssh_keys_error_not_found)
        is SshKeyError.Unreadable -> str(R.string.ssh_keys_error_unreadable)
        else -> str(fallback)
    }

    private fun str(id: Int, vararg args: Any): String =
        if (args.isEmpty()) PGPonyApp.instance.getString(id) else PGPonyApp.instance.getString(id, *args)
}
