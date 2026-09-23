// ExchangeViewModel.kt
// PGPony Android
//
// ViewModel for the Exchange tab: QR code display, QR scan import,
// and key server search/upload. Matches iOS ExchangeView sections.

package com.pgpony.android.ui.exchange

import android.graphics.Bitmap
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.qr.QrBitmap
import com.pgpony.android.data.repository.ImportResolution
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.network.KeyServerRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class ExchangeSection { SHOW_KEY, SCAN_KEY, KEY_SERVER }

/** 4.6.0 (item 18 follow-up): the key-server import outcome shown on screen. */
data class ExchangeImportedNotice(
    val message: String,
    val userId: String,
    val fingerprint: String
)

data class ExchangeUiState(
    val section: ExchangeSection = ExchangeSection.SHOW_KEY,
    val myKeyPairs: List<PGPKeyEntity> = emptyList(),
    val selectedKey: PGPKeyEntity? = null,
    /** 4.1.0 Phase 9 (issue #3): a list, because a post-quantum key does
     *  not fit in one symbol. One entry for anything that does. */
    val qrFrames: List<Bitmap> = emptyList(),
    val qrIndex: Int = 0,
    val armoredPublicKey: String? = null,
    // Key server
    val searchQuery: String = "",
    val searchResult: String? = null,
    val isSearching: Boolean = false,
    val isUploading: Boolean = false,
    /** 4.6.0 (item 18 follow-up): what the last Import did, shown in place of
     *  the "Key Found" card so the import visibly lands. Cleared by the next
     *  search or an edit to the query. */
    val importedNotice: ExchangeImportedNotice? = null,
    // Import from scan
    val scannedText: String? = null,
    val showImportConfirm: Boolean = false,
    // Messages
    val errorMessage: String? = null,
    val successMessage: String? = null
)

class ExchangeViewModel(
    private val repo: KeyRepository,
    private val keyServer: KeyServerRepository = KeyServerRepository.shared
) : ViewModel() {

    private val _state = MutableStateFlow(ExchangeUiState())
    val state: StateFlow<ExchangeUiState> = _state.asStateFlow()

    init { loadKeys() }

    // Made public so the screen can call this from a LaunchedEffect on
    // recomposition entry — the ViewModel is scoped to the activity / nav
    // entry and survives tab switches, so init's one-shot load is stale by
    // the time the user navigates back from Keyring after generating keys.
    fun loadKeys() {
        viewModelScope.launch {
            val pairs = repo.getKeyPairs()
            // Card-backed keys have a shareable public key too (the private
            // key lives on the card), so include them in the Show-Key list.
            val cards = repo.getAllKeys().filter {
                it.isCardBacked && !it.isKeyPair && it.armoredPublicKey != null
            }
            val all = pairs + cards
            val selected = all.firstOrNull { it.isDefault } ?: all.firstOrNull()
            _state.value = _state.value.copy(myKeyPairs = all, selectedKey = selected)
            selected?.let { generateQR(it) }
        }
    }

    fun setSection(section: ExchangeSection) {
        _state.value = _state.value.copy(section = section)
    }

    // ── Show Key (QR) ──────────────────────────────────────────────────

    fun selectKey(key: PGPKeyEntity) {
        _state.value = _state.value.copy(selectedKey = key)
        generateQR(key)
    }

    private fun generateQR(key: PGPKeyEntity) {
        // §5.6.5 (#37): export + QR encode off the main thread so a large
        // post-quantum key does not stall the Exchange tab on selection.
        viewModelScope.launch {
            val armored = withContext(Dispatchers.IO) {
                repo.exportArmoredPublicKey(key.fingerprint)
            } ?: return@launch
            _state.value = _state.value.copy(armoredPublicKey = armored)
            try {
                val frames = withContext(Dispatchers.Default) { QrBitmap.encodeFrames(armored) }
                if (frames.isNullOrEmpty()) {
                    _state.value = _state.value.copy(
                        qrFrames = emptyList(),
                        qrIndex = 0,
                        errorMessage = PGPonyApp.instance.getString(R.string.qr_too_large)
                    )
                    return@launch
                }
                _state.value = _state.value.copy(qrFrames = frames, qrIndex = 0)
            } catch (e: Exception) {
                _state.value = _state.value.copy(errorMessage = PGPonyApp.instance.getString(R.string.exchange_vm_error_qr_failed_format, e.message ?: ""))
            }
        }
    }

    /** 4.1.0 Phase 9 — step through a multi-part QR. */
    fun qrNext() {
        val s = _state.value
        if (s.qrFrames.size < 2) return
        _state.value = s.copy(qrIndex = (s.qrIndex + 1) % s.qrFrames.size)
    }

    fun qrPrev() {
        val s = _state.value
        if (s.qrFrames.size < 2) return
        _state.value = s.copy(qrIndex = (s.qrIndex - 1 + s.qrFrames.size) % s.qrFrames.size)
    }

    // ── Scan Key ───────────────────────────────────────────────────────

    fun onQRScanned(text: String) {
        if (text.contains("-----BEGIN PGP")) {
            _state.value = _state.value.copy(scannedText = text, showImportConfirm = true)
        } else {
            _state.value = _state.value.copy(errorMessage = PGPonyApp.instance.getString(R.string.exchange_vm_error_not_pgp_key))
        }
    }

    fun importScannedKey() {
        val text = _state.value.scannedText ?: return
        viewModelScope.launch {
            try {
                // 4.0.0 Phase 1 (iOS v7.1.1 F3) — outcome-aware commit:
                // scanning a key you already hold no longer errors.
                val outcome = repo.importArmoredKeyDetailed(text)
                val message = when (outcome.resolution) {
                    ImportResolution.ALREADY_IN_KEYRING ->
                        PGPonyApp.instance.getString(R.string.import_result_already_in_keyring)
                    ImportResolution.MERGED_NEW_MATERIAL ->
                        PGPonyApp.instance.getString(R.string.import_result_merged)
                    else -> "Key imported from QR code"
                }
                _state.value = _state.value.copy(
                    scannedText = null,
                    showImportConfirm = false,
                    successMessage = message
                )
                loadKeys()
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    showImportConfirm = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.exchange_vm_error_import_failed_format, e.message ?: "")
                )
            }
        }
    }

    fun dismissImportConfirm() {
        _state.value = _state.value.copy(showImportConfirm = false, scannedText = null)
    }

    // ── Key Server ─────────────────────────────────────────────────────

    fun updateSearchQuery(query: String) {
        _state.value = _state.value.copy(searchQuery = query, importedNotice = null)
    }

    fun searchKeyServer() {
        val query = _state.value.searchQuery.trim()
        if (query.isBlank()) return

        viewModelScope.launch {
            _state.value = _state.value.copy(isSearching = true, searchResult = null, errorMessage = null,
                importedNotice = null)
            try {
                val result = if (query.contains("@")) {
                    keyServer.searchByEmail(query)
                } else {
                    keyServer.findByFingerprint(query)?.armoredKey
                }
                if (result != null) {
                    _state.value = _state.value.copy(isSearching = false, searchResult = result)
                } else {
                    _state.value = _state.value.copy(isSearching = false, errorMessage = PGPonyApp.instance.getString(R.string.exchange_vm_error_no_key_found_format, query))
                }
            } catch (e: Exception) {
                _state.value = _state.value.copy(isSearching = false, errorMessage = PGPonyApp.instance.getString(R.string.exchange_vm_error_search_failed_format, e.message ?: ""))
            }
        }
    }

    fun importSearchResult() {
        val armored = _state.value.searchResult ?: return
        viewModelScope.launch {
            try {
                // 4.0.0 Phase 1 (iOS v7.1.1 F3) — outcome-aware commit:
                // importing a search hit you already hold no longer
                // errors.
                val outcome = repo.importArmoredKeyDetailed(armored)
                val message = when (outcome.resolution) {
                    ImportResolution.ALREADY_IN_KEYRING ->
                        PGPonyApp.instance.getString(R.string.import_result_already_in_keyring)
                    ImportResolution.MERGED_NEW_MATERIAL ->
                        PGPonyApp.instance.getString(R.string.import_result_merged)
                    else -> PGPonyApp.instance.getString(R.string.exchange_keyserver_imported)
                }
                // 4.6.0 (item 18 follow-up): the card used to vanish with only a
                // short snackbar (easy to miss under the keyboard), so an
                // import looked like nothing happened. Show the outcome in place.
                _state.value = _state.value.copy(
                    searchResult = null,
                    importedNotice = ExchangeImportedNotice(
                        message = message,
                        userId = outcome.entity.userID,
                        fingerprint = outcome.entity.fingerprint
                    )
                )
                loadKeys()
            } catch (e: Exception) {
                _state.value = _state.value.copy(errorMessage = PGPonyApp.instance.getString(R.string.exchange_vm_error_import_failed_format, e.message ?: ""))
            }
        }
    }

    fun uploadToKeyServer() {
        val key = _state.value.selectedKey ?: return

        viewModelScope.launch {
            _state.value = _state.value.copy(isUploading = true, errorMessage = null)
            try {
                // 4.6.0 (item 9): the same payload builder and primary-identity
                // check as Key Detail's publish sheet.
                val armored = when (val payload = withContext(Dispatchers.IO) {
                    repo.publishPayload(key.fingerprint, key.userID)
                }) {
                    is KeyRepository.PublishPayload.Ready -> payload.armored
                    is KeyRepository.PublishPayload.NeedsRepair -> {
                        _state.value = _state.value.copy(
                            isUploading = false,
                            errorMessage = PGPonyApp.instance.getString(
                                R.string.publish_primary_repair_format,
                                payload.flagged.joinToString(", ").ifEmpty { "-" },
                                payload.shown
                            )
                        )
                        return@launch
                    }
                    KeyRepository.PublishPayload.Unavailable -> {
                        _state.value = _state.value.copy(isUploading = false)
                        return@launch
                    }
                }
                keyServer.upload(armored)
                repo.markKeyServerUploaded(key.fingerprint, com.pgpony.android.keyserver.KeyServerDirectory.ID_OPENPGP)
                _state.value = _state.value.copy(
                    isUploading = false,
                    successMessage = PGPonyApp.instance.getString(R.string.exchange_vm_status_uploaded)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isUploading = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.exchange_vm_error_upload_failed_format, e.message ?: "")
                )
            }
        }
    }

    fun clearError() { _state.value = _state.value.copy(errorMessage = null) }
    fun clearSuccess() { _state.value = _state.value.copy(successMessage = null) }
}
