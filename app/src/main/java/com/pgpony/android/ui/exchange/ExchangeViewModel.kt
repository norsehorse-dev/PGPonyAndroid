// ExchangeViewModel.kt
// PGPony Android
//
// ViewModel for the Exchange tab: QR code display, QR scan import,
// and key server search/upload. Matches iOS ExchangeView sections.

package com.pgpony.android.ui.exchange

import android.graphics.Bitmap
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.network.KeyServerRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

enum class ExchangeSection { SHOW_KEY, SCAN_KEY, KEY_SERVER }

data class ExchangeUiState(
    val section: ExchangeSection = ExchangeSection.SHOW_KEY,
    val myKeyPairs: List<PGPKeyEntity> = emptyList(),
    val selectedKey: PGPKeyEntity? = null,
    val qrBitmap: Bitmap? = null,
    val armoredPublicKey: String? = null,
    // Key server
    val searchQuery: String = "",
    val searchResult: String? = null,
    val isSearching: Boolean = false,
    val isUploading: Boolean = false,
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
        val armored = repo.exportArmoredPublicKey(key.fingerprint) ?: return
        _state.value = _state.value.copy(armoredPublicKey = armored)

        try {
            val hints = mapOf(EncodeHintType.MARGIN to 1)
            val matrix = QRCodeWriter().encode(armored, BarcodeFormat.QR_CODE, 800, 800, hints)
            val width = matrix.width
            val height = matrix.height
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
            for (x in 0 until width) {
                for (y in 0 until height) {
                    bitmap.setPixel(x, y, if (matrix.get(x, y)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
                }
            }
            _state.value = _state.value.copy(qrBitmap = bitmap)
        } catch (e: Exception) {
            _state.value = _state.value.copy(errorMessage = PGPonyApp.instance.getString(R.string.exchange_vm_error_qr_failed_format, e.message ?: ""))
        }
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
                repo.importArmoredKey(text)
                _state.value = _state.value.copy(
                    scannedText = null,
                    showImportConfirm = false,
                    successMessage = "Key imported from QR code"
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
        _state.value = _state.value.copy(searchQuery = query)
    }

    fun searchKeyServer() {
        val query = _state.value.searchQuery.trim()
        if (query.isBlank()) return

        viewModelScope.launch {
            _state.value = _state.value.copy(isSearching = true, searchResult = null, errorMessage = null)
            try {
                val result = if (query.contains("@")) {
                    keyServer.searchByEmail(query)
                } else {
                    keyServer.searchByFingerprint(query)
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
                repo.importArmoredKey(armored)
                _state.value = _state.value.copy(
                    searchResult = null,
                    successMessage = "Key imported from key server"
                )
                loadKeys()
            } catch (e: Exception) {
                _state.value = _state.value.copy(errorMessage = PGPonyApp.instance.getString(R.string.exchange_vm_error_import_failed_format, e.message ?: ""))
            }
        }
    }

    fun uploadToKeyServer() {
        val key = _state.value.selectedKey ?: return
        val armored = _state.value.armoredPublicKey ?: return

        viewModelScope.launch {
            _state.value = _state.value.copy(isUploading = true, errorMessage = null)
            try {
                keyServer.upload(armored)
                repo.markKeyServerUploaded(key.fingerprint)
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
