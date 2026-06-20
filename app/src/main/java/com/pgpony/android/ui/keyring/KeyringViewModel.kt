// KeyringViewModel.kt
// PGPony Android
//
// ViewModel for the Keyring tab. Manages key list state, triggers
// generate/import/delete through KeyRepository.
// Matches iOS KeyringListView + GenerateKeyView + ImportKeyView patterns.

package com.pgpony.android.ui.keyring

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.PgpSubkeyEntity
import com.pgpony.android.data.repository.ImportPreview
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.network.KeyLookupSource
import com.pgpony.android.network.KeyServerRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Phase A10a — the four ways a user can bring a key into the keyring.
 * Mirrors iOS ImportKeyView.ImportMethod enum case-for-case.
 *
 *   • PASTE      — paste armored text into a TextField
 *   • FILE       — open a .asc/.gpg/.pgp/.key file via
 *                  ACTION_OPEN_DOCUMENT
 *   • QR_CODE    — scan a QR code containing armored key text
 *   • KEY_SERVER — search by email (WKD → Hagrid) or fingerprint
 *
 * Each method runs different data-acquisition UI but they all
 * funnel through previewArmoredKey → confirmImportPreview →
 * repo.importArmoredKey. The method enum is also surfaced as a
 * lookupSource badge for the KEY_SERVER path (via
 * importLookupSource).
 */
enum class ImportMethod(val displayName: String) {
    PASTE("Paste"),
    FILE("File"),
    QR_CODE("QR Code"),
    KEY_SERVER("Key Server")
}

data class KeyringUiState(
    val allKeys: List<PGPKeyEntity> = emptyList(),
    // Phase A1: subkey rows loaded alongside keys. Empty map means
    // either migration hasn't run yet or the keyring is empty. Keyed
    // by PGPKeyEntity.id (NOT fingerprint) for direct lookup from a
    // rendered KeyCard.
    val subkeysByPrimaryId: Map<String, List<PgpSubkeyEntity>> = emptyMap(),
    val isLoading: Boolean = false,
    // Phase A8.5: separate from isLoading. isLoading drives the
    // initial-load full-screen spinner; isRefreshing drives only the
    // PullToRefreshBox indicator on user pull-down. Distinguishing
    // them keeps the two affordances from clobbering each other (an
    // initial load happening alongside a swipe would otherwise either
    // show two spinners or hide the pull indicator entirely).
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
    val successMessage: String? = null,
    // Generate sheet
    val showGenerateSheet: Boolean = false,
    val generateName: String = "",
    val generateEmail: String = "",
    val generateAlgorithm: KeyAlgorithm = KeyAlgorithm.ED25519_CV25519,
    val generatePassphrase: String = "",
    val generateConfirmPassphrase: String = "",
    val generateExpiration: ExpirationOption = ExpirationOption.TWO_YEARS,
    val isGenerating: Boolean = false,
    // Import sheet
    val showImportSheet: Boolean = false,
    val importArmoredText: String = "",
    val isImporting: Boolean = false,
    // ── Phase A10a: Import 4-method picker ─────────────────────────────
    /** Currently active import method. PASTE is the default; the
     *  user picks one of the four via a top-of-sheet segmented control. */
    val importMethod: ImportMethod = ImportMethod.PASTE,
    /** Key Server search query — separate from the Exchange tab's
     *  search query because Import has its own search box. Matches
     *  iOS searchQuery state on ImportKeyView. */
    val importSearchQuery: String = "",
    /** True while a Key Server lookup is in flight. Drives the
     *  in-row progress indicator on the Search button. */
    val isSearchingKeyServer: Boolean = false,
    /** True while the in-memory parse for previewArmoredKey is
     *  running. Brief — parsing is fast — but used to disable the
     *  Import button during the round-trip. */
    val isPreviewing: Boolean = false,
    /** Lookup source surfaced as a badge on the preview card when
     *  the key arrived via the Key Server method. WKD-found keys
     *  get a green "Found via WKD" badge to signal that the
     *  recipient's own domain published the key (more authoritative
     *  than Hagrid). Null for Paste / File / QR methods. */
    val importLookupSource: KeyLookupSource? = null,
    /** Source filename surfaced on the preview card when the key
     *  arrived via the File method. Null for other methods. */
    val importSourceFilename: String? = null,
    /** Populated by previewArmoredKey when the parse succeeds.
     *  Triggers the inline preview section + Import confirm button.
     *  Cleared by [clearImportPreview] when the user backs out or
     *  switches method. */
    val importPreview: ImportPreview? = null,
    /** True when the QR scanner activity should be visible. The
     *  scanner is a full-screen overlay rather than a separate
     *  navigation destination — keeps the import sheet's state
     *  intact while scanning. */
    val showImportQRScanner: Boolean = false,
    // Delete confirm
    val keyToDelete: PGPKeyEntity? = null,
    // Keyring sorting (Lukas feedback). Default MANUAL + empty order
    // preserves the existing createdAt-DESC order on upgrade until the
    // user picks alphabetical or drags something.
    val sortMode: SortMode = SortMode.MANUAL,
    val manualOrder: List<String> = emptyList()
) {
    val myKeys: List<PGPKeyEntity> get() = sortKeys(allKeys.filter { it.isKeyPair })
    val contactKeys: List<PGPKeyEntity> get() = sortKeys(allKeys.filter { !it.isKeyPair })

    private fun sortKeys(list: List<PGPKeyEntity>): List<PGPKeyEntity> = when (sortMode) {
        SortMode.ALPHA_ASC -> list.sortedBy { ownerLabel(it).lowercase() }
        SortMode.ALPHA_DESC -> list.sortedByDescending { ownerLabel(it).lowercase() }
        SortMode.MANUAL -> {
            // Keys present in the saved order sort by their saved position;
            // any not yet in the order (newly added) fall to the end while
            // preserving their incoming (createdAt-DESC) relative order.
            list.sortedBy { key ->
                val idx = manualOrder.indexOf(key.fingerprint)
                if (idx >= 0) idx else Int.MAX_VALUE
            }
        }
    }

    private fun ownerLabel(key: PGPKeyEntity): String =
        key.userName.ifBlank { key.userEmail.ifBlank { key.fingerprint } }
}

enum class SortMode { ALPHA_ASC, ALPHA_DESC, MANUAL }

enum class ExpirationOption(val displayName: String, val seconds: Long?) {
    ONE_YEAR("1 Year", (365.25 * 24 * 60 * 60).toLong()),
    TWO_YEARS("2 Years", (2 * 365.25 * 24 * 60 * 60).toLong()),
    FIVE_YEARS("5 Years", (5 * 365.25 * 24 * 60 * 60).toLong()),
    NEVER("Never", null)
}

class KeyringViewModel(private val repo: KeyRepository) : ViewModel() {

    private val _state = MutableStateFlow(KeyringUiState())
    val state: StateFlow<KeyringUiState> = _state.asStateFlow()

    private val prefs by lazy {
        PGPonyApp.instance.getSharedPreferences("pgpony_prefs", android.content.Context.MODE_PRIVATE)
    }

    init {
        // Load persisted sort preferences before the first list render.
        val savedMode = when (prefs.getString("keyring_sort_mode", null)) {
            "ALPHA_ASC" -> SortMode.ALPHA_ASC
            "ALPHA_DESC" -> SortMode.ALPHA_DESC
            "MANUAL" -> SortMode.MANUAL
            else -> SortMode.MANUAL
        }
        val savedOrder = prefs.getString("keyring_manual_order", null)
            ?.split("\n")
            ?.filter { it.isNotBlank() }
            ?: emptyList()
        _state.value = _state.value.copy(sortMode = savedMode, manualOrder = savedOrder)
        loadKeys()
    }

    /** Change the sort mode and persist it. */
    fun setSortMode(mode: SortMode) {
        prefs.edit().putString("keyring_sort_mode", mode.name).apply()
        _state.value = _state.value.copy(sortMode = mode)
    }

    /**
     * Manual drag-reorder. [fromId] / [toId] are PGPKeyEntity ids (the
     * LazyColumn item keys). Moves the dragged key to the target's slot,
     * but only within the same section (My Keys vs Contacts) — cross-section
     * drags and header drops are ignored. Persists the new full order.
     */
    fun moveManual(fromId: String, toId: String) {
        if (fromId == toId) return
        val all = _state.value.allKeys
        val fromKey = all.firstOrNull { it.id == fromId } ?: return
        val toKey = all.firstOrNull { it.id == toId } ?: return
        // Same section only.
        if (fromKey.isKeyPair != toKey.isKeyPair) return

        // Seed the working order from the current display order if we don't
        // have a saved one yet (keeps what the user currently sees).
        val current = _state.value
        val seeded = current.manualOrder.ifEmpty {
            current.myKeys.map { it.fingerprint } + current.contactKeys.map { it.fingerprint }
        }.toMutableList()

        // Make sure both fingerprints are represented before moving.
        if (!seeded.contains(fromKey.fingerprint)) seeded.add(fromKey.fingerprint)
        if (!seeded.contains(toKey.fingerprint)) seeded.add(toKey.fingerprint)

        // Capture BOTH indices before mutating. Using add(toIndex,
        // removeAt(fromIndex)) — Kotlin evaluates the removeAt argument
        // first, so the target index (taken pre-removal) lands the item
        // correctly whether dragging up or down. (Recomputing the target
        // index after removal was the bug that broke downward drags.)
        val fromIndex = seeded.indexOf(fromKey.fingerprint)
        val toIndex = seeded.indexOf(toKey.fingerprint)
        if (fromIndex < 0 || toIndex < 0) return
        seeded.add(toIndex, seeded.removeAt(fromIndex))

        prefs.edit().putString("keyring_manual_order", seeded.joinToString("\n")).apply()
        _state.value = _state.value.copy(manualOrder = seeded)
    }

    fun loadKeys() {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true)
            try {
                val keys = repo.getAllKeys()
                // Phase A1: pull subkeys for each primary so the
                // KeyringScreen's KeyCard can render the expanded
                // subkey list on tap. This is currently N+1 queries
                // — acceptable for the typical keyring size (1–20
                // keys). If keyrings grow large we'll move this to a
                // single JOIN in a later phase.
                val subkeyMap = mutableMapOf<String, List<PgpSubkeyEntity>>()
                for (key in keys) {
                    // Phase A6 cleanup: repo.getSubkeysFor was speculative
                    // A1 wiring that never landed on the repo side. No UI
                    // consumer reads subkeysByPrimaryId either, so the map
                    // stays empty for now. If subkey listing returns as a
                    // feature, restore the call here and reintroduce
                    // KeyRepository.getSubkeysFor(id): List<PgpSubkeyEntity>.
                    subkeyMap[key.id] = emptyList()
                }
                _state.value = _state.value.copy(
                    allKeys = keys,
                    subkeysByPrimaryId = subkeyMap,
                    isLoading = false
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isLoading = false,
                    errorMessage = e.message
                )
            }
        }
    }

    /**
     * Phase A8.5 — user-initiated refresh from PullToRefreshBox.
     *
     * Re-reads the keyring from local DB and updates the displayed
     * list. The DB read itself is essentially instant; the
     * user-facing spinner exists mostly as feedback ("I asked, the
     * app responded"). Compose's PullToRefreshBox handles the
     * spinner show/hide timing based on isRefreshing alone.
     *
     * Distinct from [loadKeys] in two ways:
     *   • Drives the `isRefreshing` flag (PullToRefreshBox indicator)
     *     instead of `isLoading` (which is the initial-load spinner).
     *   • Doesn't show the empty-state "No keys" screen during the
     *     reload — the prior list stays visible with just the
     *     pull-indicator on top, so there's no flicker.
     *
     * The DB schema is reactive via the underlying repo queries; an
     * explicit refresh is mainly useful when the user wants
     * confirmation that recent external changes (e.g. a key just
     * imported via share-intent from another app, or a key whose
     * keyserver status just changed after a verification email click)
     * are reflected.
     */
    fun refresh() {
        viewModelScope.launch {
            _state.value = _state.value.copy(isRefreshing = true)
            try {
                val keys = repo.getAllKeys()
                val subkeyMap = mutableMapOf<String, List<PgpSubkeyEntity>>()
                for (key in keys) {
                    subkeyMap[key.id] = emptyList()
                }
                _state.value = _state.value.copy(
                    allKeys = keys,
                    subkeysByPrimaryId = subkeyMap,
                    isRefreshing = false
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isRefreshing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_refresh_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── Generate ───────────────────────────────────────────────────────

    fun showGenerate() {
        _state.value = _state.value.copy(
            showGenerateSheet = true,
            generateName = "",
            generateEmail = "",
            generateAlgorithm = KeyAlgorithm.ED25519_CV25519,
            generatePassphrase = "",
            generateConfirmPassphrase = "",
            generateExpiration = ExpirationOption.TWO_YEARS,
            errorMessage = null
        )
    }

    fun dismissGenerate() {
        _state.value = _state.value.copy(showGenerateSheet = false)
    }

    fun updateGenerateName(name: String) {
        _state.value = _state.value.copy(generateName = name)
    }

    fun updateGenerateEmail(email: String) {
        _state.value = _state.value.copy(generateEmail = email)
    }

    fun updateGenerateAlgorithm(algo: KeyAlgorithm) {
        _state.value = _state.value.copy(generateAlgorithm = algo)
    }

    fun updateGeneratePassphrase(pp: String) {
        _state.value = _state.value.copy(generatePassphrase = pp)
    }

    fun updateGenerateConfirmPassphrase(pp: String) {
        _state.value = _state.value.copy(generateConfirmPassphrase = pp)
    }

    fun updateGenerateExpiration(exp: ExpirationOption) {
        _state.value = _state.value.copy(generateExpiration = exp)
    }

    fun generateKey() {
        val s = _state.value
        if (s.generateName.isBlank()) {
            _state.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_name_required))
            return
        }
        if (s.generateEmail.isBlank() || !s.generateEmail.contains("@")) {
            _state.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_email_required))
            return
        }
        if (s.generatePassphrase != s.generateConfirmPassphrase) {
            _state.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_passphrase_mismatch))
            return
        }

        viewModelScope.launch {
            _state.value = _state.value.copy(isGenerating = true, errorMessage = null)
            try {
                val passphrase = s.generatePassphrase.ifBlank { null }
                repo.generateKey(
                    name = s.generateName.trim(),
                    email = s.generateEmail.trim(),
                    algorithm = s.generateAlgorithm,
                    passphrase = passphrase,
                    expirationSeconds = s.generateExpiration.seconds
                )
                _state.value = _state.value.copy(
                    isGenerating = false,
                    showGenerateSheet = false,
                    successMessage = PGPonyApp.instance.getString(R.string.keyring_status_key_generated)
                )
                loadKeys()
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isGenerating = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_generation_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── Import (Phase A10a — 4-method picker) ──────────────────────────
    //
    // Method-agnostic pipeline:
    //   data acquisition → previewArmoredKey(text, source?) → user
    //   confirms → confirmImportPreview → repo.importArmoredKey
    //
    // Per-method data acquisition:
    //   • PASTE      → user types into a TextField; previewArmoredKey
    //                  invoked on Preview button tap
    //   • FILE       → ImportKeyScreen launches ACTION_OPEN_DOCUMENT,
    //                  reads URI text, then calls previewArmoredKey
    //   • QR_CODE    → ImportKeyScreen overlays QRScannerScreen;
    //                  onScanned callback feeds previewArmoredKey
    //   • KEY_SERVER → searchKeyServerForImport queries WKD → Hagrid,
    //                  populates preview if a key is returned

    fun showImport() {
        _state.value = _state.value.copy(
            showImportSheet = true,
            importMethod = ImportMethod.PASTE,
            importArmoredText = "",
            importSearchQuery = "",
            importLookupSource = null,
            importSourceFilename = null,
            importPreview = null,
            isSearchingKeyServer = false,
            isPreviewing = false,
            showImportQRScanner = false,
            errorMessage = null
        )
    }

    fun dismissImport() {
        _state.value = _state.value.copy(
            showImportSheet = false,
            showImportQRScanner = false,
            importPreview = null
        )
    }

    /** A10a — switch the active method tab. Clears any in-flight
     *  preview because switching method means starting over with
     *  fresh input. */
    fun setImportMethod(method: ImportMethod) {
        _state.value = _state.value.copy(
            importMethod = method,
            importPreview = null,
            importLookupSource = null,
            importSourceFilename = null,
            errorMessage = null
        )
    }

    fun updateImportText(text: String) {
        _state.value = _state.value.copy(importArmoredText = text)
    }

    /** A10a — Key Server search field text. */
    fun updateImportSearchQuery(query: String) {
        _state.value = _state.value.copy(importSearchQuery = query)
    }

    /**
     * A10a — clear the preview without dismissing the whole sheet.
     * Called by the "X" / "Cancel" button on the preview card so the
     * user can adjust their input and re-preview.
     */
    fun clearImportPreview() {
        _state.value = _state.value.copy(
            importPreview = null,
            importLookupSource = null,
            importSourceFilename = null,
            errorMessage = null
        )
    }

    /**
     * A10a — central preview entry point. Parses [armoredText]
     * in-memory (no DB write) and populates importPreview on
     * success, errorMessage on failure. [source] is the WKD/Hagrid
     * lookup source for Key Server imports, null otherwise.
     * [sourceFilename] is the user-visible filename for File-method
     * imports, null otherwise.
     */
    fun previewArmoredKey(
        armoredText: String,
        source: KeyLookupSource? = null,
        sourceFilename: String? = null
    ) {
        val trimmed = armoredText.trim()
        if (trimmed.isBlank()) {
            _state.value = _state.value.copy(
                errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_no_key_data)
            )
            return
        }
        viewModelScope.launch {
            _state.value = _state.value.copy(isPreviewing = true, errorMessage = null)
            val preview = repo.previewArmoredKey(trimmed)
            if (preview != null) {
                _state.value = _state.value.copy(
                    isPreviewing = false,
                    importPreview = preview,
                    importLookupSource = source,
                    importSourceFilename = sourceFilename,
                    importArmoredText = trimmed,
                    errorMessage = null
                )
            } else {
                _state.value = _state.value.copy(
                    isPreviewing = false,
                    importPreview = null,
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_couldnt_parse_key)
                )
            }
        }
    }

    /**
     * A10a — Key Server method action. Searches WKD → Hagrid (same
     * unified path as Exchange tab), and on hit feeds the armored
     * key into [previewArmoredKey] with the lookup source attached
     * so the preview card can show a "Found via WKD" badge.
     */
    fun searchKeyServerForImport() {
        val query = _state.value.importSearchQuery.trim()
        if (query.isBlank()) {
            _state.value = _state.value.copy(errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_search_no_email_or_fp))
            return
        }
        viewModelScope.launch {
            _state.value = _state.value.copy(
                isSearchingKeyServer = true,
                errorMessage = null,
                importPreview = null
            )
            try {
                // Heuristic: email addresses contain '@', fingerprints don't.
                // findByEmail does WKD → Hagrid fallback; fingerprint search
                // goes directly to Hagrid.
                val result = if (query.contains('@')) {
                    KeyServerRepository.shared.findByEmail(query)
                } else {
                    val armored = KeyServerRepository.shared.searchByFingerprint(query)
                    armored?.let {
                        com.pgpony.android.network.KeyLookupResult(
                            armoredKey = it,
                            source = KeyLookupSource.HAGRID
                        )
                    }
                }
                _state.value = _state.value.copy(isSearchingKeyServer = false)
                if (result != null) {
                    previewArmoredKey(result.armoredKey, source = result.source)
                } else {
                    _state.value = _state.value.copy(
                        errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_search_no_match_format, query)
                    )
                }
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isSearchingKeyServer = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_search_failed_format, e.message ?: "")
                )
            }
        }
    }

    /** A10a — open the QR scanner overlay from the QR method tab. */
    fun showImportQRScanner() {
        _state.value = _state.value.copy(showImportQRScanner = true, errorMessage = null)
    }

    fun dismissImportQRScanner() {
        _state.value = _state.value.copy(showImportQRScanner = false)
    }

    /** A10a — QR scanner callback. Closes scanner overlay, feeds
     *  scanned text through the preview pipeline. */
    fun onImportQRScanned(scannedText: String) {
        _state.value = _state.value.copy(showImportQRScanner = false)
        previewArmoredKey(scannedText)
    }

    /**
     * A10a — commit the previewed key to the keyring. Runs the same
     * repo.importArmoredKey as the pre-A10 path; the preview phase
     * only added confidence, the commit semantics are unchanged.
     *
     * Success → dismiss sheet, refresh list, success snackbar.
     * Duplicate → if willUpgradeToKeyPair, success message reflects
     * the upgrade. Otherwise surface AlreadyExists as an error so
     * the user can navigate to the existing row.
     */
    fun confirmImportPreview() {
        val preview = _state.value.importPreview ?: return
        viewModelScope.launch {
            _state.value = _state.value.copy(isImporting = true, errorMessage = null)
            try {
                repo.importArmoredKey(preview.armoredText)
                val message = when {
                    preview.willUpgradeToKeyPair -> PGPonyApp.instance.getString(R.string.keyring_status_key_upgraded)
                    preview.hasPrivateKey -> "Key pair imported"
                    else -> "Public key imported"
                }
                _state.value = _state.value.copy(
                    isImporting = false,
                    showImportSheet = false,
                    importPreview = null,
                    successMessage = message
                )
                loadKeys()
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isImporting = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_import_failed_format, e.message ?: "")
                )
            }
        }
    }

    /**
     * Legacy Phase-A1 entry point. The pre-A10a paste-only import
     * sheet wired its single Import button straight to this method.
     * Kept so any old call site keeps working; new code routes
     * through previewArmoredKey → confirmImportPreview instead.
     */
    @Suppress("unused")
    fun importKey() {
        val text = _state.value.importArmoredText.trim()
        if (text.isBlank()) {
            _state.value = _state.value.copy(errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_no_armored_text))
            return
        }
        viewModelScope.launch {
            _state.value = _state.value.copy(isImporting = true, errorMessage = null)
            try {
                repo.importArmoredKey(text)
                _state.value = _state.value.copy(
                    isImporting = false,
                    showImportSheet = false,
                    successMessage = "Key imported successfully"
                )
                loadKeys()
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isImporting = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_import_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── Delete ─────────────────────────────────────────────────────────

    fun confirmDelete(key: PGPKeyEntity) {
        _state.value = _state.value.copy(keyToDelete = key)
    }

    fun cancelDelete() {
        _state.value = _state.value.copy(keyToDelete = null)
    }

    fun deleteKey() {
        val key = _state.value.keyToDelete ?: return
        viewModelScope.launch {
            try {
                repo.deleteKey(key)
                _state.value = _state.value.copy(
                    keyToDelete = null,
                    successMessage = PGPonyApp.instance.getString(R.string.keyring_status_key_deleted)
                )
                loadKeys()
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    keyToDelete = null,
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_delete_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── Export ──────────────────────────────────────────────────────────

    fun exportPublicKey(fingerprint: String): String? = repo.exportArmoredPublicKey(fingerprint)
    fun exportPrivateKey(fingerprint: String): String? = repo.exportArmoredPrivateKey(fingerprint)

    // ── Misc ───────────────────────────────────────────────────────────

    fun clearError() {
        _state.value = _state.value.copy(errorMessage = null)
    }

    fun clearSuccess() {
        _state.value = _state.value.copy(successMessage = null)
    }

    fun setDefaultKey(fingerprint: String) {
        viewModelScope.launch {
            repo.setDefaultKey(fingerprint)
            loadKeys()
        }
    }
}
