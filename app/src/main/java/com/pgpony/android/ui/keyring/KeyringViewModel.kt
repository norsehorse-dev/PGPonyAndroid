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
import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.GranularSubkeySpec
import com.pgpony.android.crypto.pqc.CompositeLibrePGPKeyMaterial
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.PgpSubkeyEntity
import com.pgpony.android.data.repository.ImportPreview
import com.pgpony.android.data.repository.ImportResolution
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
    KEY_SERVER("Key Server"),
    /** 4.6.0 (item 2): fetch a public key from a link. */
    URL("Link")
}

/**
 * 4.0.0 Phase 1 (iOS v7.1.1 F3) — payload for the "Already in Keyring"
 * dialog. Set on KeyringUiState when an import commit resolves
 * ALREADY_IN_KEYRING (byte-identical material, nothing merged); the
 * dialog is hosted in KeyringScreen so its View Key button can use the
 * screen's onKeyClick navigation hook to push KeyDetail — the Android
 * shape of iOS's appState.pendingShowKeyFingerprint handoff, without
 * needing a pending flag because the dialog lives beside the
 * NavController-aware host.
 */
data class DuplicateImportOutcome(
    val fingerprint: String,
    val keyName: String
)

data class KeyringUiState(
    val allKeys: List<PGPKeyEntity> = emptyList(),
    // §5.6.1 recycle bin: soft-deleted keys, loaded on demand for the
    // Recently Deleted screen.
    val deletedKeys: List<PGPKeyEntity> = emptyList(),
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
    // item 7 (#55): advanced granular keygen — compose the primary's subkey set.
    val generateGranular: Boolean = false,
    val granularIncludeDefaultEncryption: Boolean = true,
    val granularSubkeys: List<AddSubkeyChoice> = emptyList(),
    val isGenerating: Boolean = false,
    // 4.0.0 Phase 5a (§6 Q6) — set to the new key's fingerprint right
    // after a successful generate so the UI can offer the publish
    // prompt (both servers pre-checked, skippable). iOS parity.
    val pendingPublishFingerprint: String? = null,
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
    /** 4.6.0 (item 2): the link typed on the Link tab, whether a fetch is
     *  running, and the address the previewed key finally came from. */
    val importUrl: String = "",
    val isFetchingUrl: Boolean = false,
    val importSourceUrl: String? = null,
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
    // ── 4.0.0 Phase 1 (iOS v7.1.1 F3): duplicate-import alert ──────────
    /** Set when an import commit resolved ALREADY_IN_KEYRING. Drives
     *  the "Already in Keyring" dialog (with its View Key jump) hosted
     *  in KeyringScreen. Null when no dialog is showing. */
    val duplicateImportResult: DuplicateImportOutcome? = null,
    // #58 (CertainBot): one-shot signal to jump to Encrypt with this
    // just-shared key preselected as recipient. Consumed by the host.
    val pendingEncryptToFingerprint: String? = null,
    // Delete confirm
    val keyToDelete: PGPKeyEntity? = null,
    // Keyring sorting (Lukas feedback). Default MANUAL + empty order
    // preserves the existing createdAt-DESC order on upgrade until the
    // user picks alphabetical or drags something.
    val sortMode: SortMode = SortMode.MANUAL,
    val manualOrder: List<String> = emptyList(),
    // 4.2.0 RC2 workstream F — LibrePGP composite keys (768/1024)
    // generated before the RC2 wire fixes use an ECC point encoding gpg
    // cannot encrypt to (see CompositeLibrePGPKeyMaterial.usesLegacyPointEncoding).
    // legacyCompositeFingerprints is computed once per load/refresh from
    // allKeys; dismissedRegenHintFingerprints is loaded from prefs at
    // init, same pattern as manualOrder. The hint is one-time per key: once
    // dismissed a fingerprint stays out of regenHintKeys even after a
    // reload, but a NEWLY imported affected key (a fingerprint not yet
    // dismissed) still surfaces.
    val legacyCompositeFingerprints: Set<String> = emptySet(),
    val dismissedRegenHintFingerprints: Set<String> = emptySet(),
    // #45: live search over the keyring — matches name, email, key id, or
    // fingerprint. Not persisted; a fresh keyring open starts unfiltered.
    val searchQuery: String = "",
    // #45: sections the user has collapsed, by KeySection name. Persisted, so
    // a user who collapses My Keys can open the app without private keys shown.
    val collapsedSections: Set<String> = emptySet()
) {
    // ── 4.1.0 Phase 12b — three sections ──────────────────────────────
    //
    // The split used to be one boolean, isKeyPair, and it put a hardware
    // key in the wrong half: a card imported on its own is stored with
    // isKeyPair = false (correctly — the private material is on the card,
    // not in SecureKeyStore) and so appeared under other people's keys.
    //
    // First cut is whether the user can ACT with the key. Second is
    // whether it has a face attached, which is what contactId already
    // means.

    /** Affected keys not yet dismissed, in keyring display order (My Keys
     *  first, matching how a user scans the list top to bottom). */
    val regenHintKeys: List<PGPKeyEntity> get() = allKeys.filter {
        it.fingerprint in legacyCompositeFingerprints && it.fingerprint !in dismissedRegenHintFingerprints
    }

    val myKeys: List<PGPKeyEntity> get() = sortKeys(allKeys.filter { it.section() == KeySection.MINE && matchesQuery(it) })
    val contactKeys: List<PGPKeyEntity> get() = sortKeys(allKeys.filter { it.section() == KeySection.CONTACT && matchesQuery(it) })
    val publicKeys: List<PGPKeyEntity> get() = sortKeys(allKeys.filter { it.section() == KeySection.PUBLIC && matchesQuery(it) })

    /** #45: does [key] match the current [searchQuery]? Empty query matches
     *  everything. Fingerprint / key-id matching ignores spaces and case so a
     *  pasted grouped fingerprint still hits. */
    private fun matchesQuery(key: PGPKeyEntity): Boolean {
        val needle = searchQuery.trim().lowercase()
        if (needle.isEmpty()) return true
        val compact = needle.replace(" ", "")
        if (key.userName.lowercase().contains(needle)) return true
        if (key.userEmail.lowercase().contains(needle)) return true
        if (key.fingerprint.lowercase().replace(" ", "").contains(compact)) return true
        if (key.longKeyId.lowercase().contains(compact)) return true
        // #45 (CertainBot): search notes too, since a key's purpose often lives
        // there when the name and email do not say what it is for.
        if (key.notes?.lowercase()?.contains(needle) == true) return true
        return false
    }

    /**
     * Key PAIRS the user has generated or imported with private material.
     *
     * Deliberately NOT myKeys.size: a card-backed row counts as one of
     * the user's own keys for display but is not a key pair, so the two
     * counts drift. (This originally existed for the free-tier key-pair
     * gate; RC3 §J removed billing entirely, but the distinct count is
     * still the correct semantic and Settings shows it.)
     */
    val keyPairCount: Int get() = allKeys.count { it.isKeyPair }

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

/**
 * 4.1.0 Phase 12b — which keyring section a key belongs to.
 *
 * Ordered as they are displayed. Declared at file scope rather than inside
 * the state so moveManual can compare sections without rebuilding lists.
 */
enum class KeySection { MINE, CONTACT, PUBLIC }

/**
 * MINE covers a card-backed key even though isKeyPair is false for one: the
 * user signs and decrypts with it, which is what the section means.
 */
fun PGPKeyEntity.section(): KeySection = when {
    isKeyPair || isCardBacked -> KeySection.MINE
    !contactId.isNullOrBlank() -> KeySection.CONTACT
    else -> KeySection.PUBLIC
}

enum class SortMode { ALPHA_ASC, ALPHA_DESC, MANUAL }

enum class ExpirationOption(val displayName: String, val seconds: Long?) {
    ONE_YEAR("1 Year", (365.25 * 24 * 60 * 60).toLong()),
    TWO_YEARS("2 Years", (2 * 365.25 * 24 * 60 * 60).toLong()),
    FIVE_YEARS("5 Years", (5 * 365.25 * 24 * 60 * 60).toLong()),
    NEVER("Never", null)
}

class KeyringViewModel(private val repo: KeyRepository) : ViewModel() {

    private companion object {
        /** RC5 P3 (#23): minimum visible duration for the pull-to-refresh
         *  indicator. Long enough to read as "the app responded", short
         *  enough not to feel like fake work. */
        const val MIN_REFRESH_SPIN_MS = 650L
    }

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
        val dismissedRegenHints = prefs.getString("keyring_regen_hint_dismissed", null)
            ?.split("\n")
            ?.filter { it.isNotBlank() }
            ?.toSet()
            ?: emptySet()
        val collapsed = prefs.getString("keyring_collapsed_sections", null)
            ?.split("\n")
            ?.filter { it.isNotBlank() }
            ?.toSet()
            ?: emptySet()
        _state.value = _state.value.copy(
            sortMode = savedMode,
            manualOrder = savedOrder,
            dismissedRegenHintFingerprints = dismissedRegenHints,
            collapsedSections = collapsed
        )
        loadKeys()
    }

    /**
     * 4.2.0 RC2 workstream F — which of [keys] carry a v5 algo-8 LibrePGP
     * composite subkey using the pre-fix ECC point encoding. Only keys with
     * a cached armored public key can be checked; a key missing one (e.g.
     * still mid-import) is skipped rather than treated as affected.
     */
    private fun computeLegacyCompositeFingerprints(keys: List<PGPKeyEntity>): Set<String> =
        keys.filter { it.algorithm.isComposite && !it.algorithm.isV6 }
            .mapNotNull { key -> key.armoredPublicKey?.let { key.fingerprint to it } }
            .filter { (_, armored) -> CompositeLibrePGPKeyMaterial.keyNeedsRegeneration(armored) }
            .map { (fp, _) -> fp }
            .toSet()

    /** Persist that the regeneration hint for [fingerprint] was dismissed. */
    fun dismissRegenHint(fingerprint: String) {
        val updated = _state.value.dismissedRegenHintFingerprints + fingerprint
        prefs.edit().putString("keyring_regen_hint_dismissed", updated.joinToString("\n")).apply()
        _state.value = _state.value.copy(dismissedRegenHintFingerprints = updated)
    }

    /** #45: update the live keyring search query. */
    fun setSearchQuery(query: String) {
        _state.value = _state.value.copy(searchQuery = query)
    }

    /** #45: collapse or expand a keyring section, persisting the choice so it
     *  survives an app restart (the point of "open without private keys on
     *  screen"). [sectionKey] is a KeySection name. */
    fun toggleSection(sectionKey: String) {
        val current = _state.value.collapsedSections
        val updated = if (sectionKey in current) current - sectionKey else current + sectionKey
        prefs.edit().putString("keyring_collapsed_sections", updated.joinToString("\n")).apply()
        _state.value = _state.value.copy(collapsedSections = updated)
    }

    /** Change the sort mode and persist it. */
    fun setSortMode(mode: SortMode) {
        prefs.edit().putString("keyring_sort_mode", mode.name).apply()
        _state.value = _state.value.copy(sortMode = mode)
    }

    /**
     * Manual drag-reorder. [fromId] / [toId] are PGPKeyEntity ids (the
     * LazyColumn item keys). Moves the dragged key to the target's slot,
     * but only within the same section (My Keys / Contacts / Public Keys) —
     * cross-section drags and header drops are ignored. Persists the new
     * full order.
     */
    fun moveManual(fromId: String, toId: String) {
        if (fromId == toId) return
        val all = _state.value.allKeys
        val fromKey = all.firstOrNull { it.id == fromId } ?: return
        val toKey = all.firstOrNull { it.id == toId } ?: return
        // Same section only. 4.1.0 Phase 12b — this compared isKeyPair,
        // which with three sections is not merely incomplete but wrong: it
        // would let a contact key be dragged into the Public Keys block,
        // since both have isKeyPair = false.
        if (fromKey.section() != toKey.section()) return

        // Seed the working order from the current display order if we don't
        // have a saved one yet (keeps what the user currently sees).
        val current = _state.value
        val seeded = current.manualOrder.ifEmpty {
            current.myKeys.map { it.fingerprint } +
                current.contactKeys.map { it.fingerprint } +
                current.publicKeys.map { it.fingerprint }
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
                    legacyCompositeFingerprints = computeLegacyCompositeFingerprints(keys),
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
     * Re-query the list WITHOUT the loading flash. The Keyring caches its
     * keys and reloads only on its own mutations, so a delete or a trust
     * change made on the Key Detail screen left the row stale until an app
     * reload (CertainBot, RC4). KeyringScreen calls this each time it
     * re-enters composition, including the pop back from Key Detail, so
     * those changes show at once. No isLoading toggle means no spinner on
     * return.
     */
    fun reloadSilently() {
        viewModelScope.launch {
            try {
                val keys = repo.getAllKeys()
                _state.value = _state.value.copy(
                    allKeys = keys,
                    legacyCompositeFingerprints = computeLegacyCompositeFingerprints(keys)
                )
            } catch (_: Exception) {
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
            // RC5 P3 (#23): the DB re-read completes sub-frame, so without a
            // floor the isRefreshing true→false round-trip lands inside one
            // composition and PullToRefreshBox's indicator never animates
            // (the "refresh arrow does not spin" report). Hold the flag for
            // a short minimum so the spinner visibly runs.
            val startedAt = android.os.SystemClock.elapsedRealtime()
            try {
                val keys = repo.getAllKeys()
                val subkeyMap = mutableMapOf<String, List<PgpSubkeyEntity>>()
                for (key in keys) {
                    subkeyMap[key.id] = emptyList()
                }
                _state.value = _state.value.copy(
                    allKeys = keys,
                    subkeysByPrimaryId = subkeyMap,
                    legacyCompositeFingerprints = computeLegacyCompositeFingerprints(keys),
                )
                holdRefreshIndicator(startedAt)
            } catch (e: Exception) {
                holdRefreshIndicator(startedAt)
                _state.value = _state.value.copy(
                    isRefreshing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_refresh_failed_format, e.message ?: "")
                )
            }
        }
    }

    /** RC5 P3 (#23): keep the pull-to-refresh indicator visible for at
     *  least [MIN_REFRESH_SPIN_MS] measured from [startedAt], then drop
     *  isRefreshing. The success path clears the flag here (after the data
     *  copy above) so the list updates immediately while the spinner
     *  finishes its arc; the error path calls this before surfacing the
     *  message. */
    private suspend fun holdRefreshIndicator(startedAt: Long) {
        val elapsed = android.os.SystemClock.elapsedRealtime() - startedAt
        val remaining = MIN_REFRESH_SPIN_MS - elapsed
        if (remaining > 0) kotlinx.coroutines.delay(remaining)
        _state.value = _state.value.copy(isRefreshing = false)
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

    // ── item 7 (#55): advanced granular keygen controls ──────────────────
    fun toggleGenerateGranular(on: Boolean) {
        _state.value = _state.value.copy(generateGranular = on)
    }

    fun setGranularIncludeDefaultEncryption(on: Boolean) {
        _state.value = _state.value.copy(granularIncludeDefaultEncryption = on)
    }

    fun addGranularSubkey(choice: AddSubkeyChoice) {
        _state.value = _state.value.copy(granularSubkeys = _state.value.granularSubkeys + choice)
    }

    fun removeGranularSubkey(index: Int) {
        _state.value = _state.value.copy(
            granularSubkeys = _state.value.granularSubkeys.filterIndexed { i, _ -> i != index }
        )
    }

    fun generateKey() {
        val s = _state.value
        // #48: synchronous re-entry guard. isGenerating was set inside the
        // launch below, so two fast taps both cleared this check and each
        // spawned a generation, creating duplicate keys. Guard on the Main
        // thread before any coroutine starts.
        if (s.isGenerating) return
        if (s.generateName.isBlank()) {
            _state.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_name_required))
            return
        }
        // item 3 (#request): email is optional now (name-only key). Only a
        // non-blank address must still look like an email.
        if (s.generateEmail.isNotBlank() && !s.generateEmail.contains("@")) {
            _state.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_email_invalid))
            return
        }
        if (s.generatePassphrase != s.generateConfirmPassphrase) {
            _state.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_passphrase_mismatch))
            return
        }

        _state.value = _state.value.copy(isGenerating = true, errorMessage = null)
        viewModelScope.launch {
            try {
                val passphrase = s.generatePassphrase.ifBlank { null }
                val generated = if (s.generateGranular) {
                    repo.generateGranularKey(
                        name = s.generateName.trim(),
                        email = s.generateEmail.trim(),
                        includeDefaultEncryptionSubkey = s.granularIncludeDefaultEncryption,
                        subkeys = s.granularSubkeys.map {
                            GranularSubkeySpec(it, s.generateExpiration.seconds)
                        },
                        passphrase = passphrase,
                        expirationSeconds = s.generateExpiration.seconds
                    )
                } else {
                    repo.generateKey(
                        name = s.generateName.trim(),
                        email = s.generateEmail.trim(),
                        algorithm = s.generateAlgorithm,
                        passphrase = passphrase,
                        expirationSeconds = s.generateExpiration.seconds
                    )
                }
                _state.value = _state.value.copy(
                    isGenerating = false,
                    showGenerateSheet = false,
                    // 4.0.0 Phase 5a (§6 Q6) — offer to publish the new key.
                    // item 8 (#request): suppressed while offline and when the
                    // "offer to publish new keys" suggestion is turned off.
                    // A name-only (email-less) key has no address to publish, and
                    // key servers key discovery off the email, so skip the prompt.
                    pendingPublishFingerprint =
                        if (shouldOfferPublish() && generated.userEmail.isNotBlank()) generated.fingerprint else null,
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

    /** 4.0.0 Phase 5a (§6 Q6) — user skipped or finished the post-
     *  generation publish prompt. */
    fun dismissPublishPrompt() {
        _state.value = _state.value.copy(pendingPublishFingerprint = null)
    }

    /** item 8 (#request): whether keygen offers the post-generation publish
     *  prompt. Off while offline mode is on (publishing contradicts the
     *  offline guarantee) and off when the user disabled the "offer to publish
     *  new keys" suggestion in Settings. Default on preserves prior behavior. */
    private fun shouldOfferPublish(): Boolean {
        if (com.pgpony.android.network.OfflineMode.isEnabled()) return false
        return PGPonyApp.instance
            .getSharedPreferences("pgpony_prefs", android.content.Context.MODE_PRIVATE)
            .getBoolean("offer_publish_after_keygen", true)
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
            importUrl = "",
            importSourceUrl = null,
            isFetchingUrl = false,
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
            importSourceUrl = null,
            errorMessage = null
        )
    }

    fun updateImportText(text: String) {
        _state.value = _state.value.copy(importArmoredText = text)
    }

    /** A10a — Key Server search field text. */
    fun updateImportUrl(url: String) {
        _state.value = _state.value.copy(importUrl = url)
    }

    /**
     * 4.6.0 (item 2): fetch the link on the Link tab through the proxy-aware
     * client (UrlKeyFetcher) and, when it holds public key material, show it
     * in the preview card for a fingerprint check. Nothing is stored until the
     * user confirms, through the same import path as every other method.
     */
    fun fetchKeyFromUrl() {
        val url = _state.value.importUrl.trim()
        if (url.isBlank() || _state.value.isFetchingUrl) return
        viewModelScope.launch {
            _state.value = _state.value.copy(isFetchingUrl = true, errorMessage = null, importPreview = null)
            val app = PGPonyApp.instance
            val result = com.pgpony.android.network.UrlKeyFetcher.fetch(url)
            _state.value = _state.value.copy(isFetchingUrl = false)
            when (result) {
                is com.pgpony.android.network.UrlKeyFetcher.Result.Keys ->
                    previewArmoredKey(result.armored, sourceUrl = result.finalUrl)
                com.pgpony.android.network.UrlKeyFetcher.Result.NotHttps ->
                    _state.value = _state.value.copy(errorMessage = app.getString(R.string.import_url_error_https))
                com.pgpony.android.network.UrlKeyFetcher.Result.Offline ->
                    _state.value = _state.value.copy(errorMessage = app.getString(R.string.import_url_error_offline))
                com.pgpony.android.network.UrlKeyFetcher.Result.NoKey ->
                    _state.value = _state.value.copy(errorMessage = app.getString(R.string.import_url_error_no_key))
                com.pgpony.android.network.UrlKeyFetcher.Result.TooManyRedirects ->
                    _state.value = _state.value.copy(errorMessage = app.getString(R.string.import_url_error_redirects))
                is com.pgpony.android.network.UrlKeyFetcher.Result.HttpError ->
                    _state.value = _state.value.copy(errorMessage = app.getString(R.string.import_url_error_http_format, result.status))
                is com.pgpony.android.network.UrlKeyFetcher.Result.Failed ->
                    _state.value = _state.value.copy(errorMessage = app.getString(R.string.import_url_error_failed_format, result.message))
            }
        }
    }

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
    /**
     * 3.1.0 Phase 8 Fix1 — byte-level entry for FILE imports. Splits
     * the failure modes that previously all collapsed into "No key
     * data":
     *   • bytes == null (the read itself failed — virtual/cloud doc,
     *     revoked grant) → a dedicated "couldn't read the file" error,
     *     because the file may be perfectly fine once saved locally.
     *   • binary OpenPGP keyrings (gpg --export without --armor) →
     *     wrapped through ArmoredOutputStream (BC picks the correct
     *     BEGIN header from the packet tag) and fed to the normal
     *     armored preview, so .gpg/.pgp key files import like .asc.
     *   • armored text → straight to previewArmoredKey, as before.
     */
    fun previewKeyBytes(
        bytes: ByteArray?,
        sourceFilename: String? = null,
        declaredSize: Long? = null
    ) {
        if (bytes == null) {
            _state.value = _state.value.copy(
                errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_file_read)
            )
            return
        }
        val asText = bytes.toString(Charsets.UTF_8)
        if (asText.contains("-----BEGIN PGP")) {
            previewArmoredKey(asText, sourceFilename = sourceFilename)
            return
        }
        val armored = try {
            val bos = java.io.ByteArrayOutputStream()
            org.bouncycastle.bcpg.ArmoredOutputStream(bos).use { it.write(bytes) }
            bos.toString("UTF-8")
        } catch (_: Exception) {
            null
        }
        // 3.1.0 Phase 8 Fix2 — DIAGNOSTIC: a valid armored .asc that
        // pastes fine still failed by file, so whatever reached this
        // point was NOT the file's content. When the binary-wrap path
        // is about to run (no BEGIN marker in what we read), first
        // check whether BC can actually read the bytes as a keyring;
        // if it can't, surface WHAT was read (size + printable head)
        // instead of a generic parse error, so the device shows us
        // whether the provider served an error page, truncation, or
        // something else entirely.
        val bcReadable = try {
            val objIn = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(
                java.io.ByteArrayInputStream(bytes)
            )
            org.bouncycastle.openpgp.PGPObjectFactory(
                objIn, org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator()
            ).nextObject() != null
        } catch (_: Exception) {
            false
        }
        if (!bcReadable) {
            val head = asText.take(48)
                .map { if (it.code in 32..126) it else '·' }
                .joinToString("")
            // 3.1.0 Phase 8 Fix3: name the file and the declared size so a
            // lying provider identifies itself in one screenshot.
            _state.value = _state.value.copy(
                errorMessage = PGPonyApp.instance.getString(
                    R.string.keyring_error_parse_diag2,
                    sourceFilename ?: "?",
                    bytes.size,
                    declaredSize?.toString() ?: "?",
                    head
                )
            )
            return
        }
        if (armored != null) {
            previewArmoredKey(armored, sourceFilename = sourceFilename)
        } else {
            previewArmoredKey("")
        }
    }

    fun previewArmoredKey(
        armoredText: String,
        source: KeyLookupSource? = null,
        sourceFilename: String? = null,
        sourceUrl: String? = null
    ) {
        // item 19 (#58): a shared browser text selection wraps the key in page
        // text; pull out the armored key block(s) and ignore the surrounding
        // noise. A clean .asc is a single block and comes back unchanged; text
        // with no armored block falls through to the "no key data" error below.
        val extracted = com.pgpony.android.crypto.ArmorExtractor.extractForImport(armoredText)
        val trimmed = (extracted ?: armoredText).trim()
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
                    importSourceUrl = sourceUrl,
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
                // Both paths now try WKD (email only) → configured directory
                // servers (keys.pgpony.app first) → keys.openpgp.org.
                val result = if (query.contains('@')) {
                    KeyServerRepository.shared.findByEmail(query)
                } else {
                    KeyServerRepository.shared.findByFingerprint(query)
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
     * A10a — commit the previewed key to the keyring.
     *
     * 4.0.0 Phase 1 (iOS v7.1.1 F3) — the commit is now outcome-aware
     * via repo.importArmoredKeyDetailed. A plain duplicate no longer
     * errors:
     *   • ALREADY_IN_KEYRING (byte-identical) → dismiss the sheet and
     *     raise the "Already in Keyring" dialog with a View Key jump
     *     (duplicateImportResult; dialog hosted in KeyringScreen).
     *   • MERGED_NEW_MATERIAL → the re-import doubled as a manual
     *     refresh; success snackbar says so.
     *   • UPGRADED_TO_KEY_PAIR / PAIRED_WITH_CARD / INSERTED → same
     *     success messages as before.
     */
    fun confirmImportPreview() {
        val preview = _state.value.importPreview ?: return
        viewModelScope.launch {
            _state.value = _state.value.copy(isImporting = true, errorMessage = null)
            try {
                // 4.0.0 Phase 3 (Succession) — a file/paste holding more than
                // one key block (OpenKeychain "export all keys", or a
                // decrypted OpenKeychain backup) imports ALL of them and
                // reports a summary instead of just the first.
                //
                // 4.0.4 fix — route on the RING count, not the armor-BLOCK
                // count. splitArmoredKeyBlocks counts BEGIN/END markers, but
                // `gpg --export alice bob carol` puts all three rings inside
                // ONE block, and previewKeyBytes wraps a binary export into
                // one block before it gets here. Both are the ordinary way to
                // hand over several keys, and both scored blocks.size == 1 —
                // so they fell through to the single-key branch below, which
                // imported ONLY THE FIRST key and reported "Public key
                // imported" as if nothing had been dropped.
                //
                // repo.countKeyRings shares its explode step with
                // importAllArmoredKeysDetailed, so the count that routes here
                // is by construction the count that gets imported.
                if (repo.countKeyRings(preview.armoredText) > 1) {
                    val outcomes = repo.importAllArmoredKeysDetailed(preview.armoredText)
                    val added = outcomes.count { it.resolution == ImportResolution.INSERTED }
                    val updated = outcomes.count {
                        it.resolution == ImportResolution.UPGRADED_TO_KEY_PAIR ||
                            it.resolution == ImportResolution.MERGED_NEW_MATERIAL ||
                            it.resolution == ImportResolution.PAIRED_WITH_CARD
                    }
                    val unchanged = outcomes.count {
                        it.resolution == ImportResolution.ALREADY_IN_KEYRING
                    }
                    _state.value = _state.value.copy(
                        isImporting = false,
                        showImportSheet = false,
                        importPreview = null,
                        successMessage = PGPonyApp.instance.getString(
                            R.string.import_multi_result_format,
                            outcomes.size, added, updated, unchanged
                        )
                    )
                    loadKeys()
                    return@launch
                }
                val outcome = repo.importArmoredKeyDetailed(preview.armoredText)
                if (outcome.resolution == ImportResolution.ALREADY_IN_KEYRING) {
                    val name = outcome.entity.userName.ifBlank { outcome.entity.shortFingerprint }
                    _state.value = _state.value.copy(
                        isImporting = false,
                        showImportSheet = false,
                        importPreview = null,
                        duplicateImportResult = DuplicateImportOutcome(
                            fingerprint = outcome.entity.fingerprint,
                            keyName = name
                        )
                    )
                    loadKeys()
                    return@launch
                }
                val message = when (outcome.resolution) {
                    ImportResolution.MERGED_NEW_MATERIAL ->
                        PGPonyApp.instance.getString(R.string.import_result_merged)
                    ImportResolution.UPGRADED_TO_KEY_PAIR ->
                        PGPonyApp.instance.getString(R.string.keyring_status_key_upgraded)
                    else -> if (preview.hasPrivateKey) "Key pair imported" else "Public key imported"
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

    /** 4.0.0 Phase 1 — dismiss the "Already in Keyring" dialog. */
    fun dismissDuplicateAlert() {
        _state.value = _state.value.copy(duplicateImportResult = null)
    }

    /**
     * #58 (CertainBot): import the previewed public key and then jump to the
     * Encrypt screen with it selected as recipient. A key shared into PGPony
     * is often shared to encrypt TO that person, not only to file it away.
     * Tolerant of an already-in-keyring key: the goal is to encrypt to it.
     */
    fun confirmImportAndEncrypt() {
        val preview = _state.value.importPreview ?: return
        val fp = preview.fingerprint
        viewModelScope.launch {
            _state.value = _state.value.copy(isImporting = true, errorMessage = null)
            try {
                repo.importArmoredKeyDetailed(preview.armoredText)
                _state.value = _state.value.copy(
                    isImporting = false,
                    showImportSheet = false,
                    importPreview = null,
                    pendingEncryptToFingerprint = fp
                )
                loadKeys()
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isImporting = false,
                    errorMessage = PGPonyApp.instance.getString(
                        R.string.keyring_error_import_failed_format, e.message ?: ""
                    )
                )
            }
        }
    }

    /** #58 — host acknowledges the encrypt-to jump so it fires once. */
    fun consumeEncryptToFingerprint() {
        _state.value = _state.value.copy(pendingEncryptToFingerprint = null)
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

    /**
     * RC3 §L (#21): armored private key for the delete sheet's backup
     * offer. Null for public-only keys or when export fails (missing
     * private material) — the caller snackbars the failure.
     */
    fun armoredPrivateFor(key: PGPKeyEntity, exportPassphrase: String? = null): String? =
        if (key.isKeyPair) repo.exportArmoredPrivateKey(key.fingerprint, exportPassphrase) else null

    fun confirmDelete(key: PGPKeyEntity) {
        _state.value = _state.value.copy(keyToDelete = key)
    }

    fun cancelDelete() {
        _state.value = _state.value.copy(keyToDelete = null)
    }

    // ── §5.6.1 recycle bin ────────────────────────────────────────────
    fun loadDeletedKeys() {
        viewModelScope.launch {
            _state.value = _state.value.copy(deletedKeys = repo.getDeletedKeys())
        }
    }

    fun restoreDeletedKey(entity: PGPKeyEntity) {
        viewModelScope.launch {
            repo.restoreKey(entity.id)
            loadKeys()
            _state.value = _state.value.copy(
                deletedKeys = repo.getDeletedKeys(),
                successMessage = PGPonyApp.instance.getString(R.string.recycle_bin_restored)
            )
        }
    }

    fun purgeDeletedKey(entity: PGPKeyEntity) {
        viewModelScope.launch {
            repo.purgeKey(entity)
            _state.value = _state.value.copy(deletedKeys = repo.getDeletedKeys())
        }
    }

    fun emptyRecycleBin() {
        viewModelScope.launch {
            repo.emptyRecycleBin()
            _state.value = _state.value.copy(deletedKeys = emptyList())
        }
    }

    fun deleteKey() {
        val key = _state.value.keyToDelete ?: return
        viewModelScope.launch {
            try {
                repo.softDeleteKey(key)
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
