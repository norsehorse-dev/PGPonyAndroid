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
import com.pgpony.android.i18n.ErrorText
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
    URL("Link"),
    /** 4.7.0 (item 42, #81): fetch the OpenPGP keys of a GitHub user. */
    GITHUB("GitHub")
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
    val keyName: String,
    /** 4.7.0 (item 24, #78): the existing row is your key pair, so the dialog
     *  says why nothing from the import was applied. */
    val isKeyPair: Boolean = false
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
    // 4.6.3 (#74): true once the keyring has been read at least once. Before
    // that, allKeys is empty because nothing has loaded yet, not because the
    // keyring is empty, and isLoading starts false, so the first frame looked
    // like an empty keyring and flashed the "tap the +" tip on every launch.
    val hasLoaded: Boolean = false,
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
    // 4.6.0 (item 16): add an [A] subkey to the new key. Off by default so the
    // default key shape is unchanged. Granular mode offers the same subkey in
    // its own list, so this applies to the simple mode. 4.8.0 RC11 (#109): it is
    // the Authentication subkey now, on the primary's own algorithm and curve
    // (ClassicalSubkeyGen.authTypeFor), no longer SSH only.
    val generateAuthSubkey: Boolean = false,
    // 4.8.0 RC11 (#109): on brainpool and secp256k1, which SSH has no type for,
    // true picks Ed25519 (for SSH) instead of the same curve (for a security key).
    val generateAuthForSsh: Boolean = false,
    val granularIncludeDefaultEncryption: Boolean = true,
    val granularSubkeys: List<AddSubkeyChoice> = emptyList(),
    // 4.8.0 RC11 (#109): picking another primary removed subkeys it can't hold.
    // The composer builds on the picked primary now; the v4/v6 base chips are gone.
    // 4.8.0 RC11 (#109): the subkeys removed, so the note can name them.
    val granularDroppedSubkeys: List<AddSubkeyChoice> = emptyList(),
    // 4.8.0 RC11 (#109): "Primary certifies only" (v4 composer): the primary gets
    // Certify alone, for a security key that holds the S, E and A subkeys.
    val granularCertifyOnly: Boolean = false,
    // 4.8.0 (item 4j): the user set the default encryption subkey switch, so
    // the composer stops choosing its value from the subkey list.
    val granularIncludeDefaultTouched: Boolean = false,
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
    /** 4.7.0 (item 42, #81): the username typed on the GitHub tab and whether
     *  its lookup is running. A found key shows its github.com link as the
     *  preview's source (importSourceUrl). */
    val importGitHubUser: String = "",
    val isFetchingGitHub: Boolean = false,
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
    val qrPreviewTiming: com.pgpony.android.qr.QrPreviewTiming? = null,
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
    // Keyring sorting (lukascomer feedback). Default MANUAL + empty order
    // preserves the existing createdAt-DESC order on upgrade until the
    // user picks alphabetical or drags something.
    val sortMode: SortMode = SortMode.MANUAL,
    // 4.8.0 (#101): Settings can turn off the drag handle on the Keyring.
    val dragReorderEnabled: Boolean = true,
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

    companion object {
        /** RC5 P3 (#23): minimum visible duration for the pull-to-refresh
         *  indicator. Long enough to read as "the app responded", short
         *  enough not to feel like fake work. */
        private const val MIN_REFRESH_SPIN_MS = 650L

        /** 4.6.3 (4.7.0 item 19 F): the largest file read as a key to import.
         *  Far above any real keyring export, small enough that the preview's
         *  String and armored copies of it fit in memory. */
        const val KEY_FILE_MAX_BYTES: Long = 32L * 1024 * 1024
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
            dragReorderEnabled = prefs.getBoolean("keyring_drag_reorder", true),
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
        val (fromFp, toFp) = resolveMove(fromId, toId) ?: return
        // Seed the working order from the current display order if we don't
        // have a saved one yet (keeps what the user currently sees).
        val current = _state.value
        val seeded = ManualOrder.seed(
            current.manualOrder,
            current.myKeys.map { it.fingerprint } +
                current.contactKeys.map { it.fingerprint } +
                current.publicKeys.map { it.fingerprint }
        )
        // 4.8.0 (4m): the move itself is ManualOrder.move, shared with
        // reorder mode's draft.
        val moved = ManualOrder.move(seeded, fromFp, toFp) ?: return
        saveManualOrder(moved)
    }

    /**
     * 4.8.0 (4m): the fingerprints behind a drag from [fromId] onto [toId]
     * (PGPKeyEntity ids, the LazyColumn item keys), or null when the drag
     * moves nothing: the same row, a row that is gone, or a drop in another
     * section. Reorder mode moves its draft with the result.
     */
    fun resolveMove(fromId: String, toId: String): Pair<String, String>? {
        if (fromId == toId) return null
        val all = _state.value.allKeys
        val fromKey = all.firstOrNull { it.id == fromId } ?: return null
        val toKey = all.firstOrNull { it.id == toId } ?: return null
        // Same section only. 4.1.0 Phase 12b: this compared isKeyPair,
        // which with three sections is not merely incomplete but wrong: it
        // would let a contact key be dragged into the Public Keys block,
        // since both have isKeyPair = false.
        if (fromKey.section() != toKey.section()) return null
        return fromKey.fingerprint to toKey.fingerprint
    }

    /**
     * 4.8.0 (4m): the order reorder mode starts from. Every key in Custom
     * order, whatever the sort and the search show right now, so the draft
     * covers keys a search hides.
     */
    fun reorderStartOrder(): List<String> {
        val all = _state.value.copy(sortMode = SortMode.MANUAL, searchQuery = "")
        return all.myKeys.map { it.fingerprint } +
            all.contactKeys.map { it.fingerprint } +
            all.publicKeys.map { it.fingerprint }
    }

    /**
     * 4.8.0 (4m): Done in reorder mode. Saves [order] and switches the sort
     * to Custom order, the only sort that shows it, so the list stays as the
     * user left it.
     */
    fun commitManualOrder(order: List<String>) {
        saveManualOrder(order)
        if (_state.value.sortMode != SortMode.MANUAL) setSortMode(SortMode.MANUAL)
    }

    private fun saveManualOrder(order: List<String>) {
        prefs.edit().putString("keyring_manual_order", order.joinToString("\n")).apply()
        _state.value = _state.value.copy(manualOrder = order)
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
                    isLoading = false,
                    hasLoaded = true
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isLoading = false,
                    hasLoaded = true,
                    errorMessage = ErrorText.localize(e.message)
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
                    legacyCompositeFingerprints = computeLegacyCompositeFingerprints(keys),
                    hasLoaded = true,
                    // 4.8.0 (#101): Settings may have changed it since init.
                    dragReorderEnabled = prefs.getBoolean("keyring_drag_reorder", true)
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
                    hasLoaded = true,
                )
                holdRefreshIndicator(startedAt)
            } catch (e: Exception) {
                holdRefreshIndicator(startedAt)
                _state.value = _state.value.copy(
                    isRefreshing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_refresh_failed_format, ErrorText.detail(e.message) ?: "")
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
            generateAuthSubkey = false,
            generateAuthForSsh = false,
            // 4.8.0: the composer starts fresh each time the sheet opens.
            generateGranular = false,
            granularIncludeDefaultEncryption = true,
            granularSubkeys = emptyList(),
            granularDroppedSubkeys = emptyList(),
            granularCertifyOnly = false,
            granularIncludeDefaultTouched = false,
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
        // 4.8.0 RC11 (#109): the composer follows the picked primary (GenerateForm).
        _state.value = GenerateForm.withAlgorithm(_state.value, algo)
    }

    /**
     * 4.8.0 RC11 (#109): onboarding's first-key sheet makes a plain key. It
     * shares this state with the Keyring's Generate sheet, so compose mode or
     * the Authentication subkey left on there must not carry over.
     */
    fun useSimpleGenerate() {
        _state.value = GenerateForm.simple(_state.value)
    }

    /** 4.8.0 RC11 (#109): "Primary certifies only" in the v4 composer. */
    fun setGranularCertifyOnly(on: Boolean) {
        _state.value = _state.value.copy(granularCertifyOnly = on)
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
    fun setGenerateAuthSubkey(on: Boolean) {
        _state.value = _state.value.copy(generateAuthSubkey = on)
    }

    /** 4.8.0 RC11 (#109): Ed25519 (for SSH) instead of the same curve (for a security key). */
    fun setGenerateAuthForSsh(forSsh: Boolean) {
        _state.value = _state.value.copy(generateAuthForSsh = forSsh)
    }

    fun toggleGenerateGranular(on: Boolean) {
        // 4.8.0 RC11 (#109): never changes the picked primary (GenerateForm).
        _state.value = GenerateForm.withCompose(_state.value, on)
    }

    fun setGranularIncludeDefaultEncryption(on: Boolean) {
        _state.value = _state.value.copy(granularIncludeDefaultEncryption = on, granularIncludeDefaultTouched = true)
    }

    fun addGranularSubkey(choice: AddSubkeyChoice) {
        setGranularSubkeys(_state.value.granularSubkeys + choice)
    }

    fun removeGranularSubkey(index: Int) {
        setGranularSubkeys(_state.value.granularSubkeys.filterIndexed { i, _ -> i != index })
    }

    private fun setGranularSubkeys(list: List<AddSubkeyChoice>, keepDroppedNote: Boolean = false) {
        val s = _state.value
        _state.value = s.copy(
            granularSubkeys = list,
            granularDroppedSubkeys = if (keepDroppedNote) s.granularDroppedSubkeys else emptyList(),
            granularIncludeDefaultEncryption = if (s.granularIncludeDefaultTouched) s.granularIncludeDefaultEncryption
                else GranularComposer.defaultEncryptionSubkey(list)
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
                // 4.8.0 RC11 (#109): compose on the picked primary, when it can be composed.
                val compose = GenerateForm.composes(s)
                val generated = if (compose) {
                    repo.generateGranularKey(
                        name = s.generateName.trim(),
                        email = s.generateEmail.trim(),
                        includeDefaultEncryptionSubkey = s.granularIncludeDefaultEncryption,
                        subkeys = s.granularSubkeys.map {
                            GranularSubkeySpec(it, s.generateExpiration.seconds)
                        },
                        passphrase = passphrase,
                        expirationSeconds = s.generateExpiration.seconds,
                        primary = s.generateAlgorithm,
                        // A v6 primary already certifies only (buildV6Ed25519X25519KeyRings).
                        certifyOnly = s.granularCertifyOnly && !s.generateAlgorithm.isV6
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
                // 4.6.0 (item 16): the SSH authentication subkey, bound with
                // the key's own expiry. A failure here keeps the new key and
                // says so; the subkey can still be added from Key Detail.
                var sshAuthError: String? = null
                if (!compose && s.generateAuthSubkey) {
                    try {
                        // 4.8.0 RC11 (#109): the primary's own algorithm and curve, or Ed25519 for SSH.
                        repo.addAuthSubkeyAtGeneration(
                            generated.fingerprint,
                            com.pgpony.android.crypto.ClassicalSubkeyGen.authTypeFor(s.generateAlgorithm, s.generateAuthForSsh),
                            s.generateExpiration.seconds, passphrase
                        )
                    } catch (e: Exception) {
                        sshAuthError = PGPonyApp.instance.getString(
                            R.string.keyring_generate_auth_failed, ErrorText.localize(e.message) ?: ""
                        )
                    }
                }
                _state.value = _state.value.copy(
                    errorMessage = sshAuthError,
                    isGenerating = false,
                    showGenerateSheet = false,
                    // 4.8.0 (item 4d): the new key's passphrase leaves memory with the sheet.
                    generatePassphrase = "",
                    generateConfirmPassphrase = "",
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
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_generation_failed_format, ErrorText.detail(e.message) ?: "")
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
    //   • GITHUB     → fetchKeysFromGitHub reads github.com/<user>.gpg
    //                  (4.7.0 item 42), populates preview with every key

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
            importGitHubUser = "",
            isFetchingGitHub = false,
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
                    _state.value = _state.value.copy(errorMessage = app.getString(R.string.import_url_error_failed_format, ErrorText.localize(result.message) ?: result.message))
            }
        }
    }

    fun updateImportGitHubUser(user: String) {
        _state.value = _state.value.copy(importGitHubUser = user)
    }

    /**
     * 4.7.0 (item 42, #81): fetch github.com/<user>.gpg through the
     * proxy-aware client (GitHubKeyFetcher). Every key found goes to the
     * preview card, which lists them all, and nothing is stored until the
     * user confirms. Failures other than "no keys" and "no such user" use the
     * key server search messages.
     */
    fun fetchKeysFromGitHub() {
        val input = _state.value.importGitHubUser.trim()
        if (input.isBlank() || _state.value.isFetchingGitHub) return
        viewModelScope.launch {
            _state.value = _state.value.copy(isFetchingGitHub = true, errorMessage = null, importPreview = null)
            val app = PGPonyApp.instance
            val result = com.pgpony.android.network.GitHubKeyFetcher.fetch(input)
            _state.value = _state.value.copy(isFetchingGitHub = false)
            val error: String? = when (result) {
                is com.pgpony.android.network.GitHubKeyFetcher.Result.Keys -> {
                    previewArmoredKey(result.armored, sourceUrl = result.url)
                    null
                }
                is com.pgpony.android.network.GitHubKeyFetcher.Result.NoKeys ->
                    app.getString(R.string.import_github_error_no_keys_format, result.username)
                is com.pgpony.android.network.GitHubKeyFetcher.Result.NotFound ->
                    app.getString(R.string.import_github_error_not_found_format, result.username)
                is com.pgpony.android.network.GitHubKeyFetcher.Result.Unreadable ->
                    app.getString(R.string.import_github_error_unreadable_format, result.username)
                com.pgpony.android.network.GitHubKeyFetcher.Result.InvalidUsername ->
                    app.getString(R.string.import_github_error_invalid)
                com.pgpony.android.network.GitHubKeyFetcher.Result.Offline ->
                    app.getString(
                        R.string.keyring_error_search_failed_format,
                        ErrorText.detail(com.pgpony.android.network.OfflineModeException().message) ?: ""
                    )
                is com.pgpony.android.network.GitHubKeyFetcher.Result.HttpError ->
                    app.getString(
                        R.string.keyring_error_search_failed_format,
                        app.getString(R.string.import_url_error_http_format, result.status)
                    )
                is com.pgpony.android.network.GitHubKeyFetcher.Result.Failed ->
                    app.getString(R.string.keyring_error_search_failed_format, ErrorText.detail(result.message) ?: "")
            }
            if (error != null) _state.value = _state.value.copy(errorMessage = error)
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
    /** 4.6.3 (4.7.0 item 19 F): a picked key file over [KEY_FILE_MAX_BYTES]. */
    fun reportKeyFileTooLarge() {
        _state.value = _state.value.copy(
            errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_file_too_large)
        )
    }

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
        sourceUrl: String? = null,
        qrTiming: com.pgpony.android.qr.QrPreviewTiming? = null,
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
                    qrPreviewTiming = qrTiming,
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
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_search_failed_format, ErrorText.detail(e.message) ?: "")
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
    fun onImportQRScanned(scannedText: String, timing: com.pgpony.android.qr.QrPreviewTiming? = null) {
        _state.value = _state.value.copy(showImportQRScanner = false)
        previewArmoredKey(scannedText, qrTiming = timing)
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
    fun confirmImportPreview(replaceSecrets: Boolean = false, secretPassphrase: CharArray? = null) {
        val preview = _state.value.importPreview ?: run { secretPassphrase?.fill('\u0000'); return }
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
                // 4.7.0 (item 47, #78): Use the secret keys from this file.
                val outcome = if (replaceSecrets) {
                    repo.importReplacingSecrets(preview.armoredText, secretPassphrase)
                } else {
                    repo.importArmoredKeyDetailed(preview.armoredText)
                }
                // 4.8.0 (item 4c): a key pair brought back from Recently Deleted
                // says so, since a public key import returned its private key.
                if (outcome.restoredFromBin && outcome.entity.isKeyPair) {
                    _state.value = _state.value.copy(
                        isImporting = false,
                        showImportSheet = false,
                        importPreview = null,
                        successMessage = PGPonyApp.instance.getString(R.string.import_result_restored_key_pair)
                    )
                    loadKeys()
                    return@launch
                }
                if (outcome.resolution == ImportResolution.ALREADY_IN_KEYRING) {
                    val name = outcome.entity.userName.ifBlank { outcome.entity.shortFingerprint }
                    _state.value = _state.value.copy(
                        isImporting = false,
                        showImportSheet = false,
                        importPreview = null,
                        duplicateImportResult = DuplicateImportOutcome(
                            fingerprint = outcome.entity.fingerprint,
                            keyName = name,
                            isKeyPair = outcome.entity.isKeyPair
                        )
                    )
                    loadKeys()
                    return@launch
                }
                val message = when (outcome.resolution) {
                    ImportResolution.MERGED_NEW_MATERIAL -> {
                        val base = PGPonyApp.instance.getString(
                            if (outcome.selfSignaturesApplied > 0) R.string.import_result_own_key_updated
                            else R.string.import_result_merged
                        )
                        // 4.7.0 (item 40, #82): say how many subkeys your own
                        // secret export added, next to the self-signature note.
                        val withSubkeys = if (outcome.subkeysAdded > 0) {
                            base + " " + PGPonyApp.instance.resources.getQuantityString(
                                R.plurals.import_result_subkeys_added, outcome.subkeysAdded, outcome.subkeysAdded
                            )
                        } else base
                        // 4.7.0 (item 47, #78): and how many secret keys the file replaced.
                        if (outcome.secretsReplaced > 0) {
                            withSubkeys + " " + PGPonyApp.instance.resources.getQuantityString(
                                R.plurals.import_result_secrets_replaced, outcome.secretsReplaced, outcome.secretsReplaced
                            )
                        } else withSubkeys
                    }
                    ImportResolution.UPGRADED_TO_KEY_PAIR ->
                        PGPonyApp.instance.getString(R.string.keyring_status_key_upgraded)
                    else -> PGPonyApp.instance.getString(
                        if (preview.hasPrivateKey) R.string.keyring_status_key_pair_imported
                        else R.string.keyring_status_public_key_imported
                    )
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
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_import_failed_format, ErrorText.detail(e.message) ?: "")
                )
            } finally {
                secretPassphrase?.fill('\u0000') // 4.7.0 (item 47)
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
                        R.string.keyring_error_import_failed_format, ErrorText.detail(e.message) ?: ""
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
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_import_failed_format, ErrorText.detail(e.message) ?: "")
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
                    errorMessage = PGPonyApp.instance.getString(R.string.keyring_error_delete_failed_format, ErrorText.detail(e.message) ?: "")
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

/**
 * 4.8.0 (items 4i and 4j): the subkey composer's rules, kept apart from the
 * ViewModel so they can be tested on their own.
 * 4.8.0 RC11 (#109): the composer builds on the primary picked in Generate Key.
 */
object GranularComposer {

    /** Whether the composer can build on [primary] (see AddSubkeyChoice.composerBaseFor). */
    fun supports(primary: KeyAlgorithm): Boolean = AddSubkeyChoice.composerBaseFor(primary) != null

    /**
     * The subkeys the composer's picker offers for a key on [primary], given the
     * subkeys already [chosen]: what Add subkey offers in Key Details for a key of
     * that type, on every curve (SubkeyPick.options, same order and labels). Two
     * differences: an Ed25519 v4 key takes a single ML-KEM-768 subkey here,
     * because Bouncy Castle cannot carry that subkey through a later edit, so the
     * composer grafts it last and only once; and a v6 key is always made with an
     * Ed25519 signing subkey ([fixedSubkeys]), so a second one is not offered.
     * 4.8.0 RC11 (#109): every curve at once, since the picker asks for the curve
     * itself; this was a menu with one curve at a time.
     */
    fun options(primary: KeyAlgorithm, chosen: List<AddSubkeyChoice>): List<AddSubkeyChoice> {
        val base = AddSubkeyChoice.composerBaseFor(primary) ?: return emptyList()
        var all = SubkeyPick.options(base, primary = primary)
        if (base == AddSubkeyChoice.Base.V6) all = all - V6_SIGNING
        if (base != AddSubkeyChoice.Base.V4 || chosen.none { it is AddSubkeyChoice.PqEncryption }) return all
        return all.filterNot { it is AddSubkeyChoice.PqEncryption }
    }

    /**
     * 4.8.0 RC11 (#109): the uses the composed key already covers, so the picker
     * starts on the first it lacks: signing (the primary, or the fixed signing
     * subkey when it certifies only), encryption when the default encryption
     * subkey is on, and the use of every subkey [chosen].
     */
    fun have(primary: KeyAlgorithm, includeDefaultEncryption: Boolean, chosen: List<AddSubkeyChoice>): Set<AddSubkeyChoice.Usage> {
        val have = mutableSetOf(AddSubkeyChoice.Usage.SIGN)
        if (includeDefaultEncryption && AddSubkeyChoice.defaultEncryptionFor(primary) != null) have += AddSubkeyChoice.Usage.ENCRYPT
        chosen.forEach { have += AddSubkeyChoice.usageOf(it) }
        return have
    }

    private val V6_SIGNING = AddSubkeyChoice.Classical(
        com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN
    )

    /**
     * 4.8.0 RC11 (#109): subkeys the key gets without being picked, shown as
     * fixed chips: a v6 key's Ed25519 signing subkey (its primary certifies
     * only), and on v4 with "Primary certifies only" and no signing subkey
     * composed, a signing subkey of the primary's type.
     */
    fun fixedSubkeys(primary: KeyAlgorithm, certifyOnly: Boolean, chosen: List<AddSubkeyChoice>): List<AddSubkeyChoice> =
        when (AddSubkeyChoice.composerBaseFor(primary)) {
            null -> emptyList()
            AddSubkeyChoice.Base.V6 -> listOf(V6_SIGNING)
            else -> AddSubkeyChoice.addedSigningSubkey(primary, certifyOnly, chosen)
        }

    /**
     * [chosen] with what a key on [primary] can't hold removed: ECDSA, ECDH and
     * RSA leave a v6 key; ML-DSA and ML-KEM-1024 leave a v4 key; ML-KEM-768
     * leaves an RSA or ECDSA key; an Ed25519 v4 key keeps one ML-KEM-768. A
     * primary the composer can't build on keeps the list for when a classical
     * one is picked again.
     */
    fun keptFor(primary: KeyAlgorithm, chosen: List<AddSubkeyChoice>): List<AddSubkeyChoice> {
        val base = AddSubkeyChoice.composerBaseFor(primary) ?: return chosen
        var pqKept = false
        return chosen.filter { c ->
            when {
                !AddSubkeyChoice.allowedOn(base, c) -> false
                base == AddSubkeyChoice.Base.V4 && c is AddSubkeyChoice.PqEncryption ->
                    if (pqKept) false else { pqKept = true; true }
                else -> true
            }
        }
    }

    /**
     * Whether the default classical encryption subkey is on when the user has
     * not set the switch: off once the list has a post-quantum encryption
     * subkey and nothing classical, so a key composed as post-quantum only
     * gets no classical encryption subkey it wasn't asked for.
     */
    fun defaultEncryptionSubkey(chosen: List<AddSubkeyChoice>): Boolean =
        !(chosen.any { it is AddSubkeyChoice.PqEncryption } && chosen.none { it is AddSubkeyChoice.Classical })
}

/**
 * 4.8.0 RC11 (#109): how the Generate Key form changes when the primary or
 * the compose switch changes, apart from the ViewModel so it can be tested.
 * The tester picked NIST P-256, turned on compose, and the key became an
 * Ed25519 v6 key: compose hid the picker and built its own base. Now nothing
 * here changes the picked primary.
 */
object GenerateForm {

    /** Whether Generate composes: the switch is on and the primary can be composed. */
    fun composes(s: KeyringUiState): Boolean = s.generateGranular && GranularComposer.supports(s.generateAlgorithm)

    /**
     * Onboarding's plain key: compose and the Authentication subkey off, and the
     * default expiry, since onboarding has no expiry picker.
     */
    fun simple(s: KeyringUiState): KeyringUiState = s.copy(
        generateGranular = false, generateAuthSubkey = false, generateAuthForSsh = false,
        generateExpiration = ExpirationOption.TWO_YEARS
    )

    /** The compose switch. It never changes the primary. */
    fun withCompose(s: KeyringUiState, on: Boolean): KeyringUiState = s.copy(generateGranular = on)

    /**
     * A new primary. The composer keeps the subkeys it can hold (and names the
     * ones it removed). A primary the composer can't build on
     * turns compose off and clears it, so nothing stays hidden to come back later.
     */
    fun withAlgorithm(s: KeyringUiState, algorithm: KeyAlgorithm): KeyringUiState {
        val next = s.copy(generateAlgorithm = algorithm)
        if (!GranularComposer.supports(algorithm)) {
            return next.copy(
                generateGranular = false,
                granularSubkeys = emptyList(),
                granularDroppedSubkeys = emptyList(),
                granularCertifyOnly = false
            )
        }
        val kept = GranularComposer.keptFor(algorithm, s.granularSubkeys)
        return next.copy(
            granularSubkeys = kept,
            // Each kept subkey once, so a second ML-KEM-768 counts as removed.
            granularDroppedSubkeys = s.granularSubkeys.toMutableList().apply { kept.forEach { remove(it) } },
            granularIncludeDefaultEncryption = if (s.granularIncludeDefaultTouched) s.granularIncludeDefaultEncryption
                else GranularComposer.defaultEncryptionSubkey(kept)
        )
    }
}
