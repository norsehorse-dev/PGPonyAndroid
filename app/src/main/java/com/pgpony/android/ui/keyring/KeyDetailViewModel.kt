// KeyDetailViewModel.kt
// PGPony Android — Phase A4a
//
// Backing state for KeyDetailScreen. Loads the key by fingerprint
// (passed via NavController route arg), generates the QR-code bitmap
// lazily when the QR sheet opens, manages the brief "Copied!" badge
// flip on fingerprint tap, and exposes a "coming soon" channel for the
// action buttons whose real implementations land in Phase A4b.
//
// Architectural note: this VM doesn't own any business logic that's
// shared with KeyringViewModel — it's a per-screen ephemeral VM that
// the factory hands out a fresh instance of each time the detail
// route is entered. The load() call is idempotent so re-entering the
// same route with the same fingerprint is cheap.

package com.pgpony.android.ui.keyring

import android.graphics.Bitmap
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.contacts.ContactsService
import com.pgpony.android.contacts.DeviceContact
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.KeyExpirationService
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.RevocationError
import com.pgpony.android.crypto.SubkeyCapability
import com.pgpony.android.crypto.UserIdService
import com.pgpony.android.data.KeyRefreshResult
import com.pgpony.android.data.KeyRefreshService
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.qr.QrBitmap
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.TrustLevel
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.data.repository.KeyRepoError
import com.pgpony.android.i18n.ErrorText
import com.pgpony.android.network.KeyServerRepository
import org.bouncycastle.openpgp.PGPPublicKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 4.0.0 Phase 2 (iOS v7.1.1 F4) — one User ID (tag-13) off the key
 * bytes. [isPrimary] marks the ID the row displays (the stored
 * entity.userID), falling back to the first when none matches.
 */
/**
 * 4.7.0 (item 18): turn the Add Subkey sheet's expiry date (epoch seconds, null =
 * never) into the lifetime the subkey generators expect (seconds after creation,
 * which is now). A date already past becomes one second, so the subkey is born
 * expired rather than never expiring.
 */
internal fun addSubkeyLifetimeSeconds(expiresAtEpochSeconds: Long?, nowMs: Long): Long? =
    expiresAtEpochSeconds?.let { (it - nowMs / 1000L).coerceAtLeast(1L) }

data class KeyUserIdInfo(
    val raw: String,
    val name: String,
    val email: String,
    val isPrimary: Boolean,
    val isRevoked: Boolean = false,
    /** 4.7.0 (item 27, #67): bound only by a SHA-1 self-certification made
     *  after the cutoff. Shown with a weak-hash mark. */
    val weakHash: Boolean = false
)

/**
 * RC3 §17.2 I — which UID a pending UserIdActionSheet confirmation is
 * for, and which of the two lightweight (passphrase-only) actions:
 * revoke or make-primary. Add User ID has its own richer sheet
 * (AddUserIdSheet) since it needs a text field, not just a confirm.
 */
data class UserIdActionRequest(
    val userId: String,
    val kind: Kind
) {
    enum class Kind { REVOKE, MAKE_PRIMARY, REMOVE }
}

/**
 * 4.2.0 RC3 workstream G (§11.2) — one non-primary key in the ring, for
 * the read-only Subkey section. Parsed at load time from the same
 * `repo.loadPublicKeyRing` call [deriveUserIds] already makes, so the
 * ring bytes stay the single source of truth rather than a second,
 * possibly-stale copy. [isCardBacked] is inherited from the parent
 * entity rather than tracked per subkey: PGPony's card model keeps the
 * primary in a vault and puts only the subkeys' private material on
 * the card (see KeyRepository's card-linking comment), so every
 * subkey of a card-backed key is itself card-backed.
 */
data class SubkeyDisplayInfo(
    val fingerprint: String,
    val keyId: String,
    /**
     * Display label for THIS subkey specifically, not the KeyAlgorithm
     * family label. KeyAlgorithm.ED25519_CV25519 covers both halves of
     * an Ed25519+Cv25519 pair under one shortName ("Ed25519") because
     * it names the ring as a whole; reusing that per-subkey here would
     * show "Ed25519" on an X25519 encryption subkey, which is what
     * happened before this field existed (RC3 §17.2 H bug, fixed 9
     * August: an Add Subkey X25519 test showed as "Ed25519 Encrypt").
     * See [KeyDetailViewModel.subkeyAlgorithmLabel].
     */
    val algorithmLabel: String,
    val capabilities: Int,
    val createdAt: Long,
    val expiresAt: Long?,
    val isRevoked: Boolean,
    val isCardBacked: Boolean,
    /** 4.7.0 (item 40, #82): where this subkey's secret is; null for a public
     *  key, which shows only why a subkey is not usable. */
    val secretLocation: com.pgpony.android.crypto.SubkeyAdmission.SecretLocation? = null,
    /** 4.7.0 (item 40, #82): why this subkey is not usable now; null when it is. */
    val issue: com.pgpony.android.crypto.SubkeyAdmission.Issue? = null,
    /** 4.7.0 (item 53, #86): its binding is one KeyExpirationService can
     *  re-sign (a Bouncy Castle subkey; not the hand-built ML-KEM ones). */
    val expiryEditable: Boolean = false
)

/**
 * 4.7.0 RC4 (item 13, #71): one key of a key pair, for Move to Security Key:
 * what it can do, and whether it can go to a card ([refusal] says why not).
 */
data class MoveToCardCandidate(
    val fingerprint: String,
    val keyIdHex: String,
    val algorithmLabel: String,
    val isPrimary: Boolean,
    val createdAt: Long,
    val canSign: Boolean,
    val canEncrypt: Boolean,
    val canAuthenticate: Boolean,
    val canCertify: Boolean,
    val kind: com.pgpony.android.crypto.card.KeyToCard.Kind?,
    val refusal: com.pgpony.android.crypto.card.KeyToCard.Refusal?
) {
    fun fits(slot: com.pgpony.android.crypto.card.CardSlot): Boolean =
        kind != null && com.pgpony.android.crypto.card.KeyToCard.fitsSlot(
            kind, slot, canSign, canEncrypt, canAuthenticate, primaryCanCertify = isPrimary && canCertify
        )
}

/** 4.7.0 RC4 (item 13): the done dialog after Move to Security Key. */
data class MoveToCardDone(val moved: Int, val removedFromPhone: Boolean)

/**
 * RC3 §N (#34): one row of the Key Detail fallback list — another
 * private key of the user's, with whether it is enabled as a decryption
 * fallback for THIS key. Enabled rows come first, in the user's saved
 * trial order; disabled rows follow.
 */
data class FallbackKeyChoice(
    val key: PGPKeyEntity,
    val enabled: Boolean
)

/** item 16 (#54): a subkey revoke/remove paused on the last-encryption-subkey
 *  warning, carrying what it needs to retry once the user confirms. */
data class PendingSubkeyOp(
    val kind: Kind,
    val subkeyFingerprint: String,
    val reason: RevocationReason? = null,
    val comment: String? = null,
    val passphrase: String? = null
) { enum class Kind { REVOKE, REMOVE } }

data class KeyDetailUiState(
    /** The loaded key. Null while loading or if not found. */
    val key: PGPKeyEntity? = null,
    /** 4.6.0 (item 16): the key's SSH public key line (authorized_keys
     *  form) when it has a usable authentication subkey, else null. */
    val sshPublicKey: String? = null,
    // RC3 §N (#34): decryption fallbacks + backwards-compatible signing
    // defaults, both key-pair-only surfaces. signerChoices is the picker
    // pool (software key pairs, this key included).
    val fallbackKeys: List<FallbackKeyChoice> = emptyList(),
    /** RC4 O3 (#34): strict mode — drop the all-keys compatibility tail. */
    val strictFallbacks: Boolean = false,
    /** RC4 O5 (#16): the stored ring already carries its own passphrase,
     *  so the export-passphrase fields are pointless and hidden. */
    val privateKeyIsProtected: Boolean = false,
    /** 4.7.0 (item 22): the stored primary is a stub (offline primary or
     *  divert-to-card), so the edits that need the primary are hidden. */
    val primaryStub: com.pgpony.android.crypto.OfflineStub.Kind? = null,
    /** 4.7.0 (item 58, #89): the primary key's usage (SubkeyCapability bits)
     *  from its newest self-signature carrying key flags; null when unknown. */
    val primaryUsage: Int? = null,
    /** 4.7.0 (item 60, #90): the last key server check's answer. */
    val keyServerCheck: com.pgpony.android.data.KeyServerCheckStore.Result? = null,
    /** 4.7.0 (item 61, #88): the certifier lookup sheet, when open, and what
     *  it searched for (a fingerprint, or a key ID when the certification
     *  names no fingerprint). */
    val certifierLookup: com.pgpony.android.ui.decrypt.SignerLookupState? = null,
    val certifierLookupQuery: String? = null,
    /** 4.7.0 (item 51, #86): the Refresh self-signatures dialog. */
    val showRefreshSigs: Boolean = false,
    val refreshSigsInFlight: Boolean = false,
    val refreshSigsError: String? = null,
    // 4.7.0 (item 31, #79): certifications of this key's User IDs, and the
    // Certify flow (public keys only).
    val certifications: List<com.pgpony.android.data.repository.KeyRepository.CertificationRow> = emptyList(),
    val canCertify: Boolean = false,
    val showCertifySheet: Boolean = false,
    val certifierChoices: List<PGPKeyEntity> = emptyList(),
    val certifyInFlight: Boolean = false,
    val certifyError: String? = null,
    /** Set after a certification is made: true when it was exportable (so
     *  the done dialog offers to share the key back). */
    val certifyDoneExportable: Boolean? = null,
    val certRevokeRequest: com.pgpony.android.data.repository.KeyRepository.CertificationRow? = null,
    val certRevokeInFlight: Boolean = false,
    val certRevokeError: String? = null,
    val signingDefaults: com.pgpony.android.data.SigningDefaultsEntity? = null,
    val signerChoices: List<PGPKeyEntity> = emptyList(),
    /** True while the initial load() coroutine is in flight. */
    val isLoading: Boolean = true,
    /** Set if the fingerprint passed in didn't resolve to anything. The
     *  screen renders a "Key not found — go back" placeholder. */
    val notFound: Boolean = false,
    /** Generated lazily when the user opens the QR sheet. We cache it
     *  so re-opening doesn't re-encode.
     *
     *  4.1.0 Phase 9 (issue #3): a LIST, because a post-quantum key does not
     *  fit in one symbol. One entry for anything that fits, which is what
     *  every classic key still produces. */
    val qrFrames: List<Bitmap> = emptyList(),
    /** Which frame the QR sheet is showing. */
    val qrIndex: Int = 0,
    /** Flipped briefly true on fingerprint tap → drives the "Copied!"
     *  green check + label in FingerprintSection. Reset to false after
     *  2 seconds by a coroutine in copyFingerprintFeedback(). */
    val copiedFingerprint: Boolean = false,
    /** Drives the QR ModalBottomSheet's visibility. */
    val showQRSheet: Boolean = false,
    /** Label of the action the user just tapped that isn't wired yet
     *  (e.g. "Export Private Key", "Revoke Key"). Drives the
     *  "Coming in next update" snackbar. Cleared on dismissal. The
     *  remaining stubbed-in-A4b actions are Export Private Key and
     *  Revoke Key — both wait on later phases for the underlying
     *  biometric / revocation-cert primitives. */
    val comingSoonLabel: String? = null,
    // HW Phase 3 / expiration editing — drives EditExpirationSheet.
    val showExpirySheet: Boolean = false,
    /** 4.7.0 (item 53, #86): the subkey whose expiry the sheet edits; null
     *  for the primary key. */
    val expirySubkey: SubkeyDisplayInfo? = null,
    val expiryInFlight: Boolean = false,
    val expiryError: String? = null,
    // RC3 §17.2 H — add subkey, drives AddSubkeySheet.
    val showAddSubkeySheet: Boolean = false,
    val addSubkeyInFlight: Boolean = false,
    val addSubkeyError: String? = null,
    // RC3 §17.2 I (#29) — add/revoke/promote User IDs.
    val showAddUserIdSheet: Boolean = false,
    val addUserIdInFlight: Boolean = false,
    val addUserIdError: String? = null,
    val showChangePassphraseSheet: Boolean = false,
    val changePassphraseInFlight: Boolean = false,
    val changePassphraseError: String? = null,
    // §5.6.7 (Play review) — editable primary-UID notations.
    val notations: List<UserIdService.Notation> = emptyList(),
    val showNotationsSheet: Boolean = false,
    val notationsInFlight: Boolean = false,
    val notationsError: String? = null,
    /** Non-null while UserIdActionSheet (revoke or make-primary) is open,
     *  identifying which UID and which action it's confirming. */
    val userIdAction: UserIdActionRequest? = null,
    val userIdActionInFlight: Boolean = false,
    val userIdActionError: String? = null,
    /** Generic error surface (key-load failure, QR encoding failure). */
    val errorMessage: String? = null,
    /** Phase A4b — modal sheet visibility flags. Each gates its own
     *  ModalBottomSheet in KeyDetailScreen. Only one is true at a time
     *  in practice but the type system doesn't enforce that — the screen
     *  renders in z-order so behavior is well-defined regardless. */
    val showTrustSheet: Boolean = false,
    val showNotesSheet: Boolean = false,
    val showContactSheet: Boolean = false,
    val showDeleteConfirm: Boolean = false,
    val showUnlinkConfirm: Boolean = false,
    /** Phase A4b — when non-null the ContactLinkSheet renders in
     *  auto-match mode and pre-filters to contacts whose email matches.
     *  Null = full picker mode. */
    val contactFilterEmail: String? = null,
    /** Phase A4b — populated when the contact picker is open. Lazily
     *  fetched on first open via ContactsService.fetchContactsWithEmail(). */
    val deviceContacts: List<DeviceContact> = emptyList(),
    /** Phase A4b — drives the "Contacts permission required" banner that
     *  appears inside the contact sheet if the user denies the runtime
     *  permission request. */
    val contactsPermissionDenied: Boolean = false,
    /** Phase A4b — toast-style success surface for write actions (Set
     *  as Default, Upload to Key Server, Notes saved, Contact linked).
     *  One-shot per emit. */
    val successMessage: String? = null,
    /** Phase A4b — separate flag from generic isLoading because we want
     *  to disable specific action rows during their respective network
     *  calls (e.g. Upload to Key Server shows a spinner inline while
     *  the rest of the screen stays interactive). */
    val isUploadingToKeyServer: Boolean = false,
    /** 3.0.0-KS1 — true while the "Check key server" lookup is in flight, so
     *  that action row shows an inline spinner. */
    val isCheckingKeyServer: Boolean = false,
    /** 4.0.0 Phase 2 (F4) — every User ID on the key, parsed at load
     *  time from the stored ring bytes (the bytes are the source of
     *  truth, so a keyserver refresh updates the list with no schema
     *  change). Never empty once [key] is loaded: falls back to the
     *  single stored ID when the ring can't be read. */
    val userIds: List<KeyUserIdInfo> = emptyList(),
    /** 4.2.0 RC3 (§11.2) — every non-primary key in the ring, parsed at
     *  load time alongside [userIds]. Empty for a key with no subkeys
     *  or before the ring can be read. */
    val subkeys: List<SubkeyDisplayInfo> = emptyList(),
    /** 4.7.0 (item 46, #82): the signing keys that may sign now, automatic
     *  order (newest valid subkey first). The chooser shows when there are two
     *  or more, or when a pin is set. */
    val signingSubkeyChoices: List<com.pgpony.android.crypto.SigningKeyOption> = emptyList(),
    /** 4.7.0 (item 46): the subkey fingerprint chosen in Use for signing, or
     *  null for automatic. */
    val signingSubkeyPin: String? = null,
    /** 4.7.0 RC4 (item 13, #71): Move to Security Key. */
    val showMoveToCardSheet: Boolean = false,
    val moveToCardCandidates: List<MoveToCardCandidate> = emptyList(),
    /** How many keys of this key pair have their secret on the phone; the moved
     *  keys may only leave the phone when every one of them is moved. */
    val moveToCardSecretCount: Int = 0,
    val moveToCardInFlight: Boolean = false,
    val moveToCardError: String? = null,
    /** Set after a move, for the done dialog: how many keys, and whether they left the phone. */
    val moveToCardDone: MoveToCardDone? = null,
    /** 4.0.0 Phase 2 (F5) — true while "Refresh from key server" is in
     *  flight; drives that row's inline spinner. */
    val isRefreshingFromKeyServer: Boolean = false,
    // ── Phase A6: Revocation ──────────────────────────────────────────
    /** Drives the RevokeKeySheet's visibility. */
    val showRevokeSheet: Boolean = false,
    /** Drives the RevocationResultSheet's visibility. Only set true
     *  after a successful applyRevocation; the sheet renders the cert
     *  text + Copy / Share buttons. */
    val showRevocationResultSheet: Boolean = false,
    /** Set true while the applyRevocation coroutine is in flight. Bound
     *  to the RevokeKeySheet's [isProcessing] flag so its Revoke button
     *  shows a spinner instead of being mashable twice. */
    val isRevoking: Boolean = false,
    /** Inline error surface for the RevokeKeySheet — e.g. "Incorrect
     *  passphrase". Cleared by [dismissRevokeSheet] and on each retry. */
    val revokeError: String? = null,
    /** The just-generated armored revocation certificate. Populated by
     *  applyRevocation on success, surfaced by RevocationResultSheet
     *  for the user to copy / share. Persisted in the same write via
     *  PGPKeyEntity.revocationCertificate so the user can re-export
     *  later from Danger Zone. */
    val pendingRevocationCert: String? = null,
    // ── item 16 (#54): per-subkey revoke / remove ────────────────────
    /** Target subkey for the reused RevokeKeySheet (subkey revoke). */
    val subkeyRevokeTarget: SubkeyDisplayInfo? = null,
    val showSubkeyRevokeSheet: Boolean = false,
    val subkeyRevokeInFlight: Boolean = false,
    val subkeyRevokeError: String? = null,
    /** Target subkey for the local-remove confirmation dialog. */
    val subkeyRemoveTarget: SubkeyDisplayInfo? = null,
    val subkeyRemoveInFlight: Boolean = false,
    /** Set when an op would strip the last encryption subkey; drives the
     *  confirm dialog that retries with allowLastEncryptionSubkey. */
    val lastEncryptionWarning: PendingSubkeyOp? = null,
    // ── Phase A7: Export private key ──────────────────────────────────
    /** Drives the export-private-key confirmation AlertDialog. The
     *  dialog warns the user that the private key includes secret
     *  material and that PGPony can't claw it back once shared. On
     *  confirm, the screen-level code invokes BiometricGate (if
     *  available) and only then surfaces the share Intent. */
    val showExportPrivateConfirm: Boolean = false,

    // 4.5.3 (#57): key-storage recovery. needsRecovery is set at load time when
    // this key's material can't be read via the hardware keystore (the OS wiped
    // it) but a passphrase recovery wrap exists. The banner offers to restore
    // access; the dialog takes the passphrase.
    val needsRecovery: Boolean = false,
    val showRecoveryDialog: Boolean = false,
    val isRecovering: Boolean = false,
    val recoveryError: String? = null,

    // ── Phase A7 Fix4: Export private key result sheet ────────────────
    /** Drives the result bottom sheet shown after a successful
     *  biometric-gated export. Hosts Copy + Save-As-File + Done
     *  actions; the armored material itself is held in
     *  pendingExportedPrivate and cleared on dismiss. */
    val showExportPrivateResultSheet: Boolean = false,
    /** The just-produced armored private key, pending user delivery.
     *  Held only while showExportPrivateResultSheet is true; cleared
     *  to null on dismiss to minimize the window during which it
     *  lives in VM memory. */
    val pendingExportedPrivate: String? = null,

    // ── Phase A8.6: Export public key result sheet ────────────────────
    /** Drives the public-key result sheet shown on "Share Public Key".
     *  Same Copy + Save-As-File + Done shape as the private-key sheet
     *  but no warning header and no biometric gate (public keys are
     *  meant to be distributed). */
    val showExportPublicResultSheet: Boolean = false,
    /** Cached armored public key for the open result sheet. Cleared
     *  on dismiss — public keys aren't sensitive, but holding them
     *  beyond the sheet's lifetime serves no purpose. */
    val pendingExportedPublic: String? = null
)

/** Phase A4b — one-shot navigation hint emitted when the user confirms
 *  delete. KeyDetailScreen subscribes via LaunchedEffect and pops the
 *  back stack so the user returns to the Keyring tab. */
sealed class KeyDetailEvent {
    object KeyDeleted : KeyDetailEvent()
}

class KeyDetailViewModel(
    private val repo: KeyRepository,
    // Phase A4b — needed for the Link to Contact + Auto-match flows.
    // Lazy-fetched contacts (the full address book scan is heavy) only
    // happen when the user actually triggers a contact action.
    private val contactsService: ContactsService
) : ViewModel() {

    // Phase A4b — keyserver client used by Upload to Key Server. Lazy
    // because constructing the HTTP client has a small up-front cost.
    private val keyServer by lazy { KeyServerRepository() }

    // 4.0.0 Phase 2 (F5) — the refresh pipeline. Lazy for the same
    // reason as keyServer; shares that client so both keyserver rows
    // ride one HTTP stack.
    private val keyRefresh by lazy { KeyRefreshService(repo, keyServer) }

    private val _state = MutableStateFlow(KeyDetailUiState())
    val state: StateFlow<KeyDetailUiState> = _state.asStateFlow()

    // Phase A4b — one-shot events for the screen to react to (delete →
    // pop back stack). Replay buffer 0 because these are strictly
    // ephemeral signals; missing one because the screen wasn't
    // subscribed yet would mean missing the navigation.
    private val _events = MutableSharedFlow<KeyDetailEvent>(extraBufferCapacity = 1)
    val events: SharedFlow<KeyDetailEvent> = _events.asSharedFlow()

    /**
     * Load the key with the supplied fingerprint. Idempotent — calling
     * twice with the same fingerprint is a no-op after the first load
     * completes. The screen calls this in a LaunchedEffect keyed on
     * the fingerprint arg.
     */
    /** 4.6.0 (item 16): see KeyDetailUiState.sshPublicKey. */
    private suspend fun deriveSshPublicKey(key: PGPKeyEntity): String? = withContext(Dispatchers.Default) {
        runCatching {
            val cert = repo.sshAuthCertificate(key.fingerprint) ?: return@runCatching null
            val sub = com.pgpony.android.crypto.ssh.SshAuth.authSubkey(cert) ?: return@runCatching null
            val m = com.pgpony.android.crypto.ssh.SshAuth.material(sub.publicBody) ?: return@runCatching null
            com.pgpony.android.crypto.ssh.SshAuth.authorizedKeysLine(m, key.userEmail.ifBlank { key.userName })
        }.getOrNull()
    }

    fun load(fingerprint: String) {
        // Skip if already loaded with the same fingerprint
        val current = _state.value.key
        if (current?.fingerprint.equals(fingerprint, ignoreCase = true) && !_state.value.isLoading) {
            return
        }
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, errorMessage = null)
            // item 24 (#55, lukascomer): reconcile the primary expiry live
            // from the ring so a stale stored "Never" self-corrects on open.
            val loaded = repo.getByFingerprint(fingerprint)
                ?.let { repo.reconcilePrimaryExpiry(it) }
                ?.let { repo.reconcileShownUserId(it) } // 4.7.0 (item 52)
            _state.value = _state.value.copy(
                key = loaded,
                isLoading = false,
                notFound = loaded == null,
                // 4.0.0 Phase 2 (F4) — parse the User ID list off the key
                // bytes alongside the entity load.
                userIds = loaded?.let { deriveUserIds(it) } ?: emptyList(),
                // 4.2.0 RC3 (§11.2) — same treatment for subkeys.
                subkeys = loaded?.let { deriveSubkeys(it) } ?: emptyList(),
                sshPublicKey = loaded?.let { deriveSshPublicKey(it) },
                // RC3 §N (#34)
                fallbackKeys = loaded?.let { deriveFallbacks(it) } ?: emptyList(),
                strictFallbacks = loaded?.let {
                    com.pgpony.android.crypto.FallbackPrefs.isStrict(it.fingerprint)
                } ?: false,
                privateKeyIsProtected = loaded?.takeIf { it.isKeyPair }?.let {
                    withContext(Dispatchers.IO) { repo.isPrivateKeyPassphraseProtected(it.fingerprint) }
                } ?: false,
                primaryStub = loaded?.takeIf { it.isKeyPair }?.let {
                    withContext(Dispatchers.IO) { runCatching { repo.primaryStubKind(it.fingerprint) }.getOrNull() }
                },
                keyServerCheck = loaded?.let { com.pgpony.android.data.KeyServerCheckStore.last(it.fingerprint) },
                primaryUsage = loaded?.let { e ->
                    withContext(Dispatchers.IO) {
                        repo.loadPublicKeyRing(e.fingerprint)?.publicKey?.let { primaryUsageOf(it) }
                    }
                },
                certifications = loaded?.let { runCatching { repo.certificationsOf(it.fingerprint) }.getOrNull() }.orEmpty(),
                canCertify = loaded?.let { withContext(Dispatchers.IO) { runCatching { repo.canBeCertified(it) }.getOrDefault(false) } } ?: false,
                signingDefaults = loaded?.takeIf { it.isKeyPair }
                    ?.let { repo.signingDefaultsFor(it.fingerprint) },
                signerChoices = loaded?.takeIf { it.isKeyPair }
                    ?.let { signerChoicePool() } ?: emptyList(),
                // §5.6.7 — human-readable notations on the primary self-cert.
                notations = loaded?.let {
                    withContext(Dispatchers.IO) { repo.readNotations(it.fingerprint) }
                } ?: emptyList(),
                needsRecovery = loaded?.takeIf { it.isKeyPair }?.let {
                    withContext(Dispatchers.IO) { repo.needsPassphraseRecovery(it.fingerprint) }
                } ?: false
            )
            refreshSigningSubkeys()
        }
    }

    // ── 4.5.3 (#57): storage recovery ──────────────────────────────────

    fun showRecoveryDialog() {
        _state.value = _state.value.copy(showRecoveryDialog = true, recoveryError = null)
    }

    fun dismissRecoveryDialog() {
        _state.value = _state.value.copy(showRecoveryDialog = false, recoveryError = null)
    }

    /**
     * Restore access to a key whose stored material the hardware keystore can
     * no longer open, by re-deriving it from [passphrase]. On success the
     * hardware wrap is re-established and the key works again everywhere
     * (in-app and the OpenPGP provider); on a wrong passphrase we surface an
     * inline error and leave the dialog open.
     */
    fun submitRecovery(passphrase: String) {
        val fp = _state.value.key?.fingerprint ?: return
        if (passphrase.isEmpty()) return
        viewModelScope.launch {
            _state.value = _state.value.copy(isRecovering = true, recoveryError = null)
            val ok = repo.recoverKeyWithPassphrase(fp, passphrase)
            if (ok) {
                _state.value = _state.value.copy(
                    isRecovering = false,
                    showRecoveryDialog = false,
                    needsRecovery = false,
                    recoveryError = null
                )
            } else {
                _state.value = _state.value.copy(
                    isRecovering = false,
                    recoveryError = PGPonyApp.instance.getString(R.string.key_detail_recovery_wrong_passphrase)
                )
            }
        }
    }

    // ── RC3 §N (#34): fallbacks + signing defaults ─────────────────────

    /** Software key pairs eligible as fallbacks / signing defaults. */
    private suspend fun signerChoicePool(): List<PGPKeyEntity> =
        repo.getAllKeys().filter { it.isKeyPair && !it.isCardBacked && !it.isRevoked }

    /**
     * Enabled fallbacks first in saved order, then the remaining
     * eligible keys (everything except this key itself) disabled.
     */
    private suspend fun deriveFallbacks(entity: PGPKeyEntity): List<FallbackKeyChoice> {
        if (!entity.isKeyPair) return emptyList()
        val pool = signerChoicePool().filter { it.fingerprint != entity.fingerprint }
        val byFp = pool.associateBy { it.fingerprint }
        val enabledOrder = repo.fallbacksFor(entity.fingerprint)
        val rows = mutableListOf<FallbackKeyChoice>()
        enabledOrder.forEach { fp -> byFp[fp]?.let { rows.add(FallbackKeyChoice(it, enabled = true)) } }
        pool.forEach { k ->
            if (rows.none { it.key.fingerprint == k.fingerprint }) {
                rows.add(FallbackKeyChoice(k, enabled = false))
            }
        }
        return rows
    }

    private fun persistAndShowFallbacks(primary: String, rows: List<FallbackKeyChoice>) {
        viewModelScope.launch {
            repo.setFallbacks(primary, rows.filter { it.enabled }.map { it.key.fingerprint })
            _state.value = _state.value.copy(fallbackKeys = rows)
        }
    }

    /** RC4 O3 (#34): persist + reflect the per-key strict-mode switch. */
    fun setStrictFallbacks(enabled: Boolean) {
        val key = _state.value.key ?: return
        com.pgpony.android.crypto.FallbackPrefs.setStrict(key.fingerprint, enabled)
        _state.value = _state.value.copy(strictFallbacks = enabled)
    }

    /**
     * 4.7.0 (item 46, #82): read the signing keys and the Use for signing pin
     * again. Called after the key loads and after every subkey change, since
     * a new, revoked, removed or re-dated subkey changes the choices.
     */
    private fun refreshSigningSubkeys() {
        val key = _state.value.key ?: return
        if (!key.isKeyPair || key.isCardBacked) {
            _state.value = _state.value.copy(signingSubkeyChoices = emptyList(), signingSubkeyPin = null)
            return
        }
        viewModelScope.launch {
            val choices = repo.signingSubkeyChoices(key.fingerprint)
            val pin = withContext(Dispatchers.IO) {
                runCatching { com.pgpony.android.crypto.SigningSubkeyPins.pinnedFor(key.fingerprint) }.getOrNull()
            }
            if (_state.value.key?.fingerprint != key.fingerprint) return@launch
            _state.value = _state.value.copy(signingSubkeyChoices = choices, signingSubkeyPin = pin)
        }
    }

    /** 4.7.0 (item 46, #82): pin [subkeyFingerprint] for signing, or null for automatic. */
    fun setSigningSubkey(subkeyFingerprint: String?) {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                runCatching { com.pgpony.android.crypto.SigningSubkeyPins.set(key.fingerprint, subkeyFingerprint) }
            }
            refreshSigningSubkeys()
        }
    }

    fun toggleFallback(fingerprint: String) {
        val key = _state.value.key ?: return
        val rows = _state.value.fallbackKeys.toMutableList()
        val idx = rows.indexOfFirst { it.key.fingerprint == fingerprint }
        if (idx < 0) return
        val row = rows.removeAt(idx)
        if (row.enabled) {
            // Turning off: drop to the head of the disabled block.
            val insertAt = rows.indexOfFirst { !it.enabled }.let { if (it >= 0) it else rows.size }
            rows.add(insertAt, row.copy(enabled = false))
        } else {
            // Turning on: append to the end of the enabled block.
            val insertAt = rows.indexOfFirst { !it.enabled }.let { if (it >= 0) it else rows.size }
            rows.add(insertAt, row.copy(enabled = true))
        }
        persistAndShowFallbacks(key.fingerprint, rows)
    }

    /** Move an ENABLED fallback one slot up (-1) or down (+1) within the
     *  enabled block. Same captured-indices care as
     *  KeyringViewModel.moveManual. */
    fun moveFallback(fingerprint: String, delta: Int) {
        val key = _state.value.key ?: return
        val rows = _state.value.fallbackKeys.toMutableList()
        val from = rows.indexOfFirst { it.key.fingerprint == fingerprint }
        if (from < 0 || !rows[from].enabled) return
        val to = from + delta
        if (to < 0 || to >= rows.size || !rows[to].enabled) return
        val row = rows.removeAt(from)
        rows.add(to, row)
        persistAndShowFallbacks(key.fingerprint, rows)
    }

    /** slot: 0 = PQC recipients, 1 = classical recipients, 2 = sign-only.
     *  null fingerprint = back to "this key" (clears the column). */
    fun setSigningDefault(slot: Int, fingerprint: String?) {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            val current = repo.signingDefaultsFor(key.fingerprint)
                ?: com.pgpony.android.data.SigningDefaultsEntity(key.fingerprint)
            val cleaned = fingerprint?.takeIf { it != key.fingerprint }
            val updated = when (slot) {
                0 -> current.copy(pqcSignerFingerprint = cleaned)
                1 -> current.copy(classicalSignerFingerprint = cleaned)
                else -> current.copy(signOnlySignerFingerprint = cleaned)
            }
            repo.setSigningDefaults(updated)
            _state.value = _state.value.copy(signingDefaults = updated)
        }
    }

    /**
     * Open the QR sheet. Generates the QR bitmap on the first open so
     * we don't spend ZXing cycles for users who never tap the button.
     * Subsequent opens reuse the cached bitmap.
     */
    fun showQR() {
        val key = _state.value.key ?: return
        if (_state.value.qrFrames.isNotEmpty()) {
            _state.value = _state.value.copy(showQRSheet = true, qrIndex = 0)
            return
        }
        // #36 (AraafRoyall): open the sheet immediately so the tap feels live.
        // With no frames yet the sheet shows its spinner while ZXing runs,
        // instead of the tap sitting dead until the QR is fully encoded.
        _state.value = _state.value.copy(showQRSheet = true, qrFrames = emptyList(), qrIndex = 0)
        viewModelScope.launch {
            // §5.6.5 (#37): export + QR encode off the main thread so a
            // large post-quantum key does not stall the sheet on open.
            val armored = withContext(Dispatchers.IO) { repo.exportArmoredPublicKey(key.fingerprint) }
            if (armored.isNullOrBlank()) {
                _state.value = _state.value.copy(
                    errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_export_for_qr),
                    showQRSheet = false
                )
                return@launch
            }
            // 4.1.0 Phase 9 (issue #3) — a key too large for one symbol is
            // now split across several instead of failing. Past even that,
            // encodeFrames returns null and the user gets an instruction
            // rather than ZXing's "data too big", which is the half of #3
            // that could always have been fixed cheaply.
            val frames = try {
                withContext(Dispatchers.Default) { QrBitmap.encodeFrames(armored) }
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_qr_failed_format, ErrorText.detail(e.message) ?: ""),
                    showQRSheet = false
                )
                return@launch
            }
            if (frames.isNullOrEmpty()) {
                _state.value = _state.value.copy(
                    errorMessage = PGPonyApp.instance.getString(R.string.qr_too_large),
                    showQRSheet = false
                )
                return@launch
            }
            _state.value = _state.value.copy(
                qrFrames = frames,
                qrIndex = 0,
                showQRSheet = true
            )
        }
    }

    fun hideQR() {
        _state.value = _state.value.copy(showQRSheet = false)
    }

    /** 4.1.0 Phase 9 — step through a multi-part QR. Wraps at both ends so
     *  the other person can keep the camera up and let it cycle. */
    fun qrNext() {
        val s = _state.value
        if (s.qrFrames.size < 2) return
        _state.value = s.copy(qrIndex = (s.qrIndex + 1) % s.qrFrames.size)
    }

    fun qrPrev() {
        val s = _state.value
        if (s.qrFrames.size < 2) return
        _state.value = s.copy(
            qrIndex = (s.qrIndex - 1 + s.qrFrames.size) % s.qrFrames.size
        )
    }

    /**
     * Flip [KeyDetailUiState.copiedFingerprint] to true and schedule a
     * 2-second reset. Drives the inline "Copied!" feedback in the
     * Fingerprint section; the actual clipboard write is the caller's
     * job (LocalClipboardManager from the Composable side).
     */
    fun copyFingerprintFeedback() {
        viewModelScope.launch {
            _state.value = _state.value.copy(copiedFingerprint = true)
            delay(2000)
            _state.value = _state.value.copy(copiedFingerprint = false)
        }
    }

    /** Action buttons not yet wired (A4b) route here for a snackbar. */
    fun showComingSoon(label: String) {
        _state.value = _state.value.copy(comingSoonLabel = label)
    }

    fun dismissComingSoon() {
        _state.value = _state.value.copy(comingSoonLabel = null)
    }

    fun clearError() {
        _state.value = _state.value.copy(errorMessage = null)
    }

    // ── Phase A4b: Trust Level ────────────────────────────────────────

    fun showTrustSheet() {
        _state.value = _state.value.copy(showTrustSheet = true)
    }

    fun dismissTrustSheet() {
        _state.value = _state.value.copy(showTrustSheet = false)
    }

    fun setTrustLevel(level: TrustLevel) {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            repo.updateTrustLevel(key.fingerprint, level)
            // Refresh local snapshot — banner / row should reflect the
            // new trust immediately.
            val reloaded = repo.getByFingerprint(key.fingerprint)
            _state.value = _state.value.copy(
                key = reloaded ?: key,
                showTrustSheet = false,
                successMessage = PGPonyApp.instance.getString(R.string.kd_vm_status_trust_updated)
            )
        }
    }

    // ── Phase A4b: Notes ──────────────────────────────────────────────

    fun showNotesSheet() {
        _state.value = _state.value.copy(showNotesSheet = true)
    }

    fun dismissNotesSheet() {
        _state.value = _state.value.copy(showNotesSheet = false)
    }

    fun saveNotes(notes: String?) {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            repo.updateNotes(key.fingerprint, notes)
            val reloaded = repo.getByFingerprint(key.fingerprint)
            _state.value = _state.value.copy(
                key = reloaded ?: key,
                showNotesSheet = false,
                successMessage = if (notes.isNullOrBlank()) PGPonyApp.instance.getString(R.string.kd_vm_status_notes_cleared) else PGPonyApp.instance.getString(R.string.kd_vm_status_notes_saved)
            )
        }
    }

    // ── Phase A4b: Contact link ───────────────────────────────────────

    /**
     * Open the full-picker contact sheet. Caller (KeyDetailScreen) is
     * responsible for ensuring READ_CONTACTS is granted before invoking
     * this — the permission flow lives at the Composable layer because
     * rememberLauncherForActivityResult only works there.
     */
    fun showContactPicker() {
        viewModelScope.launch {
            // Fetch on each open — the address book can change between
            // visits and the cost is bounded by the number of contacts
            // with email addresses.
            val contacts = contactsService.fetchContactsWithEmail()
            _state.value = _state.value.copy(
                showContactSheet = true,
                contactFilterEmail = null,
                deviceContacts = contacts,
                contactsPermissionDenied = false
            )
        }
    }

    /**
     * Trigger an auto-match flow. Fetches contacts, filters by the
     * key's email, and:
     *   • exactly one hit → link directly, show success snackbar
     *   • zero or 2+ hits → open the picker sheet pre-filtered to the
     *     hits (zero hits → empty state with explanatory message)
     */
    fun autoMatchByEmail() {
        val key = _state.value.key ?: return
        val email = key.userEmail
        if (email.isBlank()) {
            _state.value = _state.value.copy(
                errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_no_email_to_match)
            )
            return
        }
        viewModelScope.launch {
            val all = contactsService.fetchContactsWithEmail()
            val matches = all.filter { c -> c.emails.any { it.equals(email, ignoreCase = true) } }
            when (matches.size) {
                1 -> {
                    // Single match — link directly, no sheet needed.
                    val match = matches.first()
                    repo.updateContactLink(
                        fingerprint = key.fingerprint,
                        contactId = match.contactId,
                        contactName = match.displayName,
                        contactPhotoUri = match.photoUri
                    )
                    val reloaded = repo.getByFingerprint(key.fingerprint)
                    _state.value = _state.value.copy(
                        key = reloaded ?: key,
                        successMessage = PGPonyApp.instance.getString(R.string.kd_vm_status_linked_to_format, match.displayName)
                    )
                }
                else -> {
                    // Zero or multiple matches — let the user pick (or
                    // see the empty state).
                    _state.value = _state.value.copy(
                        showContactSheet = true,
                        contactFilterEmail = email,
                        deviceContacts = all,
                        contactsPermissionDenied = false
                    )
                }
            }
        }
    }

    fun selectContact(contact: DeviceContact) {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            repo.updateContactLink(
                fingerprint = key.fingerprint,
                contactId = contact.contactId,
                contactName = contact.displayName,
                contactPhotoUri = contact.photoUri
            )
            val reloaded = repo.getByFingerprint(key.fingerprint)
            _state.value = _state.value.copy(
                key = reloaded ?: key,
                showContactSheet = false,
                successMessage = PGPonyApp.instance.getString(R.string.kd_vm_status_linked_to_format, contact.displayName)
            )
        }
    }

    fun dismissContactSheet() {
        _state.value = _state.value.copy(showContactSheet = false)
    }

    fun reportContactsPermissionDenied() {
        _state.value = _state.value.copy(
            contactsPermissionDenied = true,
            errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_contacts_permission_needed)
        )
    }

    fun showUnlinkConfirm() {
        _state.value = _state.value.copy(showUnlinkConfirm = true)
    }

    fun dismissUnlinkConfirm() {
        _state.value = _state.value.copy(showUnlinkConfirm = false)
    }

    fun unlinkContact() {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            repo.updateContactLink(
                fingerprint = key.fingerprint,
                contactId = null,
                contactName = null,
                contactPhotoUri = null
            )
            val reloaded = repo.getByFingerprint(key.fingerprint)
            _state.value = _state.value.copy(
                key = reloaded ?: key,
                showUnlinkConfirm = false,
                successMessage = PGPonyApp.instance.getString(R.string.kd_vm_status_contact_unlinked)
            )
        }
    }

    // ── Phase A4b: Set as default ─────────────────────────────────────

    fun setAsDefault() {
        val key = _state.value.key ?: return
        if (!key.isKeyPair) return  // shouldn't happen — action row hidden
        viewModelScope.launch {
            repo.setDefaultKey(key.fingerprint)
            val reloaded = repo.getByFingerprint(key.fingerprint)
            _state.value = _state.value.copy(
                key = reloaded ?: key,
                successMessage = PGPonyApp.instance.getString(R.string.kd_vm_status_set_as_default_format, key.userName.ifBlank { key.userEmail })
            )
        }
    }

    // ── Phase A4b: Upload to keyserver ────────────────────────────────

    fun uploadToKeyServer() {
        val key = _state.value.key ?: return
        if (!key.isKeyPair) return
        viewModelScope.launch {
            _state.value = _state.value.copy(isUploadingToKeyServer = true)
            try {
                val armored = repo.exportArmoredPublicKey(key.fingerprint)
                    ?: throw IllegalStateException("Could not export public key")
                // A8 Fix2: keyServer.upload now auto-triggers email
                // verification for every address in the key. The result
                // tells us which addresses got verification requests so
                // we can show the user a precise, actionable message.
                val result = keyServer.upload(armored)
                repo.markKeyServerUploaded(key.fingerprint)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    isUploadingToKeyServer = false,
                    successMessage = uploadSuccessMessage(result)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isUploadingToKeyServer = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_upload_failed_format, ErrorText.detail(e.message) ?: "")
                )
            }
        }
    }

    /**
     * 3.0.0-KS1 (lukascomer request) — check/refresh this key against a keyserver.
     * Looks the key up by fingerprint; whether or not it's found, the attempt
     * stamps `lastCheckedAt` so the detail screen shows "Last checked: <date>".
     * The success message reports whether the key is still published.
     */
    fun checkKeyServer() {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            _state.value = _state.value.copy(isCheckingKeyServer = true)
            try {
                // 4.7.0 (item 60, #90): fetchByFingerprint throws on a transport
                // failure, so a failed check is no longer reported as "not found".
                val found = keyServer.fetchByFingerprint(key.fingerprint)
                val server = com.pgpony.android.network.KeyServerRepository.CHECK_SERVER_NAME
                com.pgpony.android.data.KeyServerCheckStore.record(key.fingerprint, server, found != null)
                repo.markKeyServerChecked(key.fingerprint)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    isCheckingKeyServer = false,
                    keyServerCheck = com.pgpony.android.data.KeyServerCheckStore.last(key.fingerprint),
                    successMessage = PGPonyApp.instance.getString(
                        if (found != null) R.string.kd_vm_check_found_on else R.string.kd_vm_check_not_found_on,
                        server
                    )
                )
            } catch (e: Exception) {
                // Still record the attempt, then surface the error.
                repo.markKeyServerChecked(key.fingerprint)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    isCheckingKeyServer = false,
                    errorMessage = PGPonyApp.instance.getString(
                        R.string.kd_vm_check_failed_format, ErrorText.detail(e.message) ?: ""
                    )
                )
            }
        }
    }

    // ── 4.0.0 Phase 2 (F4): all User IDs off the key bytes ─────────────

    /**
     * Every tag-13 User ID on the key, in ring order, parsed from the
     * stored public ring (BC exposes them directly on the primary key —
     * no packet walk needed, unlike iOS). Primary = the ID this row
     * displays (entity.userID), falling back to the first. Never empty:
     * when the ring can't be loaded (fresh card record with no cert
     * paired yet, storage hiccup) it falls back to the single stored
     * ID. Mirrors iOS PGPKeyModel.allUserIDs().
     */
    // 4.0.4 — suspend + dispatched. loadPublicKeyRing is a blocking
    // EncryptedSharedPreferences read plus a Bouncy Castle parse, and all
    // seven callers sit inside a viewModelScope.launch, i.e. on
    // Dispatchers.Main.immediate. One key rather than the whole keyring, so
    // this was jank rather than an ANR — but it is the same mistake.
    private suspend fun deriveUserIds(entity: PGPKeyEntity): List<KeyUserIdInfo> {
        val fromRing = mutableListOf<KeyUserIdInfo>()
        val pubRing = withContext(Dispatchers.IO) { repo.loadPublicKeyRing(entity.fingerprint) }
        val primaryPub = pubRing?.publicKey
        val weakUids = withContext(Dispatchers.Default) {
            pubRing?.let { runCatching { com.pgpony.android.crypto.CertificateBindings.analyze(it.encoded)?.weakUserIds }.getOrNull() }
        }.orEmpty()
        primaryPub?.userIDs?.let { ids ->
            while (ids.hasNext()) {
                val raw = ids.next() as? String ?: continue
                if (raw.isEmpty()) continue
                val parsed = PGPKeyEntity.parseUserID(raw)
                fromRing.add(
                    KeyUserIdInfo(
                        raw = raw,
                        name = parsed.first,
                        email = parsed.second,
                        isPrimary = false,
                        isRevoked = primaryPub?.let { UserIdService.shared.isRevoked(it, raw) } ?: false,
                        weakHash = raw in weakUids
                    )
                )
            }
        }
        if (fromRing.isEmpty() && entity.algorithm.isCompositeSign) {
            // #55 item 4: a composite ML-DSA key is not a BouncyCastle ring, so
            // its User IDs come from CompositeKeyFacade metadata rather than from
            // primaryPub (which is null for algo 30/31). Show every one.
            val compositeUids = withContext(Dispatchers.IO) {
                repo.loadCompositePublicInfo(entity.fingerprint)?.userIds
            }
            if (!compositeUids.isNullOrEmpty()) {
                return compositeUids.mapIndexed { index, raw ->
                    val parsed = PGPKeyEntity.parseUserID(raw)
                    KeyUserIdInfo(
                        raw = raw,
                        name = parsed.first,
                        email = parsed.second,
                        isPrimary = index == 0
                    )
                }
            }
        }
        if (fromRing.isEmpty()) {
            val parsed = PGPKeyEntity.parseUserID(entity.userID)
            return listOf(
                KeyUserIdInfo(
                    raw = entity.userID,
                    name = parsed.first,
                    email = parsed.second,
                    isPrimary = true
                )
            )
        }
        // RC3 §17.2 I fix: read the ring's actual IsPrimaryUserId
        // subpacket via UserIdService rather than string-matching the
        // entity's cached userID column, which could disagree with the
        // real primary flag (e.g. right after an import, or once
        // workstream I's add/promote/revoke actions start mutating it).
        // 4.7.0 (item 52): the same pick as the shown identity (newest primary
        // flag among live User IDs), so the PRIMARY badge and the publish
        // check agree and any other flagged User ID keeps Make primary.
        val primaryUid = primaryPub?.let { UserIdService.shared.shownUserId(it) }
        val primaryIndex = fromRing.indexOfFirst { it.raw == primaryUid }
            .let { if (it >= 0) it else 0 }
        return fromRing.mapIndexed { index, uid ->
            if (index == primaryIndex) uid.copy(isPrimary = true) else uid
        }
    }

    /**
     * 4.2.0 RC3 workstream G. Every key in the ring after the primary
     * (BC always returns the primary first), skipping any entry that
     * fails to parse rather than aborting the whole section, the same
     * failure handling SubkeyMigrationService used for the Room-backed
     * version of this that never got wired up.
     */
    /**
     * 4.4.0 RC3 (#30/#31): a composite key cannot be loaded as a
     * PGPPublicKeyRing, so its ML-KEM encryption subkey row is built from the
     * CompositeKeyFacade metadata rather than a BouncyCastle ring.
     */
    private suspend fun compositeSubkeys(entity: PGPKeyEntity): List<SubkeyDisplayInfo> {
        // #55: enumerate ALL subkeys on the composite primary (the original
        // ML-KEM subkey plus any added ML-KEM / ML-DSA / classical subkeys),
        // reading each one's capabilities from its 0x18 binding.
        val descriptors = withContext(Dispatchers.IO) {
            repo.loadCompositeSubkeys(entity.fingerprint)
        }
        return descriptors.map { d ->
            val fpHex = d.fingerprintHex.uppercase()
            // 4.6.0 (item 21): RSA's one algorithm id covers every size, so no
            // KeyAlgorithm (which would say 4096) labels it.
            val algo = if (d.algId in 1..3) null else KeyAlgorithm.from(d.algId, 6)
            val capabilities = if (d.keyFlags != 0) {
                SubkeyCapability.fromBcKeyFlags(d.keyFlags)
            } else when (d.algId) {
                35, 36, 25 -> SubkeyCapability.Encrypt.flag
                30, 31, 27 -> SubkeyCapability.Sign.flag
                else -> 0
            }
            SubkeyDisplayInfo(
                fingerprint = fpHex,
                keyId = fpHex.take(16),
                algorithmLabel = algo?.displayName ?: compositeSubkeyLabel(d.algId),
                capabilities = capabilities,
                createdAt = d.createdAtMillis,
                expiresAt = d.expirationSeconds?.let { d.createdAtMillis + it * 1000L },
                isRevoked = d.isRevoked,
                isCardBacked = entity.isCardBacked
            )
        }
    }

    private fun compositeSubkeyLabel(algId: Int): String = when (algId) {
        35 -> "ML-KEM-768 + X25519"
        36 -> "ML-KEM-1024 + X448"
        30 -> "ML-DSA-65 + Ed25519"
        31 -> "ML-DSA-87 + Ed448"
        25 -> "X25519"
        27 -> "Ed25519"
        1, 2, 3 -> "RSA"
        else -> PGPonyApp.instance.getString(R.string.sign_as_subkey_subkey_label, "v6")
    }

    /**
     * 4.7.0 (item 40, #82): the subkey rows with each one's status line (where
     * its secret is, and why it is not usable), so a subkey that is present
     * but never used says why instead of looking like the others.
     */
    private suspend fun deriveSubkeys(entity: PGPKeyEntity): List<SubkeyDisplayInfo> {
        val rows = deriveSubkeyRows(entity)
        if (rows.isEmpty()) return rows
        return withContext(Dispatchers.Default) {
            val rawPublic: ByteArray? = runCatching { repo.exportPublicKeyBytes(entity.fingerprint) }.getOrNull()
            val held: Map<String, com.pgpony.android.crypto.SubkeyAdmission.SecretLocation> =
                if (entity.isKeyPair) repo.subkeySecretLocations(entity.fingerprint) else emptyMap()
            val cardFingerprints: Set<String> = listOfNotNull(
                entity.cardSigFingerprint, entity.cardDecFingerprint, entity.cardAuthFingerprint
            ).toSet()
            SubkeyRows.withStatus(rows, rawPublic, entity.isKeyPair, entity.isCardBacked, cardFingerprints, held)
        }
    }

    private suspend fun deriveSubkeyRows(entity: PGPKeyEntity): List<SubkeyDisplayInfo> {
        if (entity.algorithm.isCompositeSign) return compositeSubkeys(entity)
        // 4.6.0 (item 19): a classical primary with a composite ML-KEM subkey
        // (algo 35 / 36, or a LibrePGP v5 algo 8) is listed from its
        // certificate; the Bouncy Castle mapping below cannot read those
        // subkeys and used to drop every one of them. See SubkeyRows.
        val certRows = withContext(Dispatchers.IO) {
            repo.exportPublicKeyBytes(entity.fingerprint)
                ?.takeIf { SubkeyRows.hasCompositeSubkey(it) }
                ?.let { SubkeyRows.fromCertificate(it, entity.isCardBacked) }
        }
        if (certRows != null) return certRows
        val ring = withContext(Dispatchers.IO) { repo.loadPublicKeyRing(entity.fingerprint) }
            ?: return emptyList()
        val keys = ring.publicKeys.asSequence().toList()
        if (keys.size <= 1) return emptyList()
        val crypto = PGPCryptoService.shared
        return keys.drop(1).mapNotNull { pubKey ->
            try {
                val algorithm = crypto.detectAlgorithm(pubKey)
                val capabilities = SubkeyCapability.fromPgpPublicKey(
                    pubKey = pubKey,
                    algorithm = algorithm,
                    isPrimary = false
                )
                val expiresAtMs = pubKey.validSeconds.takeIf { it > 0L }?.let { secs ->
                    pubKey.creationTime.time + secs * 1000L
                }
                SubkeyDisplayInfo(
                    fingerprint = pubKey.fingerprint.joinToString("") { String.format("%02X", it) },
                    keyId = String.format("%016X", pubKey.keyID),
                    algorithmLabel = subkeyAlgorithmLabel(pubKey, algorithm),
                    capabilities = capabilities,
                    createdAt = pubKey.creationTime.time,
                    expiresAt = expiresAtMs,
                    isRevoked = pubKey.hasRevocation(),
                    isCardBacked = entity.isCardBacked,
                    expiryEditable = true
                )
            } catch (e: Exception) {
                null
            }
        }
    }

    /**
     * Per-subkey display label. detectAlgorithm's algo-18/algo-22
     * collapse onto KeyAlgorithm.ED25519_CV25519 ("Ed25519") is correct
     * when labeling a whole Ed25519+Cv25519 ring, wrong when labeling
     * one packet in isolation — an ECDH(18) subkey generated as an
     * X25519 encryption key (workstream H's AddSubkeySheet, or the
     * classic Ed25519+Cv25519 pair's own encrypt half) needs to read
     * "X25519", not "Ed25519", or the two are indistinguishable in the
     * Subkeys list. Composite/RSA/v6 algorithms aren't ambiguous this
     * way, so they still use [algorithm]'s own shortName.
     */
    private fun subkeyAlgorithmLabel(pubKey: PGPPublicKey, algorithm: KeyAlgorithm): String {
        // 4.7.1 (#102): read the curve instead of assuming the 25519 family.
        // An ECDH subkey on secp256k1 or a NIST curve showed as X25519, and an
        // ECDSA subkey took the primary's label.
        val curve = com.pgpony.android.crypto.EcCurveOid.label(pubKey)
        return when (pubKey.algorithm) {
            org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ECDH -> when (curve) {
                null, "Curve25519", "X25519" -> "X25519"
                else -> "ECDH $curve"
            }
            org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EDDSA_LEGACY -> curve ?: "Ed25519"
            org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ECDSA -> if (curve != null) "ECDSA $curve" else "ECDSA"
            else -> algorithm.shortName
        }
    }

    // ── 4.0.0 Phase 2 (F5): keyserver refresh-and-merge ────────────────

    /**
     * Re-fetch this key's material from the keyserver and merge it into
     * the stored row. Thin caller over KeyRefreshService — the pipeline
     * (fetch → mandatory fingerprint verification → Phase 1 merge →
     * revocation scan → lastCheckedAt stamp) lives there so Phase 7's
     * background worker exercises the exact same code. Every outcome
     * reloads [KeyDetailUiState.key] and re-derives the F4 User ID list
     * so the screen reflects the refreshed material immediately.
     */
    fun refreshFromKeyServer() {
        val key = _state.value.key ?: return
        if (_state.value.isRefreshingFromKeyServer) return
        viewModelScope.launch {
            _state.value = _state.value.copy(isRefreshingFromKeyServer = true)
            val app = PGPonyApp.instance
            when (val result = keyRefresh.refresh(key.fingerprint)) {
                is KeyRefreshResult.UpToDate -> _state.value = _state.value.copy(
                    key = result.entity,
                    userIds = deriveUserIds(result.entity),
                    isRefreshingFromKeyServer = false,
                    successMessage = app.getString(R.string.kd_vm_refresh_up_to_date)
                )
                is KeyRefreshResult.Merged -> _state.value = _state.value.copy(
                    key = result.entity,
                    userIds = deriveUserIds(result.entity),
                    isRefreshingFromKeyServer = false,
                    successMessage = app.getString(R.string.kd_vm_refresh_merged)
                )
                is KeyRefreshResult.RevokedUpstream -> _state.value = _state.value.copy(
                    key = result.entity,
                    userIds = deriveUserIds(result.entity),
                    isRefreshingFromKeyServer = false,
                    // Revocation leads regardless of whether material
                    // also merged — matches iOS message precedence.
                    successMessage = app.getString(R.string.kd_vm_refresh_revoked)
                )
                is KeyRefreshResult.NotFound -> _state.value = _state.value.copy(
                    key = result.entity,
                    userIds = deriveUserIds(result.entity),
                    isRefreshingFromKeyServer = false,
                    // Same copy as the KS1 check row — identical situation.
                    successMessage = app.getString(R.string.kd_vm_check_not_found)
                )
                is KeyRefreshResult.FingerprintMismatch -> _state.value = _state.value.copy(
                    key = result.entity,
                    userIds = deriveUserIds(result.entity),
                    isRefreshingFromKeyServer = false,
                    errorMessage = app.getString(R.string.kd_vm_refresh_mismatch)
                )
                is KeyRefreshResult.Failed -> _state.value = _state.value.copy(
                    key = result.entity,
                    userIds = deriveUserIds(result.entity),
                    isRefreshingFromKeyServer = false,
                    errorMessage = app.getString(
                        R.string.kd_vm_refresh_failed_format, ErrorText.detail(result.detail) ?: result.detail
                    )
                )
                KeyRefreshResult.KeyMissing -> _state.value = _state.value.copy(
                    isRefreshingFromKeyServer = false
                )
            }
        }
    }

    /**
     * Phase A8 Fix2 — build a user-facing summary of the upload-and-
     * verify result. Four cases:
     *   1. Verification requested for one or more emails — tell the
     *      user to check each inbox.
     *   2. All emails already published from a prior verification —
     *      no action needed.
     *   3. Hagrid returned no emails (key has no email UIDs, unusual)
     *      — generic "uploaded" message.
     *   4. Verification couldn't be triggered (rate limit, network
     *      blip) — key is on Hagrid but only searchable by
     *      fingerprint; user can retry later.
     *
     * Reads from KeyServerUploadResult.emailStatuses + .verificationRequested.
     */
    private fun uploadSuccessMessage(result: com.pgpony.android.network.KeyServerUploadResult): String {
        val statuses = result.emailStatuses
        if (statuses.isEmpty()) {
            return PGPonyApp.instance.getString(R.string.kd_vm_upload_success_generic)
        }
        val pendingEmails = statuses
            .filter { (_, s) -> s == "unpublished" || s == "pending" }
            .keys
            .toList()
        val publishedEmails = statuses
            .filter { (_, s) -> s == "published" }
            .keys
            .toList()

        return when {
            // Happy path — verification email(s) sent. User needs to
            // click each link to activate email-based search.
            result.verificationRequested && pendingEmails.isNotEmpty() -> {
                if (pendingEmails.size == 1) {
                    PGPonyApp.instance.getString(R.string.kd_vm_upload_success_verify_single_format, pendingEmails[0])
                } else {
                    PGPonyApp.instance.getString(R.string.kd_vm_upload_success_verify_multi_format, pendingEmails.joinToString(", "))
                }
            }
            // No verification needed (already published from a prior run).
            publishedEmails.isNotEmpty() && pendingEmails.isEmpty() -> {
PGPonyApp.instance.getString(R.string.kd_vm_upload_already_published)
            }
            // Upload succeeded but request-verify didn't go through.
            pendingEmails.isNotEmpty() && !result.verificationRequested -> {
PGPonyApp.instance.getString(R.string.kd_vm_upload_verify_skipped)
            }
            // Catch-all for any other status mix Hagrid returns.
            else -> PGPonyApp.instance.getString(R.string.kd_vm_upload_success_generic)
        }
    }

    // ── Phase A4b: Share public key (returns armored for Intent) ──────

    /**
     * Returns the armored public key for the loaded key, or null if
     * export failed. The actual Intent.ACTION_SEND is launched at the
     * Composable layer via KeyShareIntents — VMs don't own Intents.
     */
    fun armoredPublicKeyForShare(): String? {
        val key = _state.value.key ?: return null
        // 4.0.0 Phase 9b — the user-facing copy/share/save path honors
        // the "Include comment in exported public keys" setting. QR and
        // keyserver upload in this VM keep the comment-free export.
        return repo.exportArmoredPublicKeyForSharing(key.fingerprint)
    }

    // ── Phase A4b: Delete ─────────────────────────────────────────────

    fun showDeleteConfirm() {
        _state.value = _state.value.copy(showDeleteConfirm = true)
    }

    fun dismissDeleteConfirm() {
        _state.value = _state.value.copy(showDeleteConfirm = false)
    }

    fun deleteKey() {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            try {
                repo.softDeleteByFingerprint(key.fingerprint)
                // No state cleanup — the screen pops the back stack via
                // the event, the VM dies with the back stack entry.
                _events.tryEmit(KeyDetailEvent.KeyDeleted)
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    showDeleteConfirm = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_delete_failed_format, ErrorText.detail(e.message) ?: "")
                )
            }
        }
    }

    // ── Phase A4b: Success message dismissal ──────────────────────────

    fun clearSuccess() {
        _state.value = _state.value.copy(successMessage = null)
    }

    // ── Phase A6: Revocation ──────────────────────────────────────────

    fun showRevokeSheet() {
        // Reset any stale error from a previous attempt at the same key.
        _state.value = _state.value.copy(
            showRevokeSheet = true,
            revokeError = null
        )
    }

    fun dismissRevokeSheet() {
        _state.value = _state.value.copy(
            showRevokeSheet = false,
            revokeError = null
        )
    }

    /**
     * Drive the full revocation flow:
     *   1. Generate cert + apply to public ring + persist
     *   2. On success, swap RevokeKeySheet for RevocationResultSheet
     *      with the generated cert
     *   3. On RevocationError, surface the message inline in the
     *      revoke sheet's [errorMessage] field so the user can fix the
     *      passphrase and retry. Other errors bubble to the generic
     *      errorMessage snackbar surface.
     *
     * The reloaded entity has isRevoked=true, so the screen re-renders
     * with the Revoked banner + filtered Danger Zone next time it
     * collects state.
     */
    fun applyRevocation(
        reason: RevocationReason,
        comment: String?,
        passphrase: String?
    ) {
        val key = _state.value.key ?: return
        _state.value = _state.value.copy(
            isRevoking = true,
            revokeError = null
        )
        viewModelScope.launch {
            try {
                val armoredCert = repo.applyRevocation(
                    fingerprint = key.fingerprint,
                    reason = reason,
                    comment = comment.takeIf { !it.isNullOrBlank() },
                    passphrase = passphrase
                )
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    isRevoking = false,
                    showRevokeSheet = false,
                    showRevocationResultSheet = true,
                    pendingRevocationCert = armoredCert
                )
            } catch (e: RevocationError.PassphraseRequired) {
                _state.value = _state.value.copy(
                    isRevoking = false,
                    revokeError = PGPonyApp.instance.getString(R.string.kd_vm_error_revoke_passphrase_required)
                )
            } catch (e: RevocationError.InvalidPassphrase) {
                _state.value = _state.value.copy(
                    isRevoking = false,
                    revokeError = PGPonyApp.instance.getString(R.string.kd_vm_error_revoke_incorrect_passphrase)
                )
            } catch (e: RevocationError) {
                _state.value = _state.value.copy(
                    isRevoking = false,
                    revokeError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.kd_vm_error_revocation_failed_default)
                )
            } catch (e: Exception) {
                // Anything non-RevocationError (DB write fail, store write
                // fail, etc.) — bubble to the generic snackbar surface so
                // the user can see it without it cluttering the revoke
                // sheet. The sheet stays open for retry.
                _state.value = _state.value.copy(
                    isRevoking = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_revocation_failed_format, ErrorText.detail(e.message) ?: "")
                )
            }
        }
    }

    /** 4.7.0 (item 58, #89): key flags on the primary's newest self-signature
     *  (a User ID self-certification or a direct-key signature), read only from
     *  signatures the primary made. */
    private fun primaryUsageOf(primary: org.bouncycastle.openpgp.PGPPublicKey): Int? {
        var newest: org.bouncycastle.openpgp.PGPSignature? = null
        val selfTypes = setOf(
            org.bouncycastle.openpgp.PGPSignature.DEFAULT_CERTIFICATION,
            org.bouncycastle.openpgp.PGPSignature.NO_CERTIFICATION,
            org.bouncycastle.openpgp.PGPSignature.CASUAL_CERTIFICATION,
            org.bouncycastle.openpgp.PGPSignature.POSITIVE_CERTIFICATION,
            org.bouncycastle.openpgp.PGPSignature.DIRECT_KEY
        )
        primary.signatures.forEach { sig ->
            if (sig.keyID != primary.keyID || sig.signatureType !in selfTypes) return@forEach
            if (sig.hashedSubPackets?.hasSubpacket(org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_FLAGS) != true) return@forEach
            if (newest == null || sig.creationTime.after(newest!!.creationTime)) newest = sig
        }
        return newest?.hashedSubPackets?.keyFlags?.let { SubkeyCapability.fromBcKeyFlags(it) }
    }

    // ── 4.7.0 (item 51, #86): refresh self-signatures ─────────────────

    fun openRefreshSigs() {
        _state.value = _state.value.copy(showRefreshSigs = true, refreshSigsError = null)
    }

    fun dismissRefreshSigs() {
        if (_state.value.refreshSigsInFlight) return
        _state.value = _state.value.copy(showRefreshSigs = false, refreshSigsError = null)
    }

    fun applyRefreshSigs(passphrase: String?) {
        val key = _state.value.key ?: return
        _state.value = _state.value.copy(refreshSigsInFlight = true, refreshSigsError = null)
        viewModelScope.launch {
            try {
                val restored = repo.refreshSelfSignatures(key.fingerprint, passphrase)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    userIds = reloaded?.let { deriveUserIds(it) } ?: _state.value.userIds,
                    subkeys = reloaded?.let { deriveSubkeys(it) } ?: _state.value.subkeys,
                    refreshSigsInFlight = false,
                    showRefreshSigs = false,
                    successMessage = if (restored == 0) PGPonyApp.instance.getString(R.string.key_detail_refresh_sigs_done)
                        else PGPonyApp.instance.resources.getQuantityString(R.plurals.key_detail_refresh_sigs_done_restored, restored, restored)
                )
                refreshSigningSubkeys()
            } catch (e: KeyExpirationService.ExpirationError.PassphraseRequired) {
                _state.value = _state.value.copy(refreshSigsInFlight = false,
                    refreshSigsError = PGPonyApp.instance.getString(R.string.kd_vm_error_revoke_passphrase_required))
            } catch (e: KeyExpirationService.ExpirationError.InvalidPassphrase) {
                _state.value = _state.value.copy(refreshSigsInFlight = false,
                    refreshSigsError = PGPonyApp.instance.getString(R.string.kd_vm_error_revoke_incorrect_passphrase))
            } catch (e: Exception) {
                _state.value = _state.value.copy(refreshSigsInFlight = false,
                    refreshSigsError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_expiry_failed))
            }
        }
    }

    // ── 4.7.0 (item 61, #88): look up a certifier ──────────────────────

    /** Search the configured key servers for the key that made [row], by the
     *  issuer fingerprint when the certification has one, else by key ID. The
     *  user sees the key before anything is imported. */
    fun lookUpCertifier(row: com.pgpony.android.data.repository.KeyRepository.CertificationRow) {
        val c = row.certification
        val fp = c.issuerFingerprint
        val query = fp ?: String.format("%016X", c.issuerKeyId)
        _state.value = _state.value.copy(
            certifierLookup = com.pgpony.android.ui.decrypt.SignerLookupState.Searching,
            certifierLookupQuery = query
        )
        viewModelScope.launch {
            val armored = try {
                if (fp != null) keyServer.findByFingerprint(fp)?.armoredKey else keyServer.findByKeyId(query)?.armoredKey
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    certifierLookup = com.pgpony.android.ui.decrypt.SignerLookupState.Failed(
                        ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.encdec_error_keyserver_network)
                    )
                )
                return@launch
            }
            if (armored.isNullOrBlank()) {
                _state.value = _state.value.copy(
                    certifierLookup = com.pgpony.android.ui.decrypt.SignerLookupState.NotFound(query)
                )
                return@launch
            }
            val preview = runCatching {
                withContext(Dispatchers.Default) { PGPCryptoService.shared.importKeyData(armored.toByteArray(Charsets.UTF_8)) }
            }.getOrElse { e ->
                _state.value = _state.value.copy(
                    certifierLookup = com.pgpony.android.ui.decrypt.SignerLookupState.Failed(
                        PGPonyApp.instance.getString(R.string.encdec_error_keyserver_parse_format, ErrorText.detail(e.message) ?: "")
                    )
                )
                return@launch
            }
            _state.value = _state.value.copy(
                certifierLookup = com.pgpony.android.ui.decrypt.SignerLookupState.Found(
                    armoredKey = armored,
                    previewUserId = preview.userID,
                    previewFingerprint = preview.fingerprint,
                    previewAlgorithm = preview.algorithm.displayName
                )
            )
        }
    }

    /** Import the key the lookup found, then reload this key's certifications
     *  so the certifier shows by name and its signature is checked. */
    fun importCertifier(armoredKey: String) {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            try {
                val imported = repo.importArmoredKey(armoredKey)
                _state.value = _state.value.copy(
                    certifierLookup = com.pgpony.android.ui.decrypt.SignerLookupState.ImportSuccess(imported.userID),
                    certifications = runCatching { repo.certificationsOf(key.fingerprint) }.getOrNull() ?: _state.value.certifications
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    certifierLookup = com.pgpony.android.ui.decrypt.SignerLookupState.Failed(
                        PGPonyApp.instance.getString(R.string.encdec_error_signer_import_failed_format, ErrorText.detail(e.message) ?: "")
                    )
                )
            }
        }
    }

    fun dismissCertifierLookup() {
        _state.value = _state.value.copy(certifierLookup = null, certifierLookupQuery = null)
    }

    // ── Expiration editing ──────────────────────────────────────────────

    fun showExpirySheet() {
        _state.value = _state.value.copy(showExpirySheet = true, expirySubkey = null, expiryError = null)
    }

    /** 4.7.0 (item 53, #86): change one subkey's expiry. */
    fun showSubkeyExpirySheet(sub: SubkeyDisplayInfo) {
        _state.value = _state.value.copy(showExpirySheet = true, expirySubkey = sub, expiryError = null)
    }

    fun dismissExpirySheet() {
        if (_state.value.expiryInFlight) return
        _state.value = _state.value.copy(showExpirySheet = false, expirySubkey = null, expiryError = null)
    }

    /** What the open sheet changes: the chosen subkey, or the primary (and,
     *  when asked, the subkeys valid now). */
    fun expiryTarget(alsoCurrentSubkeys: Boolean): KeyExpirationService.Target =
        _state.value.expirySubkey?.let { sub ->
            KeyExpirationService.Target.Subkey(java.lang.Long.parseUnsignedLong(sub.fingerprint.takeLast(16), 16))
        } ?: KeyExpirationService.Target.Primary(alsoCurrentSubkeys)

    /**
     * Software key pair: re-sign with the new expiry and persist. Mirrors
     * applyRevocation's error handling. [expiresAtEpochSeconds] null = never.
     */
    fun applyExpirationSoftware(expiresAtEpochSeconds: Long?, passphrase: String?, alsoCurrentSubkeys: Boolean = false) {
        val key = _state.value.key ?: return
        val target = expiryTarget(alsoCurrentSubkeys)
        _state.value = _state.value.copy(expiryInFlight = true, expiryError = null)
        viewModelScope.launch {
            try {
                repo.setKeyExpirationSoftware(key.fingerprint, expiresAtEpochSeconds, passphrase, target)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    subkeys = reloaded?.let { deriveSubkeys(it) } ?: _state.value.subkeys,
                    expiryInFlight = false,
                    showExpirySheet = false,
                    expirySubkey = null
                )
                refreshSigningSubkeys() // 4.7.0 (item 46): expiry decides which keys may sign
            } catch (e: KeyExpirationService.ExpirationError.PassphraseRequired) {
                _state.value = _state.value.copy(
                    expiryInFlight = false,
                    expiryError = PGPonyApp.instance.getString(R.string.kd_vm_error_revoke_passphrase_required)
                )
            } catch (e: KeyExpirationService.ExpirationError.InvalidPassphrase) {
                _state.value = _state.value.copy(
                    expiryInFlight = false,
                    expiryError = PGPonyApp.instance.getString(R.string.kd_vm_error_revoke_incorrect_passphrase)
                )
            } catch (e: KeyExpirationService.ExpirationError) {
                _state.value = _state.value.copy(
                    expiryInFlight = false,
                    expiryError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_expiry_failed)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    expiryInFlight = false,
                    expiryError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_expiry_failed)
                )
            }
        }
    }

    /** Card-backed: the screen runs the NFC op (KeyExpirationService
     *  .setExpirationCard) and reports here. */
    fun onCardExpiryStarted() {
        _state.value = _state.value.copy(expiryInFlight = true, expiryError = null)
    }

    fun onCardExpiryFailure(message: String) {
        _state.value = _state.value.copy(expiryInFlight = false, expiryError = ErrorText.localize(message) ?: message)
    }

    /** Persist the card-updated public ring and refresh. */
    fun persistCardExpiry(
        updatedPublicRing: org.bouncycastle.openpgp.PGPPublicKeyRing,
        expiresAtEpochSeconds: Long?,
        target: KeyExpirationService.Target = KeyExpirationService.Target.Primary()
    ) {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            try {
                repo.persistCardExpiration(key.fingerprint, updatedPublicRing, expiresAtEpochSeconds, target)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    subkeys = reloaded?.let { deriveSubkeys(it) } ?: _state.value.subkeys,
                    expiryInFlight = false,
                    showExpirySheet = false,
                    expirySubkey = null
                )
                refreshSigningSubkeys() // 4.7.0 (item 46): expiry decides which keys may sign
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    expiryInFlight = false,
                    expiryError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_expiry_failed)
                )
            }
        }
    }

    // ── Add Subkey (RC3 §17.2 H) ─────────────────────────────────────────

    fun showAddSubkeySheet() {
        _state.value = _state.value.copy(showAddSubkeySheet = true, addSubkeyError = null)
    }

    fun dismissAddSubkeySheet() {
        if (_state.value.addSubkeyInFlight) return
        _state.value = _state.value.copy(showAddSubkeySheet = false, addSubkeyError = null)
    }

    /**
     * Generate and bind [type] as a new subkey, then persist and reload
     * both the entity and the subkeys list so the new row appears in
     * SubkeysSection immediately. Mirrors applyExpirationSoftware's
     * error handling shape.
     */
    fun addSubkey(
        choice: AddSubkeyChoice,
        expiresAtEpochSeconds: Long?,
        passphrase: String?
    ) {
        val key = _state.value.key ?: return
        // 4.7.0 (item 18): AddSubkeySheet hands over the chosen expiry DATE, while
        // every generator writes a key-expiration subpacket, which is seconds after
        // the subkey's creation. Passing the date straight through set "1 year" to
        // roughly 58 years.
        val expirationSeconds = addSubkeyLifetimeSeconds(expiresAtEpochSeconds, System.currentTimeMillis())
        _state.value = _state.value.copy(addSubkeyInFlight = true, addSubkeyError = null)
        viewModelScope.launch {
            try {
                when (choice) {
                    is AddSubkeyChoice.Classical ->
                        repo.addSubkey(key.fingerprint, choice.type, expirationSeconds, passphrase)
                    is AddSubkeyChoice.PqEncryption ->
                        repo.addCompositeEncryptionSubkey(key.fingerprint, choice.suite, expirationSeconds, passphrase)
                    is AddSubkeyChoice.PqSigning ->
                        repo.addCompositeSigningSubkey(key.fingerprint, choice.suite, expirationSeconds, passphrase)
                }
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    subkeys = reloaded?.let { deriveSubkeys(it) } ?: _state.value.subkeys,
                    sshPublicKey = reloaded?.let { deriveSshPublicKey(it) },
                    addSubkeyInFlight = false,
                    showAddSubkeySheet = false
                )
                refreshSigningSubkeys()
            } catch (e: ClassicalSubkeyGen.SubkeyAddError) {
                _state.value = _state.value.copy(
                    addSubkeyInFlight = false,
                    addSubkeyError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_add_subkey_failed)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    addSubkeyInFlight = false,
                    addSubkeyError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_add_subkey_failed)
                )
            }
        }
    }

    // ── Subkey revoke / remove (item 16, #54) ────────────────────────────

    fun showSubkeyRevokeSheet(sub: SubkeyDisplayInfo) {
        _state.value = _state.value.copy(
            subkeyRevokeTarget = sub, showSubkeyRevokeSheet = true, subkeyRevokeError = null
        )
    }

    fun dismissSubkeyRevokeSheet() {
        if (_state.value.subkeyRevokeInFlight) return
        _state.value = _state.value.copy(
            showSubkeyRevokeSheet = false, subkeyRevokeTarget = null, subkeyRevokeError = null
        )
    }

    fun revokeSubkey(reason: RevocationReason, comment: String?, passphrase: String?) {
        val sub = _state.value.subkeyRevokeTarget ?: return
        doRevokeSubkey(sub.fingerprint, reason, comment, passphrase, allowLast = false)
    }

    private fun doRevokeSubkey(
        subkeyFp: String, reason: RevocationReason, comment: String?, passphrase: String?, allowLast: Boolean
    ) {
        val key = _state.value.key ?: return
        _state.value = _state.value.copy(subkeyRevokeInFlight = true, subkeyRevokeError = null)
        viewModelScope.launch {
            try {
                repo.revokeSubkey(
                    key.fingerprint, subkeyFp, reason,
                    comment.takeIf { !it.isNullOrBlank() }, passphrase, allowLast
                )
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    subkeys = reloaded?.let { deriveSubkeys(it) } ?: _state.value.subkeys,
                    sshPublicKey = reloaded?.let { deriveSshPublicKey(it) },
                    subkeyRevokeInFlight = false,
                    showSubkeyRevokeSheet = false,
                    subkeyRevokeTarget = null
                )
                refreshSigningSubkeys()
            } catch (e: KeyRepoError.LastEncryptionSubkey) {
                _state.value = _state.value.copy(
                    subkeyRevokeInFlight = false,
                    showSubkeyRevokeSheet = false,
                    lastEncryptionWarning = PendingSubkeyOp(
                        PendingSubkeyOp.Kind.REVOKE, subkeyFp, reason, comment, passphrase
                    )
                )
            } catch (e: com.pgpony.android.crypto.pqc.CompositeSecretProtection.ProtectedKeyException) {
                // 4.6.3 (item 20): as for Add User ID.
                _state.value = _state.value.copy(
                    subkeyRevokeInFlight = false,
                    subkeyRevokeError = PGPonyApp.instance.getString(R.string.kd_vm_error_revoke_passphrase_required)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    subkeyRevokeInFlight = false,
                    subkeyRevokeError = ErrorText.localize(e.message)
                        ?: PGPonyApp.instance.getString(R.string.key_detail_subkey_action_failed)
                )
            }
        }
    }

    fun requestSubkeyRemove(sub: SubkeyDisplayInfo) {
        _state.value = _state.value.copy(subkeyRemoveTarget = sub)
    }

    fun dismissSubkeyRemove() {
        if (_state.value.subkeyRemoveInFlight) return
        _state.value = _state.value.copy(subkeyRemoveTarget = null)
    }

    /** #36 (CertainBot): from the subkey-remove dialog, switch to revoke instead,
     *  since a removed subkey cannot be revoked afterward. Closes the remove
     *  dialog and opens the existing subkey revoke sheet. */
    fun revokeSubkeyInstead() {
        if (_state.value.subkeyRemoveInFlight) return
        val target = _state.value.subkeyRemoveTarget ?: return
        _state.value = _state.value.copy(subkeyRemoveTarget = null)
        showSubkeyRevokeSheet(target)
    }

    fun confirmSubkeyRemove() {
        val sub = _state.value.subkeyRemoveTarget ?: return
        doRemoveSubkey(sub.fingerprint, allowLast = false)
    }

    private fun doRemoveSubkey(subkeyFp: String, allowLast: Boolean) {
        val key = _state.value.key ?: return
        _state.value = _state.value.copy(subkeyRemoveInFlight = true)
        viewModelScope.launch {
            try {
                repo.removeSubkey(key.fingerprint, subkeyFp, allowLast)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    subkeys = reloaded?.let { deriveSubkeys(it) } ?: _state.value.subkeys,
                    sshPublicKey = reloaded?.let { deriveSshPublicKey(it) },
                    subkeyRemoveInFlight = false,
                    subkeyRemoveTarget = null,
                    successMessage = PGPonyApp.instance.getString(R.string.kd_vm_status_subkey_removed)
                )
                refreshSigningSubkeys()
            } catch (e: KeyRepoError.LastEncryptionSubkey) {
                _state.value = _state.value.copy(
                    subkeyRemoveInFlight = false,
                    subkeyRemoveTarget = null,
                    lastEncryptionWarning = PendingSubkeyOp(PendingSubkeyOp.Kind.REMOVE, subkeyFp)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    subkeyRemoveInFlight = false,
                    subkeyRemoveTarget = null,
                    errorMessage = ErrorText.localize(e.message)
                        ?: PGPonyApp.instance.getString(R.string.key_detail_subkey_action_failed)
                )
            }
        }
    }

    fun confirmLastEncryptionSubkey() {
        val op = _state.value.lastEncryptionWarning ?: return
        _state.value = _state.value.copy(lastEncryptionWarning = null)
        when (op.kind) {
            PendingSubkeyOp.Kind.REVOKE -> doRevokeSubkey(
                op.subkeyFingerprint, op.reason ?: RevocationReason.NO_REASON,
                op.comment, op.passphrase, allowLast = true
            )
            PendingSubkeyOp.Kind.REMOVE -> doRemoveSubkey(op.subkeyFingerprint, allowLast = true)
        }
    }

    fun dismissLastEncryptionSubkey() {
        _state.value = _state.value.copy(lastEncryptionWarning = null)
    }

    // ── User ID editing (RC3 §17.2 I / #29) ──────────────────────────────

    fun showAddUserIdSheet() {
        _state.value = _state.value.copy(showAddUserIdSheet = true, addUserIdError = null)
    }

    fun dismissAddUserIdSheet() {
        if (_state.value.addUserIdInFlight) return
        _state.value = _state.value.copy(showAddUserIdSheet = false, addUserIdError = null)
    }

    /** Add a new User ID, then reload both the entity and the UID list so
     *  the new row (and any primary-badge change) appears immediately. */
    fun showChangePassphraseSheet() {
        _state.value = _state.value.copy(showChangePassphraseSheet = true, changePassphraseError = null)
    }

    fun dismissChangePassphraseSheet() {
        _state.value = _state.value.copy(showChangePassphraseSheet = false, changePassphraseError = null)
    }

    /**
     * §1.1 (#26) Change, set, or remove the key's passphrase. Empty
     * [newPassphrase] removes protection. A wrong [oldPassphrase] surfaces as
     * the incorrect-passphrase retry; on success the sheet dismisses and the
     * protected flag is updated so the export sheet reflects the new state.
     */
    fun changePassphrase(oldPassphrase: String, newPassphrase: String) {
        val key = _state.value.key ?: return
        _state.value = _state.value.copy(changePassphraseInFlight = true, changePassphraseError = null)
        viewModelScope.launch {
            try {
                val ok = withContext(Dispatchers.Default) {
                    repo.changePassphrase(key.fingerprint, oldPassphrase, newPassphrase)
                }
                if (!ok) {
                    _state.value = _state.value.copy(
                        changePassphraseInFlight = false,
                        changePassphraseError = PGPonyApp.instance.getString(R.string.change_passphrase_failed)
                    )
                    return@launch
                }
                com.pgpony.android.session.InAppPassphraseCache.clear(key.fingerprint)
                val wasProtected = _state.value.privateKeyIsProtected
                val confirmation = when {
                    newPassphrase.isEmpty() -> R.string.change_passphrase_removed
                    wasProtected -> R.string.change_passphrase_changed
                    else -> R.string.change_passphrase_set
                }
                _state.value = _state.value.copy(
                    changePassphraseInFlight = false,
                    showChangePassphraseSheet = false,
                    privateKeyIsProtected = newPassphrase.isNotEmpty(),
                    successMessage = PGPonyApp.instance.getString(confirmation)
                )
            } catch (e: org.bouncycastle.openpgp.PGPException) {
                _state.value = _state.value.copy(
                    changePassphraseInFlight = false,
                    changePassphraseError = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase_retry)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    changePassphraseInFlight = false,
                    changePassphraseError = ErrorText.localize(e.message)
                        ?: PGPonyApp.instance.getString(R.string.change_passphrase_failed)
                )
            }
        }
    }

    fun showNotationsSheet() {
        _state.value = _state.value.copy(showNotationsSheet = true, notationsError = null)
    }

    fun dismissNotationsSheet() {
        if (_state.value.notationsInFlight) return
        _state.value = _state.value.copy(showNotationsSheet = false, notationsError = null)
    }

    /** §5.6.7 — replace the primary UID's notation set and re-sign it,
     *  then reload so the Notations section reflects the change. */
    fun saveNotations(notations: List<UserIdService.Notation>, passphrase: String?) {
        val key = _state.value.key ?: return
        _state.value = _state.value.copy(notationsInFlight = true, notationsError = null)
        viewModelScope.launch {
            try {
                repo.setNotations(key.fingerprint, notations, passphrase)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                val refreshed = withContext(Dispatchers.IO) { repo.readNotations(key.fingerprint) }
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    notations = refreshed,
                    notationsInFlight = false,
                    showNotationsSheet = false
                )
            } catch (e: UserIdService.UserIdError) {
                val msg = when (e) {
                    is UserIdService.UserIdError.InvalidPassphrase,
                    is UserIdService.UserIdError.PassphraseRequired ->
                        PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase_retry)
                    else -> ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_notations_failed)
                }
                _state.value = _state.value.copy(notationsInFlight = false, notationsError = msg)
            } catch (e: org.bouncycastle.openpgp.PGPException) {
                _state.value = _state.value.copy(
                    notationsInFlight = false,
                    notationsError = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase_retry)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    notationsInFlight = false,
                    notationsError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_notations_failed)
                )
            }
        }
    }

    // ── 4.7.0 (item 31, #79): certify this key ─────────────────────────

    fun openCertifySheet() {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            val choices = runCatching { repo.certifierChoices(key.fingerprint) }.getOrDefault(emptyList())
            _state.value = _state.value.copy(
                showCertifySheet = true,
                certifierChoices = choices,
                certifyError = null
            )
        }
    }

    fun dismissCertifySheet() {
        _state.value = _state.value.copy(showCertifySheet = false, certifyError = null)
    }

    fun certify(
        certifierFingerprint: String,
        passphrase: String?,
        userIds: List<String>,
        level: com.pgpony.android.crypto.CertificationService.Level,
        expirySeconds: Long?,
        exportable: Boolean
    ) {
        val key = _state.value.key ?: return
        _state.value = _state.value.copy(certifyInFlight = true, certifyError = null)
        viewModelScope.launch {
            try {
                repo.certifyKey(key.fingerprint, certifierFingerprint, passphrase, userIds, level, expirySeconds, exportable)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    certifications = runCatching { repo.certificationsOf(key.fingerprint) }.getOrDefault(_state.value.certifications),
                    certifyInFlight = false,
                    showCertifySheet = false,
                    certifyDoneExportable = exportable
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(certifyInFlight = false, certifyError = certifyErrorText(e))
            }
        }
    }

    // ── 4.7.0 RC4 (item 13, #71): Move to Security Key ─────────────────

    /** Open the sheet: every key of this key pair with its secret here, valid now. */
    fun openMoveToCardSheet() {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            val secretCount = withContext(Dispatchers.Default) {
                runCatching {
                    repo.loadSecretKeyRing(key.fingerprint)?.secretKeys?.asSequence()
                        ?.count { !com.pgpony.android.crypto.OfflineStub.isStub(it) } ?: 0
                }.getOrDefault(0)
            }
            val candidates = withContext(Dispatchers.Default) {
                runCatching {
                    val ring = repo.loadSecretKeyRing(key.fingerprint) ?: return@runCatching emptyList()
                    val now = System.currentTimeMillis()
                    ring.secretKeys.asSequence()
                        .filter { !com.pgpony.android.crypto.OfflineStub.isStub(it) }
                        .map { it.publicKey }
                        .filter { pub ->
                            !pub.hasRevocation() &&
                                (pub.validSeconds == 0L || pub.creationTime.time + pub.validSeconds * 1000 > now)
                        }
                        .map { pub ->
                            val algo = PGPCryptoService.shared.detectAlgorithm(pub)
                            val caps = com.pgpony.android.crypto.SubkeyCapability.fromPgpPublicKey(pub, algo, pub.isMasterKey)
                            val e = com.pgpony.android.crypto.card.KeyToCard.eligibility(pub)
                            MoveToCardCandidate(
                                fingerprint = org.bouncycastle.util.encoders.Hex.toHexString(pub.fingerprint).uppercase(),
                                keyIdHex = String.format("%016X", pub.keyID),
                                algorithmLabel = algo.displayName,
                                isPrimary = pub.isMasterKey,
                                createdAt = pub.creationTime.time,
                                canSign = com.pgpony.android.crypto.SubkeyCapability.hasCapability(caps, com.pgpony.android.crypto.SubkeyCapability.Sign),
                                canEncrypt = com.pgpony.android.crypto.SubkeyCapability.hasCapability(caps, com.pgpony.android.crypto.SubkeyCapability.Encrypt),
                                canAuthenticate = com.pgpony.android.crypto.SubkeyCapability.hasCapability(caps, com.pgpony.android.crypto.SubkeyCapability.Authenticate),
                                canCertify = com.pgpony.android.crypto.SubkeyCapability.hasCapability(caps, com.pgpony.android.crypto.SubkeyCapability.Certify),
                                kind = (e as? com.pgpony.android.crypto.card.KeyToCard.Eligibility.Movable)?.kind,
                                refusal = (e as? com.pgpony.android.crypto.card.KeyToCard.Eligibility.Refused)?.reason
                            )
                        }.toList()
                }.getOrDefault(emptyList())
            }
            _state.value = _state.value.copy(
                showMoveToCardSheet = true,
                moveToCardCandidates = candidates,
                moveToCardSecretCount = secretCount,
                moveToCardError = null
            )
        }
    }

    fun dismissMoveToCardSheet() {
        if (_state.value.moveToCardInFlight) return
        _state.value = _state.value.copy(showMoveToCardSheet = false, moveToCardError = null)
    }

    /**
     * Unlock the chosen keys with [passphrase] and hand them, with the
     * certificate, to [onReady] (the screen runs the card operation). A wrong
     * passphrase stops here, before any card is touched.
     */
    fun prepareMoveToCard(
        choices: Map<com.pgpony.android.crypto.card.CardSlot, String>,
        passphrase: String?,
        onReady: (List<com.pgpony.android.crypto.card.KeyToCardService.Move>, org.bouncycastle.openpgp.PGPPublicKeyRing) -> Unit
    ) {
        val key = _state.value.key ?: return
        if (choices.isEmpty()) return
        _state.value = _state.value.copy(moveToCardInFlight = true, moveToCardError = null)
        viewModelScope.launch {
            try {
                val (moves, certificate) = withContext(Dispatchers.Default) {
                    val ring = repo.loadSecretKeyRing(key.fingerprint)
                        ?: throw IllegalStateException(PGPonyApp.instance.getString(R.string.move_to_card_failed))
                    val certificate = repo.loadPublicKeyRing(key.fingerprint)
                        ?: throw IllegalStateException(PGPonyApp.instance.getString(R.string.move_to_card_failed))
                    val moves = choices.map { (slot, fp) ->
                        val sk = ring.secretKeys.asSequence().first {
                            org.bouncycastle.util.encoders.Hex.toHexString(it.publicKey.fingerprint).equals(fp, ignoreCase = true)
                        }
                        val priv = try {
                            com.pgpony.android.crypto.SecretKeyUnlock.extract(sk, passphrase?.takeIf { it.isNotEmpty() }?.toCharArray())
                        } catch (e: org.bouncycastle.openpgp.PGPException) {
                            if (sk.s2KUsage.toInt() == 0) throw e
                            if (passphrase.isNullOrEmpty()) throw com.pgpony.android.crypto.PGPCryptoError.PassphraseRequired()
                            throw com.pgpony.android.crypto.PGPCryptoError.InvalidPassphrase()
                        } ?: throw IllegalStateException(PGPonyApp.instance.getString(R.string.move_to_card_failed))
                        com.pgpony.android.crypto.card.KeyToCardService.Move(slot, sk.publicKey, priv)
                    }
                    moves to certificate
                }
                onReady(moves, certificate)
            } catch (e: Exception) {
                _state.value = _state.value.copy(moveToCardInFlight = false, moveToCardError = moveErrorText(e))
            }
        }
    }

    /** The card operation finished; on success link the card and, if asked, drop the secrets. */
    fun onMoveToCardResult(result: Result<com.pgpony.android.crypto.card.KeyToCardService.Done>, removeFromPhone: Boolean) {
        val key = _state.value.key ?: return
        result.fold(
            onSuccess = { done ->
                viewModelScope.launch {
                    try {
                        val (updated, removed) = repo.finishKeyToCard(key.fingerprint, done.cardInfo, done.movedFingerprints, removeFromPhone)
                        _state.value = _state.value.copy(
                            key = updated,
                            subkeys = deriveSubkeys(updated),
                            moveToCardInFlight = false,
                            showMoveToCardSheet = false,
                            moveToCardDone = MoveToCardDone(done.movedFingerprints.size, removed)
                        )
                        refreshSigningSubkeys()
                    } catch (e: Exception) {
                        _state.value = _state.value.copy(moveToCardInFlight = false, moveToCardError = moveErrorText(e))
                    }
                }
            },
            onFailure = { e ->
                _state.value = _state.value.copy(moveToCardInFlight = false, moveToCardError = moveErrorText(e))
            }
        )
    }

    fun onMoveToCardNoLink() {
        _state.value = _state.value.copy(
            moveToCardInFlight = false,
            moveToCardError = PGPonyApp.instance.getString(R.string.card_scan_nfc_unavailable)
        )
    }

    fun dismissMoveToCardDone() {
        _state.value = _state.value.copy(moveToCardDone = null)
    }

    private fun moveErrorText(e: Throwable): String {
        val app = PGPonyApp.instance
        return when (e) {
            is com.pgpony.android.crypto.PGPCryptoError.PassphraseRequired ->
                app.getString(R.string.kd_vm_error_revoke_passphrase_required)
            is com.pgpony.android.crypto.PGPCryptoError.InvalidPassphrase ->
                app.getString(R.string.kd_vm_error_revoke_incorrect_passphrase)
            is com.pgpony.android.crypto.card.OpenPgpCardException.WrongPin ->
                app.getString(R.string.move_to_card_wrong_user_pin, e.triesRemaining)
            is com.pgpony.android.crypto.card.OpenPgpCardException.WrongAdminPin ->
                app.getString(R.string.move_to_card_wrong_admin_pin, e.triesRemaining)
            is com.pgpony.android.crypto.card.OpenPgpCardException.SlotsOccupied ->
                app.getString(R.string.move_to_card_slots_occupied)
            else -> ErrorText.localize(e.message) ?: app.getString(R.string.move_to_card_failed)
        }
    }

    // ── 4.7.0 RC4 (item 31): certifying with a key on a card ────────────
    // The screen runs the card operation (NFC or USB, through
    // MainActivity.startCardOperation) and reports here.

    fun onCardCertifyStarted() {
        _state.value = _state.value.copy(certifyInFlight = true, certifyError = null)
    }

    fun onCardCertified(
        certifierFingerprint: String,
        made: List<com.pgpony.android.crypto.CertificationService.Made>,
        userIds: List<String>,
        exportable: Boolean
    ) {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            try {
                repo.storeCardCertifications(key.fingerprint, certifierFingerprint, made, userIds, exportable)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    certifications = runCatching { repo.certificationsOf(key.fingerprint) }.getOrDefault(_state.value.certifications),
                    certifyInFlight = false,
                    showCertifySheet = false,
                    certifyDoneExportable = exportable
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(certifyInFlight = false, certifyError = certifyErrorText(e))
            }
        }
    }

    fun onCardCertifyFailure(e: Throwable) {
        _state.value = _state.value.copy(certifyInFlight = false, certifyError = cardErrorText(e))
    }

    fun onCardRevokeStarted() {
        _state.value = _state.value.copy(certRevokeInFlight = true, certRevokeError = null)
    }

    fun onCardRevoked(certifierFingerprint: String, made: com.pgpony.android.crypto.CertificationService.Made) {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            try {
                repo.storeCardCertificationRevocation(key.fingerprint, certifierFingerprint, made)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    certifications = runCatching { repo.certificationsOf(key.fingerprint) }.getOrDefault(_state.value.certifications),
                    certRevokeInFlight = false,
                    certRevokeRequest = null
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(certRevokeInFlight = false, certRevokeError = certifyErrorText(e))
            }
        }
    }

    fun onCardRevokeFailure(e: Throwable) {
        _state.value = _state.value.copy(certRevokeInFlight = false, certRevokeError = cardErrorText(e))
    }

    private fun cardErrorText(e: Throwable): String {
        val app = PGPonyApp.instance
        return when (e) {
            is com.pgpony.android.crypto.card.OpenPgpCardException.WrongPin ->
                app.getString(R.string.provider_cardop_wrong_pin_usb, e.triesRemaining)
            is Exception -> certifyErrorText(e)
            else -> app.getString(R.string.certify_failed)
        }
    }

    fun dismissCertifyDone() {
        _state.value = _state.value.copy(certifyDoneExportable = null)
    }

    /** From the done dialog: the key was just certified, so mark it Verified. */
    fun markVerifiedAfterCertify() {
        dismissCertifyDone()
        setTrustLevel(TrustLevel.VERIFIED)
    }

    fun requestRevokeCertification(row: com.pgpony.android.data.repository.KeyRepository.CertificationRow) {
        _state.value = _state.value.copy(certRevokeRequest = row, certRevokeError = null)
    }

    fun dismissRevokeCertification() {
        _state.value = _state.value.copy(certRevokeRequest = null, certRevokeError = null)
    }

    fun confirmRevokeCertification(passphrase: String?) {
        val key = _state.value.key ?: return
        val row = _state.value.certRevokeRequest ?: return
        val issuer = row.issuer ?: return
        _state.value = _state.value.copy(certRevokeInFlight = true, certRevokeError = null)
        viewModelScope.launch {
            try {
                repo.revokeCertification(
                    key.fingerprint, issuer.fingerprint, passphrase,
                    row.certification.userId, localOnly = !row.certification.exportable
                )
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    certifications = runCatching { repo.certificationsOf(key.fingerprint) }.getOrDefault(_state.value.certifications),
                    certRevokeInFlight = false,
                    certRevokeRequest = null
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(certRevokeInFlight = false, certRevokeError = certifyErrorText(e))
            }
        }
    }

    private fun certifyErrorText(e: Exception): String = when (e) {
        is com.pgpony.android.crypto.PGPCryptoError.PassphraseRequired ->
            PGPonyApp.instance.getString(R.string.kd_vm_error_revoke_passphrase_required)
        is com.pgpony.android.crypto.PGPCryptoError.InvalidPassphrase ->
            PGPonyApp.instance.getString(R.string.kd_vm_error_revoke_incorrect_passphrase)
        else -> ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.certify_failed)
    }

    fun addUserId(userId: String, makePrimary: Boolean, passphrase: String?) {
        val key = _state.value.key ?: return
        _state.value = _state.value.copy(addUserIdInFlight = true, addUserIdError = null)
        viewModelScope.launch {
            try {
                repo.addUserId(key.fingerprint, userId, makePrimary, passphrase)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    userIds = reloaded?.let { deriveUserIds(it) } ?: _state.value.userIds,
                    addUserIdInFlight = false,
                    showAddUserIdSheet = false
                )
            } catch (e: UserIdService.UserIdError) {
                _state.value = _state.value.copy(
                    addUserIdInFlight = false,
                    addUserIdError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_add_userid_failed)
                )
            } catch (e: com.pgpony.android.crypto.pqc.CompositeSecretProtection.ProtectedKeyException) {
                // 4.6.3 (item 20): a protected ML-DSA key reached without its
                // passphrase gets the normal prompt text, not the raw message.
                _state.value = _state.value.copy(
                    addUserIdInFlight = false,
                    addUserIdError = PGPonyApp.instance.getString(R.string.kd_vm_error_revoke_passphrase_required)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    addUserIdInFlight = false,
                    addUserIdError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_add_userid_failed)
                )
            }
        }
    }

    fun requestUserIdAction(userId: String, kind: UserIdActionRequest.Kind) {
        _state.value = _state.value.copy(
            userIdAction = UserIdActionRequest(userId, kind),
            userIdActionError = null
        )
    }

    fun dismissUserIdAction() {
        if (_state.value.userIdActionInFlight) return
        _state.value = _state.value.copy(userIdAction = null, userIdActionError = null)
    }

    /** Runs whichever action [UserIdActionRequest.kind] the pending
     *  confirmation is for — revoke or make-primary — sharing the same
     *  passphrase-only sheet and reload shape as addUserId above. */
    fun confirmUserIdAction(passphrase: String?) {
        val key = _state.value.key ?: return
        val request = _state.value.userIdAction ?: return
        _state.value = _state.value.copy(userIdActionInFlight = true, userIdActionError = null)
        viewModelScope.launch {
            try {
                when (request.kind) {
                    UserIdActionRequest.Kind.REVOKE -> repo.revokeUserId(
                        key.fingerprint, request.userId, RevocationReason.USER_ID_INVALID, null, passphrase
                    )
                    UserIdActionRequest.Kind.MAKE_PRIMARY -> repo.setPrimaryUserId(
                        key.fingerprint, request.userId, passphrase
                    )
                    UserIdActionRequest.Kind.REMOVE -> repo.removeUserId(
                        key.fingerprint, request.userId
                    )
                }
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    userIds = reloaded?.let { deriveUserIds(it) } ?: _state.value.userIds,
                    userIdActionInFlight = false,
                    userIdAction = null
                )
            } catch (e: UserIdService.UserIdError) {
                _state.value = _state.value.copy(
                    userIdActionInFlight = false,
                    userIdActionError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_userid_action_failed)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    userIdActionInFlight = false,
                    userIdActionError = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(R.string.key_detail_userid_action_failed)
                )
            }
        }
    }

    fun dismissRevocationResultSheet() {
        _state.value = _state.value.copy(
            showRevocationResultSheet = false,
            pendingRevocationCert = null
        )
    }

    /**
     * Return the stored armored revocation certificate. Used by the
     * "Export Revocation Certificate" action in Danger Zone (rendered
     * only when isRevoked = true). Suspends because the repo call is a
     * DB read. Returns null if there's no cert stored, which is the
     * rare-but-possible state where pre-cache failed at key gen AND
     * the user has not yet revoked (in that case Danger Zone wouldn't
     * surface the export action anyway).
     */
    suspend fun exportRevocationCertificate(): String? {
        val key = _state.value.key ?: return null
        return repo.exportRevocationCertificate(key.fingerprint)
    }

    // ── Phase A7: Export private key ──────────────────────────────────

    fun showExportPrivateConfirm() {
        _state.value = _state.value.copy(showExportPrivateConfirm = true)
    }

    fun dismissExportPrivateConfirm() {
        _state.value = _state.value.copy(showExportPrivateConfirm = false)
    }

    /**
     * Return the armored private key for the loaded key, or null if
     * export failed. Mirror of [armoredPublicKeyForShare] — the actual
     * Intent.ACTION_SEND happens at the Composable layer via
     * KeyShareIntents because ViewModels don't own Intents. Caller is
     * expected to have already passed the biometric gate before
     * invoking this.
     *
     * Returns null in two cases:
     *   • Key isn't loaded (defensive — UI shouldn't reach here)
     *   • Export failed (the key has no private material, or
     *     SecureKeyStore couldn't decrypt; both indicate something
     *     wrong with the key pair and the screen surfaces a snackbar)
     */
    fun armoredPrivateKeyForShare(exportPassphrase: String? = null): String? {
        val key = _state.value.key ?: return null
        if (!key.isKeyPair) return null
        // RC4 O5 (#16): optional passphrase on the export copy.
        return repo.exportArmoredPrivateKey(key.fingerprint, exportPassphrase)
    }

    /**
     * issue #2 symptom D: same as [armoredPrivateKeyForShare] but emits
     * GnuPG's native composite-secret format so GPG4WIN / gpg 2.5.x can
     * import a PGPony composite key. [exportPassphrase] protects the copy.
     */
    fun armoredPrivateKeyGpgCompatForShare(exportPassphrase: String? = null): String? {
        val key = _state.value.key ?: return null
        if (!key.isKeyPair) return null
        return repo.exportArmoredPrivateKeyGpgCompat(key.fingerprint, exportPassphrase)
    }

    // ── Phase A7 Fix4: Export private key result sheet ────────────────

    /**
     * Open the result sheet with the freshly-exported armored private
     * key. Called by the screen-level export flow AFTER biometric
     * success — at this point all gates have been passed and we hold
     * the material briefly to give the user Copy + Save options.
     *
     * Storing the armored string in VM state means it lives in memory
     * until [dismissExportPrivateResult]. Dismiss clears it explicitly
     * to minimize the residency window.
     */
    fun showExportPrivateResult(armored: String) {
        _state.value = _state.value.copy(
            showExportPrivateResultSheet = true,
            pendingExportedPrivate = armored
        )
        // §4.3: producing a private-key copy counts as a backup for the
        // delete-safeguard state (the delete sheet reads lastBackedUpAt).
        _state.value.key?.let { k ->
            if (k.isKeyPair) viewModelScope.launch { repo.markBackedUp(k.fingerprint) }
        }
    }

    /**
     * Close the result sheet AND zero the cached armored material.
     * Called on Done button, outside-tap dismiss, and as a defensive
     * sweep after either action button finishes.
     */
    fun dismissExportPrivateResult() {
        _state.value = _state.value.copy(
            showExportPrivateResultSheet = false,
            pendingExportedPrivate = null
        )
    }

    // ── Phase A8.6: Export public key result sheet ────────────────────

    /**
     * Open the public-key result sheet. Called from KeyDetailScreen's
     * "Share Public Key" action — no biometric gate because public
     * keys are meant to be distributed.
     *
     * The screen-level helper resolves the armored bytes via
     * [armoredPublicKeyForShare] and hands them in here; we cache
     * them in state.pendingExportedPublic for the sheet's Copy /
     * Save callbacks to consume. Cleared by [dismissExportPublicResult].
     */
    fun showExportPublicResult(armored: String) {
        _state.value = _state.value.copy(
            showExportPublicResultSheet = true,
            pendingExportedPublic = armored
        )
    }

    /**
     * Close the public-key result sheet and clear the cached bytes.
     */
    fun dismissExportPublicResult() {
        _state.value = _state.value.copy(
            showExportPublicResultSheet = false,
            pendingExportedPublic = null
        )
    }

    // ── Phase A8.6: Revocation cert re-export entry point ─────────────

    /**
     * Show the RevocationResultSheet for an already-stored revocation
     * certificate. Called by the "Export Revocation Certificate"
     * action in Danger Zone (visible only once a key is revoked).
     *
     * Unlike the post-revocation flow that runs at the end of
     * [applyRevocation], this entry point assumes the cert is already
     * stored on PGPKeyEntity.revocationCertificate. Pulls it via
     * [exportRevocationCertificate], populates the same state fields
     * (showRevocationResultSheet, pendingRevocationCert), and lets the
     * sheet render normally. Single source of truth = the sheet, two
     * entry points.
     */
    suspend fun showRevocationCertResult(): Boolean {
        val cert = exportRevocationCertificate() ?: return false
        _state.value = _state.value.copy(
            showRevocationResultSheet = true,
            pendingRevocationCert = cert
        )
        return true
    }

    // 4.1.0 Phase 9 — encodeQR moved to qr/QrBitmap.kt. It was duplicated
    // verbatim in ExchangeViewModel, with a comment promising to keep the two
    // "in sync" by hand. There is one copy now.
}
