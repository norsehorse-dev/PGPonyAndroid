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
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.contacts.ContactsService
import com.pgpony.android.contacts.DeviceContact
import com.pgpony.android.crypto.KeyExpirationService
import com.pgpony.android.crypto.RevocationError
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.TrustLevel
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.network.KeyServerRepository
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class KeyDetailUiState(
    /** The loaded key. Null while loading or if not found. */
    val key: PGPKeyEntity? = null,
    /** True while the initial load() coroutine is in flight. */
    val isLoading: Boolean = true,
    /** Set if the fingerprint passed in didn't resolve to anything. The
     *  screen renders a "Key not found — go back" placeholder. */
    val notFound: Boolean = false,
    /** Generated lazily when the user opens the QR sheet. We cache it
     *  so re-opening doesn't re-encode. */
    val qrBitmap: Bitmap? = null,
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
    val expiryInFlight: Boolean = false,
    val expiryError: String? = null,
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
    // ── Phase A7: Export private key ──────────────────────────────────
    /** Drives the export-private-key confirmation AlertDialog. The
     *  dialog warns the user that the private key includes secret
     *  material and that PGPony can't claw it back once shared. On
     *  confirm, the screen-level code invokes BiometricGate (if
     *  available) and only then surfaces the share Intent. */
    val showExportPrivateConfirm: Boolean = false,

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
    fun load(fingerprint: String) {
        // Skip if already loaded with the same fingerprint
        val current = _state.value.key
        if (current?.fingerprint.equals(fingerprint, ignoreCase = true) && !_state.value.isLoading) {
            return
        }
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, errorMessage = null)
            val loaded = repo.getByFingerprint(fingerprint)
            _state.value = _state.value.copy(
                key = loaded,
                isLoading = false,
                notFound = loaded == null
            )
        }
    }

    /**
     * Open the QR sheet. Generates the QR bitmap on the first open so
     * we don't spend ZXing cycles for users who never tap the button.
     * Subsequent opens reuse the cached bitmap.
     */
    fun showQR() {
        val key = _state.value.key ?: return
        if (_state.value.qrBitmap != null) {
            _state.value = _state.value.copy(showQRSheet = true)
            return
        }
        viewModelScope.launch {
            val armored = repo.exportArmoredPublicKey(key.fingerprint)
            if (armored.isNullOrBlank()) {
                _state.value = _state.value.copy(
                    errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_export_for_qr),
                    showQRSheet = false
                )
                return@launch
            }
            val bitmap = try {
                encodeQR(armored)
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_qr_failed_format, e.message ?: "")
                )
                return@launch
            }
            _state.value = _state.value.copy(qrBitmap = bitmap, showQRSheet = true)
        }
    }

    fun hideQR() {
        _state.value = _state.value.copy(showQRSheet = false)
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
                    errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_upload_failed_format, e.message ?: "")
                )
            }
        }
    }

    /**
     * 3.0.0-KS1 (Lukas request) — check/refresh this key against a keyserver.
     * Looks the key up by fingerprint; whether or not it's found, the attempt
     * stamps `lastCheckedAt` so the detail screen shows "Last checked: <date>".
     * The success message reports whether the key is still published.
     */
    fun checkKeyServer() {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            _state.value = _state.value.copy(isCheckingKeyServer = true)
            try {
                val found = keyServer.searchByFingerprint(key.fingerprint)
                repo.markKeyServerChecked(key.fingerprint)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    isCheckingKeyServer = false,
                    successMessage = PGPonyApp.instance.getString(
                        if (found != null) R.string.kd_vm_check_found
                        else R.string.kd_vm_check_not_found
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
                        R.string.kd_vm_check_failed_format, e.message ?: ""
                    )
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
        return repo.exportArmoredPublicKey(key.fingerprint)
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
                repo.deleteByFingerprint(key.fingerprint)
                // No state cleanup — the screen pops the back stack via
                // the event, the VM dies with the back stack entry.
                _events.tryEmit(KeyDetailEvent.KeyDeleted)
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    showDeleteConfirm = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_delete_failed_format, e.message ?: "")
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
                    revokeError = e.message ?: PGPonyApp.instance.getString(R.string.kd_vm_error_revocation_failed_default)
                )
            } catch (e: Exception) {
                // Anything non-RevocationError (DB write fail, store write
                // fail, etc.) — bubble to the generic snackbar surface so
                // the user can see it without it cluttering the revoke
                // sheet. The sheet stays open for retry.
                _state.value = _state.value.copy(
                    isRevoking = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.kd_vm_error_revocation_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── Expiration editing ──────────────────────────────────────────────

    fun showExpirySheet() {
        _state.value = _state.value.copy(showExpirySheet = true, expiryError = null)
    }

    fun dismissExpirySheet() {
        if (_state.value.expiryInFlight) return
        _state.value = _state.value.copy(showExpirySheet = false, expiryError = null)
    }

    /**
     * Software key pair: re-sign with the new expiry and persist. Mirrors
     * applyRevocation's error handling. [expiresAtEpochSeconds] null = never.
     */
    fun applyExpirationSoftware(expiresAtEpochSeconds: Long?, passphrase: String?) {
        val key = _state.value.key ?: return
        _state.value = _state.value.copy(expiryInFlight = true, expiryError = null)
        viewModelScope.launch {
            try {
                repo.setKeyExpirationSoftware(key.fingerprint, expiresAtEpochSeconds, passphrase)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    expiryInFlight = false,
                    showExpirySheet = false
                )
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
                    expiryError = e.message ?: PGPonyApp.instance.getString(R.string.key_detail_expiry_failed)
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    expiryInFlight = false,
                    expiryError = e.message ?: PGPonyApp.instance.getString(R.string.key_detail_expiry_failed)
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
        _state.value = _state.value.copy(expiryInFlight = false, expiryError = message)
    }

    /** Persist the card-updated public ring and refresh. */
    fun persistCardExpiry(
        updatedPublicRing: org.bouncycastle.openpgp.PGPPublicKeyRing,
        expiresAtEpochSeconds: Long?
    ) {
        val key = _state.value.key ?: return
        viewModelScope.launch {
            try {
                repo.persistCardExpiration(key.fingerprint, updatedPublicRing, expiresAtEpochSeconds)
                val reloaded = repo.getByFingerprint(key.fingerprint)
                _state.value = _state.value.copy(
                    key = reloaded ?: key,
                    expiryInFlight = false,
                    showExpirySheet = false
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    expiryInFlight = false,
                    expiryError = e.message ?: PGPonyApp.instance.getString(R.string.key_detail_expiry_failed)
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
    fun armoredPrivateKeyForShare(): String? {
        val key = _state.value.key ?: return null
        if (!key.isKeyPair) return null
        return repo.exportArmoredPrivateKey(key.fingerprint)
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

    /** Encode the armored key as a 800x800 monochrome QR bitmap. Same
     *  parameters used by ExchangeViewModel — kept in sync so QR sheets
     *  in both surfaces produce visually equivalent codes. */
    private fun encodeQR(armored: String): Bitmap {
        val hints = mapOf(EncodeHintType.MARGIN to 1)
        val matrix = QRCodeWriter().encode(armored, BarcodeFormat.QR_CODE, 800, 800, hints)
        val width = matrix.width
        val height = matrix.height
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(
                    x, y,
                    if (matrix.get(x, y)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
                )
            }
        }
        return bitmap
    }
}
