// EncryptDecryptViewModel.kt
// PGPony Android
//
// Shared ViewModel for Encrypt and Decrypt tabs.
// Routes to PGPCryptoService through KeyRepository for key lookup.
//
// Phase A2: added EncryptMode (TEXT / SIGN), `signOnly()` action that
// produces RFC 4880 §7 clear-signed text via SigningService, and the
// matching SignSuccess event for haptics on the sign path. File mode
// is reserved by name in the enum but its UI path lands in Phase A10
// alongside the rest of the encrypt/decrypt feature-parity work.
//
// Phase A10b: file-mode encrypt is now wired up. New state on
// EncryptUiState — selectedFileName/Size/Bytes for the picked input
// file, encryptedFileBytes for the produced ciphertext, plus
// showEncryptResultSheet/showFileEncryptResultSheet flags so the
// dedicated result screens can be shown on success. Actions:
// setFileToEncrypt() (call with the bytes the ImportKeyScreen-style
// content://-read path produced), clearFile(), encryptFile(),
// dismissEncryptResult(), dismissFileEncryptResult(). The text-mode
// encrypt() path now flips showEncryptResultSheet on success in
// addition to its existing outputText update — the legacy inline
// result block in Screens.kt stays for now and renders the same
// data the sheet does.
//
// Phase A10c: file-mode decrypt now ships alongside file-mode
// encrypt. New DecryptMode enum (TEXT / FILE), state additions on
// DecryptUiState mirror the encrypt side — selectedFile{Name,Size,
// Bytes} for the picked encrypted .pgp/.gpg/.asc, decryptedFile-
// Bytes for the produced plaintext, decryptedOutputFilename for
// the save-dialog suggestion. Actions: setDecryptMode(),
// setFileToDecrypt(), clearDecryptFile(), decryptFile(),
// dismissFileDecryptResult(). The internal decryptFileAndVerify-
// Path() mirrors decryptAndVerifyPath() but feeds raw bytes to
// crypto.decrypt() (which sniffs armored vs binary via
// isArmored()) instead of armored text to decryptArmored().

package com.pgpony.android.ui.encrypt

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SignedInputType
import com.pgpony.android.crypto.SigningError
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.ui.settings.DefaultRecipientPrefs
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.network.KeyServerRepository
import com.pgpony.android.ui.decrypt.SignerLookupState
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// ── Mode picker (Phase A2) ─────────────────────────────────────────────
//
// Top-level Encrypt-tab mode. Phase A2 ships TEXT and SIGN; FILE is
// declared so the Composable's segmented control can render its slot
// even though the file flow lands in Phase A10. Selecting FILE in A2
// surfaces a "coming soon" placeholder rather than a working picker.

enum class EncryptMode(val displayName: String) {
    TEXT("Text"),
    SIGN("Sign"),
    FILE("File"),
    // Phase A1: symmetric / passphrase-only encryption (`gpg -c`). No
    // recipient keypair — the message is sealed to a passphrase via
    // PGPCryptoService.encryptSymmetric.
    PASSWORD("Password")
}

/**
 * Phase A10c: top-level mode picker for the Decrypt tab. iOS has the
 * same two-mode shape (text/file) and we mirror it for parity. Sign-
 * only doesn't exist on this side — clear-signed verification is
 * routed automatically by [VerifyService.detectInputType] within the
 * text path, and the file path is binary-only for now (a future
 * extension could detect clear-signed text inside an .asc file too).
 */
enum class DecryptMode(val displayName: String) {
    TEXT("Text"),
    FILE("File")
}

data class EncryptUiState(
    val inputText: String = "",
    val outputText: String = "",
    val selectedRecipients: List<PGPKeyEntity> = emptyList(),
    val availableRecipients: List<PGPKeyEntity> = emptyList(),
    val signingKey: PGPKeyEntity? = null,
    val availableSigningKeys: List<PGPKeyEntity> = emptyList(),
    val signMessage: Boolean = false,
    // Sign tab: produce a standalone detached signature block instead of
    // a clear-signed message. Only consulted in EncryptMode.SIGN.
    val detachedSignature: Boolean = false,
    val isProcessing: Boolean = false,
    val errorMessage: String? = null,
    val isFileMode: Boolean = false,
    val filename: String? = null,
    // Phase A2: top-level mode + sign-only passphrase prompt state.
    // The passphrase fields parallel DecryptUiState's pattern so the UI
    // layer can reuse the same dialog Composable shape.
    val mode: EncryptMode = EncryptMode.TEXT,
    val signPassphrase: String = "",
    val showSignPassphraseDialog: Boolean = false,
    // ── Phase A10b: file-mode encrypt state ────────────────────────
    //
    // selectedFileBytes is the raw input file content read via the
    // system file picker (DocumentPicker → contentResolver). We keep
    // bytes in memory rather than a URI because the URI's read-grant
    // is scoped to the activity and would need re-validation across
    // process death; encrypt() is fast enough that holding the bytes
    // around until the user taps Encrypt is fine for typical file
    // sizes (<10 MB). Larger files would warrant streaming — out of
    // scope for A10b.
    //
    // encryptedFileBytes is the produced ciphertext. armor=false is
    // implied for file mode (we want binary, not ASCII-armored, to
    // keep file size small and match standard .pgp convention). The
    // file save flow in FileEncryptionResultScreen writes these bytes
    // to a content:// URI obtained via ACTION_CREATE_DOCUMENT.
    val selectedFileName: String? = null,
    val selectedFileSize: Long? = null,
    val selectedFileBytes: ByteArray? = null,
    val encryptedFileBytes: ByteArray? = null,
    // Result-sheet visibility. Mutually exclusive in practice — only
    // one of them is ever true at a time — but kept as separate flags
    // so the screen layer can render two distinct Composables without
    // coupling them via an enum.
    val showEncryptResultSheet: Boolean = false,
    val showFileEncryptResultSheet: Boolean = false,
    // ── A15 preflight fix ──────────────────────────────────────────────
    //
    // Screens.kt references state.asciiArmor + viewModel.setAsciiArmor(...)
    // for the toggle UI added during A13 string extraction. The toggle
    // was wired into the Composable but the backing state field +
    // setter were never added to EncryptDecryptViewModel, so the call
    // sites failed to resolve.
    //
    // Default true: text-mode encrypt has always emitted armored output;
    // file-mode encrypt now also defaults to armored (which is what
    // the toggle UI implies — flipping it off opts the user into
    // smaller binary output for large files). Behavior change from
    // pre-A15 file-mode (was hard-coded armor=false): minor — the file
    // output is now armored by default, which means a slightly larger
    // .pgp file but more portable / pasteable into email.
    val asciiArmor: Boolean = true,
    // ── Phase A1: symmetric / passphrase-only (Password) mode ──────────
    //
    // Independent of the sign-passphrase dialog (that unlocks a signing
    // key). These back the in-body passphrase + confirm fields shown in
    // EncryptMode.PASSWORD. The passphrase never leaves the device and is
    // cleared from state after a successful encrypt.
    val passwordPassphrase: String = "",
    val passwordConfirm: String = "",
    val passwordVisible: Boolean = false,
    // ── Phase A5: "Sign a file" (detached signature, software key) ─────
    //
    // Sign a file on its own (no encryption) → standalone detached signature
    // (.asc or .sig) to share alongside the original. Lives on the Encrypt
    // tab's FILE mode, next to the existing sign-a-message flow. Card-backed
    // signing is deferred to the card phase.
    val showSignFileSheet: Boolean = false,
    val signFileName: String? = null,
    val signFileBytes: ByteArray? = null,
    val signFileSelectedKey: PGPKeyEntity? = null,
    val showSignFileKeyPicker: Boolean = false,
    val signFilePassphrase: String = "",
    /** true = armored .asc; false = binary .sig. Default armored (portable). */
    val signFileArmor: Boolean = true,
    val signFileResultBytes: ByteArray? = null,
    val signFileResultName: String? = null,
    val signFileProcessing: Boolean = false,
)

data class DecryptUiState(
    val inputText: String = "",
    val outputText: String = "",
    val outputData: ByteArray? = null,
    val availableKeys: List<PGPKeyEntity> = emptyList(),
    val selectedKeyFingerprint: String? = null,
    val passphrase: String = "",
    val showPassphraseDialog: Boolean = false,
    val isProcessing: Boolean = false,
    val errorMessage: String? = null,
    val signatureVerified: Boolean = false,
    val signerKeyID: String? = null,
    // HW Phase 3 — set when the input message is encrypted to a card-backed
    // key (a recipient key ID matches a card key's encryption subkey). The
    // Decrypt tab then hides the passphrase field and offers PIN + tap
    // instead. cardMessageKeyName is the display name for the prompt.
    val isCardMessage: Boolean = false,
    val cardMessageKeyFingerprint: String? = null,
    val cardMessageKeyName: String? = null,
    // Phase A1: set when the pasted/loaded message is password-encrypted
    // (symmetric SKESK, `gpg -c`) and addressed to no public key. The Decrypt
    // tab then hides the key picker and shows a "Password-encrypted" note +
    // the passphrase field, since no keypair applies.
    val isPasswordMessage: Boolean = false,
    val decryptedFilename: String? = null,
    // Phase A3: full verification result for the 4-state banner. Populated
    // by both the clear-signed verify path AND the encrypted-and-signed
    // path (derived from PGPCryptoService.decryptArmored output). Null
    // means no result yet — banner is hidden.
    val verificationResult: VerificationResult? = null,
    // Phase A3: signer-lookup modal sheet state.
    val showSignerLookup: Boolean = false,
    val signerLookupState: SignerLookupState = SignerLookupState.Searching,
    // Phase A3: remember the claimed fingerprint of the unknown signer so
    // we can re-verify after the user imports the discovered key.
    val pendingUnknownClaimedFingerprint: String? = null,
    // ── Phase A10c: file-mode decrypt state ────────────────────────
    //
    // Mirrors the encrypt-side fields on EncryptUiState. The picked
    // .pgp/.gpg/.asc input is read into memory at pick time
    // (selectedFileBytes) — same in-memory-only approach as A10b
    // encrypt. PGPCryptoService.decrypt() sniffs whether the bytes
    // are ASCII-armored or binary, so we don't need a separate path
    // per format. decryptedFileBytes holds the plaintext until the
    // user saves or shares it; decryptedOutputFilename pre-seeds the
    // save-dialog suggestion (encrypted name minus .pgp/.gpg/.asc
    // extension, or "decrypted_<name>" if there was no recognized
    // extension to strip).
    val mode: DecryptMode = DecryptMode.TEXT,
    val selectedFileName: String? = null,
    val selectedFileSize: Long? = null,
    val selectedFileBytes: ByteArray? = null,
    val decryptedFileBytes: ByteArray? = null,
    val decryptedOutputFilename: String? = null,
    val showFileDecryptResultSheet: Boolean = false,
    // ── Phase A3: "Verify a file" (detached signature) sheet ───────────
    //
    // Self-contained from the decrypt result above: the user picks the
    // original file + its detached .sig/.asc, and VerifyService checks them.
    // Reuses the shared signer-lookup fields (showSignerLookup /
    // pendingUnknownClaimedFingerprint) since decrypt and verify-file are
    // never active at the same time.
    val showVerifyFileSheet: Boolean = false,
    val verifyFileSignedName: String? = null,
    val verifyFileSignedBytes: ByteArray? = null,
    val verifyFileSigName: String? = null,
    val verifyFileSigBytes: ByteArray? = null,
    val verifyFileResult: VerificationResult? = null,
    val verifyFileProcessing: Boolean = false,
)

class EncryptDecryptViewModel(private val repo: KeyRepository) : ViewModel() {

    private val crypto = PGPCryptoService.shared
    // Phase A2: dedicated signing service (separate from PGPCryptoService
    // so we can grow clear-sign / detached / revocation / per-key export
    // without further bloating the crypto service).
    private val signing = SigningService.shared

    // Phase A4 — app prefs for the default/remembered recipient.
    private val appPrefs by lazy {
        PGPonyApp.instance.getSharedPreferences(
            "pgpony_prefs", android.content.Context.MODE_PRIVATE
        )
    }
    // Phase A3: verification service for clear-signed input. Encrypted-
    // and-signed messages still go through PGPCryptoService.decryptArmored
    // (which parses one-pass-signature packets inline); the VerifyService
    // result is then derived from the DecryptResult for banner display.
    private val verify = VerifyService.shared
    // Phase A3: keyserver client used by the unknown-signer lookup flow.
    // Lazy-instantiated because constructing the HTTP client has a small
    // up-front cost we'd rather defer to first use.
    private val keyServer by lazy { KeyServerRepository() }

    private val _encryptState = MutableStateFlow(EncryptUiState())
    val encryptState: StateFlow<EncryptUiState> = _encryptState.asStateFlow()

    private val _decryptState = MutableStateFlow(DecryptUiState())
    val decryptState: StateFlow<DecryptUiState> = _decryptState.asStateFlow()

    // Public rings cached on key load so the card-decrypt NFC lambda can
    // verify embedded one-pass signatures without touching suspend DB calls
    // on the binder thread. Refreshed every loadKeys().
    private var verifyRingsCache: List<org.bouncycastle.openpgp.PGPPublicKeyRing> = emptyList()

    /** Public rings for verifying a card-decrypted message's signature. */
    fun cardVerificationRings(): List<org.bouncycastle.openpgp.PGPPublicKeyRing> = verifyRingsCache

    // One-shot events for UI side effects (haptics, snackbars, etc.).
    // SharedFlow with replay=0 so late subscribers don't re-fire past events.
    private val _events = MutableSharedFlow<Event>(extraBufferCapacity = 4)
    val events: SharedFlow<Event> = _events.asSharedFlow()

    sealed class Event {
        object EncryptSuccess : Event()
        object DecryptSuccess : Event()
        // Phase A2: separate event so the Sign-mode button can fire its
        // own haptic without piggy-backing on EncryptSuccess (different
        // user-perceived action).
        object SignSuccess : Event()
    }

    init {
        loadKeys()
    }

    private fun loadKeys() {
        viewModelScope.launch {
            val allKeys = repo.getAllKeys()
            // Cache public rings so the card-decrypt NFC lambda (which runs
            // on a non-suspend binder thread) can verify embedded signatures
            // synchronously. loadPublicKeyRing reads the in-memory store.
            verifyRingsCache = allKeys.mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
            val keyPairs = allKeys.filter { it.isKeyPair }

            // Phase A6 — revoked keys are excluded from the encrypt-side
            // selection pools. Reason: encrypting NEW messages to a
            // revoked recipient or signing NEW messages with a revoked
            // key is exactly what revocation is supposed to prevent.
            // They stay available for decrypt though (see below) — the
            // secret material is intact, just no longer trusted for new
            // operations.
            //
            // HW Phase 1.5 — also exclude card-backed entries that have
            // no public key yet. A freshly-scanned OpenPGP card is stored
            // as identity + fingerprints only (armoredPublicKey == null);
            // there's nothing to encrypt to until the user pairs it with
            // a real public key (import / keyserver / WKD). Offering it as
            // a recipient before then produces a confusing "no encryption
            // methods" failure. Once paired, armoredPublicKey is set and
            // it reappears here automatically. Normal (non-card) keys
            // always have armoredPublicKey, so this only affects unpaired
            // cards.
            val unrevokedRecipients = allKeys.filter {
                !it.isRevoked && (!it.isCardBacked || it.armoredPublicKey != null)
            }
            val unrevokedKeyPairs = keyPairs.filter { !it.isRevoked }

            // HW Phase 2b-step2 — card-backed keys that are paired (have a
            // public key) can sign too: the private key lives on the card,
            // so they're public-only records (isKeyPair == false) but still
            // signable via the NFC card-sign path. Include them in the
            // signing pool after the software key pairs. The UI branches on
            // signingKey.isCardBacked to drive PIN + tap instead of the
            // passphrase/secret-key path.
            val cardSigners = allKeys.filter {
                !it.isRevoked && it.isCardBacked && !it.isKeyPair && it.armoredPublicKey != null
            }
            val signableKeys = unrevokedKeyPairs + cardSigners

            // Phase A4 — default/remembered recipient pre-selection. Only seed
            // when nothing is selected yet (loadKeys also runs on tab return,
            // and we must not clobber an in-progress selection). The saved
            // fingerprint is matched against the LIVE recipient pool, so a
            // deleted/stale key simply pre-selects nothing.
            val preselectedRecipients = if (_encryptState.value.selectedRecipients.isEmpty()) {
                DefaultRecipientPrefs.preselectFingerprint(appPrefs)
                    ?.let { fp -> unrevokedRecipients.firstOrNull { it.fingerprint == fp } }
                    ?.let { listOf(it) }
                    ?: emptyList()
            } else {
                _encryptState.value.selectedRecipients
            }

            _encryptState.value = _encryptState.value.copy(
                availableRecipients = unrevokedRecipients,
                availableSigningKeys = signableKeys,
                selectedRecipients = preselectedRecipients,
                // If the currently-selected signing key was just revoked
                // (loadKeys runs on tab return, so this can happen), bump
                // it back to default-or-first to avoid the user signing
                // with a revoked key on autopilot.
                signingKey = signableKeys.firstOrNull { it.isDefault }
                    ?: signableKeys.firstOrNull()
            )
            // Phase A6 — DECRYPT side keeps revoked keys available.
            // A user can still legitimately decrypt messages that were
            // encrypted to them BEFORE revocation; the private material
            // is unchanged. Stripping them here would lock users out of
            // their own past correspondence.
            // HW — card-backed paired keys can decrypt via PIN + tap (the
            // private key lives on the card). They're public-only records
            // (isKeyPair == false) so the keyPairs filter above misses them;
            // add them to the decrypt pool so the picker offers them when
            // auto-detection doesn't fire and the user picks the card
            // manually. They carry no secret ring, so the software decrypt
            // path harmlessly skips them; selecting one routes to the card
            // PIN+tap flow (see selectDecryptKey).
            val cardDecryptors = allKeys.filter {
                it.isCardBacked && !it.isKeyPair && it.armoredPublicKey != null
            }
            // Phase AU-1 — order the decrypt pool for the "Decrypt With"
            // picker: hardware (card) keys first, then most-used
            // (decryptUseCount desc), then the default key, then name. The top
            // of this order is the pre-selection when no message is loaded;
            // auto-detection overrides it once a message addressed to a
            // specific key is pasted (see detectCardRecipient).
            val orderedKeys = (keyPairs + cardDecryptors).sortedWith(
                compareByDescending<PGPKeyEntity> { it.isCardBacked }
                    .thenByDescending { it.decryptUseCount }
                    .thenByDescending { it.isDefault }
                    .thenBy { it.userName.ifBlank { it.userEmail }.lowercase() }
            )
            _decryptState.value = _decryptState.value.copy(
                availableKeys = orderedKeys,
                selectedKeyFingerprint = _decryptState.value.selectedKeyFingerprint
                    ?: orderedKeys.firstOrNull()?.fingerprint
            )
        }
    }

    // ── Encrypt ────────────────────────────────────────────────────────

    fun updateEncryptInput(text: String) {
        _encryptState.value = _encryptState.value.copy(inputText = text, outputText = "", errorMessage = null)
    }

    fun toggleRecipient(key: PGPKeyEntity) {
        val current = _encryptState.value.selectedRecipients.toMutableList()
        if (current.any { it.fingerprint == key.fingerprint }) {
            current.removeAll { it.fingerprint == key.fingerprint }
        } else {
            current.add(key)
        }
        _encryptState.value = _encryptState.value.copy(selectedRecipients = current)
    }

    // ── A15 preflight fix ──────────────────────────────────────────────
    //
    // Screens.kt references these helpers in the recipient picker row
    // ("Select all" / "Clear" text buttons that appear when the user
    // has more than one key in their ring). Both were added to the UI
    // layer during A13 string extraction but never to the ViewModel.
    fun selectAllRecipients() {
        val all = _encryptState.value.availableRecipients
        _encryptState.value = _encryptState.value.copy(selectedRecipients = all.toList())
    }

    fun clearRecipients() {
        _encryptState.value = _encryptState.value.copy(selectedRecipients = emptyList())
    }

    fun setAsciiArmor(value: Boolean) {
        _encryptState.value = _encryptState.value.copy(asciiArmor = value)
    }

    fun setSigningKey(key: PGPKeyEntity?) {
        _encryptState.value = _encryptState.value.copy(signingKey = key)
    }

    fun setDetachedSignature(enabled: Boolean) {
        _encryptState.value = _encryptState.value.copy(detachedSignature = enabled)
    }

    fun toggleSign(enabled: Boolean) {
        _encryptState.value = _encryptState.value.copy(signMessage = enabled)
    }

    // Phase A2: mode picker + sign-only path
    //
    // Switching modes clears any in-flight result and error, but preserves
    // the input text (users often want to switch Text -> Sign and re-use
    // the same message body) and the selected signing key (a deliberate
    // choice — the user picked it; flipping modes shouldn't reset their
    // selection).

    fun setMode(mode: EncryptMode) {
        _encryptState.value = _encryptState.value.copy(
            mode = mode,
            outputText = "",
            errorMessage = null
        )
    }

    fun updateSignPassphrase(passphrase: String) {
        _encryptState.value = _encryptState.value.copy(signPassphrase = passphrase)
    }

    fun dismissSignPassphraseDialog() {
        _encryptState.value = _encryptState.value.copy(
            showSignPassphraseDialog = false,
            signPassphrase = ""
        )
    }

    // ── A15 preflight fix ──────────────────────────────────────────────
    //
    // Escape hatch wired into Screens.kt from the sign-passphrase
    // dialog: when the user can't recall the signing-key passphrase
    // (or just doesn't want to sign), they tap "Encrypt without
    // signing" and we proceed with the recipient set, skipping the
    // signing leg. signMessage is flipped off in state and encrypt()
    // is dispatched without a passphrase.
    fun encryptWithoutSigning() {
        _encryptState.value = _encryptState.value.copy(
            signMessage = false,
            showSignPassphraseDialog = false,
            signPassphrase = "",
            errorMessage = null,
        )
        encrypt(passphrase = null)
    }

    /**
     * Phase A2: produce an RFC 4880 §7 clear-signed message using the
     * currently-selected `signingKey`. Output lands in `outputText` and
     * SignSuccess is emitted for haptics. Errors map to user-friendly
     * messages on `errorMessage`; missing/wrong passphrases route through
     * `showSignPassphraseDialog` so the UI can prompt and retry.
     *
     * If `passphrase` is null and the dialog isn't already showing, we
     * make a first attempt with an empty passphrase — that succeeds for
     * unprotected keys (the common onboarding case) without ever
     * surfacing a prompt.
     */
    // ── HW Phase 2b-step2: card sign result hooks ─────────────────────
    //
    // Card signing needs an NFC tap, which only the Activity can drive, so
    // the UI layer (Screens.kt) runs the PIN + tap + CardSigningService and
    // reports back here. These mirror the success/error tail of signOnly so
    // the output sheet, haptics, and error surface behave identically.

    fun onCardSignStarted() {
        _encryptState.value = _encryptState.value.copy(isProcessing = true, errorMessage = null)
    }

    fun onCardSignSuccess(signed: String) {
        _encryptState.value = _encryptState.value.copy(
            outputText = signed,
            isProcessing = false,
            showEncryptResultSheet = true
        )
        _events.tryEmit(Event.SignSuccess)
    }

    fun onCardSignFailure(message: String) {
        _encryptState.value = _encryptState.value.copy(
            isProcessing = false,
            errorMessage = message
        )
    }

    /**
     * HW Phase 3 — file-mode encrypt-and-sign with a card key. The Encrypt
     * screen runs the NFC op (PGPCryptoService.encrypt with cardSession,
     * armor=false) and reports the encrypted file bytes back here. Mirrors
     * the success tail of encryptFile() (file result sheet).
     */
    fun onCardEncryptFileSuccess(bytes: ByteArray) {
        _encryptState.value = _encryptState.value.copy(
            encryptedFileBytes = bytes,
            isProcessing = false,
            showFileEncryptResultSheet = true
        )
        _events.tryEmit(Event.EncryptSuccess)
    }

    /** True when the no-input guard should block a card sign. */
    fun signInputIsBlank(): Boolean = _encryptState.value.inputText.isBlank()

    fun reportNoSignInput() {
        _encryptState.value = _encryptState.value.copy(
            errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_sign_no_input)
        )
    }

    fun signOnly(passphrase: String? = null) {
        val s = _encryptState.value
        if (s.inputText.isBlank()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_sign_no_input))
            return
        }
        val signingKey = s.signingKey ?: run {
            _encryptState.value = s.copy(
                errorMessage = "No signing key available. Generate or import a key pair first."
            )
            return
        }

        viewModelScope.launch {
            _encryptState.value = _encryptState.value.copy(isProcessing = true, errorMessage = null)
            try {
                val secRing = repo.loadSecretKeyRing(signingKey.fingerprint)
                    ?: throw SigningError.NoSigningKey()

                val signed = if (s.detachedSignature) {
                    // Detached: standalone armored signature block over the
                    // UTF-8 bytes of the message (BINARY_DOCUMENT).
                    String(
                        signing.signDetached(
                            data = s.inputText.toByteArray(Charsets.UTF_8),
                            secretKeyRing = secRing,
                            passphrase = passphrase
                        ),
                        Charsets.UTF_8
                    )
                } else {
                    signing.signClear(
                        text = s.inputText,
                        secretKeyRing = secRing,
                        passphrase = passphrase
                    )
                }

                _encryptState.value = _encryptState.value.copy(
                    outputText = signed,
                    isProcessing = false,
                    showSignPassphraseDialog = false,
                    signPassphrase = "",
                    // Phase A10b: same result-sheet flow as the text
                    // encrypt path. EncryptionResultScreen's title
                    // and badges adapt via the mode field passed
                    // alongside it.
                    showEncryptResultSheet = true
                )
                _events.tryEmit(Event.SignSuccess)
            } catch (e: SigningError.PassphraseRequired) {
                // Surface the passphrase prompt; caller can retry signOnly
                // with the user-entered passphrase via the dialog's
                // confirm action.
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    errorMessage = null
                )
            } catch (e: SigningError.InvalidPassphrase) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    // Keep the dialog visible so the user can correct the
                    // passphrase without retyping the message.
                    showSignPassphraseDialog = true,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase)
                )
            } catch (e: SigningError) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    errorMessage = e.message
                )
            } catch (e: Exception) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_signing_failed_format, e.message ?: "")
                )
            }
        }
    }

    fun encrypt(passphrase: String? = null) {
        val s = _encryptState.value
        if (s.inputText.isBlank()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_encrypt_no_input))
            return
        }
        if (s.selectedRecipients.isEmpty()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_recipients))
            return
        }
        // Phase A4 — remember the recipient just used (for REMEMBER_LAST mode).
        DefaultRecipientPrefs.recordLastUsed(appPrefs, s.selectedRecipients.firstOrNull()?.fingerprint)
        // HW Phase 3 — encrypt-and-sign with a card key is now supported,
        // but it needs an NFC tap mid-pipeline, so the Encrypt screen
        // routes that case to the card path (PGPCryptoService.encrypt with
        // cardSession set) BEFORE calling encrypt(). This software path is
        // reached only for software signing keys or no signing.

        viewModelScope.launch {
            _encryptState.value = _encryptState.value.copy(isProcessing = true, errorMessage = null)
            try {
                val recipientRings = s.selectedRecipients.mapNotNull {
                    repo.loadPublicKeyRing(it.fingerprint)
                }
                val signingRing = if (s.signMessage && s.signingKey != null) {
                    repo.loadSecretKeyRing(s.signingKey.fingerprint)
                } else null

                val encrypted = crypto.encrypt(
                    data = s.inputText.toByteArray(Charsets.UTF_8),
                    recipientPublicKeys = recipientRings,
                    signingSecretKey = signingRing,
                    passphrase = passphrase,
                    filename = s.filename,
                    armor = true
                )
                _encryptState.value = _encryptState.value.copy(
                    outputText = String(encrypted, Charsets.UTF_8),
                    isProcessing = false,
                    // Phase A10b: also flip the sheet flag so the
                    // dedicated EncryptionResultScreen renders. Inline
                    // result block in Screens.kt keeps rendering too —
                    // both code paths show the same outputText.
                    showEncryptResultSheet = true
                )
                _events.tryEmit(Event.EncryptSuccess)
            } catch (e: SigningError.PassphraseRequired) {
                // Phase A10b Fix1: imported keys (or anything with
                // s2KUsage != 0) need a passphrase to unlock for
                // signing. Surface the existing sign-passphrase
                // dialog instead of the BC-internal "checksum
                // mismatch" wrap. The dialog's confirm button (see
                // Screens.kt) dispatches back to encrypt(passphrase)
                // by reading state.mode == TEXT.
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    signPassphrase = "",
                    errorMessage = null
                )
            } catch (e: SigningError.InvalidPassphrase) {
                // Re-show the dialog with an error message — the
                // dialog body renders state.errorMessage inline so
                // the user doesn't lose their typed passphrase
                // context.
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    signPassphrase = "",
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase_retry)
                )
            } catch (e: Exception) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_encryption_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── Phase A10b: file-mode encrypt actions ──────────────────────────
    //
    // The UI hands bytes (already read from a content:// URI on its
    // side via contentResolver.openInputStream) rather than a URI so
    // we don't have to thread Context through the ViewModel. This
    // does mean the entire file sits in memory during the encrypt
    // round-trip — fine for typical key/document sizes, would need
    // streaming refactor for multi-MB files.

    /**
     * Phase A10b: store the picked input file's metadata and bytes
     * in encrypt state. Called by the UI after the system file
     * picker returns a URI and the bytes have been read from
     * contentResolver. Clears any pending output bytes so a fresh
     * encrypt() runs against the new input.
     */
    fun setFileToEncrypt(name: String, size: Long, bytes: ByteArray) {
        _encryptState.value = _encryptState.value.copy(
            selectedFileName = name,
            selectedFileSize = size,
            selectedFileBytes = bytes,
            encryptedFileBytes = null,
            errorMessage = null
        )
    }

    /** Phase A10b: clear the picked file. */
    fun clearFile() {
        _encryptState.value = _encryptState.value.copy(
            selectedFileName = null,
            selectedFileSize = null,
            selectedFileBytes = null,
            encryptedFileBytes = null,
            errorMessage = null
        )
    }

    /**
     * Phase A10b: encrypt the currently-selected file. armor=false
     * because file mode produces binary .pgp ciphertext (the iOS app
     * does the same — text mode uses ASCII armor, file mode does
     * not). Recipients and the signing-key/sign-message toggle work
     * the same way as text-mode encrypt.
     */
    fun encryptFile(passphrase: String? = null) {
        val s = _encryptState.value
        val bytes = s.selectedFileBytes
        if (bytes == null) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_file_to_encrypt))
            return
        }
        if (s.selectedRecipients.isEmpty()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_recipients))
            return
        }
        // Phase A4 — remember the recipient just used (for REMEMBER_LAST mode).
        DefaultRecipientPrefs.recordLastUsed(appPrefs, s.selectedRecipients.firstOrNull()?.fingerprint)
        // HW Phase 3 — file encrypt-and-sign with a card key is routed to
        // the card path by the Encrypt screen (PGPCryptoService.encrypt with
        // cardSession set, armor=false) before encryptFile() is called. This
        // software path handles software signing keys or no signing.
        viewModelScope.launch {
            _encryptState.value = _encryptState.value.copy(isProcessing = true, errorMessage = null)
            try {
                val recipientRings = s.selectedRecipients.mapNotNull {
                    repo.loadPublicKeyRing(it.fingerprint)
                }
                val signingRing = if (s.signMessage && s.signingKey != null) {
                    repo.loadSecretKeyRing(s.signingKey.fingerprint)
                } else null

                val encrypted = crypto.encrypt(
                    data = bytes,
                    recipientPublicKeys = recipientRings,
                    signingSecretKey = signingRing,
                    passphrase = passphrase,
                    filename = s.selectedFileName,
                    armor = false
                )
                _encryptState.value = _encryptState.value.copy(
                    encryptedFileBytes = encrypted,
                    isProcessing = false,
                    showFileEncryptResultSheet = true
                )
                _events.tryEmit(Event.EncryptSuccess)
            } catch (e: SigningError.PassphraseRequired) {
                // Phase A10b Fix1: same passphrase-prompt routing as
                // text-mode encrypt. Dialog confirm in Screens.kt
                // dispatches back to encryptFile(passphrase) by
                // reading state.mode == FILE.
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    signPassphrase = "",
                    errorMessage = null
                )
            } catch (e: SigningError.InvalidPassphrase) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    signPassphrase = "",
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase_retry)
                )
            } catch (e: Exception) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_encryption_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── Phase A1: symmetric / passphrase-only (Password) mode ──────────

    fun updatePasswordPassphrase(pp: String) {
        _encryptState.value = _encryptState.value.copy(passwordPassphrase = pp, errorMessage = null)
    }

    fun updatePasswordConfirm(pp: String) {
        _encryptState.value = _encryptState.value.copy(passwordConfirm = pp, errorMessage = null)
    }

    fun togglePasswordVisible() {
        _encryptState.value = _encryptState.value.copy(passwordVisible = !_encryptState.value.passwordVisible)
    }

    /**
     * Phase A1: encrypt the text input to a passphrase only (`gpg -c`),
     * with no recipient keypair. Validates non-empty input, a non-empty
     * passphrase, and that the confirm field matches. On success the
     * armored ciphertext lands in outputText (same surface as text-mode
     * encrypt) and the passphrase fields are cleared. Symmetric + file is
     * a planned fast-follow; this v1 covers the text input.
     */
    fun encryptWithPassword() {
        val s = _encryptState.value
        if (s.inputText.isBlank()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_encrypt_no_input))
            return
        }
        if (s.passwordPassphrase.isEmpty()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_password_required))
            return
        }
        if (s.passwordPassphrase != s.passwordConfirm) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_password_mismatch))
            return
        }

        viewModelScope.launch {
            _encryptState.value = _encryptState.value.copy(isProcessing = true, errorMessage = null)
            try {
                val encrypted = crypto.encryptSymmetricMessage(
                    message = s.inputText,
                    passphrase = s.passwordPassphrase
                )
                _encryptState.value = _encryptState.value.copy(
                    outputText = encrypted,
                    isProcessing = false,
                    // Clear the secret from state once it has done its job.
                    passwordPassphrase = "",
                    passwordConfirm = "",
                    passwordVisible = false,
                    showEncryptResultSheet = true
                )
                _events.tryEmit(Event.EncryptSuccess)
            } catch (e: Exception) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_encryption_failed_format, e.message ?: "")
                )
            }
        }
    }

    /**
     * Phase A10b: dismiss the text/sign result sheet. The outputText
     * in state stays so the inline result block in Screens.kt keeps
     * showing it after dismissal — the sheet is a one-shot "you just
     * encrypted something" celebration, not the authoritative copy
     * surface.
     */
    fun dismissEncryptResult() {
        _encryptState.value = _encryptState.value.copy(showEncryptResultSheet = false)
    }

    /**
     * Phase A10b: dismiss the file-mode result sheet. Unlike the
     * text-mode dismissal we clear the encrypted bytes — there's no
     * inline display of binary output, so once the sheet closes the
     * user has either saved/shared the ciphertext or they haven't.
     */
    fun dismissFileEncryptResult() {
        _encryptState.value = _encryptState.value.copy(
            showFileEncryptResultSheet = false,
            encryptedFileBytes = null
        )
    }

    // ── Decrypt ────────────────────────────────────────────────────────

    fun updateDecryptInput(text: String) {
        _decryptState.value = _decryptState.value.copy(
            inputText = text, outputText = "", outputData = null,
            errorMessage = null, signatureVerified = false,
            // Phase A3: clear any stale verification result when input changes
            verificationResult = null
        )
        detectCardRecipient(text)
    }

    /**
     * HW Phase 3 — decide whether [text] is encrypted to a card-backed key
     * so the Decrypt tab can swap the passphrase field for a PIN + tap
     * flow. Cheap: reads the message's recipient key IDs (no decryption)
     * and checks them against the encryption subkeys of card-backed keys
     * in the ring. Runs only once a full PGP MESSAGE block is present, and
     * guards against races by re-checking the input hasn't changed before
     * publishing the result.
     */
    private fun detectCardRecipient(text: String) {
        if (!text.contains("BEGIN PGP MESSAGE")) {
            val cur = _decryptState.value
            if (cur.isCardMessage || cur.cardMessageKeyFingerprint != null || cur.isPasswordMessage) {
                _decryptState.value = cur.copy(
                    isCardMessage = false,
                    cardMessageKeyFingerprint = null,
                    cardMessageKeyName = null,
                    isPasswordMessage = false
                )
            }
            return
        }
        viewModelScope.launch {
            // Phase AU-1 — resolve both a card-key match (which routes to the
            // PIN+tap path) and, failing that, a software-key match, so the
            // picker can snap its selection to the message's recipient.
            // Auto-detection wins over the most-used default whenever a
            // message addressed to a specific key is loaded.
            var cardMatch: PGPKeyEntity? = null
            var softwareMatchFp: String? = null
            var isPassword = false
            try {
                // Phase A1: one inspection yields both the public-key recipient
                // IDs (for card/software matching) and whether the message is
                // password-encrypted (SKESK, `gpg -c`).
                val info = crypto.inspectEncryptedMessage(text.toByteArray(Charsets.UTF_8))
                isPassword = info.isSymmetricOnly
                val recipientIds = info.publicKeyIDs
                if (recipientIds.isNotEmpty()) {
                    val cardEntities = repo.getAllKeys().filter {
                        it.isCardBacked && it.armoredPublicKey != null
                    }
                    cardMatch = cardEntities.firstOrNull { entity ->
                        val ring = repo.loadPublicKeyRing(entity.fingerprint)
                        ring != null && ringContainsAnyKeyId(ring, recipientIds)
                    }
                    if (cardMatch == null) {
                        softwareMatchFp = _decryptState.value.availableKeys
                            .filter { !it.isCardBacked }
                            .firstOrNull { entity ->
                                val ring = repo.loadPublicKeyRing(entity.fingerprint)
                                ring != null && ringContainsAnyKeyId(ring, recipientIds)
                            }?.fingerprint
                    }
                }
            } catch (e: Exception) {
                cardMatch = null
                softwareMatchFp = null
                isPassword = false
            }
            // Only publish if the input still matches what we inspected.
            if (_decryptState.value.inputText == text) {
                val match = cardMatch
                _decryptState.value = _decryptState.value.copy(
                    isCardMessage = match != null,
                    cardMessageKeyFingerprint = match?.fingerprint,
                    cardMessageKeyName = match?.let { it.userName.ifBlank { it.userEmail } },
                    // Phase A1: a password-encrypted message has no recipient,
                    // so this is independent of card/software matching.
                    isPasswordMessage = isPassword,
                    // Snap the picker selection: a card recipient → its
                    // fingerprint; else a software recipient when found; else
                    // leave the existing (most-used default) selection.
                    selectedKeyFingerprint = match?.fingerprint
                        ?: softwareMatchFp
                        ?: _decryptState.value.selectedKeyFingerprint
                )
            }
        }
    }

    private fun ringContainsAnyKeyId(
        ring: org.bouncycastle.openpgp.PGPPublicKeyRing,
        keyIds: List<Long>
    ): Boolean {
        val it = ring.publicKeys
        while (it.hasNext()) {
            if (keyIds.contains(it.next().keyID)) return true
        }
        return false
    }

    /**
     * HW Phase 3 — result hooks for the Decrypt tab's card path. The screen
     * runs the NFC operation (CardDecryptService.decrypt) and reports back
     * here. Card decryption returns plaintext only; inline signature
     * verification isn't performed, so the verification banner stays hidden.
     */
    fun onCardDecryptStarted() {
        _decryptState.value = _decryptState.value.copy(isProcessing = true, errorMessage = null)
    }

    fun onCardDecryptSuccess(result: com.pgpony.android.crypto.card.CardDecryptResult) {
        val plaintext = result.data.toString(Charsets.UTF_8)
        // Show the recovered text immediately; verification (a suspend
        // keyring lookup for the signer's identity) resolves a beat later
        // and fills in the banner.
        _decryptState.value = _decryptState.value.copy(
            isProcessing = false,
            outputText = plaintext,
            outputData = result.data,
            verificationResult = null,
            signatureVerified = result.signatureVerified,
            signerKeyID = result.signerKeyID,
            errorMessage = null
        )
        _events.tryEmit(Event.DecryptSuccess)
        recordDecryptUsage(
            _decryptState.value.cardMessageKeyFingerprint
                ?: _decryptState.value.selectedKeyFingerprint
        )
        viewModelScope.launch {
            val verResult = buildVerificationResultForCard(result, plaintext)
            _decryptState.value = _decryptState.value.copy(verificationResult = verResult)
        }
    }

    /**
     * Build a VerificationResult from a card-decrypt result, mirroring the
     * software path's buildVerificationResultForEncrypted: Unsigned when no
     * signature, Verified (with signer identity from the keyring) when it
     * checks out, UnknownSigner when the signer isn't in the keyring, and
     * Invalid when a known signer's signature fails to verify.
     */
    private suspend fun buildVerificationResultForCard(
        result: com.pgpony.android.crypto.card.CardDecryptResult,
        plaintext: String
    ): VerificationResult {
        if (!result.hadSignature) return VerificationResult.Unsigned(plaintext)
        val signerKeyId = result.signerKeyID
        if (signerKeyId == null || !result.signerKnown) {
            return VerificationResult.UnknownSigner(
                signerKeyID = signerKeyId ?: "",
                claimedFingerprint = null,
                signedContent = null
            )
        }
        if (!result.signatureVerified) {
            return VerificationResult.Invalid(
                reason = PGPonyApp.instance.getString(R.string.encdec_error_signer_not_in_keyring),
                signerKeyID = signerKeyId,
                signedContent = null
            )
        }
        val signer = resolveSignerEntity(signerKeyId)
        return VerificationResult.Verified(
            signerKeyID = signerKeyId,
            signerFingerprint = signer?.fingerprint ?: "",
            signerName = signer?.userName?.ifBlank { null },
            signerEmail = signer?.userEmail?.ifBlank { null },
            signedContent = null
        )
    }

    fun onCardDecryptFailure(message: String) {
        _decryptState.value = _decryptState.value.copy(
            isProcessing = false,
            errorMessage = message
        )
    }

    /**
     * Phase AU-1 — record a successful decrypt against [fingerprint] so the
     * "Decrypt With" picker can default to the most-used key. Fire-and-forget
     * on the VM scope: a DB hiccup must never fail a decrypt the user already
     * completed, and a null/blank fingerprint (e.g. clear-signed verify) is a
     * no-op.
     */
    private fun recordDecryptUsage(fingerprint: String?) {
        val fp = fingerprint?.takeIf { it.isNotBlank() } ?: return
        viewModelScope.launch {
            runCatching { repo.incrementDecryptUseCount(fp) }
        }
    }

    fun updatePassphrase(pp: String) {
        _decryptState.value = _decryptState.value.copy(passphrase = pp)
    }

    fun selectDecryptKey(fingerprint: String) {
        val key = _decryptState.value.availableKeys.firstOrNull { it.fingerprint == fingerprint }
        if (key != null && key.isCardBacked) {
            // Card key picked manually: flip to the PIN + tap path by setting
            // the same card-message state that auto-detection would, so the
            // existing card decrypt UI + NFC flow take over. (Decrypt only
            // succeeds if the message is actually encrypted to this card.)
            _decryptState.value = _decryptState.value.copy(
                selectedKeyFingerprint = fingerprint,
                isCardMessage = true,
                cardMessageKeyFingerprint = fingerprint,
                cardMessageKeyName = key.userName.ifBlank { key.userEmail }
            )
        } else {
            // Software key: clear any card-message state and select normally.
            _decryptState.value = _decryptState.value.copy(
                selectedKeyFingerprint = fingerprint,
                isCardMessage = false,
                cardMessageKeyFingerprint = null,
                cardMessageKeyName = null
            )
        }
    }

    /**
     * Phase A3 entry point. Inspects the input text to decide whether to
     * route through verify-only (clear-signed), decrypt+verify (encrypted,
     * optionally signed), or surface an error (detached-sig-alone, garbage
     * input). Keeping a single public action surface lets the UI keep its
     * single "Decrypt" button regardless of input type.
     */
    fun decrypt() {
        val s = _decryptState.value
        if (s.inputText.isBlank()) {
            _decryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_decrypt_input))
            return
        }

        when (verify.detectInputType(s.inputText)) {
            SignedInputType.CLEAR_SIGNED       -> verifyClearSignedPath(s)
            SignedInputType.ENCRYPTED          -> decryptAndVerifyPath(s)
            SignedInputType.DETACHED_SIGNATURE -> {
                _decryptState.value = s.copy(
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_detached_signature)
                )
            }
            SignedInputType.UNKNOWN -> {
                _decryptState.value = s.copy(
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_not_pgp_message)
                )
            }
        }
    }

    /**
     * Phase A3 verify-only path for clear-signed input. No decryption
     * happens — the cleartext is already visible to anyone holding the
     * input. We just verify the signature and surface the result.
     */
    private fun verifyClearSignedPath(s: DecryptUiState) {
        viewModelScope.launch {
            _decryptState.value = s.copy(isProcessing = true, errorMessage = null)
            val publicRings = repo.getAllKeys().mapNotNull {
                repo.loadPublicKeyRing(it.fingerprint)
            }
            val result = verify.verifyClearSigned(s.inputText, publicRings)

            val outputText = when (result) {
                is VerificationResult.Verified      -> result.signedContent.orEmpty()
                is VerificationResult.Invalid       -> result.signedContent.orEmpty()
                is VerificationResult.UnknownSigner -> result.signedContent.orEmpty()
                is VerificationResult.Unsigned      -> result.content
            }
            val pendingFp = (result as? VerificationResult.UnknownSigner)?.claimedFingerprint

            _decryptState.value = _decryptState.value.copy(
                outputText = outputText,
                isProcessing = false,
                verificationResult = result,
                pendingUnknownClaimedFingerprint = pendingFp,
                // For clear-signed there's no signer-keyID-via-decrypt path
                // to surface; the verificationResult holds everything.
                signatureVerified = result is VerificationResult.Verified,
                signerKeyID = when (result) {
                    is VerificationResult.Verified      -> result.signerKeyID
                    is VerificationResult.UnknownSigner -> result.signerKeyID
                    is VerificationResult.Invalid       -> result.signerKeyID
                    else                                 -> null
                },
                errorMessage = null
            )
            _events.tryEmit(Event.DecryptSuccess)
        }
    }

    /**
     * Phase A3 decrypt-and-verify path for encrypted messages. The
     * existing PGPCryptoService.decryptArmored already parses one-pass-
     * signature packets inline; this method wraps its output into a
     * VerificationResult so the banner has uniform rendering across
     * clear-signed and encrypted-signed paths.
     *
     * Note: the existing decryptArmored can't distinguish "signature
     * present but key not in keyring" from "signature present but
     * verification failed" — both end up with signatureVerified=false.
     * Phase A10 will revisit this to give encrypted-signed messages
     * the same UnknownSigner-with-lookup affordance clear-signed gets
     * today.
     */
    private fun decryptAndVerifyPath(s: DecryptUiState) {
        viewModelScope.launch {
            _decryptState.value = _decryptState.value.copy(isProcessing = true, errorMessage = null)
            try {
                // Put selected key first, then include the rest as fallbacks
                val selectedFirst = s.selectedKeyFingerprint
                val orderedKeys = if (selectedFirst != null) {
                    val selected = s.availableKeys.filter { it.fingerprint == selectedFirst }
                    val rest = s.availableKeys.filter { it.fingerprint != selectedFirst }
                    selected + rest
                } else {
                    s.availableKeys
                }
                val secretRings = orderedKeys.mapNotNull {
                    repo.loadSecretKeyRing(it.fingerprint)
                }
                val verifyRings = repo.getAllKeys().mapNotNull {
                    repo.loadPublicKeyRing(it.fingerprint)
                }

                val result = crypto.decryptArmored(
                    armoredMessage = s.inputText,
                    secretKeyRings = secretRings,
                    passphrase = s.passphrase.ifBlank { null },
                    verificationKeys = verifyRings
                )

                val verResult = buildVerificationResultForEncrypted(result)

                _decryptState.value = _decryptState.value.copy(
                    outputText = result.plaintext,
                    outputData = result.data,
                    isProcessing = false,
                    signatureVerified = result.signatureVerified,
                    signerKeyID = result.signerKeyID,
                    decryptedFilename = result.filename,
                    showPassphraseDialog = false,
                    verificationResult = verResult
                )
                _events.tryEmit(Event.DecryptSuccess)
                recordDecryptUsage(s.selectedKeyFingerprint)
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.PassphraseRequired) {
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    showPassphraseDialog = true,
                    errorMessage = null
                )
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.InvalidPassphrase) {
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase)
                )
            } catch (e: Exception) {
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_decryption_failed_format, e.message ?: "")
                )
            }
        }
    }

    /**
     * Map a DecryptResult into the same VerificationResult shape the
     * clear-signed path produces, so VerificationBanner can render both
     * uniformly. The signer's user ID is looked up from the local keyring
     * by 16-hex-char key ID (matches the last 16 chars of a v4 fingerprint).
     */
    /**
     * V6-6: Resolve the local key entity that produced a signature with key
     * ID [signerKeyId]. First tries a direct primary-key match (the fast path
     * for v4 keys that sign with the primary). That misses for v6 keys and any
     * key signing with a dedicated subkey — the signature carries the subkey's
     * key ID, which no primary record equals — so it then walks the cached
     * public key rings with BC's getPublicKey(keyId) (which matches subkeys)
     * and maps the owning ring's primary key ID back to the stored entity.
     * Mirrors VerifyService.resolveSignerIdentity so the decrypt banner names a
     * subkey signer the same way detached verification already does. Returns
     * null when the signer isn't local (caller then shows the key ID alone).
     */
    private suspend fun resolveSignerEntity(signerKeyId: String): PGPKeyEntity? {
        val all = repo.getAllKeys()
        all.firstOrNull { it.longKeyId.equals(signerKeyId, ignoreCase = true) }?.let { return it }
        val keyIdLong = signerKeyId.toULongOrNull(16)?.toLong() ?: return null
        val ownerPrimaryKeyId = verifyRingsCache
            .firstOrNull { ring -> ring.getPublicKey(keyIdLong) != null }
            ?.let { String.format("%016X", it.publicKey.keyID) }
            ?: return null
        return all.firstOrNull { it.longKeyId.equals(ownerPrimaryKeyId, ignoreCase = true) }
    }

    private suspend fun buildVerificationResultForEncrypted(
        result: com.pgpony.android.crypto.DecryptResult
    ): VerificationResult {
        val signerKeyId = result.signerKeyID
        if (signerKeyId == null) {
            return VerificationResult.Unsigned(result.plaintext)
        }
        if (!result.signatureVerified) {
            return VerificationResult.Invalid(
                reason = PGPonyApp.instance.getString(R.string.encdec_error_signer_not_in_keyring),
                signerKeyID = signerKeyId,
                signedContent = null
            )
        }
        // Verified — resolve the signer (primary key, or a signing subkey via
        // its owning ring) to a local entity for name/email/fingerprint.
        val signer = resolveSignerEntity(signerKeyId)
        return VerificationResult.Verified(
            signerKeyID = signerKeyId,
            signerFingerprint = signer?.fingerprint ?: "",
            signerName = signer?.userName?.ifBlank { null },
            signerEmail = signer?.userEmail?.ifBlank { null },
            signedContent = null
        )
    }

    // ── Phase A10c: file-mode decrypt actions ──────────────────────────
    //
    // Parallel to the A10b encrypt-side helpers. UI hands raw bytes
    // read from the SAF content:// URI; PGPCryptoService.decrypt()
    // figures out armored-vs-binary on its own via isArmored().

    /**
     * Phase A10c: switch the Decrypt tab between text and file modes.
     * Clears the opposite mode's transient state so a half-completed
     * text decrypt doesn't bleed into a fresh file decrypt (or vice
     * versa). Output state (outputText / decryptedFileBytes) is
     * cleared too — a fresh mode means a fresh operation.
     */
    fun setDecryptMode(m: DecryptMode) {
        _decryptState.value = _decryptState.value.copy(
            mode = m,
            outputText = "",
            outputData = null,
            errorMessage = null,
            verificationResult = null,
            signatureVerified = false,
            signerKeyID = null,
            // HW Phase 3 — card-message detection is per-input; clear it on
            // mode switch so a stale TEXT detection doesn't leak into FILE
            // (and vice-versa). Re-runs when new input/file is provided.
            isCardMessage = false,
            cardMessageKeyFingerprint = null,
            cardMessageKeyName = null,
            decryptedFilename = null,
            decryptedFileBytes = null,
            showFileDecryptResultSheet = false
        )
    }

    /**
     * Phase A10c: store the picked encrypted file's metadata and
     * bytes in decrypt state. Same shape as setFileToEncrypt() on
     * the encrypt side.
     */
    fun setFileToDecrypt(name: String, size: Long, bytes: ByteArray) {
        _decryptState.value = _decryptState.value.copy(
            selectedFileName = name,
            selectedFileSize = size,
            selectedFileBytes = bytes,
            decryptedFileBytes = null,
            errorMessage = null
        )
        detectCardRecipientFile(bytes)
    }

    /**
     * HW Phase 3 — file-mode counterpart to detectCardRecipient. Reads the
     * picked file's recipient key IDs (binary-aware) and flags a card match
     * so the Decrypt tab shows PIN + tap instead of the passphrase field.
     */
    private fun detectCardRecipientFile(bytes: ByteArray) {
        viewModelScope.launch {
            var isPassword = false
            val match: PGPKeyEntity? = try {
                val info = crypto.inspectEncryptedMessage(bytes)
                isPassword = info.isSymmetricOnly
                val recipientIds = info.publicKeyIDs
                if (recipientIds.isEmpty()) {
                    null
                } else {
                    val cardEntities = repo.getAllKeys().filter {
                        it.isCardBacked && it.armoredPublicKey != null
                    }
                    cardEntities.firstOrNull { entity ->
                        val ring = repo.loadPublicKeyRing(entity.fingerprint)
                        ring != null && ringContainsAnyKeyId(ring, recipientIds)
                    }
                }
            } catch (e: Exception) {
                isPassword = false
                null
            }
            // Only publish if this file is still the selected one.
            if (_decryptState.value.selectedFileBytes === bytes) {
                _decryptState.value = _decryptState.value.copy(
                    isCardMessage = match != null,
                    cardMessageKeyFingerprint = match?.fingerprint,
                    cardMessageKeyName = match?.let { it.userName.ifBlank { it.userEmail } },
                    isPasswordMessage = isPassword
                )
            }
        }
    }

    /**
     * HW Phase 3 — file-mode card decrypt result. The Decrypt screen runs
     * CardDecryptService.decryptBytes over the NFC op and reports the
     * recovered bytes + embedded filename. Mirrors the file-result tail of
     * decryptFileAndVerifyPath (output filename derivation, result sheet).
     */
    fun onCardDecryptFileSuccess(result: com.pgpony.android.crypto.card.CardDecryptResult) {
        val s = _decryptState.value
        val bytes = result.data
        val filename = result.filename
        val literalName = filename?.takeIf { it.isNotBlank() }
        val stripped = s.selectedFileName?.let { stripPgpExtension(it) }
        val outName = literalName
            ?: stripped
            ?: s.selectedFileName?.let { "decrypted_$it" }
            ?: "decrypted_output"
        _decryptState.value = s.copy(
            isProcessing = false,
            decryptedFileBytes = bytes,
            decryptedOutputFilename = outName,
            showFileDecryptResultSheet = true,
            verificationResult = null,
            signatureVerified = result.signatureVerified,
            signerKeyID = result.signerKeyID,
            errorMessage = null
        )
        _events.tryEmit(Event.DecryptSuccess)
        recordDecryptUsage(
            _decryptState.value.cardMessageKeyFingerprint
                ?: _decryptState.value.selectedKeyFingerprint
        )
        viewModelScope.launch {
            val plaintext = try { bytes.toString(Charsets.UTF_8) } catch (_: Exception) { "" }
            val verResult = buildVerificationResultForCard(result, plaintext)
            _decryptState.value = _decryptState.value.copy(verificationResult = verResult)
        }
    }

    /** Phase A10c: clear the picked encrypted file. */
    fun clearDecryptFile() {
        _decryptState.value = _decryptState.value.copy(
            selectedFileName = null,
            selectedFileSize = null,
            selectedFileBytes = null,
            decryptedFileBytes = null,
            errorMessage = null,
            // HW Phase 3 — drop any card-message detection from the cleared file.
            isCardMessage = false,
            cardMessageKeyFingerprint = null,
            cardMessageKeyName = null,
            // Phase A1 — drop password-message detection too.
            isPasswordMessage = false
        )
    }

    /**
     * Phase A10c: decrypt the currently-selected encrypted file.
     * Mirrors decrypt() for text mode but skips the
     * verify.detectInputType() routing — file mode only supports
     * encrypted input (clear-signed-as-file would be a future
     * extension). Routes to decryptFileAndVerifyPath() which
     * mirrors decryptAndVerifyPath() but feeds bytes to
     * crypto.decrypt() instead of armored text to decryptArmored().
     */
    fun decryptFile(passphrase: String? = null) {
        val s = _decryptState.value
        val bytes = s.selectedFileBytes
        if (bytes == null) {
            _decryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_file_to_decrypt))
            return
        }
        if (passphrase != null) {
            _decryptState.value = s.copy(passphrase = passphrase)
        }
        decryptFileAndVerifyPath(_decryptState.value, bytes)
    }

    /**
     * Phase A10c: dismiss the file-decrypt result sheet. Clears the
     * decrypted bytes — once the sheet closes the user has either
     * saved/shared the plaintext or they haven't, and we don't want
     * decrypted material lingering in memory longer than necessary.
     */
    fun dismissFileDecryptResult() {
        _decryptState.value = _decryptState.value.copy(
            showFileDecryptResultSheet = false,
            decryptedFileBytes = null
        )
    }

    /**
     * Phase A10c: file-mode counterpart to decryptAndVerifyPath(). Same
     * structure — order keys, load secret rings, gather verify rings,
     * call crypto.decrypt() (binary-aware), build VerificationResult,
     * push state, fire haptic event. Differs in:
     *   • input is raw bytes (sniffed by isArmored) not armored text
     *   • on success, flips showFileDecryptResultSheet and stores
     *     decryptedFileBytes + decryptedOutputFilename for the
     *     FileDecryptionResultScreen to render
     *   • passphrase prompt dispatches by mode in Screens.kt so the
     *     existing showPassphraseDialog is reused (same as encrypt
     *     A10b Fix1 pattern)
     */
    private fun decryptFileAndVerifyPath(s: DecryptUiState, bytes: ByteArray) {
        viewModelScope.launch {
            _decryptState.value = _decryptState.value.copy(isProcessing = true, errorMessage = null)
            try {
                val selectedFirst = s.selectedKeyFingerprint
                val orderedKeys = if (selectedFirst != null) {
                    val selected = s.availableKeys.filter { it.fingerprint == selectedFirst }
                    val rest = s.availableKeys.filter { it.fingerprint != selectedFirst }
                    selected + rest
                } else {
                    s.availableKeys
                }
                val secretRings = orderedKeys.mapNotNull {
                    repo.loadSecretKeyRing(it.fingerprint)
                }
                val verifyRings = repo.getAllKeys().mapNotNull {
                    repo.loadPublicKeyRing(it.fingerprint)
                }

                val result = crypto.decrypt(
                    encryptedData = bytes,
                    secretKeyRings = secretRings,
                    passphrase = s.passphrase.ifBlank { null },
                    verificationKeys = verifyRings
                )

                val verResult = buildVerificationResultForEncrypted(result)

                // Derive the suggested output filename. Prefer the
                // OpenPGP literal-data filename (carries the original
                // name embedded by the encrypt-time encoder). Fall
                // back to stripping .pgp/.gpg/.asc from the picked
                // encrypted filename; if neither yields a usable
                // name, prefix "decrypted_" — matches iOS behavior.
                val literalName = result.filename?.takeIf { it.isNotBlank() }
                val stripped = s.selectedFileName?.let { stripPgpExtension(it) }
                val outName = literalName
                    ?: stripped
                    ?: s.selectedFileName?.let { "decrypted_$it" }
                    ?: "decrypted_output"

                _decryptState.value = _decryptState.value.copy(
                    outputText = result.plaintext,
                    outputData = result.data,
                    isProcessing = false,
                    signatureVerified = result.signatureVerified,
                    signerKeyID = result.signerKeyID,
                    decryptedFilename = result.filename,
                    showPassphraseDialog = false,
                    verificationResult = verResult,
                    decryptedFileBytes = result.data,
                    decryptedOutputFilename = outName,
                    showFileDecryptResultSheet = true
                )
                _events.tryEmit(Event.DecryptSuccess)
                recordDecryptUsage(s.selectedKeyFingerprint)
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.PassphraseRequired) {
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    showPassphraseDialog = true,
                    errorMessage = null
                )
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.InvalidPassphrase) {
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase)
                )
            } catch (e: Exception) {
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_decryption_failed_format, e.message ?: "")
                )
            }
        }
    }

    /**
     * Phase A10c: helper that strips the OpenPGP-encrypted-file
     * extension off a name and returns the remainder, or null if
     * the name doesn't end in one of the recognized extensions.
     * Mirrors iOS FileDecryptionResultView's originalFileName logic.
     */
    private fun stripPgpExtension(name: String): String? {
        val extensions = listOf(".pgp", ".gpg", ".asc")
        for (ext in extensions) {
            if (name.lowercase().endsWith(ext)) {
                return name.dropLast(ext.length)
            }
        }
        return null
    }

    // ── Phase A3: Signer lookup actions ───────────────────────────────

    /**
     * Open the SignerLookupSheet and kick off a Hagrid keyserver query
     * for the supplied fingerprint. Phase A8 will add WKD discovery in
     * front of this (try WKD by email if we can extract one, fall back
     * to Hagrid by fingerprint). For A3 the only source is Hagrid.
     */
    fun lookupSigner() {
        val claimedFp = _decryptState.value.pendingUnknownClaimedFingerprint
            ?: return  // No fingerprint to look up — banner shouldn't be tappable
        _decryptState.value = _decryptState.value.copy(
            showSignerLookup = true,
            signerLookupState = SignerLookupState.Searching
        )
        viewModelScope.launch {
            val armored = try {
                keyServer.searchByFingerprint(claimedFp)
            } catch (e: Exception) {
                _decryptState.value = _decryptState.value.copy(
                    signerLookupState = SignerLookupState.Failed(
                        e.message ?: PGPonyApp.instance.getString(R.string.encdec_error_keyserver_network)
                    )
                )
                return@launch
            }
            if (armored.isNullOrBlank()) {
                _decryptState.value = _decryptState.value.copy(
                    signerLookupState = SignerLookupState.NotFound(claimedFp)
                )
                return@launch
            }
            // Parse for preview without saving — we want the user to confirm
            // before adding anything to the keyring.
            val preview = try {
                crypto.importKeyData(armored.toByteArray(Charsets.UTF_8))
            } catch (e: Exception) {
                _decryptState.value = _decryptState.value.copy(
                    signerLookupState = SignerLookupState.Failed(
                        PGPonyApp.instance.getString(R.string.encdec_error_keyserver_parse_format, e.message ?: "")
                    )
                )
                return@launch
            }
            _decryptState.value = _decryptState.value.copy(
                signerLookupState = SignerLookupState.Found(
                    armoredKey = armored,
                    previewUserId = preview.userID,
                    previewFingerprint = preview.fingerprint,
                    previewAlgorithm = preview.algorithm.displayName
                )
            )
        }
    }

    /**
     * Import the key fetched by lookupSigner, then re-verify the
     * currently-pasted clear-signed input. The banner should flip to
     * green Verified once the freshly-imported key is in the rings.
     */
    fun importDiscoveredSigner(armoredKey: String) {
        viewModelScope.launch {
            try {
                val imported = repo.importArmoredKey(armoredKey)
                _decryptState.value = _decryptState.value.copy(
                    signerLookupState = SignerLookupState.ImportSuccess(
                        previewUserId = imported.userID
                    )
                )
                // Refresh keys + re-verify with the larger keyring. The
                // sheet stays on ImportSuccess until the user explicitly
                // closes it so they see confirmation; the banner update
                // happens regardless.
                refreshKeys()
                val cur = _decryptState.value
                if (cur.inputText.isNotBlank()) {
                    // Re-run decrypt(), which will re-route based on input type
                    decrypt()
                }
            } catch (e: Exception) {
                _decryptState.value = _decryptState.value.copy(
                    signerLookupState = SignerLookupState.Failed(
                        "Could not import key: ${e.message}"
                    )
                )
            }
        }
    }

    fun dismissSignerLookup() {
        _decryptState.value = _decryptState.value.copy(
            showSignerLookup = false,
            signerLookupState = SignerLookupState.Searching
        )
    }

    // ── Phase A3: "Verify a file" (detached signature) ─────────────────

    fun openVerifyFileSheet() {
        _decryptState.value = _decryptState.value.copy(
            showVerifyFileSheet = true,
            verifyFileSignedName = null,
            verifyFileSignedBytes = null,
            verifyFileSigName = null,
            verifyFileSigBytes = null,
            verifyFileResult = null,
            verifyFileProcessing = false,
            errorMessage = null,
        )
    }

    fun dismissVerifyFileSheet() {
        _decryptState.value = _decryptState.value.copy(
            showVerifyFileSheet = false,
            verifyFileSignedName = null,
            verifyFileSignedBytes = null,
            verifyFileSigName = null,
            verifyFileSigBytes = null,
            verifyFileResult = null,
            verifyFileProcessing = false,
        )
    }

    /** The original (signed) file the user picked. */
    fun setVerifyFileSigned(name: String, bytes: ByteArray) {
        _decryptState.value = _decryptState.value.copy(
            verifyFileSignedName = name,
            verifyFileSignedBytes = bytes,
            verifyFileResult = null,
            errorMessage = null,
        )
    }

    /** The detached signature file (.sig / .asc) the user picked. */
    fun setVerifyFileSignature(name: String, bytes: ByteArray) {
        _decryptState.value = _decryptState.value.copy(
            verifyFileSigName = name,
            verifyFileSigBytes = bytes,
            verifyFileResult = null,
            errorMessage = null,
        )
    }

    /**
     * Verify the picked detached signature against the picked original file.
     * Uses the binary-aware `verifyDetached(ByteArray, …)` overload (A3) so a
     * downloaded `.sig` (binary) or `.asc` (armored) both work. On
     * UnknownSigner, the claimed fingerprint is stashed so the banner's
     * keyserver/WKD lookup (shared with the decrypt flow) can run.
     */
    fun runVerifyFile() {
        val s = _decryptState.value
        val signed = s.verifyFileSignedBytes
        val sig = s.verifyFileSigBytes
        if (signed == null || sig == null) {
            _decryptState.value = s.copy(
                errorMessage = PGPonyApp.instance.getString(R.string.verify_file_error_pick_both)
            )
            return
        }
        _decryptState.value = s.copy(verifyFileProcessing = true, errorMessage = null)
        viewModelScope.launch {
            val rings = withContext(Dispatchers.IO) {
                repo.getAllKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
            }
            val result = withContext(Dispatchers.Default) {
                verify.verifyDetached(sig, signed, rings)
            }
            val claimedFp = (result as? VerificationResult.UnknownSigner)?.claimedFingerprint
            _decryptState.value = _decryptState.value.copy(
                verifyFileProcessing = false,
                verifyFileResult = result,
                pendingUnknownClaimedFingerprint = claimedFp
                    ?: _decryptState.value.pendingUnknownClaimedFingerprint,
            )
        }
    }

    // ── Phase A5: "Sign a file" (detached signature, software key) ─────

    fun openSignFileSheet() {
        val softwareKeys = _encryptState.value.availableSigningKeys.filter {
            it.isKeyPair && !it.isCardBacked
        }
        _encryptState.value = _encryptState.value.copy(
            showSignFileSheet = true,
            signFileName = null,
            signFileBytes = null,
            // Default to the already-selected signing key if it's software,
            // else the first software key pair.
            signFileSelectedKey = _encryptState.value.signingKey
                ?.takeIf { it.isKeyPair && !it.isCardBacked }
                ?: softwareKeys.firstOrNull(),
            showSignFileKeyPicker = false,
            signFilePassphrase = "",
            signFileArmor = true,
            signFileResultBytes = null,
            signFileResultName = null,
            signFileProcessing = false,
            errorMessage = null,
        )
    }

    fun dismissSignFileSheet() {
        _encryptState.value = _encryptState.value.copy(
            showSignFileSheet = false,
            signFileName = null,
            signFileBytes = null,
            showSignFileKeyPicker = false,
            signFilePassphrase = "",
            signFileResultBytes = null,
            signFileResultName = null,
            signFileProcessing = false,
        )
    }

    /** Software signing key pairs eligible for file signing (no card). */
    fun signableFileKeys(): List<PGPKeyEntity> =
        _encryptState.value.availableSigningKeys.filter {
            it.isKeyPair && !it.isCardBacked
        }

    fun setSignFile(name: String, bytes: ByteArray) {
        _encryptState.value = _encryptState.value.copy(
            signFileName = name,
            signFileBytes = bytes,
            signFileResultBytes = null,
            signFileResultName = null,
            errorMessage = null,
        )
    }

    fun showSignFileKeyPicker() {
        _encryptState.value = _encryptState.value.copy(showSignFileKeyPicker = true)
    }

    fun dismissSignFileKeyPicker() {
        _encryptState.value = _encryptState.value.copy(showSignFileKeyPicker = false)
    }

    fun setSignFileKey(key: PGPKeyEntity) {
        _encryptState.value = _encryptState.value.copy(
            signFileSelectedKey = key,
            showSignFileKeyPicker = false,
            signFileResultBytes = null,
            errorMessage = null,
        )
    }

    fun setSignFilePassphrase(text: String) {
        _encryptState.value = _encryptState.value.copy(signFilePassphrase = text)
    }

    fun setSignFileArmor(armor: Boolean) {
        _encryptState.value = _encryptState.value.copy(
            signFileArmor = armor,
            // Result is form-specific; invalidate so the user re-signs.
            signFileResultBytes = null,
            signFileResultName = null,
        )
    }

    /**
     * Phase A5 — produce a detached signature over the picked file with the
     * selected software key. `.asc` (armored) or `.sig` (binary) per
     * [EncryptUiState.signFileArmor]; output named `original.ext.asc/.sig` so
     * `gpg --verify` finds it. The original file is never modified.
     */
    fun runSignFile() {
        val s = _encryptState.value
        val bytes = s.signFileBytes
        val key = s.signFileSelectedKey
        if (bytes == null) {
            _encryptState.value = s.copy(
                errorMessage = PGPonyApp.instance.getString(R.string.sign_file_error_pick_file)
            )
            return
        }
        if (key == null) {
            _encryptState.value = s.copy(
                errorMessage = PGPonyApp.instance.getString(R.string.sign_file_error_pick_key)
            )
            return
        }
        _encryptState.value = s.copy(signFileProcessing = true, errorMessage = null)
        viewModelScope.launch {
            try {
                val secRing = withContext(Dispatchers.IO) {
                    repo.loadSecretKeyRing(key.fingerprint)
                } ?: throw SigningError.NoSigningKey()
                val sig = withContext(Dispatchers.Default) {
                    signing.signDetached(
                        data = bytes,
                        secretKeyRing = secRing,
                        passphrase = s.signFilePassphrase.ifEmpty { null },
                        armor = s.signFileArmor,
                    )
                }
                val ext = if (s.signFileArmor) ".asc" else ".sig"
                val outName = (s.signFileName ?: "file") + ext
                _encryptState.value = _encryptState.value.copy(
                    signFileProcessing = false,
                    signFileResultBytes = sig,
                    signFileResultName = outName,
                    signFilePassphrase = "",
                    errorMessage = null,
                )
            } catch (e: SigningError.PassphraseRequired) {
                _encryptState.value = _encryptState.value.copy(
                    signFileProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.sign_file_error_passphrase_required),
                )
            } catch (e: SigningError.InvalidPassphrase) {
                _encryptState.value = _encryptState.value.copy(
                    signFileProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase),
                )
            } catch (e: Exception) {
                _encryptState.value = _encryptState.value.copy(
                    signFileProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(
                        R.string.sign_file_error_failed_format, e.message ?: e.javaClass.simpleName
                    ),
                )
            }
        }
    }

    fun dismissPassphraseDialog() {
        _decryptState.value = _decryptState.value.copy(showPassphraseDialog = false)
    }

    fun clearEncryptError() {
        _encryptState.value = _encryptState.value.copy(errorMessage = null)
    }

    fun clearDecryptError() {
        _decryptState.value = _decryptState.value.copy(errorMessage = null)
    }

    /**
     * Reset the Encrypt tab to its fresh-app-start state: a brand-new
     * EncryptUiState (clears input, output, file, recipients selection,
     * toggles, mode — everything) then reload the key lists, exactly as
     * happens on launch. Resetting the whole object avoids missing any
     * field that holds displayed content.
     */
    fun clearEncrypt() {
        _encryptState.value = EncryptUiState()
        loadKeys()
    }

    /**
     * Reset the Decrypt tab to its fresh-app-start state: a brand-new
     * DecryptUiState (clears input, output, passphrase, file, verification
     * banner, card-message detection, mode) then reload the key lists.
     */
    fun clearDecrypt() {
        _decryptState.value = DecryptUiState()
        loadKeys()
    }

    fun refreshKeys() = loadKeys()
}
