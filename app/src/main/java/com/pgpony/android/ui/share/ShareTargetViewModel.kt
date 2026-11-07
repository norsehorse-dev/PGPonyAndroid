// ShareTargetViewModel.kt
// PGPony Android — Phase A15
//
// State machine for the standalone ShareTargetActivity. Owns the
// "what is the user doing right now in this share-target instance"
// state — separate from the main app's EncryptDecryptViewModel so
// invoking Quick Action from another app can't leak state into the
// main encrypt tab (and vice-versa).
//
// Why a dedicated VM instead of reusing EncryptDecryptViewModel:
//
//   • EncryptDecryptViewModel is wide — it carries File-mode state,
//     sign-only state, signer-lookup state, verification banner state,
//     and more. ShareTargetActivity needs ~30% of that, and pulling
//     in the rest means every recomposition in the activity also
//     subscribes to state changes it doesn't care about.
//   • The activity has its own lifecycle. If the user runs Quick
//     Action while a normal encrypt is mid-flight in the main app,
//     blowing away that VM's state would be a surprise. A separate
//     ViewModelStore (tied to ShareTargetActivity) means both
//     coexist cleanly.
//   • Cleaner mental model: ShareTargetViewModel = one input, one
//     output, optional passphrase, optional recipient set. No tabs,
//     no modes beyond Encrypt/Decrypt, no result sheets.
//
// Reuses everything from the data layer: KeyRepository for fetching
// keys, PGPCryptoService for encrypt/decrypt. No new crypto code.
//
// Architecture:
//
//   Phase                       state.phase
//   ────────────────────────────────────────────────────────────────────
//   Picking action              ShareTargetPhase.PickAction
//   Encrypt: pick recipients    ShareTargetPhase.PickRecipients
//   Encrypt: processing         ShareTargetPhase.Processing
//   Encrypt: result             ShareTargetPhase.EncryptResult
//   Decrypt: pick key           ShareTargetPhase.PickDecryptKey
//   Decrypt: passphrase prompt  ShareTargetPhase.NeedPassphrase
//   Decrypt: processing         ShareTargetPhase.Processing
//   Decrypt: result             ShareTargetPhase.DecryptResult
//   Sign: key, format, pass     ShareTargetPhase.PickSigner     (4.8.0, #72)
//   Sign: result                ShareTargetPhase.SignResult     (4.8.0, #72)
//   Error                       ShareTargetPhase.Error
//
// All transitions are unidirectional from the user's POV (back button
// dismisses the activity; you can't half-decrypt and back into the
// picker). This is intentional — it mirrors the iOS Action Extension
// UX, which also doesn't let you back-navigate within the extension.

package com.pgpony.android.ui.share

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SignerStatus
import com.pgpony.android.crypto.SigningError
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.pqc.CompositeSignerGate
import com.pgpony.android.data.KeyDeduplicationService
import com.pgpony.android.ui.util.ScratchFiles
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.i18n.ErrorText
import com.pgpony.android.intent.ShareIntentContent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ── Phase enum ─────────────────────────────────────────────────────────

enum class ShareTargetPhase {
    PickAction,
    PickRecipients,
    PickDecryptKey,
    NeedPassphrase,
    CardPin,
    Processing,
    EncryptResult,
    // Phase A2: binary file-encrypt result — encrypted bytes written to a
    // cache file and offered via the system share sheet (FileProvider),
    // distinct from the text EncryptResult.
    EncryptFileResult,
    DecryptResult,
    // Phase A2 (decrypt side): binary file-decrypt result — recovered bytes
    // written to a cache file and offered via the share sheet, instead of
    // dumping raw bytes as text.
    DecryptFileResult,
    // 4.8.0 (#72): a detached signature over a shared file. PickSigner holds
    // the Sign as key, the format (.asc or .sig) and the passphrase;
    // SignResult offers the signature to save or share.
    PickSigner,
    SignResult,
    Error,
}

// ── State data class ───────────────────────────────────────────────────

data class ShareTargetUiState(
    // Phase
    val phase: ShareTargetPhase = ShareTargetPhase.PickAction,

    // Input (what the user shared)
    val content: ShareIntentContent = ShareIntentContent.Empty,

    // Key data — loaded once on first appearance, refreshed only on
    // explicit user action (no live observation in the share-target
    // flow; the user wants to do one thing and dismiss).
    val availableRecipients: List<PGPKeyEntity> = emptyList(),
    val availableKeyPairs: List<PGPKeyEntity> = emptyList(),

    // Encrypt phase state
    val selectedRecipients: Set<String> = emptySet(),  // fingerprints

    // Decrypt phase state
    val selectedDecryptKey: PGPKeyEntity? = null,  // null = auto-select
    val passphrase: String = "",

    // HW Phase 3 — set when the shared message is encrypted to a card key.
    // Drives the CardPin phase (PIN + tap) instead of the passphrase prompt.
    val cardDecryptKeyFingerprint: String? = null,
    val cardDecryptKeyName: String? = null,
    val cardPin: String = "",

    // Output / result
    val outputText: String = "",
    // Phase A2: binary file-encrypt output (EncryptFileResult phase). Held in
    // memory until the user shares it; never stringified.
    val encryptedFileBytes: ByteArray? = null,
    // 4.0.4 — the streaming counterpart. Set instead of
    // encryptedFileBytes when the shared file was too large to buffer;
    // the ciphertext lives under cacheDir/scratch and is shared from
    // there in place. Exactly one of the two is ever set.
    val encryptedFile: java.io.File? = null,
    val encryptedFileName: String? = null,
    // Phase A2 (decrypt side): recovered binary file (DecryptFileResult phase).
    val decryptedFileBytes: ByteArray? = null,
    /** 4.0.4 — streaming counterpart to decryptedFileBytes. */
    val decryptedFile: java.io.File? = null,
    // 3.1.0 Phase 6 (J6) — set when the decrypted content was PGP/MIME
    // WITH attachments: the Quick Action shows the body plus this note;
    // the full attachment view lives in the main app (iOS
    // ExtensionDecryptView parity).
    val mimeAttachmentNote: String? = null,
    val decryptedFileName: String? = null,
    val signerName: String? = null,           // populated by decrypt signature info
    val signerKeyId: String? = null,
    /** 4.7.0 (item 48, #79): the key that made the signature, and its primary. */
    val signerKeyLine: com.pgpony.android.crypto.KeyIdText.Line? = null,
    /** 4.7.0 (item 48, #79): the key pair and the (sub)key that decrypted. */
    val decryptedBy: ShareTargetViewModel.DecryptedBy? = null,
    val signatureVerified: Boolean = false,
    /** 4.6.0 (item 15): signed, by a key that is not in the keyring. */
    val signatureFromUnknownKey: Boolean = false,

    // 4.8.0 (#72): signing a shared file, on its own or while encrypting it.
    /** Software key pairs that can sign here (ShareFileActions.signers). */
    val availableSigners: List<PGPKeyEntity> = emptyList(),
    /** The pinned default signer (pgpony_prefs), empty when none. */
    val defaultSignerFingerprint: String = "",
    /** The Sign as key. On Encrypt, null (the default) encrypts unsigned. */
    val signingKey: PGPKeyEntity? = null,
    /** .asc (armored, the Sign a file sheet's default) or .sig (binary). */
    val signArmor: Boolean = true,
    /** The signing passphrase, good for one attempt: cleared at Processing. */
    val signPassphrase: String = "",
    /** 4.6.0 (item 14), as on the Encrypt screen: a composite (ML-DSA)
     *  signature would go to a v4 recipient. Ask before signing. */
    val showPqcV4SignPrompt: Boolean = false,
    /** The detached signature (SignResult); a few hundred bytes. */
    val signatureBytes: ByteArray? = null,
    val signatureFileName: String? = null,

    // Status
    val errorMessage: String? = null,
)

// ── ViewModel ──────────────────────────────────────────────────────────

class ShareTargetViewModel(
    private val repository: KeyRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(ShareTargetUiState())
    val state: StateFlow<ShareTargetUiState> = _state.asStateFlow()

    // ── Initialization ─────────────────────────────────────────────────

    /**
     * Called once by ShareTargetActivity after classifying the intent.
     * Seeds the VM with the input content and loads key sets from Room
     * so the picker screens render without blocking.
     */
    fun initialize(content: ShareIntentContent) {
        _state.update { it.copy(content = content) }
        viewModelScope.launch {
            val keys = repository.getAllKeys()
            val keyPairs = repository.getKeyPairs()
            val cardMatch = detectCardRecipient(content, keys)
            // Phase A4 — apply the default/remembered recipient here too, so the
            // share flow benefits. Match the saved fingerprint against the live
            // recipient pool; pre-select nothing if it's gone.
            val prefs = PGPonyApp.instance.getSharedPreferences(
                "pgpony_prefs", android.content.Context.MODE_PRIVATE
            )
            val preselect = com.pgpony.android.ui.settings.DefaultRecipientPrefs
                .preselectFingerprint(prefs)
                ?.takeIf { fp -> keys.any { it.fingerprint == fp } }
            // 4.8.0 (#72): the same default signer the Encrypt screen uses.
            val defaultSignerFpr = prefs.getString("pgpony_default_signer_fpr", "") ?: ""
            _state.update {
                it.copy(
                    availableRecipients = keys,
                    availableKeyPairs = keyPairs,
                    availableSigners = ShareFileActions.signers(keyPairs),
                    defaultSignerFingerprint = defaultSignerFpr,
                    cardDecryptKeyFingerprint = cardMatch?.fingerprint,
                    cardDecryptKeyName = cardMatch?.userID,
                    selectedRecipients = if (it.selectedRecipients.isEmpty() && preselect != null)
                        setOf(preselect) else it.selectedRecipients,
                )
            }
        }
    }

    /**
     * HW Phase 3 — detect whether the shared message is encrypted to a
     * card-backed key (a recipient key ID matches a card key's encryption
     * subkey). Cheap: reads recipient key IDs without decrypting.
     */
    private suspend fun detectCardRecipient(
        content: ShareIntentContent,
        keys: List<PGPKeyEntity>
    // 4.0.4 — off the main thread. `suspend` alone does not move work: this
    // is called from initialize()'s viewModelScope.launch, which runs on
    // Dispatchers.Main.immediate, so it inherited the main thread. It parses
    // the shared message for recipient key IDs and then loads a public ring
    // per card-backed key — and it runs on EVERY share-in, before the user
    // has touched anything.
    ): PGPKeyEntity? = withContext(Dispatchers.Default) {
        val bytes = encryptedBytesForCardDecrypt(content) ?: return@withContext null
        try {
            val ids = PGPCryptoService.shared.recipientKeyIDs(bytes)
            if (ids.isEmpty()) {
                null
            } else {
                keys.filter { it.isCardBacked && it.armoredPublicKey != null }
                    .firstOrNull { entity ->
                        val ring = repository.loadPublicKeyRing(entity.fingerprint)
                        ring != null && ringContainsAnyKeyId(ring, ids)
                    }
            }
        } catch (e: Exception) {
            null
        }
    }

    /** Raw bytes of the shared encrypted content (binary or armored), or
     *  null if there's nothing decryptable. Used for card detection and for
     *  the card decrypt op. */
    fun encryptedBytesForCardDecrypt(content: ShareIntentContent = _state.value.content): ByteArray? =
        when (content) {
            is ShareIntentContent.Text ->
                if (content.looksLikePgpMessage) content.text.toByteArray(Charsets.UTF_8) else null
            is ShareIntentContent.PgpFile -> content.data
            ShareIntentContent.Empty -> null
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

    // ── Action picker ──────────────────────────────────────────────────

    fun beginEncrypt() {
        _state.update {
            it.copy(
                phase = ShareTargetPhase.PickRecipients,
                errorMessage = null,
                // 4.8.0 (#72): Encrypt starts unsigned, as before; Sign as
                // on the recipient screen adds a signature.
                signingKey = null,
                signPassphrase = "",
                showPqcV4SignPrompt = false,
            )
        }
        pendingSignPassphrase = null
        pqcV4SignAnswer = null
    }

    /** 4.8.0 (#72): Sign the shared file, starting with the default signer. */
    fun beginSign() {
        _state.update {
            it.copy(
                phase = ShareTargetPhase.PickSigner,
                errorMessage = null,
                signingKey = ShareFileActions.defaultSigner(it.availableSigners, it.defaultSignerFingerprint),
                signPassphrase = "",
            )
        }
    }

    // ── 4.8.0 (#72): Sign as, format, signing passphrase ───────────────

    /** The Sign as key; null signs nothing (Encrypt only). */
    fun selectSigner(key: PGPKeyEntity?) {
        pqcV4SignAnswer = null
        _state.update { it.copy(signingKey = key, signPassphrase = "", errorMessage = null) }
    }

    fun setSignArmor(armor: Boolean) {
        _state.update { it.copy(signArmor = armor) }
    }

    fun updateSignPassphrase(s: String) {
        _state.update { it.copy(signPassphrase = s) }
    }

    /** The 4.6.0 (item 14) prompt was dismissed: nothing is encrypted. */
    fun dismissPqcV4SignPrompt() {
        pendingSignPassphrase = null
        pqcV4SignAnswer = null
        _state.update { it.copy(showPqcV4SignPrompt = false) }
    }

    /** The prompt's answer: sign anyway, or encrypt without the signature. */
    fun answerPqcV4SignPrompt(signAnyway: Boolean) {
        _state.update { it.copy(showPqcV4SignPrompt = false) }
        pqcV4SignAnswer = signAnyway
        performEncrypt(pqcDecision = signAnyway)
    }

    /**
     * The prompt's answer, kept until the signer, the recipients or the
     * action change, so a run that stops for the passphrase does not ask
     * the same question again when Encrypt is tapped once more.
     */
    private var pqcV4SignAnswer: Boolean? = null

    fun beginDecrypt() {
        // HW Phase 3 — if the message is encrypted to a card key, the
        // private key lives on the card: skip the software key-pair /
        // passphrase path entirely and go to PIN + tap.
        if (_state.value.cardDecryptKeyFingerprint != null) {
            _state.update {
                it.copy(phase = ShareTargetPhase.CardPin, cardPin = "", errorMessage = null)
            }
            return
        }
        // If exactly one key pair available, skip the picker and go
        // straight to the passphrase prompt. The auto-selected key
        // becomes selectedDecryptKey. If multiple key pairs are
        // available, the picker phase lets the user choose.
        val pairs = _state.value.availableKeyPairs
        _state.update { current ->
            when {
                pairs.isEmpty() -> current.copy(
                    phase = ShareTargetPhase.Error,
                    errorMessage = PGPonyApp.instance.getString(
                        R.string.share_target_decrypt_no_key_pairs
                    ),
                )
                pairs.size == 1 -> current.copy(
                    phase = ShareTargetPhase.NeedPassphrase,
                    selectedDecryptKey = pairs[0],
                    errorMessage = null,
                )
                else -> current.copy(
                    phase = ShareTargetPhase.PickDecryptKey,
                    errorMessage = null,
                )
            }
        }
    }

    // ── Recipient picker ───────────────────────────────────────────────

    fun toggleRecipient(fingerprint: String) {
        _state.update { current ->
            val next = current.selectedRecipients.toMutableSet()
            if (fingerprint in next) next.remove(fingerprint) else next.add(fingerprint)
            current.copy(selectedRecipients = next)
        }
        pqcV4SignAnswer = null
    }

    // ── Decrypt key picker ─────────────────────────────────────────────

    fun selectDecryptKey(key: PGPKeyEntity) {
        _state.update {
            it.copy(
                selectedDecryptKey = key,
                phase = ShareTargetPhase.NeedPassphrase,
            )
        }
    }

    // ── Passphrase ─────────────────────────────────────────────────────

    fun updatePassphrase(s: String) {
        _state.update { it.copy(passphrase = s) }
    }

    // ── HW Phase 3 — card decrypt (PIN + tap) ──────────────────────────
    //
    // The share screen runs the NFC op (CardDecryptService.decryptBytes)
    // via ShareTargetActivity and reports back here. Card decryption
    // returns plaintext only — no inline signature verification.

    fun updateCardPin(s: String) {
        _state.update { it.copy(cardPin = s) }
    }

    fun onCardDecryptStarted() {
        _state.update { it.copy(phase = ShareTargetPhase.Processing, errorMessage = null) }
    }

    fun onCardDecryptSuccess(plaintext: String) {
        _state.update {
            it.copy(
                phase = ShareTargetPhase.DecryptResult,
                outputText = plaintext,
                signatureVerified = false,
                signerKeyId = null,
                signerName = null,
                signerKeyLine = null,
                decryptedBy = null,
                errorMessage = null,
                signatureFromUnknownKey = false,
            )
        }
    }

    fun onCardDecryptFailure(message: String) {
        _state.update {
            it.copy(phase = ShareTargetPhase.Error, errorMessage = message)
        }
    }

    // ── Encrypt action ─────────────────────────────────────────────────

    /**
     * 4.6.1 (#67): every selected recipient, loaded the way the Encrypt
     * screen loads them (composite ML-DSA keys through their ML-KEM subkey,
     * v4 algo-35 keys on their own channel). See ShareRecipients.
     */
    private suspend fun loadShareRecipients(
        current: ShareTargetUiState
    ): ShareRecipients.Loaded<org.bouncycastle.openpgp.PGPPublicKeyRing, com.pgpony.android.crypto.pqc.V4Algo35Recipient> =
        withContext(Dispatchers.IO) {
            val byFp = current.availableRecipients.associateBy { it.fingerprint.uppercase() }
            ShareRecipients.load(
                fingerprints = current.selectedRecipients,
                isV4Algo35 = { fp ->
                    byFp[fp.uppercase()]?.algorithm == com.pgpony.android.crypto.KeyAlgorithm.MLKEM768_X25519_V4
                },
                ring = { fp -> repository.loadEncryptionRecipientRing(fp) },
                v4Algo35 = { fp -> repository.loadV4Algo35Recipient(fp) }
            )
        }

    /**
     * 4.6.1 (#67): why encrypting to [recipients] must not go ahead, or null.
     * A selected recipient that gave no key stops the whole operation, so a
     * file is never encrypted with someone quietly left out.
     */
    private fun recipientError(
        current: ShareTargetUiState,
        recipients: ShareRecipients.Loaded<*, *>
    ): String? {
        if (!recipients.isComplete) {
            val byFp = current.availableRecipients.associateBy { it.fingerprint.uppercase() }
            val names = recipients.unusable.joinToString(", ") { fp ->
                byFp[fp.uppercase()]?.let { e -> e.userID.ifBlank { e.shortFingerprint } } ?: fp
            }
            return PGPonyApp.instance.getString(R.string.share_target_encrypt_recipient_unusable_format, names)
        }
        if (recipients.isEmpty) {
            return PGPonyApp.instance.getString(R.string.share_target_encrypt_recipients_empty)
        }
        return null
    }

    /**
     * 4.0.4 — encrypt a shared file straight from its URI into a scratch
     * file. Binary output (armor = false), matching the buffered file
     * path: the Quick Action's file result is a .gpg the user shares on,
     * and armoring a large file inflates it by a third for nothing.
     */
    private fun performEncryptStreaming(uri: android.net.Uri, sourceFilename: String?, pqcDecision: Boolean?) {
        val current = _state.value
        if (current.selectedRecipients.isEmpty()) {
            _state.update {
                it.copy(
                    phase = ShareTargetPhase.Error,
                    errorMessage = PGPonyApp.instance.getString(
                        R.string.share_target_encrypt_recipients_empty
                    ),
                )
            }
            return
        }
        signerBlock(current.signingKey)?.let { msg ->
            _state.update { it.copy(errorMessage = msg) }
            return
        }
        // 4.8.0 (item 4d, #72): a typed signing passphrase is good for this one attempt (`current` holds it).
        _state.update { it.copy(phase = ShareTargetPhase.Processing, errorMessage = null, signPassphrase = "") }
        viewModelScope.launch {
            try {
                val recipients = loadShareRecipients(current)
                recipientError(current, recipients)?.let { msg ->
                    _state.update { it.copy(phase = ShareTargetPhase.Error, errorMessage = msg) }
                    return@launch
                }
                // 4.8.0 (#72): Sign as. Paused means the 4.6.0 (item 14) prompt is up.
                val signing = prepareEncryptSigning(current, recipients, pqcDecision)
                if (signing is EncryptSigning.Paused) return@launch
                val signer = signing as? EncryptSigning.Signer
                // 3.1.0 Phase 1 (C2) — .gpg for binary output.
                val outName = "${sourceFilename ?: "shared_file"}.gpg"
                val out = withContext(Dispatchers.IO) {
                    val dest = ScratchFiles.allocate(PGPonyApp.instance, outName, ScratchFiles.SCOPE_QUICK)
                    val input = PGPonyApp.instance.contentResolver.openInputStream(uri)
                        ?: throw java.io.IOException(PGPonyApp.instance.getString(R.string.share_target_error_open_shared_file))
                    input.use { source ->
                        dest.outputStream().buffered().use { sink ->
                            PGPCryptoService.shared.encryptStream(
                                input = source,
                                output = sink,
                                recipientPublicKeys = recipients.rings,
                                signingSecretKey = signer?.ring,
                                passphrase = signer?.passphrase,
                                filename = sourceFilename,
                                armor = false,
                                v4Algo35Recipients = recipients.v4Algo35,
                                compositeSignSuite = signer?.composite?.signingSuite,
                                compositeSignSecret = signer?.compositeSecret,
                                compositeSignerFingerprint = signer?.composite?.signingFingerprint,
                                // The prompt above has been answered: "Send
                                // unsigned" left no signer at all.
                                compositeSignInSeipdV1 = true,
                            )
                        }
                    }
                    dest
                }
                signer?.let { rememberSignPassphrase(it) }
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.EncryptFileResult,
                        encryptedFileBytes = null,
                        encryptedFile = out,
                        encryptedFileName = outName,
                    )
                }
            } catch (e: Exception) {
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_QUICK)
                if (handleSignPassphraseError(e, current, ShareTargetPhase.PickRecipients)) return@launch
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(
                            R.string.share_target_error_no_input
                        ),
                    )
                }
            }
        }
    }

    /**
     * 4.0.4 — decrypt a shared file straight from its URI into a scratch
     * file. The Quick Action has no inline preview for a file result, so
     * nothing here needs the plaintext in memory.
     */
    private fun performDecryptStreaming(uri: android.net.Uri, sourceFilename: String?) {
        val current = _state.value
        // 4.8.0 (item 4d): the typed passphrase is good for this one attempt (`current` holds it).
        _state.update { it.copy(phase = ShareTargetPhase.Processing, errorMessage = null, passphrase = "") }
        viewModelScope.launch {
            try {
                val (tryRings, compositeRings) = withContext(Dispatchers.IO) { decryptRings(current) }
                if (tryRings.isEmpty() && compositeRings.isEmpty()) {
                    _state.update {
                        it.copy(
                            phase = ShareTargetPhase.Error,
                            errorMessage = PGPonyApp.instance.getString(
                                R.string.share_target_decrypt_no_key_pairs
                            ),
                        )
                    }
                    return@launch
                }
                val outName = sourceFilename?.let { stripPgpExtension(it) } ?: "decrypted_file"
                val (out, result) = withContext(Dispatchers.IO) {
                    val dest = ScratchFiles.allocate(PGPonyApp.instance, outName, ScratchFiles.SCOPE_QUICK)
                    // 4.2.0 RC6 (#32, tail-4): same envelope-skip the
                    // in-app streamed decrypt gained — a shared large
                    // .eml was fed to the armor parser headers-first.
                    val envelopeOffset = PGPonyApp.instance.contentResolver
                        .openInputStream(uri)?.use {
                            com.pgpony.android.crypto.mime.MimeEnvelope.armoredPayloadOffset(it)
                        } ?: -1L
                    val input = PGPonyApp.instance.contentResolver.openInputStream(uri)
                        ?: throw java.io.IOException(PGPonyApp.instance.getString(R.string.share_target_error_open_shared_file))
                    if (envelopeOffset > 0) {
                        var remaining = envelopeOffset
                        while (remaining > 0) {
                            val skipped = input.skip(remaining)
                            if (skipped <= 0) {
                                if (input.read() < 0) break
                                remaining--
                            } else remaining -= skipped
                        }
                    }
                    val verifyRings = allVerificationRings()
                    val r = input.use { source ->
                        dest.outputStream().buffered().use { sink ->
                            PGPCryptoService.shared.decryptStream(
                                input = source,
                                output = sink,
                                secretKeyRings = tryRings,
                                passphrase = current.passphrase.ifEmpty { null },
                                verificationKeys = verifyRings,
                                compositePrimaryRings = compositeRings,
                            )
                        }
                    }
                    dest to r
                }
                val sig = summarizeSignature(
                    result.signatureVerified, result.signerKeyID, result.hasSignature,
                    result.compositeInline, result.compositeInlineBytes, result.compositeClaimedSignerFp,
                    result.signerPrimaryFingerprint, result.compositeStreamed,
                    signingKeyFingerprint = result.signingKeyFingerprint
                )
                val decryptedBy = decryptedByOf(result.decryptingKeyIdRaw, tryRings, current)
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.DecryptFileResult,
                        decryptedFileBytes = null,
                        decryptedFile = out,
                        decryptedFileName = result.filename?.takeIf { n -> n.isNotBlank() } ?: outName,
                        signatureVerified = sig.verified,
                        signerKeyId = sig.signerKeyId,
                        signerName = sig.signerName,
                        signerKeyLine = sig.keyLine,
                        decryptedBy = decryptedBy,
                        signatureFromUnknownKey = sig.unknownSigner,
                    )
                }
            } catch (e: PGPCryptoError.PassphraseRequired) {
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_QUICK)
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.share_target_decrypt_passphrase_required
                        ),
                    )
                }
            } catch (e: Exception) {
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_QUICK)
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = ErrorText.localize(e.message) ?: PGPonyApp.instance.getString(
                            R.string.share_target_error_no_input
                        ),
                    )
                }
            }
        }
    }

    /**
     * [pqcDecision] is the answer to the 4.6.0 (item 14) prompt (4.8.0, #72):
     * null before it is asked, true to sign anyway, false to send unsigned.
     */
    fun performEncrypt(pqcDecision: Boolean? = pqcV4SignAnswer) {
        val current = _state.value

        // 4.0.4 — a shared file too large to buffer never had its bytes
        // read, so it takes the streaming path instead of the byte
        // assembly below (issue #6).
        val largeIn = current.content as? ShareIntentContent.PgpFile
        if (largeIn != null && largeIn.data == null && largeIn.uri != null) {
            performEncryptStreaming(largeIn.uri, largeIn.filename, pqcDecision)
            return
        }

        // A2: a shared FILE is encrypted as raw bytes and produces a file
        // result; only plain TEXT (and PGP files that actually parsed as armored
        // text) take the text path. The old code stringified file bytes through
        // UTF-8 here, which corrupted any non-text file (PDF/image/zip).
        val isBinaryFile = current.content is ShareIntentContent.PgpFile &&
            (current.content as ShareIntentContent.PgpFile).armoredText == null

        val plaintextBytes: ByteArray
        val literalFilename: String?
        val produceFileResult: Boolean
        val outputName: String?
        when (val c = current.content) {
            is ShareIntentContent.Text -> {
                plaintextBytes = c.text.toByteArray(Charsets.UTF_8)
                literalFilename = null
                produceFileResult = false
                outputName = null
            }
            is ShareIntentContent.PgpFile -> {
                if (isBinaryFile) {
                    // Raw bytes, never stringified. Embed the original filename
                    // in the literal packet so decryption can restore the name.
                    //
                    // 4.0.4 — data is non-null here: the streaming branch at
                    // the top of performEncrypt already returned for the
                    // null-data case. The elvis keeps the compiler happy
                    // without an assertion that could crash.
                    plaintextBytes = c.data ?: ByteArray(0)
                    literalFilename = c.filename
                    produceFileResult = true
                    // 3.1.0 Phase 1 (C2) — .gpg for binary output (was .pgp).
                    outputName = "${c.filename ?: "shared_file"}.gpg"
                } else {
                    // Parsed as armored text (e.g. a shared .asc note) — keep the
                    // text path.
                    plaintextBytes = (c.armoredText ?: "").toByteArray(Charsets.UTF_8)
                    literalFilename = null
                    produceFileResult = false
                    outputName = null
                }
            }
            ShareIntentContent.Empty -> {
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.share_target_error_no_input
                        ),
                    )
                }
                return
            }
        }
        if (current.selectedRecipients.isEmpty()) {
            _state.update {
                it.copy(
                    errorMessage = PGPonyApp.instance.getString(
                        R.string.share_target_encrypt_no_recipients_selected
                    ),
                )
            }
            return
        }
        signerBlock(current.signingKey)?.let { msg ->
            _state.update { it.copy(errorMessage = msg) }
            return
        }

        // 4.8.0 (item 4d, #72): a typed signing passphrase is good for this one attempt (`current` holds it).
        _state.update { it.copy(phase = ShareTargetPhase.Processing, errorMessage = null, signPassphrase = "") }

        viewModelScope.launch {
            try {
                val recipients = loadShareRecipients(current)
                recipientError(current, recipients)?.let { msg ->
                    _state.update { it.copy(phase = ShareTargetPhase.Error, errorMessage = msg) }
                    return@launch
                }
                // 4.8.0 (#72): Sign as. Paused means the 4.6.0 (item 14) prompt is up.
                val signing = prepareEncryptSigning(current, recipients, pqcDecision)
                if (signing is EncryptSigning.Paused) return@launch
                val signer = signing as? EncryptSigning.Signer
                val cipher = withContext(Dispatchers.Default) {
                    PGPCryptoService.shared.encrypt(
                        data = plaintextBytes,
                        recipientPublicKeys = recipients.rings,
                        signingSecretKey = signer?.ring,
                        passphrase = signer?.passphrase,
                        filename = literalFilename,
                        // Files → binary .pgp (smaller, standard). Text → armored.
                        armor = !produceFileResult,
                        v4Algo35Recipients = recipients.v4Algo35,
                        compositeSignSuite = signer?.composite?.signingSuite,
                        compositeSignSecret = signer?.compositeSecret,
                        compositeSignerFingerprint = signer?.composite?.signingFingerprint,
                        // The prompt above has been answered: "Send unsigned"
                        // left no signer at all.
                        compositeSignInSeipdV1 = true,
                    )
                }
                signer?.let { rememberSignPassphrase(it) }
                if (produceFileResult) {
                    _state.update {
                        it.copy(
                            phase = ShareTargetPhase.EncryptFileResult,
                            encryptedFileBytes = cipher,
                            encryptedFileName = outputName,
                        )
                    }
                } else {
                    _state.update {
                        it.copy(
                            phase = ShareTargetPhase.EncryptResult,
                            outputText = String(cipher, Charsets.UTF_8),
                        )
                    }
                }
            } catch (e: Throwable) {
                if (handleSignPassphraseError(e, current, ShareTargetPhase.PickRecipients)) return@launch
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.share_target_error_generic_format,
                            ErrorText.detail(e.message) ?: e.javaClass.simpleName,
                        ),
                    )
                }
            }
        }
    }

    // ── 4.8.0 (#72): signing ───────────────────────────────────────────

    /** The typed signing passphrase, kept only while the 4.6.0 (item 14)
     *  prompt is up, so answering it does not ask for it again. */
    private var pendingSignPassphrase: String? = null

    /** A signing key's material, loaded the way the Sign a file sheet loads it. */
    private sealed class SignerMaterial {
        class Classical(val ring: org.bouncycastle.openpgp.PGPSecretKeyRing) : SignerMaterial()
        class Composite(
            val info: com.pgpony.android.crypto.pqc.CompositeKeyFacade.Info,
            val secret: ByteArray,
        ) : SignerMaterial()
    }

    /** What signs an Encrypt: nobody, a key, or nothing yet (the prompt is up). */
    private sealed class EncryptSigning {
        data object None : EncryptSigning()
        data object Paused : EncryptSigning()
        class Signer(
            val fingerprint: String,
            val passphrase: String?,
            val ring: org.bouncycastle.openpgp.PGPSecretKeyRing?,
            val composite: com.pgpony.android.crypto.pqc.CompositeKeyFacade.Info?,
            val compositeSecret: ByteArray?,
        ) : EncryptSigning()
    }

    /**
     * The secret material for [key]. A composite ML-DSA key is not a
     * BouncyCastle ring and is unlocked here (a locked one throws
     * PassphraseRequired, a wrong passphrase InvalidPassphrase, as the Sign
     * screen maps them); a classical ring is unlocked by the signer itself.
     */
    private fun loadSigner(key: PGPKeyEntity, passphrase: String?): SignerMaterial {
        if (key.algorithm.isCompositeSign) {
            val info = try {
                repository.loadCompositeKeyInfo(key.fingerprint, passphrase?.toCharArray())
            } catch (e: Exception) {
                throw if (passphrase.isNullOrEmpty()) SigningError.PassphraseRequired() else SigningError.InvalidPassphrase()
            } ?: throw SigningError.NoSigningKey()
            val secret = info.signingSecret ?: throw SigningError.PassphraseRequired()
            return SignerMaterial.Composite(info, secret)
        }
        val ring = repository.loadSecretKeyRing(key.fingerprint) ?: throw SigningError.NoSigningKey()
        return SignerMaterial.Classical(ring)
    }

    /** The typed passphrase for this attempt, else the one kept for the
     *  prompt, else the in-app cache (4.3.0 RC4 §3, #15). */
    private fun signPassphraseFor(current: ShareTargetUiState, key: PGPKeyEntity): String? =
        current.signPassphrase.ifEmpty { null }
            ?: pendingSignPassphrase
            ?: com.pgpony.android.session.InAppPassphraseCache.get(key.fingerprint)

    /**
     * The Sign as key for an Encrypt, ready to sign. A composite signature
     * (an ML-DSA key, or a classical key whose signing subkey is ML-DSA) in a
     * message a v4 recipient forces into SEIPDv1 is asked about first, as on
     * the Encrypt screen (4.6.0 item 14): [pqcDecision] null puts the prompt
     * up and pauses, false encrypts without the signature, true signs.
     */
    private suspend fun prepareEncryptSigning(
        current: ShareTargetUiState,
        recipients: ShareRecipients.Loaded<org.bouncycastle.openpgp.PGPPublicKeyRing, com.pgpony.android.crypto.pqc.V4Algo35Recipient>,
        pqcDecision: Boolean?,
    ): EncryptSigning {
        val key = current.signingKey ?: return EncryptSigning.None
        val pass = signPassphraseFor(current, key)
        pendingSignPassphrase = null
        val material = withContext(Dispatchers.IO) { loadSigner(key, pass) }
        val composite = when (material) {
            is SignerMaterial.Composite -> true
            is SignerMaterial.Classical -> withContext(Dispatchers.Default) {
                PGPCryptoService.shared.picksCompositeSubkey(material.ring)
            }
        }
        val pqcInV1 = composite && PGPCryptoService.shared.compositeSignatureInSeipdV1(
            recipients.rings, emptyMap(), recipients.v4Algo35
        )
        if (pqcInV1 && pqcDecision == null) {
            pendingSignPassphrase = pass
            _state.update { it.copy(phase = ShareTargetPhase.PickRecipients, showPqcV4SignPrompt = true) }
            return EncryptSigning.Paused
        }
        if (pqcInV1 && pqcDecision == false) return EncryptSigning.None
        return when (material) {
            is SignerMaterial.Composite -> EncryptSigning.Signer(key.fingerprint, pass, null, material.info, material.secret)
            is SignerMaterial.Classical -> EncryptSigning.Signer(key.fingerprint, pass, material.ring, null, null)
        }
    }

    /** §3 (#15): a passphrase that worked is kept for the session. */
    private fun rememberSignPassphrase(signer: EncryptSigning.Signer) {
        val pass = signer.passphrase
        if (!pass.isNullOrEmpty()) com.pgpony.android.session.InAppPassphraseCache.put(signer.fingerprint, pass)
    }

    /**
     * A missing or wrong signing passphrase sends the user back to [phase]
     * to enter it, with the Sign a file sheet's message, and a wrong one is
     * dropped from the cache so it is not tried again. False for any other
     * error, which the caller reports as before.
     */
    private fun handleSignPassphraseError(e: Throwable, current: ShareTargetUiState, phase: ShareTargetPhase): Boolean {
        val key = current.signingKey ?: return false
        val messageRes = when (e) {
            is SigningError.PassphraseRequired, is PGPCryptoError.PassphraseRequired ->
                R.string.sign_file_error_passphrase_required
            is SigningError.InvalidPassphrase, is PGPCryptoError.InvalidPassphrase -> {
                com.pgpony.android.session.InAppPassphraseCache.clear(key.fingerprint)
                R.string.encdec_error_incorrect_passphrase
            }
            else -> return false
        }
        _state.update { it.copy(phase = phase, errorMessage = PGPonyApp.instance.getString(messageRes)) }
        return true
    }

    /** Why [key] must not sign, or null: the Encrypt screen's expired-key
     *  rule (expiredKeyBlock), with the same Allow expired keys setting. */
    private fun signerBlock(key: PGPKeyEntity?): String? {
        if (key == null || !key.isExpired) return null
        val allowExpired = PGPonyApp.instance.getSharedPreferences(
            "pgpony_prefs", android.content.Context.MODE_PRIVATE
        ).getBoolean("allow_expired_keys", false)
        return if (allowExpired) null
        else PGPonyApp.instance.getString(R.string.encrypt_expired_signing_blocked)
    }

    /** The shared file as a stream: its bytes when they were read, else its URI. */
    private fun openSharedFile(file: ShareIntentContent.PgpFile): java.io.InputStream {
        file.data?.let { return java.io.ByteArrayInputStream(it) }
        val uri = file.uri
            ?: throw java.io.IOException(PGPonyApp.instance.getString(R.string.share_target_error_open_shared_file))
        return PGPonyApp.instance.contentResolver.openInputStream(uri)
            ?: throw java.io.IOException(PGPonyApp.instance.getString(R.string.share_target_error_open_shared_file))
    }

    /**
     * 4.8.0 (#72): a detached signature over the shared file, made as the
     * Sign a file sheet makes it (runSignFile): .asc or .sig, the file
     * hashed as it streams so a large file is never read into memory, and a
     * composite ML-DSA key through CompositeDocumentSigner. The signature is
     * small and kept in memory for Save and Share. The passphrase follows the
     * in-app rules: typed for this one attempt, else the in-app cache, kept
     * after it works and dropped when it is wrong.
     */
    fun performSign() {
        val current = _state.value
        val file = current.content as? ShareIntentContent.PgpFile
        if (file == null || (file.data == null && file.uri == null)) {
            _state.update {
                it.copy(
                    phase = ShareTargetPhase.Error,
                    errorMessage = PGPonyApp.instance.getString(R.string.share_target_error_no_input),
                )
            }
            return
        }
        val key = current.signingKey
        if (key == null) {
            _state.update { it.copy(errorMessage = PGPonyApp.instance.getString(R.string.sign_file_error_pick_key)) }
            return
        }
        signerBlock(key)?.let { msg ->
            _state.update { it.copy(errorMessage = msg) }
            return
        }
        // 4.8.0 (item 4d): the typed passphrase is good for this one attempt (`current` holds it).
        _state.update { it.copy(phase = ShareTargetPhase.Processing, errorMessage = null, signPassphrase = "") }
        viewModelScope.launch {
            val pass = signPassphraseFor(current, key)
            try {
                val armor = current.signArmor
                val sig = withContext(Dispatchers.IO) {
                    val material = loadSigner(key, pass)
                    openSharedFile(file).use { input ->
                        when (material) {
                            is SignerMaterial.Composite ->
                                com.pgpony.android.crypto.pqc.CompositeDocumentSigner.signDetachedStream(
                                    material.info.signingSuite, material.secret,
                                    material.info.signingFingerprint, input, armor = armor
                                )
                            is SignerMaterial.Classical ->
                                SigningService.shared.signDetachedStream(
                                    input = input,
                                    secretKeyRing = material.ring,
                                    passphrase = pass,
                                    armor = armor,
                                )
                        }
                    }
                }
                if (!pass.isNullOrEmpty()) com.pgpony.android.session.InAppPassphraseCache.put(key.fingerprint, pass)
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.SignResult,
                        signatureBytes = sig,
                        signatureFileName = ShareFileActions.signatureName(file.filename, armor),
                    )
                }
            } catch (e: Exception) {
                if (handleSignPassphraseError(e, current, ShareTargetPhase.PickSigner)) return@launch
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.sign_file_error_failed_format,
                            ErrorText.detail(e.message) ?: e.javaClass.simpleName,
                        ),
                    )
                }
            }
        }
    }

    // ── Decrypt action ─────────────────────────────────────────────────

    fun performDecrypt() {
        val current = _state.value
        val armored = when (val c = current.content) {
            is ShareIntentContent.Text -> {
                // 4.6.0 (item 6): decrypt the encrypted block itself, not the
                // text around it.
                val encryptedBlock = SharePayload.of(c.text).encrypted
                if (encryptedBlock == null && !c.looksLikePgpMessage) {
                    _state.update {
                        it.copy(
                            phase = ShareTargetPhase.Error,
                            errorMessage = PGPonyApp.instance.getString(
                                R.string.share_target_error_not_pgp_for_decrypt
                            ),
                        )
                    }
                    return
                }
                encryptedBlock ?: c.text
            }
            is ShareIntentContent.PgpFile -> c.armoredText?.let { SharePayload.of(it).encrypted ?: it } ?: run {
                // Binary PGP path — decrypt the raw bytes instead.
                // Use decrypt() instead of decryptArmored().
                //
                // 4.0.4 — a file too large to buffer has no bytes; stream
                // it from the URI instead (issue #6).
                val bin = c.data
                if (bin != null) {
                    performDecryptBinary(bin, c.filename)
                } else if (c.uri != null) {
                    performDecryptStreaming(c.uri, c.filename)
                } else {
                    _state.update {
                        it.copy(
                            phase = ShareTargetPhase.Error,
                            errorMessage = PGPonyApp.instance.getString(
                                R.string.share_target_error_no_input
                            ),
                        )
                    }
                }
                return
            }
            ShareIntentContent.Empty -> {
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.share_target_error_no_input
                        ),
                    )
                }
                return
            }
        }

        // 4.8.0 (item 4d): the typed passphrase is good for this one attempt (`current` holds it).
        _state.update { it.copy(phase = ShareTargetPhase.Processing, errorMessage = null, passphrase = "") }

        viewModelScope.launch {
            try {
                // Try the user-selected key first; if decrypt fails with
                // "no matching key", fall back to all available pairs.
                val (tryRings, compositeRings) = withContext(Dispatchers.IO) { decryptRings(current) }
                if (tryRings.isEmpty() && compositeRings.isEmpty()) {
                    _state.update {
                        it.copy(
                            phase = ShareTargetPhase.Error,
                            errorMessage = PGPonyApp.instance.getString(
                                R.string.share_target_decrypt_no_key_pairs
                            ),
                        )
                    }
                    return@launch
                }
                val verifyRings = allVerificationRings()
                val result = withContext(Dispatchers.Default) {
                    PGPCryptoService.shared.decryptArmored(
                        // 3.1.0 Phase 6 (J6/J2): a shared .eml carries the
                        // RFC 3156 envelope — unwrap to the armored payload;
                        // plain armored input passes through unchanged.
                        armoredMessage = com.pgpony.android.crypto.mime.MimeParser
                            .pgpMimeEncryptedPayload(armored) ?: armored,
                        secretKeyRings = tryRings,
                        passphrase = current.passphrase.ifEmpty { null },
                        verificationKeys = verifyRings,
                        compositePrimaryRings = compositeRings,
                    )
                }
                publishDecryptResult(
                    result,
                    sourceFilename = (current.content as? ShareIntentContent.PgpFile)?.filename,
                    rings = tryRings,
                    current = current,
                )
            } catch (e: Throwable) {
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.share_target_error_generic_format,
                            ErrorText.detail(e.message) ?: e.javaClass.simpleName,
                        ),
                    )
                }
            }
        }
    }

    /**
     * #57: the Quick Action decrypt paths passed a null
     * verification set, so a signed message decrypted through the share target
     * could never be verified even though the share-decrypt screen and file
     * decrypt (which pass the real rings) verified the same message fine. Every
     * stored public key is a candidate signer, mirroring the other paths.
     */
    /**
     * 4.6.0 (items 6, 15, 21): the secret rings a Quick Action decrypt tries,
     * the selected key first: Bouncy Castle rings, the classical subkeys of a
     * composite ML-DSA key (RSA / X25519, see CompositeKeyFacade), and the raw
     * composite rings whose ML-KEM subkey opens composite mail. The Quick
     * Action used to pass only the first kind, so a composite key could not
     * decrypt anything here.
     */
    private fun decryptRings(
        current: ShareTargetUiState
    ): Pair<List<org.bouncycastle.openpgp.PGPSecretKeyRing>, List<ByteArray>> {
        val ordered = listOfNotNull(current.selectedDecryptKey) +
            current.availableKeyPairs.filter { it.fingerprint != current.selectedDecryptKey?.fingerprint }
        val rings = mutableListOf<org.bouncycastle.openpgp.PGPSecretKeyRing>()
        val composite = mutableListOf<ByteArray>()
        for (entity in ordered) {
            val ring = repository.loadSecretKeyRing(entity.fingerprint)
                ?: if (entity.algorithm.isCompositeSign) repository.loadCompositeClassicalDecryptionRing(entity.fingerprint) else null
            if (ring != null && rings.none { it.publicKey.fingerprint contentEquals ring.publicKey.fingerprint }) {
                rings.add(ring)
            }
            if (entity.algorithm.isCompositeSign) {
                repository.loadCompositePrivateRing(entity.fingerprint)?.let { composite.add(it) }
            }
        }
        return rings to composite
    }

    /** 4.6.0 (item 15): what the result screen says about the signature. */
    private data class SignatureSummary(
        val verified: Boolean,
        val signerName: String?,
        val signerKeyId: String?,
        /** Signed, but by a key that is not in the keyring. */
        val unknownSigner: Boolean,
        /** 4.7.0 (item 48, #79): the key that verified, and its primary. */
        val keyLine: com.pgpony.android.crypto.KeyIdText.Line? = null,
    )

    /** 4.7.0 (item 48, #79): which of your key pairs decrypted, and with which (sub)key. */
    data class DecryptedBy(val label: String, val line: com.pgpony.android.crypto.KeyIdText.Line?)

    /**
     * 4.7.0 (item 48, #79): the key pair holding the secret (sub)key [raw] that
     * unwrapped the session key, among the [rings] tried. A fallback key can
     * differ from the one picked, so this names the one that actually worked.
     */
    private fun decryptedByOf(
        raw: Long?,
        rings: List<org.bouncycastle.openpgp.PGPSecretKeyRing>,
        current: ShareTargetUiState,
    ): DecryptedBy? {
        if (raw == null || raw == 0L) return null
        val ring = rings.firstOrNull { it.getSecretKey(raw) != null } ?: return null
        val primaryFp = org.bouncycastle.util.encoders.Hex.toHexString(ring.publicKey.fingerprint).uppercase()
        val entity = current.availableKeyPairs.firstOrNull {
            KeyDeduplicationService.normalize(it.fingerprint) == KeyDeduplicationService.normalize(primaryFp)
        }
        val label = entity?.let { e ->
            val name = e.userName.ifBlank { e.userEmail }
            if (name.isBlank()) e.shortFingerprint else "$name \u00B7 ${e.shortFingerprint}"
        } ?: com.pgpony.android.crypto.KeyIdText.keyIdOf(primaryFp) ?: return null
        return DecryptedBy(label, com.pgpony.android.crypto.KeyIdText.decryptingLine(raw, primaryFp))
    }

    /**
     * 4.6.0 (item 15): the signature state of a Quick Action decrypt. An inline
     * COMPOSITE (ML-DSA + EdDSA) signature is verified against the stored
     * composite certificates, as the Decrypt screen does; before, the Quick
     * Action read only signatureVerified and showed such a message as
     * unverified.
     *
     * A2 (ENGINE-4): the composite signature is graded by CompositeSignerGate
     * (policy and signer validity, signer found by the key that verified).
     * The classical signer is named from the engine's primary fingerprint of
     * the certificate that validly carries the verifying key, not from the
     * 64-bit key ID.
     */
    private suspend fun summarizeSignature(
        signatureVerified: Boolean,
        signerKeyID: String?,
        hasSignature: Boolean,
        compositeInline: Boolean,
        compositeInlineBytes: ByteArray?,
        compositeClaimedSignerFp: String?,
        signerPrimaryFingerprint: String?,
        compositeStreamed: com.pgpony.android.crypto.pqc.CompositeInlineStreamReader.Result? = null,
        signingKeyFingerprint: String? = null,
    ): SignatureSummary {
        if (compositeInline && (compositeInlineBytes != null || compositeStreamed != null)) {
            val certs = withContext(Dispatchers.IO) { repository.loadCompositeSignerCerts() }
            val graded = withContext(Dispatchers.Default) {
                runCatching {
                    // 4.7.0 (item 23): a streamed decrypt carries digests, not bytes.
                    if (compositeStreamed != null) CompositeSignerGate.verifyStreamed(certs.map { it.second }, compositeStreamed)
                    else CompositeSignerGate.verifyInline(certs.map { it.second }, compositeInlineBytes!!)
                }.getOrNull()
            }
            val keyId = graded?.signerKeyID ?: compositeClaimedSignerFp?.take(16)
            if (graded == null || graded.status == SignerStatus.UNKNOWN_SIGNER) {
                return SignatureSummary(false, null, keyId, unknownSigner = true)
            }
            val entity = certs.getOrNull(graded.certIndex)?.first
            return SignatureSummary(
                graded.verified, entity?.userID, keyId, unknownSigner = false,
                keyLine = if (graded.verified) {
                    com.pgpony.android.crypto.KeyIdText.signingLine(null, keyId, entity?.fingerprint)
                } else null
            )
        }
        val recipients = _state.value.availableRecipients
        val byFingerprint = signerPrimaryFingerprint?.let { fp ->
            val target = KeyDeduplicationService.normalize(fp)
            recipients.firstOrNull { k -> KeyDeduplicationService.normalize(k.fingerprint) == target }
        }
        // A verified signer is named only through its fingerprint. A signature
        // that did not verify keeps the old key ID label, which vouches for
        // nothing.
        val name = byFingerprint?.userID ?: if (!signatureVerified) {
            signerKeyID?.let { keyId ->
                recipients.firstOrNull { k -> k.longKeyId.equals(keyId, ignoreCase = true) }?.userID
            }
        } else null
        return SignatureSummary(
            verified = signatureVerified,
            signerName = name,
            signerKeyId = signerKeyID,
            unknownSigner = hasSignature && signerKeyID == null,
            // Named only for a signature that verified, like the signer's name.
            keyLine = if (signatureVerified) {
                com.pgpony.android.crypto.KeyIdText.signingLine(signingKeyFingerprint, signerKeyID, signerPrimaryFingerprint)
            } else null,
        )
    }

    private suspend fun allVerificationRings(): List<org.bouncycastle.openpgp.PGPPublicKeyRing> =
        withContext(Dispatchers.IO) {
            repository.getAllKeys().mapNotNull { repository.loadPublicKeyRing(it.fingerprint) }
        }

    // ── Binary decrypt (file-mode PGP) ─────────────────────────────────

    private fun performDecryptBinary(data: ByteArray, sourceFilename: String?) {
        val current = _state.value
        // 4.8.0 (item 4d): the typed passphrase is good for this one attempt (`current` holds it).
        _state.update { it.copy(phase = ShareTargetPhase.Processing, errorMessage = null, passphrase = "") }
        viewModelScope.launch {
            try {
                val (tryRings, compositeRings) = withContext(Dispatchers.IO) { decryptRings(current) }
                if (tryRings.isEmpty() && compositeRings.isEmpty()) {
                    _state.update {
                        it.copy(
                            phase = ShareTargetPhase.Error,
                            errorMessage = PGPonyApp.instance.getString(
                                R.string.share_target_decrypt_no_key_pairs
                            ),
                        )
                    }
                    return@launch
                }
                val verifyRings = allVerificationRings()
                val result = withContext(Dispatchers.Default) {
                    PGPCryptoService.shared.decrypt(
                        // 3.1.0 Phase 6 (J6/J2): an .eml opened as bytes — unwrap the
                        // envelope when present.
                        encryptedData = unwrapEnvelopeBytes(data),
                        secretKeyRings = tryRings,
                        passphrase = current.passphrase.ifEmpty { null },
                        verificationKeys = verifyRings,
                        compositePrimaryRings = compositeRings,
                    )
                }
                publishDecryptResult(result, sourceFilename = sourceFilename, rings = tryRings, current = current)
            } catch (e: Throwable) {
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.share_target_error_generic_format,
                            ErrorText.detail(e.message) ?: e.javaClass.simpleName,
                        ),
                    )
                }
            }
        }
    }

    // ── Reset / Cancel ─────────────────────────────────────────────────

    /**
     * Phase A2 — publish a successful decrypt as either a TEXT result or, when
     * the recovered content is a file (the literal packet carried a filename,
     * or the bytes aren't valid UTF-8 text), a FILE result the user can
     * save/share. Mirrors the encrypt-side file result.
     */
    // 4.0.4 — suspend so the MIME parse below can be dispatched. Both
    // callers already sit inside a viewModelScope.launch immediately after a
    // withContext(Dispatchers.Default) decrypt, so this costs them nothing.
    private suspend fun publishDecryptResult(
        result: com.pgpony.android.crypto.DecryptResult,
        sourceFilename: String?,
        rings: List<org.bouncycastle.openpgp.PGPSecretKeyRing> = emptyList(),
        current: ShareTargetUiState = _state.value,
    ) {
        // 3.1.0 Phase 6 (J6): PGP/MIME content routes to a readable TEXT
        // result — the body, plus an attachment-count note when the
        // bundle carries files (saving/previewing attachments lives in
        // the main app, iOS ExtensionDecryptView parity). Non-MIME keeps
        // the existing text/file split untouched.
        val mime = withContext(Dispatchers.Default) {
            try {
                com.pgpony.android.crypto.mime.MimeParser.parse(result.data)
            } catch (_: Exception) {
                null
            }
        }
        val sig = summarizeSignature(
            result.signatureVerified, result.signerKeyID, result.hasSignature,
            result.compositeInline, result.compositeInlineBytes, result.compositeClaimedSignerFp,
            result.signerPrimaryFingerprint,
            signingKeyFingerprint = result.signingKeyFingerprint
        )
        val decryptedBy = decryptedByOf(result.decryptingKeyIdRaw, rings, current)
        if (mime != null) {
            _state.update {
                it.copy(
                    phase = ShareTargetPhase.DecryptResult,
                    outputText = mime.body ?: "",
                    mimeAttachmentNote = if (mime.hasAttachments) {
                        PGPonyApp.instance.getString(
                            R.string.share_target_mime_attachments_note_format,
                            mime.attachments.size
                        )
                    } else null,
                    signatureVerified = sig.verified,
                    signerKeyId = sig.signerKeyId,
                    signerName = sig.signerName,
                    signerKeyLine = sig.keyLine,
                    decryptedBy = decryptedBy,
                    signatureFromUnknownKey = sig.unknownSigner,
                )
            }
            return
        }
        val literalName = result.filename?.takeIf { it.isNotBlank() }
        // 4.7.0 (item 25, #67): decide by content. The lenient UTF-8 decode
        // behind result.plaintext never fails, so without a literal name every
        // result read as text, images included.
        val isFile = literalName != null ||
            (result.data.isNotEmpty() && !com.pgpony.android.intent.PlaintextKind.isText(result.data))
        if (isFile) {
            val sniffedExt = com.pgpony.android.intent.PlaintextKind.extensionFor(result.data)
            val outName = literalName
                ?: sourceFilename?.let { stripPgpExtension(it) }
                ?: sniffedExt?.let { "decrypted_file.$it" }
                ?: "decrypted_file"
            _state.update {
                it.copy(
                    phase = ShareTargetPhase.DecryptFileResult,
                    decryptedFileBytes = result.data,
                    decryptedFileName = outName,
                    signatureVerified = sig.verified,
                    signerKeyId = sig.signerKeyId,
                    signerName = sig.signerName,
                    signerKeyLine = sig.keyLine,
                    decryptedBy = decryptedBy,
                    signatureFromUnknownKey = sig.unknownSigner,
                )
            }
        } else {
            _state.update {
                it.copy(
                    phase = ShareTargetPhase.DecryptResult,
                    outputText = result.plaintext,
                    signatureVerified = sig.verified,
                    signerKeyId = sig.signerKeyId,
                    signerName = sig.signerName,
                    signerKeyLine = sig.keyLine,
                    decryptedBy = decryptedBy,
                    signatureFromUnknownKey = sig.unknownSigner,
                )
            }
        }
    }

    /**
     * 3.1.0 Phase 6 (J6/J2) — byte-level envelope unwrap for the
     * Quick Action binary path; mirrors the main VM's
     * effectiveDecryptFileBytes.
     */
    private fun unwrapEnvelopeBytes(bytes: ByteArray): ByteArray =
        // 4.8.0 (item 4d): then only the PGP MESSAGE block, so text around it is ignored.
        com.pgpony.android.crypto.ArmorExtractor.messageOnlyBytes(
            com.pgpony.android.crypto.mime.MimeEnvelope.unwrapBytes(bytes)
        )

    private fun stripPgpExtension(name: String): String =
        name.removeSuffix(".pgp").removeSuffix(".gpg").removeSuffix(".asc")

    fun goBackToActionPicker() {
        pqcV4SignAnswer = null
        _state.update {
            it.copy(
                phase = ShareTargetPhase.PickAction,
                errorMessage = null,
                selectedRecipients = emptySet(),
                selectedDecryptKey = null,
                passphrase = "",
                cardPin = "",
                outputText = "",
                signerName = null,
                signerKeyId = null,
                signerKeyLine = null,
                decryptedBy = null,
                signatureVerified = false,
                signatureFromUnknownKey = false,
                encryptedFileBytes = null,
                encryptedFileName = null,
                decryptedFileBytes = null,
                mimeAttachmentNote = null,
                decryptedFileName = null,
                // 4.8.0 (#72)
                signingKey = null,
                signPassphrase = "",
                showPqcV4SignPrompt = false,
                signatureBytes = null,
                signatureFileName = null,
            )
        }
        pendingSignPassphrase = null
    }

    fun clearError() {
        _state.update { it.copy(errorMessage = null) }
    }

    // ── Factory ────────────────────────────────────────────────────────

    companion object {
        fun factory(repository: KeyRepository) = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                return ShareTargetViewModel(repository) as T
            }
        }
    }
}
