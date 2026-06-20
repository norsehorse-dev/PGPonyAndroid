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
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.repository.KeyRepository
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
    val encryptedFileName: String? = null,
    // Phase A2 (decrypt side): recovered binary file (DecryptFileResult phase).
    val decryptedFileBytes: ByteArray? = null,
    val decryptedFileName: String? = null,
    val signerName: String? = null,           // populated by decrypt signature info
    val signerKeyId: String? = null,
    val signatureVerified: Boolean = false,

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
            _state.update {
                it.copy(
                    availableRecipients = keys,
                    availableKeyPairs = keyPairs,
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
    ): PGPKeyEntity? {
        val bytes = encryptedBytesForCardDecrypt(content) ?: return null
        return try {
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
            )
        }
    }

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
                errorMessage = null,
            )
        }
    }

    fun onCardDecryptFailure(message: String) {
        _state.update {
            it.copy(phase = ShareTargetPhase.Error, errorMessage = message)
        }
    }

    // ── Encrypt action ─────────────────────────────────────────────────

    fun performEncrypt() {
        val current = _state.value

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
                    plaintextBytes = c.data
                    literalFilename = c.filename
                    produceFileResult = true
                    outputName = "${c.filename ?: "shared_file"}.pgp"
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

        _state.update { it.copy(phase = ShareTargetPhase.Processing, errorMessage = null) }

        viewModelScope.launch {
            try {
                val recipientRings = withContext(Dispatchers.IO) {
                    current.selectedRecipients.mapNotNull { fp ->
                        repository.loadPublicKeyRing(fp)
                    }
                }
                if (recipientRings.isEmpty()) {
                    _state.update {
                        it.copy(
                            phase = ShareTargetPhase.Error,
                            errorMessage = PGPonyApp.instance.getString(
                                R.string.share_target_encrypt_recipients_empty
                            ),
                        )
                    }
                    return@launch
                }
                val cipher = withContext(Dispatchers.Default) {
                    PGPCryptoService.shared.encrypt(
                        data = plaintextBytes,
                        recipientPublicKeys = recipientRings,
                        signingSecretKey = null,
                        passphrase = null,
                        filename = literalFilename,
                        // Files → binary .pgp (smaller, standard). Text → armored.
                        armor = !produceFileResult,
                    )
                }
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
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.share_target_error_generic_format,
                            e.message ?: e.javaClass.simpleName,
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
                if (!c.looksLikePgpMessage) {
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
                c.text
            }
            is ShareIntentContent.PgpFile -> c.armoredText ?: run {
                // Binary PGP path — decrypt the raw bytes instead.
                // Use decrypt() instead of decryptArmored().
                performDecryptBinary(c.data, c.filename)
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

        _state.update { it.copy(phase = ShareTargetPhase.Processing, errorMessage = null) }

        viewModelScope.launch {
            try {
                // Try the user-selected key first; if decrypt fails with
                // "no matching key", fall back to all available pairs.
                val tryRings = withContext(Dispatchers.IO) {
                    val rings = mutableListOf<org.bouncycastle.openpgp.PGPSecretKeyRing>()
                    current.selectedDecryptKey?.let { entity ->
                        repository.loadSecretKeyRing(entity.fingerprint)?.let { rings.add(it) }
                    }
                    // Also include all other pairs as fallback — BC
                    // walks the list to find the matching sub-key.
                    current.availableKeyPairs.forEach { pair ->
                        repository.loadSecretKeyRing(pair.fingerprint)?.let { ring ->
                            if (rings.none { it.publicKey.fingerprint contentEquals ring.publicKey.fingerprint }) {
                                rings.add(ring)
                            }
                        }
                    }
                    rings.toList()
                }
                if (tryRings.isEmpty()) {
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
                val result = withContext(Dispatchers.Default) {
                    PGPCryptoService.shared.decryptArmored(
                        armoredMessage = armored,
                        secretKeyRings = tryRings,
                        passphrase = current.passphrase.ifEmpty { null },
                        verificationKeys = null,
                    )
                }
                publishDecryptResult(
                    result,
                    sourceFilename = (current.content as? ShareIntentContent.PgpFile)?.filename,
                )
            } catch (e: Throwable) {
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.share_target_error_generic_format,
                            e.message ?: e.javaClass.simpleName,
                        ),
                    )
                }
            }
        }
    }

    // ── Binary decrypt (file-mode PGP) ─────────────────────────────────

    private fun performDecryptBinary(data: ByteArray, sourceFilename: String?) {
        val current = _state.value
        _state.update { it.copy(phase = ShareTargetPhase.Processing, errorMessage = null) }
        viewModelScope.launch {
            try {
                val tryRings = withContext(Dispatchers.IO) {
                    val rings = mutableListOf<org.bouncycastle.openpgp.PGPSecretKeyRing>()
                    current.selectedDecryptKey?.let { entity ->
                        repository.loadSecretKeyRing(entity.fingerprint)?.let { rings.add(it) }
                    }
                    current.availableKeyPairs.forEach { pair ->
                        repository.loadSecretKeyRing(pair.fingerprint)?.let { ring ->
                            if (rings.none { it.publicKey.fingerprint contentEquals ring.publicKey.fingerprint }) {
                                rings.add(ring)
                            }
                        }
                    }
                    rings.toList()
                }
                if (tryRings.isEmpty()) {
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
                val result = withContext(Dispatchers.Default) {
                    PGPCryptoService.shared.decrypt(
                        encryptedData = data,
                        secretKeyRings = tryRings,
                        passphrase = current.passphrase.ifEmpty { null },
                        verificationKeys = null,
                    )
                }
                publishDecryptResult(result, sourceFilename = sourceFilename)
            } catch (e: Throwable) {
                _state.update {
                    it.copy(
                        phase = ShareTargetPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.share_target_error_generic_format,
                            e.message ?: e.javaClass.simpleName,
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
    private fun publishDecryptResult(
        result: com.pgpony.android.crypto.DecryptResult,
        sourceFilename: String?,
    ) {
        val literalName = result.filename?.takeIf { it.isNotBlank() }
        val isFile = literalName != null ||
            (result.plaintext.isEmpty() && result.data.isNotEmpty())
        val signerName = result.signerKeyID?.let { keyId ->
            _state.value.availableRecipients.firstOrNull { k ->
                k.longKeyId.equals(keyId, ignoreCase = true)
            }?.userID
        }
        if (isFile) {
            val outName = literalName
                ?: sourceFilename?.let { stripPgpExtension(it) }
                ?: "decrypted_file"
            _state.update {
                it.copy(
                    phase = ShareTargetPhase.DecryptFileResult,
                    decryptedFileBytes = result.data,
                    decryptedFileName = outName,
                    signatureVerified = result.signatureVerified,
                    signerKeyId = result.signerKeyID,
                    signerName = signerName,
                )
            }
        } else {
            _state.update {
                it.copy(
                    phase = ShareTargetPhase.DecryptResult,
                    outputText = result.plaintext,
                    signatureVerified = result.signatureVerified,
                    signerKeyId = result.signerKeyID,
                    signerName = signerName,
                )
            }
        }
    }

    private fun stripPgpExtension(name: String): String =
        name.removeSuffix(".pgp").removeSuffix(".gpg").removeSuffix(".asc")

    fun goBackToActionPicker() {
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
                signatureVerified = false,
                encryptedFileBytes = null,
                encryptedFileName = null,
                decryptedFileBytes = null,
                decryptedFileName = null,
            )
        }
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
