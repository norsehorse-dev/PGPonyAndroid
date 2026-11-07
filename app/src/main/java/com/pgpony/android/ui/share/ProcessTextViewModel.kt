// ProcessTextViewModel.kt
// PGPony Android, 4.8.0 (#103): the state behind the text selection menu's
// Encrypt and Sign entries (ProcessTextActivity).
//
// A separate ViewModel from ShareTargetViewModel because this flow is text
// only and has one fixed job per entry, but it is built from the same parts:
// the Quick Action's recipient loading (ShareRecipients) and the Encrypt
// screen's signer pool, sign-by-default, signing defaults (#34), expiry rule,
// passphrase handling and the post-quantum signature prompt. A typed
// passphrase is used for one attempt and cleared (item 4d), as in the Quick
// Action; nothing is cached here.
//
//   Phase            Encrypt                        Sign
//   ───────────────────────────────────────────────────────────────────────
//   Loading          keyring load                   keyring load
//   NoKeys           nothing to encrypt to          no key that can sign
//   PickRecipients   recipients + "Also sign"       (not used)
//   PickSigner       Sign as, back to recipients    Sign as, then Sign
//   Passphrase       the signing key's passphrase   the signing key's passphrase
//   CardPin          PIN + tap for a card signer    PIN + tap for a card signer
//   Processing       working                        working
//   Result           armored message                cleartext signed message
//   Error            message + Back                 message + Back

package com.pgpony.android.ui.share

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SigningError
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.card.CardSigningService
import com.pgpony.android.crypto.card.OpenPgpCardException
import com.pgpony.android.crypto.card.OpenPgpCardSession
import com.pgpony.android.crypto.pqc.CompositeDocumentSigner
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.i18n.ErrorText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class ProcessTextPhase {
    Loading,
    NoKeys,
    PickRecipients,
    PickSigner,
    Passphrase,
    CardPin,
    Processing,
    Result,
    Error,
}

data class ProcessTextUiState(
    val phase: ProcessTextPhase = ProcessTextPhase.Loading,
    val mode: ProcessText.Mode = ProcessText.Mode.ENCRYPT,
    /** The selected text, exactly as the calling app sent it. */
    val text: String = "",
    /** Recipients: every key that is not revoked, cards only once paired. */
    val recipients: List<PGPKeyEntity> = emptyList(),
    /** Keys that can sign: software key pairs, then paired cards (as the Encrypt screen). */
    val signers: List<PGPKeyEntity> = emptyList(),
    val selectedRecipients: Set<String> = emptySet(),
    /** Encrypt only: sign as [signer] too. Sign mode always signs. */
    val signMessage: Boolean = false,
    val signer: PGPKeyEntity? = null,
    val passphrase: String = "",
    val cardPin: String = "",
    val output: String = "",
    val errorMessage: String? = null,
    /** The Encrypt screen's "Some recipients may not read this signature" prompt. */
    val showPqcPrompt: Boolean = false,
)

class ProcessTextViewModel(
    private val repository: KeyRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(ProcessTextUiState())
    val state: StateFlow<ProcessTextUiState> = _state.asStateFlow()

    private val prefs by lazy {
        PGPonyApp.instance.getSharedPreferences("pgpony_prefs", android.content.Context.MODE_PRIVATE)
    }
    private val allowExpiredKeys: Boolean get() = prefs.getBoolean("allow_expired_keys", false)

    /** The passphrase held while the post-quantum prompt is up, and the answer to it. */
    private var pqcPendingPassphrase: String? = null
    private var pqcDecision: Boolean? = null
    private var started = false

    /**
     * Seed the flow once per activity instance. The keyring is loaded off the
     * main thread; the first real phase depends on the mode and on what the
     * keyring holds.
     */
    fun initialize(mode: ProcessText.Mode, text: String) {
        if (started) return
        started = true
        _state.update { it.copy(mode = mode, text = text, phase = ProcessTextPhase.Loading) }
        viewModelScope.launch {
            val all = withContext(Dispatchers.IO) { repository.getAllKeys() }
            // The Encrypt screen's pools (EncryptDecryptViewModel.loadKeys):
            // no revoked keys, a card only once its public key is paired.
            val recipients = all.filter { !it.isRevoked && (!it.isCardBacked || it.armoredPublicKey != null) }
            val softwareSigners = all.filter { it.isKeyPair && !it.isRevoked }
            val cardSigners = all.filter {
                !it.isRevoked && it.isCardBacked && !it.isKeyPair && it.armoredPublicKey != null
            }
            val signers = softwareSigners + cardSigners
            val defaultFp = prefs.getString("pgpony_default_signer_fpr", "") ?: ""
            val signer = signers.firstOrNull { it.fingerprint == defaultFp }
                ?: signers.firstOrNull { it.isDefault }
                ?: signers.firstOrNull()
            val preselect = com.pgpony.android.ui.settings.DefaultRecipientPrefs
                .preselectFingerprint(prefs)
                ?.takeIf { fp -> recipients.any { it.fingerprint == fp } }
            val phase = when (mode) {
                ProcessText.Mode.ENCRYPT ->
                    if (recipients.isEmpty()) ProcessTextPhase.NoKeys else ProcessTextPhase.PickRecipients
                ProcessText.Mode.SIGN ->
                    if (signers.isEmpty()) ProcessTextPhase.NoKeys else ProcessTextPhase.PickSigner
            }
            _state.update {
                it.copy(
                    phase = phase,
                    recipients = recipients,
                    signers = signers,
                    signer = signer,
                    selectedRecipients = preselect?.let { fp -> setOf(fp) } ?: emptySet(),
                    // 3.1.0 Phase 8 (E5): the Encrypt screen's sign-by-default.
                    signMessage = signer != null && prefs.getBoolean("sign_by_default", false),
                )
            }
        }
    }

    // ── Choices ───────────────────────────────────────────────────────

    fun toggleRecipient(fingerprint: String) {
        _state.update { s ->
            val next = s.selectedRecipients.toMutableSet()
            if (!next.remove(fingerprint)) next.add(fingerprint)
            s.copy(selectedRecipients = next, errorMessage = null)
        }
    }

    fun setSignMessage(enabled: Boolean) {
        _state.update { it.copy(signMessage = enabled && it.signer != null) }
    }

    /** Encrypt: open Sign as from the recipient screen. */
    fun openSignerPicker() {
        _state.update { it.copy(phase = ProcessTextPhase.PickSigner, errorMessage = null) }
    }

    fun selectSigner(key: PGPKeyEntity) {
        _state.update { s ->
            if (s.mode == ProcessText.Mode.ENCRYPT) {
                // Picking a signer on the way to Encrypt means "sign as this one".
                s.copy(signer = key, signMessage = true, phase = ProcessTextPhase.PickRecipients)
            } else {
                s.copy(signer = key, errorMessage = null)
            }
        }
    }

    fun updatePassphrase(value: String) {
        _state.update { it.copy(passphrase = value) }
    }

    fun updateCardPin(value: String) {
        _state.update { it.copy(cardPin = value) }
    }

    /** Back from a passphrase, PIN or error to where the choice was made. */
    fun back() {
        _state.update {
            it.copy(
                phase = if (it.mode == ProcessText.Mode.ENCRYPT) ProcessTextPhase.PickRecipients
                else ProcessTextPhase.PickSigner,
                passphrase = "",
                cardPin = "",
                errorMessage = null,
                showPqcPrompt = false,
            )
        }
    }

    // ── Run ───────────────────────────────────────────────────────────

    /** True when this run signs with a card, so the screen asks for the PIN and a tap. */
    private fun ProcessTextUiState.signsWithCard(): Boolean =
        signsAtAll() && signer?.isCardBacked == true

    private fun ProcessTextUiState.signsAtAll(): Boolean =
        mode == ProcessText.Mode.SIGN || (signMessage && signer != null)

    private fun selectedRecipientEntities(s: ProcessTextUiState): List<PGPKeyEntity> =
        s.recipients.filter { it.fingerprint in s.selectedRecipients }

    /**
     * Why the run must not start, or null. Same checks and strings as the
     * Encrypt screen: a recipient to encrypt to, a signer to sign with, and
     * no expired key unless Allow expired keys is on.
     */
    private fun blockReason(s: ProcessTextUiState): String? {
        val app = PGPonyApp.instance
        if (s.mode == ProcessText.Mode.ENCRYPT && s.selectedRecipients.isEmpty()) {
            return app.getString(R.string.share_target_encrypt_no_recipients_selected)
        }
        if (s.mode == ProcessText.Mode.SIGN && s.signer == null) {
            return app.getString(R.string.encdec_error_sign_no_signing_key)
        }
        if (allowExpiredKeys) return null
        if (s.signsAtAll() && s.signer?.isExpired == true) {
            return app.getString(R.string.encrypt_expired_signing_blocked)
        }
        if (s.mode == ProcessText.Mode.ENCRYPT) {
            val expired = selectedRecipientEntities(s).filter { it.isExpired }
            if (expired.isNotEmpty()) {
                return app.getString(
                    R.string.encrypt_expired_recipient_blocked,
                    expired.joinToString(", ") { it.userName.ifBlank { it.userEmail.ifBlank { it.shortFingerprint } } }
                )
            }
        }
        return null
    }

    /**
     * Encrypt (optionally signed) or Sign, from the recipient or signer
     * screen. A card signer goes to the PIN step; a software signer is tried
     * without a passphrase first and asks for one only when its key is
     * protected, as the Encrypt screen does.
     */
    fun start() {
        val s = _state.value
        blockReason(s)?.let { msg ->
            _state.update { it.copy(errorMessage = msg) }
            return
        }
        pqcDecision = null
        if (s.signsWithCard()) {
            _state.update { it.copy(phase = ProcessTextPhase.CardPin, cardPin = "", errorMessage = null) }
            return
        }
        execute(passphrase = null)
    }

    /** The Passphrase step's button. */
    fun submitPassphrase() {
        val typed = _state.value.passphrase
        execute(passphrase = typed.ifEmpty { null })
    }

    /** The post-quantum prompt's answer: true signs anyway, false sends unsigned. */
    fun answerPqcPrompt(signAnyway: Boolean) {
        pqcDecision = signAnyway
        val pass = pqcPendingPassphrase
        pqcPendingPassphrase = null
        _state.update { it.copy(showPqcPrompt = false) }
        execute(passphrase = pass)
    }

    fun dismissPqcPrompt() {
        pqcPendingPassphrase = null
        pqcDecision = null
        _state.update { it.copy(showPqcPrompt = false, phase = ProcessTextPhase.PickRecipients) }
    }

    private fun execute(passphrase: String?) {
        val s = _state.value
        // 4.8.0 (item 4d): a typed passphrase is good for this one attempt.
        _state.update { it.copy(phase = ProcessTextPhase.Processing, errorMessage = null, passphrase = "") }
        viewModelScope.launch {
            try {
                val output = when (s.mode) {
                    ProcessText.Mode.SIGN -> signCleartext(s, passphrase)
                    ProcessText.Mode.ENCRYPT -> encrypt(s, passphrase) ?: return@launch
                }
                _state.update { it.copy(phase = ProcessTextPhase.Result, output = output) }
            } catch (e: SigningError.PassphraseRequired) {
                _state.update { it.copy(phase = ProcessTextPhase.Passphrase, errorMessage = null) }
            } catch (e: SigningError.InvalidPassphrase) {
                _state.update {
                    it.copy(
                        phase = ProcessTextPhase.Passphrase,
                        errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase_retry),
                    )
                }
            } catch (e: RecipientProblem) {
                _state.update { it.copy(phase = ProcessTextPhase.Error, errorMessage = e.message) }
            } catch (e: SigningError) {
                _state.update {
                    it.copy(
                        phase = ProcessTextPhase.Error,
                        errorMessage = ErrorText.localize(e.message)
                            ?: PGPonyApp.instance.getString(R.string.card_sign_failed_generic),
                    )
                }
            } catch (e: Throwable) {
                _state.update {
                    it.copy(
                        phase = ProcessTextPhase.Error,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.share_target_error_generic_format,
                            ErrorText.detail(e.message) ?: e.javaClass.simpleName,
                        ),
                    )
                }
            }
        }
    }

    /** A selected recipient that gave no key, or none at all; stops the run. */
    private class RecipientProblem(message: String) : Exception(message)

    /**
     * RC3 §N (#34): the Encrypt screen's signing defaults. The key's
     * signing_defaults row can name another software key pair to sign with
     * when signing only, when every recipient is post-quantum, or otherwise.
     * Mirrors EncryptDecryptViewModel.resolveEffectiveSigner.
     */
    private suspend fun effectiveSigner(
        base: PGPKeyEntity,
        recipients: List<PGPKeyEntity>,
        signOnly: Boolean,
    ): PGPKeyEntity {
        val row = withContext(Dispatchers.IO) { repository.signingDefaultsFor(base.fingerprint) } ?: return base
        val pickedFp = when {
            signOnly -> row.signOnlySignerFingerprint
            recipients.isNotEmpty() && recipients.all { it.algorithm.isPostQuantum } -> row.pqcSignerFingerprint
            else -> row.classicalSignerFingerprint
        } ?: return base
        if (pickedFp == base.fingerprint) return base
        val picked = withContext(Dispatchers.IO) { repository.getByFingerprint(pickedFp) }
        return if (picked != null && picked.isKeyPair && !picked.isCardBacked && !picked.isRevoked) picked else base
    }

    /** The composite key's unlocked signing material, or the typed errors the run maps to prompts. */
    private suspend fun compositeInfo(fingerprint: String, passphrase: String?) =
        withContext(Dispatchers.IO) {
            val info = try {
                repository.loadCompositeKeyInfo(fingerprint, passphrase?.toCharArray())
            } catch (e: Exception) {
                // #26: a wrong passphrase fails the parse.
                throw SigningError.InvalidPassphrase()
            } ?: throw SigningError.NoSigningKey()
            if (info.signingSecret == null) throw SigningError.PassphraseRequired()
            info
        }

    /** Sign: a cleartext signed message, as the Encrypt screen's Sign mode makes. */
    private suspend fun signCleartext(s: ProcessTextUiState, passphrase: String?): String {
        val base = s.signer ?: throw SigningError.NoSigningKey()
        val signer = effectiveSigner(base, emptyList(), signOnly = true)
        return if (signer.algorithm.isCompositeSign) {
            val info = compositeInfo(signer.fingerprint, passphrase)
            withContext(Dispatchers.Default) {
                CompositeDocumentSigner.signCleartext(
                    info.signingSuite, info.signingSecret!!, info.signingFingerprint, s.text
                )
            }
        } else {
            val ring = withContext(Dispatchers.IO) { repository.loadSecretKeyRing(signer.fingerprint) }
                ?: throw SigningError.NoSigningKey()
            withContext(Dispatchers.Default) {
                SigningService.shared.signClear(text = s.text, secretKeyRing = ring, passphrase = passphrase)
            }
        }
    }

    private suspend fun loadRecipients(s: ProcessTextUiState) =
        withContext(Dispatchers.IO) {
            val byFp = s.recipients.associateBy { it.fingerprint.uppercase() }
            ShareRecipients.load(
                fingerprints = s.selectedRecipients,
                isV4Algo35 = { fp ->
                    byFp[fp.uppercase()]?.algorithm == com.pgpony.android.crypto.KeyAlgorithm.MLKEM768_X25519_V4
                },
                ring = { fp -> repository.loadEncryptionRecipientRing(fp) },
                v4Algo35 = { fp -> repository.loadV4Algo35Recipient(fp) }
            )
        }

    /** 4.6.1 (#67): the Quick Action's rule; a recipient that gave no key stops the run. */
    private fun checkRecipients(s: ProcessTextUiState, loaded: ShareRecipients.Loaded<*, *>) {
        val app = PGPonyApp.instance
        if (!loaded.isComplete) {
            val byFp = s.recipients.associateBy { it.fingerprint.uppercase() }
            val names = loaded.unusable.joinToString(", ") { fp ->
                byFp[fp.uppercase()]?.let { e -> e.userID.ifBlank { e.shortFingerprint } } ?: fp
            }
            throw RecipientProblem(app.getString(R.string.share_target_encrypt_recipient_unusable_format, names))
        }
        if (loaded.isEmpty) throw RecipientProblem(app.getString(R.string.share_target_encrypt_recipients_empty))
    }

    /**
     * Encrypt, signed when the user chose to. Returns null when the run stops
     * for the post-quantum prompt (the state already shows it).
     */
    private suspend fun encrypt(s: ProcessTextUiState, passphrase: String?): String? {
        val crypto = PGPCryptoService.shared
        val recipients = loadRecipients(s)
        checkRecipients(s, recipients)
        val base = s.signer?.takeIf { s.signMessage }
        val signer = base?.let { effectiveSigner(it, selectedRecipientEntities(s), signOnly = false) }
        val signingRing = if (signer != null && !signer.algorithm.isCompositeSign) {
            withContext(Dispatchers.IO) { repository.loadSecretKeyRing(signer.fingerprint) }
                ?: throw SigningError.NoSigningKey()
        } else null
        val composite = if (signer != null && signer.algorithm.isCompositeSign) {
            compositeInfo(signer.fingerprint, passphrase)
        } else null

        // 4.6.0 (item 14): an ML-DSA signature to a v4 recipient reads in
        // PGPony but not in GnuPG or Thunderbird; ask first, as the Encrypt
        // screen does. 4.8.0 (item 4j): also a composite signing subkey.
        val pqcInV1 = (composite != null || withContext(Dispatchers.Default) { crypto.picksCompositeSubkey(signingRing) }) &&
            crypto.compositeSignatureInSeipdV1(recipients.rings, emptyMap(), recipients.v4Algo35)
        val decision = pqcDecision
        if (pqcInV1 && decision == null) {
            pqcPendingPassphrase = passphrase
            _state.update { it.copy(phase = ProcessTextPhase.PickRecipients, showPqcPrompt = true) }
            return null
        }
        val dropSignature = pqcInV1 && decision == false
        val cipher = withContext(Dispatchers.Default) {
            crypto.encrypt(
                data = s.text.toByteArray(Charsets.UTF_8),
                recipientPublicKeys = recipients.rings,
                signingSecretKey = signingRing,
                passphrase = passphrase,
                armor = true,
                v4Algo35Recipients = recipients.v4Algo35,
                compositeSignSuite = composite?.signingSuite,
                compositeSignSecret = composite?.signingSecret,
                compositeSignerFingerprint = composite?.signingFingerprint,
                compositeSignInSeipdV1 = !dropSignature,
            )
        }
        return String(cipher, Charsets.UTF_8)
    }

    // ── Card signer ───────────────────────────────────────────────────
    //
    // The card operation runs on the reader's thread with the card in the
    // field, so everything it needs is captured here and it calls only
    // blocking loaders. Same steps as the Encrypt screen's card route: the
    // card's signature slot names the key, the tolerant loader finds its
    // public ring (offline-primary layouts), and the [S]-slot key signs.

    fun onCardStarted() {
        _state.update { it.copy(phase = ProcessTextPhase.Processing, errorMessage = null) }
    }

    /**
     * The work for one tap, or null when the PIN is empty. [noSigKeyMsg] and
     * [pairFirstMsg] are resolved by the caller, which has a Context.
     */
    fun cardOperation(noSigKeyMsg: String, pairFirstMsg: String): ((OpenPgpCardSession) -> String)? {
        val s = _state.value
        val pin = s.cardPin.takeIf { it.isNotEmpty() }?.toByteArray(Charsets.UTF_8) ?: return null
        val text = s.text
        val mode = s.mode
        val selected = s.selectedRecipients.toList()
        val byFp = s.recipients.associateBy { it.fingerprint.uppercase() }
        val noRecipientsMsg = PGPonyApp.instance.getString(R.string.share_target_encrypt_recipients_empty)
        val unusableFormat = PGPonyApp.instance.getString(R.string.share_target_encrypt_recipient_unusable_format)
        _state.update { it.copy(cardPin = "") }
        return { session ->
            session.select()
            val fp = session.getApplicationRelatedData().sigFingerprint
                ?: throw OpenPgpCardException.Malformed(noSigKeyMsg)
            val pubRing = repository.loadPublicKeyRingByCardFingerprint(fp)
                ?: throw OpenPgpCardException.Malformed(pairFirstMsg)
            val signingKey = CardSigningService.shared.signingPublicKey(pubRing, fp)
            if (mode == ProcessText.Mode.SIGN) {
                CardSigningService.shared.signClear(session, signingKey, pin, text)
            } else {
                val loaded = ShareRecipients.load(
                    fingerprints = selected,
                    isV4Algo35 = { f ->
                        byFp[f.uppercase()]?.algorithm == com.pgpony.android.crypto.KeyAlgorithm.MLKEM768_X25519_V4
                    },
                    ring = { f -> repository.loadEncryptionRecipientRing(f) },
                    v4Algo35 = { f -> repository.loadV4Algo35Recipient(f) }
                )
                if (!loaded.isComplete) {
                    val names = loaded.unusable.joinToString(", ") { f ->
                        byFp[f.uppercase()]?.let { e -> e.userID.ifBlank { e.shortFingerprint } } ?: f
                    }
                    throw IllegalStateException(String.format(unusableFormat, names))
                }
                if (loaded.isEmpty) throw IllegalStateException(noRecipientsMsg)
                val out = PGPCryptoService.shared.encrypt(
                    data = text.toByteArray(Charsets.UTF_8),
                    recipientPublicKeys = loaded.rings,
                    cardSession = session,
                    cardPin = pin,
                    cardSigningPublicKey = signingKey,
                    armor = true,
                    v4Algo35Recipients = loaded.v4Algo35,
                )
                String(out, Charsets.UTF_8)
            }
        }
    }

    fun onCardSuccess(output: String) {
        _state.update { it.copy(phase = ProcessTextPhase.Result, output = output, errorMessage = null) }
    }

    fun onCardFailure(message: String) {
        _state.update { it.copy(phase = ProcessTextPhase.Error, errorMessage = message) }
    }

    companion object {
        fun factory(repository: KeyRepository) = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T =
                ProcessTextViewModel(repository) as T
        }
    }
}
