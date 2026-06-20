// EncryptScreen.kt / DecryptScreen.kt
// PGPony Android
//
// Encrypt and Decrypt tab UIs.
//
// Phase A2: EncryptScreen gains a three-segment mode picker at the top
// (Text / Sign / File). Sign mode replaces the recipient picker with a
// read-only "Sign as" row, swaps the button to "Sign", and routes to
// `viewModel.signOnly()` which produces an RFC 4880 §7 clear-signed
// message. File mode is rendered but disabled — its full picker flow
// ships with Phase A10.
//
// Phase A5: the static "Sign as" row in both sign-while-encrypting
// (EncryptModeBody) and sign-only (SignModeBody) modes is replaced by
// a proper picker. When the user has 2+ key pairs, tapping the row
// opens SignAsSheet to choose between them. When there's only one key
// pair, the row stays static (no choice to make). Auto-default to
// the user's default key on first appearance is unchanged.
//
// Phase A10b: file mode is now functional. New FileSection composable
// renders the picker chip / file card / "Choose Different File" row.
// FILE segment is enabled. The picker uses MainActivity.startDocumentPicker
// (A10a Fix1 pattern) instead of Compose's rememberLauncherForActivityResult
// to dodge the FragmentActivity 16-bit requestCode crash. Result of a
// successful encrypt now also opens a modal bottom sheet — text mode
// → EncryptionResultScreen, file mode → FileEncryptionResultScreen.
// The original inline output block in EncryptScreen stays as a
// fallback view (the sheet is one-shot, the inline block persists
// until input changes). FileModePlaceholder is kept around but
// unused.

package com.pgpony.android.ui.encrypt

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.core.content.FileProvider
import java.io.File
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.MainActivity
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.crypto.card.CardSigningService
import com.pgpony.android.crypto.card.CardDecryptService
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.card.OpenPgpCardException
import com.pgpony.android.ui.components.KeyCard
import com.pgpony.android.ui.components.ScreenTooltip
import com.pgpony.android.ui.decrypt.SignerLookupSheet
import com.pgpony.android.ui.decrypt.VerificationBanner
import com.pgpony.android.ui.keyring.BiometricAvailability
import com.pgpony.android.ui.keyring.BiometricGate
import com.pgpony.android.ui.util.ClipboardService
import com.pgpony.android.ui.util.rememberHaptics

// ── Encrypt Screen ─────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EncryptScreen(viewModel: EncryptDecryptViewModel) {
    val state by viewModel.encryptState.collectAsState()
    val clipboard = LocalClipboardManager.current
    val encryptContext = LocalContext.current  // Phase A12: for ClipboardService routing
    val haptics = rememberHaptics()

    // HW Phase 2b-step2 — card signing on the Sign tab. NFC needs the
    // Activity, so the tap is driven here (mirroring the test screen):
    // tapping Sign with a card key shows a PIN prompt, then a tap, then
    // results are reported back to the VM via onCardSign* hooks.
    val cardActivity = encryptContext as? MainActivity
    var showCardSignPin by remember { mutableStateOf(false) }
    var cardSignPin by remember { mutableStateOf("") }
    var cardSignWaiting by remember { mutableStateOf(false) }

    // Refresh keys every time screen appears
    LaunchedEffect(Unit) { viewModel.refreshKeys() }

    // Fire success haptic exactly once per encrypt or sign completion.
    // Phase A2: SignSuccess is its own event so the sign path can fire
    // its own haptic without conflating with encrypt.
    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is EncryptDecryptViewModel.Event.EncryptSuccess,
                is EncryptDecryptViewModel.Event.SignSuccess -> haptics.success()
                else -> { /* DecryptSuccess belongs to DecryptScreen */ }
            }
        }
    }

    Scaffold(
        topBar = { TopAppBar(
            title = { Text(stringResource(R.string.encrypt_screen_title)) },
            actions = {
                val hasContent = state.inputText.isNotBlank() ||
                    state.outputText.isNotBlank() || state.selectedFileBytes != null
                IconButton(onClick = { viewModel.clearEncrypt() }, enabled = hasContent) {
                    Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.common_clear))
                }
            }
        ) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(8.dp))

            // ── Phase A2: Mode picker (Text / Sign / File) ──────────────
            //
            // SingleChoiceSegmentedButtonRow because the modes are mutually
            // exclusive. File mode is shown but disabled until Phase A10
            // adds the file-picker flow — disabled state is what signals
            // "coming soon" to the user without us hiding the slot.
            //
            // Phase A13: mode.displayName from the enum is replaced by
            // a local @Composable mapping to stringResource so the
            // segmented button labels are localized. EncryptMode's
            // displayName field is now unused by the UI (enum keeps it
            // for compatibility with any future non-UI code).
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                EncryptMode.entries.forEachIndexed { index, mode ->
                    val modeLabel = when (mode) {
                        EncryptMode.TEXT -> stringResource(R.string.encrypt_mode_text)
                        EncryptMode.SIGN -> stringResource(R.string.encrypt_mode_sign)
                        EncryptMode.FILE -> stringResource(R.string.encrypt_mode_file)
                        EncryptMode.PASSWORD -> stringResource(R.string.encrypt_mode_password)
                    }
                    SegmentedButton(
                        selected = state.mode == mode,
                        onClick = { viewModel.setMode(mode) },
                        shape = SegmentedButtonDefaults.itemShape(
                            index = index,
                            count = EncryptMode.entries.size
                        ),
                        // Phase A10b: FILE mode is now functional; the
                        // disabled-state placeholder is gone. All three
                        // modes are tappable.
                        enabled = true
                    ) {
                        Text(modeLabel)
                    }
                }
            }
            Spacer(modifier = Modifier.height(12.dp))

            // ── Input ──────────────────────────────────────────────────
            //
            // Phase A10b: text input is irrelevant in FILE mode (the
            // input is the picked file's bytes, not typed text), so
            // we conditionally hide it. The composable definition
            // stays inside this branch in source for additive-only
            // compatibility; only the rendered call site is gated.
            if (state.mode != EncryptMode.FILE) {
                OutlinedTextField(
                    value = state.inputText,
                    onValueChange = { viewModel.updateEncryptInput(it) },
                    label = {
                        Text(
                            when (state.mode) {
                                EncryptMode.SIGN -> stringResource(R.string.encrypt_input_label_message_to_sign)
                                else -> stringResource(R.string.encrypt_input_label_message_to_encrypt)
                            }
                        )
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp),
                    maxLines = 10
                )
                // Phase AU-3 — paste the clipboard into the message field,
                // matching the Import tab's paste affordance.
                Spacer(modifier = Modifier.height(8.dp))
                FilledTonalButton(
                    onClick = {
                        clipboard.getText()?.text?.let { viewModel.updateEncryptInput(it) }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.ContentPaste, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        stringResource(R.string.common_paste_from_clipboard),
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            // ── Mode-specific body ─────────────────────────────────────
            when (state.mode) {
                EncryptMode.TEXT -> EncryptModeBody(state = state, viewModel = viewModel)
                EncryptMode.SIGN -> SignModeBody(state = state, viewModel = viewModel)
                // Phase A10b: route to the real FileSection. The old
                // FileModePlaceholder composable stays in this file
                // (additive-only) but is no longer rendered.
                EncryptMode.FILE -> FileSection(state = state, viewModel = viewModel)
                // Phase A1: passphrase-only (`gpg -c`) — no recipient picker.
                EncryptMode.PASSWORD -> PasswordModeBody(state = state, viewModel = viewModel)
            }

            Spacer(modifier = Modifier.height(12.dp))

            // ── Errors + primary action ────────────────────────────────
            state.errorMessage?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                Spacer(modifier = Modifier.height(8.dp))
            }

            // The primary action is mode-dependent. Sign-mode bypasses
            // the encrypt() path entirely and routes to signOnly() so
            // there's no recipient requirement and no symmetric-key
            // material ever touches the message.
            //
            // Phase A10b: FILE mode now routes to encryptFile() and is
            // gated on having both recipients and a picked file.
            Button(
                onClick = {
                    val runPrimaryAction: () -> Unit = {
                      when (state.mode) {
                        EncryptMode.SIGN -> {
                            // Card key → PIN prompt + tap (same as the test
                            // screen). Software key → existing passphrase path.
                            if (state.signingKey?.isCardBacked == true) {
                                if (viewModel.signInputIsBlank()) {
                                    viewModel.reportNoSignInput()
                                } else {
                                    cardSignPin = ""
                                    showCardSignPin = true
                                }
                            } else {
                                viewModel.signOnly()
                            }
                        }
                        EncryptMode.TEXT -> {
                            // Encrypt-and-sign with a card key needs an NFC
                            // tap mid-encrypt → route to the PIN dialog (the
                            // confirm handler branches on mode). Plain encrypt
                            // (or signing with a software key) stays on the VM
                            // path. Fall through to encrypt() when recipients
                            // or input are missing so its validation errors
                            // surface as usual.
                            val cardSign = state.signMessage && state.signingKey?.isCardBacked == true
                            if (cardSign && state.selectedRecipients.isNotEmpty() && state.inputText.isNotBlank()) {
                                cardSignPin = ""
                                showCardSignPin = true
                            } else {
                                viewModel.encrypt()
                            }
                        }
                        EncryptMode.FILE -> {
                            // File encrypt-and-sign with a card key also taps
                            // mid-encrypt → same PIN dialog. Otherwise the VM
                            // file path (software key or no signing).
                            val cardSign = state.signMessage && state.signingKey?.isCardBacked == true
                            if (cardSign && state.selectedRecipients.isNotEmpty() && state.selectedFileBytes != null) {
                                cardSignPin = ""
                                showCardSignPin = true
                            } else {
                                viewModel.encryptFile()
                            }
                        }
                        // Phase A1: symmetric / passphrase-only. No recipients,
                        // no signing key, no card — straight to the VM, which
                        // validates the passphrase + confirm.
                        EncryptMode.PASSWORD -> viewModel.encryptWithPassword()
                      }
                    }
                    // HW Phase 3 / "fingerprint to sign" — gate SOFTWARE
                    // signing behind biometrics when the user enabled it.
                    //
                    // 6.2.1 (Android port of iOS hardware-key biometric fix):
                    // the CARD sign path is no longer exempt. When the user
                    // enabled "require biometric for signing", a card-backed
                    // signing key is gated the same way — biometric runs first,
                    // and only on success does runPrimaryAction proceed to the
                    // card PIN dialog + NFC tap. When the setting is OFF,
                    // willCardSign stays false and the card flow goes straight
                    // to PIN + tap as before (the card is the primary factor;
                    // we don't force an extra step on people who didn't ask).
                    val willSoftwareSign = when (state.mode) {
                        EncryptMode.SIGN -> state.signingKey?.isCardBacked != true
                        else -> state.signMessage && state.signingKey != null &&
                            state.signingKey?.isCardBacked != true
                    }
                    // Mirrors the exact conditions that would otherwise pop the
                    // card PIN dialog (showCardSignPin = true) in runPrimaryAction.
                    val willCardSign = when (state.mode) {
                        EncryptMode.SIGN -> state.signingKey?.isCardBacked == true &&
                            !viewModel.signInputIsBlank()
                        EncryptMode.TEXT -> state.signMessage &&
                            state.signingKey?.isCardBacked == true &&
                            state.selectedRecipients.isNotEmpty() && state.inputText.isNotBlank()
                        EncryptMode.FILE -> state.signMessage &&
                            state.signingKey?.isCardBacked == true &&
                            state.selectedRecipients.isNotEmpty() && state.selectedFileBytes != null
                        // Phase A1: password mode never signs with a card.
                        EncryptMode.PASSWORD -> false
                    }
                    val signPrefs = encryptContext.getSharedPreferences(
                        "pgpony_prefs", android.content.Context.MODE_PRIVATE
                    )
                    if ((willSoftwareSign || willCardSign) && signPrefs.getBoolean("biometric_sign", false) &&
                        cardActivity != null &&
                        BiometricGate.canAuthenticate(cardActivity) == BiometricAvailability.Available
                    ) {
                        BiometricGate.authenticate(
                            activity = cardActivity,
                            title = encryptContext.getString(R.string.sign_biometric_prompt_title),
                            subtitle = encryptContext.getString(R.string.sign_biometric_prompt_subtitle),
                            onSuccess = runPrimaryAction,
                            onError = { _, _ -> }
                        )
                    } else {
                        runPrimaryAction()
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.isProcessing && when (state.mode) {
                    EncryptMode.FILE -> state.selectedFileBytes != null
                        && state.selectedRecipients.isNotEmpty()
                    else -> true
                }
            ) {
                if (state.isProcessing) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(
                    when (state.mode) {
                        EncryptMode.SIGN -> stringResource(R.string.encrypt_action_sign)
                        EncryptMode.FILE -> stringResource(R.string.encrypt_action_encrypt_file)
                        else -> stringResource(R.string.encrypt_action_encrypt)
                    }
                )
            }
            Spacer(modifier = Modifier.height(16.dp))

            // Phase A5 — "Sign a file" entry, FILE mode only: sign a file on
            // its own (no encryption) → standalone detached signature.
            if (state.mode == EncryptMode.FILE) {
                OutlinedButton(
                    onClick = { viewModel.openSignFileSheet() },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.Edit, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.sign_file_entry_button))
                }
                Spacer(modifier = Modifier.height(16.dp))
            }

            // ── Output ─────────────────────────────────────────────────
            if (state.outputText.isNotBlank()) {
                Text(
                    when (state.mode) {
                        EncryptMode.SIGN -> stringResource(R.string.encrypt_output_signed_message)
                        else -> stringResource(R.string.encrypt_output_encrypted_message)
                    },
                    style = MaterialTheme.typography.labelLarge
                )
                Spacer(modifier = Modifier.height(4.dp))
                OutlinedTextField(
                    value = state.outputText,
                    onValueChange = {},
                    readOnly = true,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp),
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    maxLines = 15
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = {
                        // Phase A12: route through ClipboardService so the
                        // user's auto-clear preference is honored. The
                        // service writes to the system clipboard then
                        // schedules a coroutine clear after the configured
                        // interval (or no-op if auto-clear is off).
                        //
                        // Phase A13: "PGPony" label string is the app
                        // name resource — generic since armored ciphertext
                        // is safe to surface in clipboard previews.
                        ClipboardService.copyText(encryptContext, state.outputText, label = encryptContext.getString(R.string.app_name))
                        haptics.tap()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.ContentCopy, stringResource(R.string.common_button_copy))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.common_button_copy_to_clipboard))
                }
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = { viewModel.clearEncrypt() },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.Clear, stringResource(R.string.common_clear))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.common_clear))
                }
            }
            Spacer(modifier = Modifier.height(24.dp))
        }
    }

    // ── Phase A2: Sign-mode passphrase prompt ──────────────────────────
    //
    // Triggered when SigningService throws PassphraseRequired or
    // InvalidPassphrase. The dialog calls signOnly(passphrase) on confirm
    // and the ViewModel re-routes through the same flow with the new
    // passphrase. On wrong passphrase, the error message renders inside
    // the dialog rather than dismissing it, so the user doesn't have to
    // retype the message.
    //
    // Phase A10e: inline AlertDialog block extracted to SignPassphraseDialog
    // composable which adds key context (name + fingerprint), the lock
    // icon, and the "Encrypt Without Signing" escape hatch in TEXT/FILE
    // modes. LegacySignPassphraseDialog preserves the previous body.
    if (state.showSignPassphraseDialog) {
        SignPassphraseDialog(state = state, viewModel = viewModel)
    }

    // ── HW Phase 2b-step2: card-sign PIN prompt + tap ──────────────────
    //
    // Strings captured here (composable scope) because the NFC operation
    // lambda runs on a binder thread and can't call stringResource.
    val cardNoSigKeyMsg = stringResource(R.string.card_sign_no_sig_key)
    val cardPairFirstMsg = stringResource(R.string.card_sign_pair_first)
    val cardNfcUnavailMsg = stringResource(R.string.card_scan_nfc_unavailable)
    val cardSignFailedMsg = stringResource(R.string.card_sign_failed_generic)
    val cardNoRecipientsMsg = stringResource(R.string.encdec_error_no_recipients)
    val cardNoFileMsg = stringResource(R.string.encdec_error_no_file_to_encrypt)

    if (showCardSignPin) {
        AlertDialog(
            onDismissRequest = { showCardSignPin = false; cardSignPin = "" },
            icon = { Icon(Icons.Filled.Nfc, contentDescription = null) },
            title = { Text(stringResource(R.string.card_sign_dialog_title)) },
            text = {
                Column {
                    Text(
                        stringResource(R.string.card_sign_dialog_message),
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = cardSignPin,
                        onValueChange = { cardSignPin = it },
                        label = { Text(stringResource(R.string.card_sign_pin_label)) },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled = cardSignPin.isNotEmpty(),
                    onClick = {
                        showCardSignPin = false
                        val pin = cardSignPin
                        cardSignPin = ""
                        val msg = state.inputText
                        viewModel.onCardSignStarted()
                        cardSignWaiting = true
                        val recipientFps = state.selectedRecipients.map { it.fingerprint }
                        // FILE mode encrypts-and-signs the picked bytes
                        // (binary, armor=false) → file result sheet. SIGN
                        // clear-signs text; TEXT encrypts-and-signs text —
                        // both produce armored String → output sheet. The
                        // op return types differ, so FILE takes its own
                        // startCardOperation call.
                        val started: Boolean? = if (state.mode == EncryptMode.FILE) {
                            val fileBytes = state.selectedFileBytes
                            val fileName = state.selectedFileName
                            cardActivity?.startCardOperation({ session ->
                                session.select()
                                val fp = session.getApplicationRelatedData().sigFingerprint
                                    ?: throw OpenPgpCardException.Malformed(cardNoSigKeyMsg)
                                val pubRing = PGPonyApp.instance.keyRepository.loadPublicKeyRing(fp)
                                    ?: throw OpenPgpCardException.Malformed(cardPairFirstMsg)
                                if (fileBytes == null) throw OpenPgpCardException.Malformed(cardNoFileMsg)
                                val recipientRings = recipientFps.mapNotNull {
                                    PGPonyApp.instance.keyRepository.loadPublicKeyRing(it)
                                }
                                if (recipientRings.isEmpty()) {
                                    throw OpenPgpCardException.Malformed(cardNoRecipientsMsg)
                                }
                                PGPCryptoService.shared.encrypt(
                                    data = fileBytes,
                                    recipientPublicKeys = recipientRings,
                                    cardSession = session,
                                    cardPin = pin.toByteArray(Charsets.UTF_8),
                                    cardSigningPublicKey = pubRing.publicKey,
                                    filename = fileName,
                                    armor = false
                                )
                            }) { result ->
                                cardSignWaiting = false
                                cardActivity?.stopCardScan()
                                result
                                    .onSuccess { viewModel.onCardEncryptFileSuccess(it) }
                                    .onFailure { e -> viewModel.onCardSignFailure(e.message ?: cardSignFailedMsg) }
                            }
                        } else {
                            // SIGN clear-signs; TEXT encrypts-and-signs.
                            val encryptAndSign = state.mode == EncryptMode.TEXT
                            cardActivity?.startCardOperation({ session ->
                                session.select()
                                val fp = session.getApplicationRelatedData().sigFingerprint
                                    ?: throw OpenPgpCardException.Malformed(cardNoSigKeyMsg)
                                val pubRing = PGPonyApp.instance.keyRepository.loadPublicKeyRing(fp)
                                    ?: throw OpenPgpCardException.Malformed(cardPairFirstMsg)
                                if (encryptAndSign) {
                                    val recipientRings = recipientFps.mapNotNull {
                                        PGPonyApp.instance.keyRepository.loadPublicKeyRing(it)
                                    }
                                    if (recipientRings.isEmpty()) {
                                        throw OpenPgpCardException.Malformed(cardNoRecipientsMsg)
                                    }
                                    val out = PGPCryptoService.shared.encrypt(
                                        data = msg.toByteArray(Charsets.UTF_8),
                                        recipientPublicKeys = recipientRings,
                                        cardSession = session,
                                        cardPin = pin.toByteArray(Charsets.UTF_8),
                                        cardSigningPublicKey = pubRing.publicKey,
                                        armor = true
                                    )
                                    String(out, Charsets.UTF_8)
                                } else if (state.detachedSignature) {
                                    val sig = CardSigningService.shared.signDetached(
                                        session, pubRing.publicKey, pin.toByteArray(Charsets.UTF_8),
                                        msg.toByteArray(Charsets.UTF_8)
                                    )
                                    String(sig, Charsets.UTF_8)
                                } else {
                                    CardSigningService.shared.signClear(
                                        session, pubRing.publicKey, pin.toByteArray(Charsets.UTF_8), msg
                                    )
                                }
                            }) { result ->
                                cardSignWaiting = false
                                cardActivity?.stopCardScan()
                                result
                                    .onSuccess { viewModel.onCardSignSuccess(it) }
                                    .onFailure { e -> viewModel.onCardSignFailure(e.message ?: cardSignFailedMsg) }
                            }
                        }
                        if (started != true) {
                            cardSignWaiting = false
                            viewModel.onCardSignFailure(cardNfcUnavailMsg)
                        }
                    }
                ) { Text(stringResource(R.string.card_sign_button)) }
            },
            dismissButton = {
                TextButton(onClick = { showCardSignPin = false; cardSignPin = "" }) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        )
    }

    if (cardSignWaiting) {
        AlertDialog(
            onDismissRequest = { },
            icon = { Icon(Icons.Filled.Contactless, contentDescription = null) },
            title = { Text(stringResource(R.string.card_sign_dialog_title)) },
            text = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(stringResource(R.string.card_sign_hold_card))
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    cardSignWaiting = false
                    cardActivity?.stopCardScan()
                }) { Text(stringResource(R.string.common_button_cancel)) }
            }
        )
    }

    // ── First-visit tooltip (Phase 4) ───────────────────────────────────
    ScreenTooltip(
        tooltipKey = "encrypt_input",
        message = stringResource(R.string.encrypt_tooltip_input)
    )

    // ── Phase A10b: Result sheets ──────────────────────────────────────
    //
    // Shown one-shot when encrypt() / signOnly() / encryptFile()
    // completes successfully. The state flag is reset via the
    // dismiss action; the underlying outputText/encryptedFileBytes
    // are kept across dismissal so a second tap of Encrypt regenerates
    // them fresh. Text and sign modes share EncryptionResultScreen
    // (it adapts via state.mode); file mode has its own screen with
    // a binary-aware Save action.
    if (state.showEncryptResultSheet && state.outputText.isNotBlank()) {
        EncryptionResultScreen(
            state = state,
            onDismiss = { viewModel.dismissEncryptResult() }
        )
    }
    if (state.showFileEncryptResultSheet && state.encryptedFileBytes != null) {
        FileEncryptionResultScreen(
            state = state,
            onDismiss = { viewModel.dismissFileEncryptResult() }
        )
    }

    // Phase A5 — "Sign a file" sheet (Encrypt tab, FILE mode).
    if (state.showSignFileSheet) {
        SignFileSheet(state = state, viewModel = viewModel)
    }
}

// ── Phase A10d: Recipient picker polish + ASCII armor toggle ───────────
//
// Two pieces shipped together because they both touch the encrypt UI:
//
//   1. RecipientPickerCard — replaces the two inline recipient-list
//      blocks that previously lived in EncryptModeBody (text mode) and
//      FileSection (file mode), each rendering the same Checkbox row
//      per available key. The new card adds:
//
//        • Selected chips row (FlowRow of AssistChips with trailing
//          Close icon) above the list — quick visual confirmation of
//          who the message goes to, tap a chip to remove a recipient.
//        • Search field above the list (only surfaced when 4+ keys
//          exist; below that, scanning the rows is just as fast and
//          the field would be visual noise).
//        • Select All / Clear buttons that wire to two new ViewModel
//          functions (selectAllRecipients / clearRecipients) — useful
//          when the keyring grows beyond a handful of keys. iOS does
//          not surface these; the Android picker exceeds parity here.
//        • Same row shape per key (Checkbox + name + short fingerprint)
//          but filtered against the search query.
//
//      Both legacy inline blocks are preserved verbatim below as
//      `LegacyInlineRecipientList` with @Suppress("unused") so the
//      additive-edit rule holds — nothing about the previous render
//      path is removed from this file, only un-called.
//
//   2. AsciiArmorToggleRow — Switch row that drives the new
//      state.asciiArmor field. iOS labels the toggle "ASCII Armor
//      Output"; we use the same label plus a one-line subtitle
//      explaining the off-state behavior (binary output → save flow).
//      Only added to text-mode (EncryptModeBody), since file-mode
//      is always binary and sign-only's clear-signed output is
//      always armored by definition.

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun RecipientPickerCard(
    state: EncryptUiState,
    viewModel: EncryptDecryptViewModel
) {
    var showPicker by remember { mutableStateOf(false) }

    Text(stringResource(R.string.encrypt_recipients_label), style = MaterialTheme.typography.labelLarge)
    Spacer(modifier = Modifier.height(4.dp))

    if (state.availableRecipients.isEmpty()) {
        Text(
            stringResource(R.string.encrypt_recipients_no_keys),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        return
    }

    // Selected-recipients chip row. FlowRow lets chips wrap onto
    // multiple lines if the user picks many recipients — important
    // because long names + 8-char fingerprints don't always fit one
    // line at typical phone widths. AssistChip's trailing icon slot
    // hosts a Close icon; tapping the chip removes the recipient.
    if (state.selectedRecipients.isNotEmpty()) {
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            state.selectedRecipients.forEach { key ->
                // Display label fallback chain: userName → userEmail →
                // shortFingerprint. Computed as a local val to avoid
                // any parser ambiguity from chained .ifBlank across
                // lines inside the @Composable lambda.
                val chipLabel = when {
                    key.userName.isNotBlank() -> key.userName
                    key.userEmail.isNotBlank() -> key.userEmail
                    else -> key.shortFingerprint
                }
                AssistChip(
                    onClick = { viewModel.toggleRecipient(key) },
                    label = {
                        Text(
                            chipLabel,
                            style = MaterialTheme.typography.bodySmall
                        )
                    },
                    trailingIcon = {
                        Icon(
                            Icons.Filled.Close,
                            contentDescription = stringResource(R.string.encrypt_recipients_remove_format, chipLabel),
                            modifier = Modifier.size(16.dp)
                        )
                    }
                )
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
    }

    // Phase E - collapse the always-visible recipient checkbox list into a
    // single selector that opens a multi-select sheet, mirroring the Decrypt
    // key picker. Multi-recipient encryption is preserved: the sheet is
    // multi-select and the chip row above shows the current selection.
    OutlinedButton(
        onClick = { showPicker = true },
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            if (state.selectedRecipients.isEmpty())
                stringResource(R.string.encrypt_recipients_choose)
            else
                stringResource(
                    R.string.encrypt_recipients_selected_count,
                    state.selectedRecipients.size
                ),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f)
        )
        Icon(Icons.Filled.ArrowDropDown, contentDescription = null)
    }

    if (showPicker) {
        RecipientPickerSheet(
            available = state.availableRecipients,
            selected = state.selectedRecipients,
            onToggle = { viewModel.toggleRecipient(it) },
            onSelectAll = { viewModel.selectAllRecipients() },
            onClear = { viewModel.clearRecipients() },
            onDismiss = { showPicker = false }
        )
    }
}


@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RecipientPickerSheet(
    available: List<PGPKeyEntity>,
    selected: List<PGPKeyEntity>,
    onToggle: (PGPKeyEntity) -> Unit,
    onSelectAll: () -> Unit,
    onClear: () -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var query by remember { mutableStateOf("") }

    fun matches(key: PGPKeyEntity): Boolean {
        if (query.isBlank()) return true
        val q = query.trim().lowercase()
        return key.userName.lowercase().contains(q) ||
            key.userEmail.lowercase().contains(q) ||
            key.fingerprint.lowercase().contains(q)
    }

    val filtered = available.filter { matches(it) }
    val allSelected = available.isNotEmpty() && selected.size == available.size
    val anySelected = selected.isNotEmpty()

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .padding(bottom = 24.dp)
        ) {
            Text(
                stringResource(R.string.encrypt_recipients_choose),
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text(stringResource(R.string.encrypt_recipients_search_label)) },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (!allSelected) {
                    TextButton(onClick = onSelectAll) {
                        Text(
                            stringResource(R.string.encrypt_recipients_select_all),
                            style = MaterialTheme.typography.labelMedium
                        )
                    }
                }
                Spacer(modifier = Modifier.weight(1f))
                if (anySelected) {
                    TextButton(onClick = onClear) {
                        Text(
                            stringResource(R.string.encrypt_recipients_clear),
                            style = MaterialTheme.typography.labelMedium
                        )
                    }
                }
            }

            if (filtered.isEmpty()) {
                Text(
                    stringResource(R.string.encrypt_recipients_no_match_format, query),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 16.dp)
                )
            } else {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 360.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    filtered.forEach { key ->
                        val isSel = selected.any { it.fingerprint == key.fingerprint }
                        RecipientPickerRow(
                            key = key,
                            selected = isSel,
                            onClick = { onToggle(key) }
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.common_button_done))
            }
        }
    }
}

@Composable
private fun RecipientPickerRow(
    key: PGPKeyEntity,
    selected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(
            checked = selected,
            onCheckedChange = { onClick() }
        )
        Spacer(modifier = Modifier.width(4.dp))
        if (key.isCardBacked) {
            Icon(
                Icons.Filled.Nfc,
                contentDescription = stringResource(R.string.decrypt_card_key_indicator),
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                key.userName.ifBlank { key.userEmail },
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                key.shortFingerprint,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// Legacy inline recipient list — kept verbatim per the additive-edit
// rule. This was the entire recipient-rendering block that lived
// inline inside EncryptModeBody and FileSection before A10d extracted
// the polished version into RecipientPickerCard. Not invoked from
// anywhere anymore; left here so the previous behavior is recoverable
// if RecipientPickerCard ever needs to be reverted in a hurry.
@Suppress("unused")
@Composable
private fun LegacyInlineRecipientList(
    state: EncryptUiState,
    viewModel: EncryptDecryptViewModel
) {
    Text("Recipients", style = MaterialTheme.typography.labelLarge)
    Spacer(modifier = Modifier.height(4.dp))
    if (state.availableRecipients.isEmpty()) {
        Text(
            "No keys available. Import or generate keys first.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    } else {
        state.availableRecipients.forEach { key ->
            val selected = state.selectedRecipients.any { it.fingerprint == key.fingerprint }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(
                    checked = selected,
                    onCheckedChange = { viewModel.toggleRecipient(key) }
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    "${key.userName.ifBlank { key.userEmail }} (${key.shortFingerprint})",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

// ASCII armor toggle. iOS uses a Form Toggle with a system-icon Label;
// Material 3 doesn't have a directly equivalent labeled-Switch primitive,
// so we use the same Switch + Column-of-Text pattern the sign-message
// row uses on this screen. Subtitle changes based on toggle state so
// the user understands what the off-state does (binary save flow).
@Composable
private fun AsciiArmorToggleRow(
    state: EncryptUiState,
    viewModel: EncryptDecryptViewModel
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Switch(
            checked = state.asciiArmor,
            onCheckedChange = { viewModel.setAsciiArmor(it) }
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                stringResource(R.string.encrypt_armor_toggle_title),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                if (state.asciiArmor) {
                    stringResource(R.string.encrypt_armor_toggle_subtitle_armored)
                } else {
                    stringResource(R.string.encrypt_armor_toggle_subtitle_binary)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// ── Phase A2: Mode-specific sub-Composables ────────────────────────────

@Composable
private fun EncryptModeBody(state: EncryptUiState, viewModel: EncryptDecryptViewModel) {
    // Phase A10d: inline Checkbox-row list (still preserved as
    // LegacyInlineRecipientList for the additive-edit rule) is
    // replaced by the polished card. Same data flow — toggleRecipient
    // for per-row toggle, plus the new selectAll / clear actions.
    RecipientPickerCard(state = state, viewModel = viewModel)

    // ── Phase A2 fix: sign-while-encrypting toggle ─────────────────────
    //
    // The encrypt() backend already supports this — PGPCryptoService.encrypt
    // takes a `signingSecretKey` parameter and produces sign+encrypt output
    // when it's non-null, and EncryptDecryptViewModel.encrypt() picks up
    // `state.signMessage` to decide whether to load the secret key ring.
    // What was missing until now was the UI toggle. Surfacing it here so
    // the feature is reachable; Phase A5 will add the proper "Sign as"
    // picker that lets users choose between multiple key pairs.
    //
    // Hidden when no signing key is available (no keypairs in the keyring)
    // — there's nothing to sign with, so showing a disabled toggle would
    // just be confusing.
    val signingKey = state.signingKey
    if (signingKey != null) {
        Spacer(modifier = Modifier.height(12.dp))
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Switch(
                checked = state.signMessage,
                onCheckedChange = { viewModel.toggleSign(it) }
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.encrypt_also_sign_message_title),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    stringResource(
                        R.string.encrypt_also_sign_subtitle_format,
                        signingKey.userName.ifBlank { signingKey.userEmail }
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // ── Phase A5: Sign-as picker row ───────────────────────────────
        //
        // Only surfaced when:
        //   • signing is enabled (toggle on), AND
        //   • the user has 2+ key pairs to choose between.
        //
        // With a single key pair there's no meaningful choice; the toggle
        // alone is enough and the row would just be visual noise. The
        // sheet visibility is local to this composable — it's pure UI
        // state with no business value to keep on the ViewModel.
        if (state.signMessage && state.availableSigningKeys.size > 1) {
            var showSignAsSheet by remember { mutableStateOf(false) }
            Spacer(modifier = Modifier.height(8.dp))
            SignAsRow(
                key = state.signingKey,
                onClick = { showSignAsSheet = true }
            )
            if (showSignAsSheet) {
                SignAsSheet(
                    keyPairs = state.availableSigningKeys,
                    currentSelection = state.signingKey,
                    onSelect = { picked ->
                        viewModel.setSigningKey(picked)
                        showSignAsSheet = false
                    },
                    onDismiss = { showSignAsSheet = false }
                )
            }
        }
    }

    // ── Phase A10d: ASCII armor toggle ─────────────────────────────────
    //
    // Placed last in the option stack (matches iOS optionsSection order
    // where the armor toggle is below the sign toggle). Always shown in
    // text mode — there's no signing-key gate because the armor choice
    // is independent of whether you're signing.
    Spacer(modifier = Modifier.height(12.dp))
    AsciiArmorToggleRow(state = state, viewModel = viewModel)
}

/**
 * Phase A5 — tappable "Sign as" row used by both EncryptModeBody (when
 * sign-while-encrypting is enabled and 2+ key pairs exist) and
 * SignModeBody (always when 2+ key pairs exist). Renders the currently
 * selected key in a Surface-backed row with a chevron on the right
 * signaling tappability.
 *
 * When [key] is null, the row reads "No signing key selected" — this
 * is a defensive state that shouldn't happen since the caller gates on
 * key availability, but it doesn't crash the UI if it does.
 */
@Composable
private fun SignAsRow(
    key: com.pgpony.android.data.PGPKeyEntity?,
    onClick: () -> Unit
) {
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Filled.VpnKey,
                contentDescription = null,
                modifier = Modifier.size(20.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.encrypt_sign_as_label),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                // Name fallback chain: name → email → no-key placeholder.
                // Avoids the nested `?.ifBlank { }` form which doesn't
                // type-check cleanly (ifBlank lives on non-null String).
                val displayName = when {
                    key == null -> stringResource(R.string.encrypt_sign_as_no_key)
                    key.userName.isNotBlank() -> key.userName
                    else -> key.userEmail.ifBlank { stringResource(R.string.encrypt_sign_as_no_identity) }
                }
                Text(
                    displayName,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
                if (key != null) {
                    Text(
                        key.shortFingerprint,
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            // Chevron — same right-side affordance KeyDetailScreen uses
            // for tappable rows. iOS uses chevron.right; the lightweight
            // text fallback "›" keeps the bundle dep-free since we don't
            // import another icon for this.
            Text(
                "›",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun SignModeBody(state: EncryptUiState, viewModel: EncryptDecryptViewModel) {
    // Phase A2: read-only "Sign as" row showing the first available key
    // pair.
    // Phase A5: replaces the read-only row with a proper tappable
    // picker when the user has 2+ key pairs. With a single key pair
    // the row stays static (no choice to make). Auto-default to the
    // user's default key is unchanged — loadKeys() in the VM still
    // populates signingKey on screen entry.
    Text(stringResource(R.string.encrypt_sign_as_label), style = MaterialTheme.typography.labelLarge)
    Spacer(modifier = Modifier.height(4.dp))
    val key = state.signingKey
    if (key == null) {
        Text(
            stringResource(R.string.encrypt_sign_as_no_key_pair),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    } else if (state.availableSigningKeys.size > 1) {
        // Phase A5 — picker mode. Tappable row + sheet on tap.
        var showSignAsSheet by remember { mutableStateOf(false) }
        SignAsRow(
            key = key,
            onClick = { showSignAsSheet = true }
        )
        if (showSignAsSheet) {
            SignAsSheet(
                keyPairs = state.availableSigningKeys,
                currentSelection = key,
                onSelect = { picked ->
                    viewModel.setSigningKey(picked)
                    showSignAsSheet = false
                },
                onDismiss = { showSignAsSheet = false }
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            stringResource(R.string.encrypt_sign_only_explainer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    } else {
        // Phase A5 — single-key-pair mode. Static informational row,
        // matches the A2 visual exactly.
        Surface(
            shape = MaterialTheme.shapes.medium,
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Filled.VpnKey,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                    tint = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        key.userName.ifBlank { key.userEmail },
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        key.shortFingerprint,
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            stringResource(R.string.encrypt_sign_only_explainer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
    // Detached signature toggle — produces a standalone signature block
    // instead of a clear-signed message. Works for software + card keys.
    if (state.signingKey != null) {
        Spacer(modifier = Modifier.height(12.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.encrypt_sign_detached_label),
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    stringResource(R.string.encrypt_sign_detached_explainer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(modifier = Modifier.width(8.dp))
            Switch(
                checked = state.detachedSignature,
                onCheckedChange = { viewModel.setDetachedSignature(it) }
            )
        }
    }
}

@Suppress("unused") // Phase A10b: replaced by FileSection; kept for source diff legibility.
@Composable
private fun FileModePlaceholder() {
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Filled.HourglassEmpty,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                "File encryption arrives in the next update.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// ── Phase A10b: real file-mode body ────────────────────────────────────
//
// Two display states:
//   1. No file picked yet → tappable "Choose a File to Encrypt" card
//      with cloud-upload icon and primary tint
//   2. File picked → file chip showing icon / name / size / clear-X,
//      plus a small "Choose Different File" link
//
// Plus the recipient picker (reused from EncryptModeBody) and the
// signing toggle/picker (reused from EncryptModeBody) — file mode
// shares those exact UIs.
//
// File picker routes through MainActivity.startDocumentPicker rather
// than Compose's rememberLauncherForActivityResult, for the same
// FragmentActivity 16-bit-requestCode reason as A10a Fix1. We unwrap
// the ContextWrapper chain via findEncryptMainActivity() to handle
// any future case where this composable is rendered inside a dialog
// (currently it isn't — EncryptScreen is hosted directly in the
// NavHost — but the helper is cheap and future-proofs the call site).
@Composable
private fun PasswordModeBody(state: EncryptUiState, viewModel: EncryptDecryptViewModel) {
    // Phase A1: symmetric / passphrase-only encryption (`gpg -c`). No
    // recipient picker and no signing key — the message is sealed to the
    // passphrase typed here. The shared message text field above (rendered
    // for every non-FILE mode) is the plaintext input; these fields are the
    // passphrase + confirmation.
    val transformation =
        if (state.passwordVisible) VisualTransformation.None else PasswordVisualTransformation()

    Text(
        stringResource(R.string.encrypt_password_section_label),
        style = MaterialTheme.typography.labelLarge
    )
    Spacer(modifier = Modifier.height(4.dp))
    Text(
        stringResource(R.string.encrypt_password_hint),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(modifier = Modifier.height(8.dp))

    OutlinedTextField(
        value = state.passwordPassphrase,
        onValueChange = { viewModel.updatePasswordPassphrase(it) },
        label = { Text(stringResource(R.string.encrypt_password_passphrase_label)) },
        singleLine = true,
        visualTransformation = transformation,
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(modifier = Modifier.height(8.dp))

    OutlinedTextField(
        value = state.passwordConfirm,
        onValueChange = { viewModel.updatePasswordConfirm(it) },
        label = { Text(stringResource(R.string.encrypt_password_confirm_label)) },
        singleLine = true,
        visualTransformation = transformation,
        isError = state.passwordConfirm.isNotEmpty() &&
            state.passwordConfirm != state.passwordPassphrase,
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(modifier = Modifier.height(8.dp))

    FilledTonalButton(
        onClick = { viewModel.togglePasswordVisible() },
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            stringResource(
                if (state.passwordVisible) R.string.encrypt_password_hide
                else R.string.encrypt_password_show
            ),
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
private fun FileSection(state: EncryptUiState, viewModel: EncryptDecryptViewModel) {
    val context = LocalContext.current
    val activity = context.findEncryptMainActivity()

    val onPickFile: () -> Unit = {
        activity?.startDocumentPicker(
            // "*/*" alone matches anything — file mode encrypts
            // arbitrary content, so we don't filter by MIME type.
            // Some Android distros honor only the top-level type
            // and ignore EXTRA_MIME_TYPES on wildcard, so we pass a
            // single-element array here for predictability.
            arrayOf("*/*")
        ) { uri ->
            if (uri != null) {
                // Read the file bytes and metadata. We do this on the
                // main thread because the typical encrypt-target file
                // (a document, photo, archive) is well under 10 MB
                // and finishes in <100 ms; larger files would warrant
                // moving this off-thread.
                try {
                    val (name, size) = queryDocumentMetadata(context, uri)
                    val bytes = context.contentResolver.openInputStream(uri)?.use {
                        it.readBytes()
                    } ?: ByteArray(0)
                    viewModel.setFileToEncrypt(
                        name = name ?: uri.lastPathSegment?.substringAfterLast('/') ?: "file",
                        size = size ?: bytes.size.toLong(),
                        bytes = bytes
                    )
                } catch (e: Exception) {
                    // openInputStream failed (permission revoked,
                    // SAF transient error). The ViewModel's error
                    // slot would normally surface this, but we don't
                    // want to interrupt the user's mode-pick flow
                    // with an alert; let them tap Browse again.
                }
            }
        }
    }

    // 1) Picked-file chip OR empty-state card
    if (state.selectedFileName != null) {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Description,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .size(40.dp)
                            .padding(8.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            state.selectedFileName,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            maxLines = 1
                        )
                        Text(
                            state.selectedFileSize?.let { formatFileSize(it) } ?: "—",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(onClick = { viewModel.clearFile() }) {
                        Icon(
                            Icons.Filled.Close,
                            contentDescription = stringResource(R.string.encrypt_file_remove),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Spacer(modifier = Modifier.height(4.dp))
                TextButton(
                    onClick = onPickFile,
                    modifier = Modifier.align(Alignment.End)
                ) {
                    Icon(
                        Icons.Filled.SwapHoriz,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.encrypt_file_choose_different), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    } else {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.primary.copy(alpha = 0.08f),
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onPickFile)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 28.dp, horizontal = 16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    Icons.Filled.UploadFile,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(36.dp)
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    stringResource(R.string.encrypt_file_choose),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    stringResource(R.string.encrypt_file_any_type),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }

    Spacer(modifier = Modifier.height(16.dp))

    // 2) Recipient picker — Phase A10d: extracted to shared
    // RecipientPickerCard composable (search field, selected chips,
    // Select All / Clear buttons). The legacy inline Checkbox-row
    // list this block previously contained is preserved verbatim as
    // LegacyInlineRecipientList per the additive-edit rule.
    RecipientPickerCard(state = state, viewModel = viewModel)

    Spacer(modifier = Modifier.height(16.dp))

    // 3) Sign-message toggle + Sign-as row. Mirrors the EncryptModeBody
    // pattern exactly — same toggleSign() API, same SignAsRow/SignAsSheet
    // composition, same gating rules.
    val signingKey = state.signingKey
    if (signingKey != null) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Switch(
                checked = state.signMessage,
                onCheckedChange = { viewModel.toggleSign(it) }
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.encrypt_also_sign_file_title),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    stringResource(
                        R.string.encrypt_also_sign_subtitle_format,
                        signingKey.userName.ifBlank { signingKey.userEmail }
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        if (state.signMessage && state.availableSigningKeys.size > 1) {
            var showSignAsSheet by remember { mutableStateOf(false) }
            Spacer(modifier = Modifier.height(8.dp))
            SignAsRow(
                key = state.signingKey,
                onClick = { showSignAsSheet = true }
            )
            if (showSignAsSheet) {
                SignAsSheet(
                    keyPairs = state.availableSigningKeys,
                    currentSelection = state.signingKey,
                    onSelect = { picked ->
                        viewModel.setSigningKey(picked)
                        showSignAsSheet = false
                    },
                    onDismiss = { showSignAsSheet = false }
                )
            }
        }
    }
}

// ── Phase A10b: helpers ────────────────────────────────────────────────

/**
 * Walk up baseContext chain to find the MainActivity. EncryptScreen
 * lives directly in the NavHost so a simple `as? MainActivity` cast
 * would currently work, but doing it the safe way costs nothing and
 * matches the ImportKeyScreen Fix2 pattern. Future-proofs against a
 * later refactor that puts this composable inside a dialog/sheet.
 */
private tailrec fun Context.findEncryptMainActivity(): MainActivity? = when (this) {
    is MainActivity -> this
    is ContextWrapper -> baseContext.findEncryptMainActivity()
    else -> null
}

/**
 * Query the system's content resolver for a content:// URI's display
 * name and size. Returns (name, size) — either may be null if the
 * provider didn't supply that column (rare, but legal per the SAF
 * spec). Used by FileSection on encrypt input and by the import key
 * file path.
 */
private fun queryDocumentMetadata(
    context: Context,
    uri: android.net.Uri
): Pair<String?, Long?> {
    val cursor = context.contentResolver.query(uri, null, null, null, null)
        ?: return Pair(null, null)
    cursor.use { c ->
        if (!c.moveToFirst()) return Pair(null, null)
        val nameIdx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
        val sizeIdx = c.getColumnIndex(android.provider.OpenableColumns.SIZE)
        val name = if (nameIdx >= 0 && !c.isNull(nameIdx)) c.getString(nameIdx) else null
        val size = if (sizeIdx >= 0 && !c.isNull(sizeIdx)) c.getLong(sizeIdx) else null
        return Pair(name, size)
    }
}

/**
 * Format a byte count as a human-readable string. Uses base-10
 * units (KB / MB / GB) for parity with the iOS ByteCountFormatter
 * default, which is what users will compare against when looking at
 * the same file on macOS Finder.
 */
internal fun formatFileSize(bytes: Long): String {
    if (bytes < 1000) return "$bytes B"
    val kb = bytes / 1000.0
    if (kb < 1000) return "%.1f KB".format(kb)
    val mb = kb / 1000.0
    if (mb < 1000) return "%.1f MB".format(mb)
    val gb = mb / 1000.0
    return "%.1f GB".format(gb)
}

// ── Phase A10c: decrypt file picker UI ─────────────────────────────────
//
// Mirrors the A10b FileSection (encrypt side) for the decrypt
// flow. Two display states: tappable "Choose Encrypted File"
// empty-state card, or chip with name/size/clear-X plus a "Choose
// Different File" link. The file picker call still routes through
// MainActivity.startDocumentPicker (A10a Fix1) — Compose's
// rememberLauncherForActivityResult breaks on FragmentActivity for
// the same 16-bit-requestCode reason that bit the import-key flow.
//
// MIME filter is "*/*" because the user might pick a .pgp / .gpg /
// .asc / .txt — anything an OpenPGP message could plausibly land
// in. PGPCryptoService.decrypt() sniffs armored-vs-binary on its
// own via isArmored(), so we don't need to filter by extension.
// ── Phase A10e: Passphrase prompt refinements ──────────────────────────
//
// Both passphrase dialogs (encrypt-side sign-passphrase, decrypt-side
// key-passphrase) get a polish pass to bring them closer to the iOS UX
// without going overboard. The visible changes:
//
//   • Lock icon at the top of the dialog (Material 3 doesn't render
//     icon slots in AlertDialog natively, but we get the same effect
//     by including an Icon as the first child of the text Column).
//   • Key context row — userName + shortFingerprint of the key the
//     passphrase belongs to. iOS line 195 of EncryptView shows this
//     inline in the alert's message body via string interpolation;
//     we surface it as a separately-styled row so the user can scan
//     "is this the key I expected?" at a glance.
//   • Inline error message on both sides. The encrypt-side dialog
//     already rendered state.errorMessage (A10b Fix1 added that);
//     the decrypt-side dialog never did, even though the ViewModel
//     sets `errorMessage = "Incorrect passphrase"` on InvalidPassphrase
//     and the dialog stays open. A10e closes that visual gap.
//   • Encrypt-side ONLY: "Encrypt Without Signing" escape hatch.
//     iOS EncryptView.swift:184 has this as a sibling alert button;
//     wires to viewModel.encryptWithoutSigning() which flips
//     signMessage off, clears the passphrase, and re-runs encrypt /
//     encryptFile. Hidden in SIGN mode because sign-only can't fall
//     back — the signature IS the operation.
//
// The legacy inline AlertDialog blocks (one in EncryptScreen, one in
// DecryptScreen) are preserved verbatim below with @Suppress("unused")
// per the additive-edit rule. Real call sites in the screen
// composables are switched to call SignPassphraseDialog /
// DecryptPassphraseDialog instead.

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SignPassphraseDialog(
    state: EncryptUiState,
    viewModel: EncryptDecryptViewModel
) {
    val signingKey = state.signingKey
    // Mode-driven copy. The primary button label changes with mode
    // (Sign vs Encrypt vs Encrypt File); the body text adapts the
    // same way the legacy dialog did.
    val primaryLabel = when (state.mode) {
        EncryptMode.SIGN -> stringResource(R.string.encrypt_action_sign)
        EncryptMode.FILE -> stringResource(R.string.encrypt_action_encrypt_file)
        EncryptMode.TEXT -> stringResource(R.string.encrypt_action_sign_and_encrypt)
        // Phase A1: this dialog never opens in PASSWORD mode (symmetric
        // encrypt has no signing-key unlock step); arm present for
        // exhaustiveness only.
        EncryptMode.PASSWORD -> stringResource(R.string.encrypt_action_encrypt)
    }
    val bodyText = stringResource(R.string.encrypt_passphrase_intro) + when (state.mode) {
        EncryptMode.SIGN -> stringResource(R.string.encrypt_passphrase_intro_sign)
        EncryptMode.FILE -> stringResource(R.string.encrypt_passphrase_intro_file)
        EncryptMode.TEXT -> stringResource(R.string.encrypt_passphrase_intro_text)
        EncryptMode.PASSWORD -> stringResource(R.string.encrypt_passphrase_intro_text)
    }
    val withoutSigningLabel = when (state.mode) {
        EncryptMode.FILE -> stringResource(R.string.encrypt_passphrase_skip_signing_file)
        else -> stringResource(R.string.encrypt_passphrase_skip_signing)
    }
    // The escape hatch only makes sense when there's an encrypt
    // operation to fall back to. In SIGN mode (sign-only / clear-
    // signed) the signature IS the operation; no fallback exists.
    val showEscapeHatch = state.mode != EncryptMode.SIGN

    AlertDialog(
        onDismissRequest = { viewModel.dismissSignPassphraseDialog() },
        // Material 3 AlertDialog renders the icon slot above the title,
        // centered. Same visual as iOS's system-padlock icon at the top
        // of the alert.
        icon = {
            Icon(
                Icons.Filled.Lock,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
        },
        title = { Text(stringResource(R.string.encrypt_passphrase_dialog_title)) },
        text = {
            Column {
                // Key context row — name (or email fallback) + short
                // fingerprint, styled to read as a "this is the key
                // being unlocked" subtitle. Only shown when we
                // actually have a signing key to reference (defensive
                // null check; the dialog shouldn't surface without
                // one but the check costs nothing).
                if (signingKey != null) {
                    val keyName = when {
                        signingKey.userName.isNotBlank() -> signingKey.userName
                        signingKey.userEmail.isNotBlank() -> signingKey.userEmail
                        else -> signingKey.shortFingerprint
                    }
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Filled.Key,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    keyName,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text(
                                    signingKey.shortFingerprint,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                }

                Text(bodyText, style = MaterialTheme.typography.bodySmall)
                Spacer(modifier = Modifier.height(12.dp))

                OutlinedTextField(
                    value = state.signPassphrase,
                    onValueChange = { viewModel.updateSignPassphrase(it) },
                    label = { Text(stringResource(R.string.encrypt_passphrase_label)) },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                state.errorMessage?.let {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        it,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        // All buttons packed into the confirmButton slot as a vertical
        // Column. The dismissButton slot would sit to the LEFT of this
        // Column in Material 3's default layout, which looks awkward
        // with 3 actions — stacking everything in one slot reads more
        // like the iOS alert's vertical button stack.
        confirmButton = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.End
            ) {
                TextButton(
                    onClick = {
                        when (state.mode) {
                            EncryptMode.SIGN -> viewModel.signOnly(passphrase = state.signPassphrase)
                            EncryptMode.TEXT -> viewModel.encrypt(passphrase = state.signPassphrase)
                            EncryptMode.FILE -> viewModel.encryptFile(passphrase = state.signPassphrase)
                            EncryptMode.PASSWORD -> {} // no signing-key unlock in symmetric mode
                        }
                    }
                ) {
                    Text(primaryLabel, fontWeight = FontWeight.SemiBold)
                }
                if (showEscapeHatch) {
                    TextButton(onClick = { viewModel.encryptWithoutSigning() }) {
                        Text(withoutSigningLabel)
                    }
                }
                TextButton(onClick = { viewModel.dismissSignPassphraseDialog() }) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DecryptPassphraseDialog(
    state: DecryptUiState,
    viewModel: EncryptDecryptViewModel
) {
    // The key the passphrase belongs to is the one whose fingerprint
    // matches state.selectedKeyFingerprint, looked up in
    // state.availableKeys. Null-fall-through if neither is set
    // (defensive — the dialog shouldn't surface without a selected
    // key, but a null check costs nothing).
    val selectedKey = state.availableKeys.find {
        it.fingerprint == state.selectedKeyFingerprint
    }
    val primaryLabel = when (state.mode) {
        DecryptMode.FILE -> stringResource(R.string.decrypt_action_decrypt_file)
        DecryptMode.TEXT -> stringResource(R.string.decrypt_action_decrypt)
    }

    AlertDialog(
        onDismissRequest = { viewModel.dismissPassphraseDialog() },
        icon = {
            Icon(
                Icons.Filled.Lock,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
        },
        title = { Text(stringResource(R.string.encrypt_passphrase_dialog_title)) },
        text = {
            Column {
                if (selectedKey != null) {
                    val keyName = when {
                        selectedKey.userName.isNotBlank() -> selectedKey.userName
                        selectedKey.userEmail.isNotBlank() -> selectedKey.userEmail
                        else -> selectedKey.shortFingerprint
                    }
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Filled.Key,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    keyName,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text(
                                    selectedKey.shortFingerprint,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                }

                Text(
                    stringResource(R.string.decrypt_passphrase_explainer),
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(modifier = Modifier.height(12.dp))

                OutlinedTextField(
                    value = state.passphrase,
                    onValueChange = { viewModel.updatePassphrase(it) },
                    label = { Text(stringResource(R.string.encrypt_passphrase_label)) },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                // Phase A10e: parity with the encrypt-side dialog —
                // surface errorMessage inline. Previously the
                // ViewModel set it on InvalidPassphrase but the
                // dialog never rendered it, so the user got a
                // dismissed dialog and a far-away inline error.
                state.errorMessage?.let {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        it,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    when (state.mode) {
                        DecryptMode.TEXT -> viewModel.decrypt()
                        DecryptMode.FILE -> viewModel.decryptFile(passphrase = state.passphrase)
                    }
                }
            ) {
                Text(primaryLabel, fontWeight = FontWeight.SemiBold)
            }
        },
        dismissButton = {
            TextButton(onClick = { viewModel.dismissPassphraseDialog() }) {
                Text(stringResource(R.string.common_button_cancel))
            }
        }
    )
}

// Legacy passphrase dialog blocks — preserved per the additive-edit
// rule. These captured the exact inline-AlertDialog behavior that
// EncryptScreen and DecryptScreen used before A10e extracted them
// into the polished SignPassphraseDialog / DecryptPassphraseDialog
// composables above. Not invoked from anywhere; kept here so reverting
// the polish is a one-line call-site swap.

@Suppress("unused")
@Composable
private fun LegacySignPassphraseDialog(
    state: EncryptUiState,
    viewModel: EncryptDecryptViewModel
) {
    AlertDialog(
        onDismissRequest = { viewModel.dismissSignPassphraseDialog() },
        title = { Text(stringResource(R.string.encrypt_passphrase_dialog_title)) },
        text = {
            Column {
                Text(
                    "This signing key is passphrase-protected. " +
                            when (state.mode) {
                                EncryptMode.SIGN -> "Enter it to sign the message."
                                EncryptMode.FILE -> "Enter it to encrypt and sign the file."
                                else -> "Enter it to encrypt and sign the message."
                            },
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = state.signPassphrase,
                    onValueChange = { viewModel.updateSignPassphrase(it) },
                    label = { Text(stringResource(R.string.encrypt_passphrase_label)) },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                state.errorMessage?.let {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        it,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                when (state.mode) {
                    EncryptMode.SIGN -> viewModel.signOnly(passphrase = state.signPassphrase)
                    EncryptMode.TEXT -> viewModel.encrypt(passphrase = state.signPassphrase)
                    EncryptMode.FILE -> viewModel.encryptFile(passphrase = state.signPassphrase)
                    EncryptMode.PASSWORD -> {} // no signing-key unlock in symmetric mode
                }
            }) {
                Text(
                    when (state.mode) {
                        EncryptMode.SIGN -> "Sign"
                        EncryptMode.FILE -> "Encrypt File"
                        else -> "Encrypt"
                    }
                )
            }
        },
        dismissButton = {
            TextButton(onClick = { viewModel.dismissSignPassphraseDialog() }) {
                Text(stringResource(R.string.common_button_cancel))
            }
        }
    )
}

@Suppress("unused")
@Composable
private fun LegacyDecryptPassphraseDialog(
    state: DecryptUiState,
    viewModel: EncryptDecryptViewModel
) {
    AlertDialog(
        onDismissRequest = { viewModel.dismissPassphraseDialog() },
        title = { Text(stringResource(R.string.encrypt_passphrase_dialog_title)) },
        text = {
            OutlinedTextField(
                value = state.passphrase,
                onValueChange = { viewModel.updatePassphrase(it) },
                label = { Text("Enter passphrase") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true
            )
        },
        confirmButton = {
            TextButton(onClick = {
                when (state.mode) {
                    DecryptMode.TEXT -> viewModel.decrypt()
                    DecryptMode.FILE -> viewModel.decryptFile(passphrase = state.passphrase)
                }
            }) {
                Text(
                    when (state.mode) {
                        DecryptMode.FILE -> stringResource(R.string.decrypt_action_decrypt_file)
                        else -> stringResource(R.string.decrypt_action_decrypt)
                    }
                )
            }
        },
        dismissButton = {
            TextButton(onClick = { viewModel.dismissPassphraseDialog() }) { Text(stringResource(R.string.common_button_cancel)) }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SignFileSheet(state: EncryptUiState, viewModel: EncryptDecryptViewModel) {
    val context = LocalContext.current
    val activity = context.findEncryptMainActivity()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    val pickFile: () -> Unit = {
        activity?.startDocumentPicker(arrayOf("*/*")) { uri ->
            if (uri != null) {
                try {
                    val (name, _) = queryDocumentMetadata(context, uri)
                    val bytes = context.contentResolver.openInputStream(uri)?.use {
                        it.readBytes()
                    } ?: ByteArray(0)
                    val fallback = uri.lastPathSegment?.substringAfterLast('/')
                    viewModel.setSignFile(name ?: fallback ?: "file", bytes)
                } catch (e: Exception) {
                    // Silent — user taps the row again.
                }
            }
        }
    }

    ModalBottomSheet(
        onDismissRequest = { viewModel.dismissSignFileSheet() },
        sheetState = sheetState,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                stringResource(R.string.sign_file_sheet_title),
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                stringResource(R.string.sign_file_sheet_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            VerifyFilePickRow(
                label = stringResource(R.string.sign_file_pick_label),
                filename = state.signFileName,
                onPick = pickFile,
            )

            // Sign-with key
            OutlinedButton(
                onClick = { viewModel.showSignFileKeyPicker() },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Filled.VpnKey, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = state.signFileSelectedKey?.let {
                        stringResource(
                            R.string.sign_file_sign_with_format,
                            it.userName.ifBlank { it.userID },
                        )
                    } ?: stringResource(R.string.sign_file_sign_with_none),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
            }

            // Armored / binary toggle
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = state.signFileArmor,
                    onClick = { viewModel.setSignFileArmor(true) },
                    label = { Text(stringResource(R.string.sign_file_format_armored)) },
                )
                FilterChip(
                    selected = !state.signFileArmor,
                    onClick = { viewModel.setSignFileArmor(false) },
                    label = { Text(stringResource(R.string.sign_file_format_binary)) },
                )
            }

            OutlinedTextField(
                value = state.signFilePassphrase,
                onValueChange = { viewModel.setSignFilePassphrase(it) },
                label = { Text(stringResource(R.string.sign_file_passphrase_label)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            state.errorMessage?.let { msg ->
                Text(
                    msg,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            if (state.signFileResultBytes != null) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            Icons.Filled.CheckCircle,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = state.signFileResultName ?: "",
                            style = MaterialTheme.typography.bodyMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
                Button(
                    onClick = {
                        shareSignatureFile(
                            context,
                            state.signFileResultBytes ?: ByteArray(0),
                            state.signFileResultName ?: "signature.asc",
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.sign_file_share_button))
                }
            } else {
                Button(
                    onClick = { viewModel.runSignFile() },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !state.signFileProcessing &&
                        state.signFileBytes != null &&
                        state.signFileSelectedKey != null,
                ) {
                    if (state.signFileProcessing) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.width(8.dp))
                    }
                    Text(stringResource(R.string.sign_file_sign_button))
                }
            }
        }
    }

    if (state.showSignFileKeyPicker) {
        SignAsSheet(
            keyPairs = viewModel.signableFileKeys(),
            currentSelection = state.signFileSelectedKey,
            onSelect = { viewModel.setSignFileKey(it) },
            onDismiss = { viewModel.dismissSignFileKeyPicker() },
        )
    }
}

/**
 * Phase A5 — share a detached signature file. Writes to cacheDir/exports and
 * hands out a FileProvider content URI with a one-shot read grant, mirroring
 * the share-target idiom. MIME is application/pgp-signature.
 */
private fun shareSignatureFile(context: Context, bytes: ByteArray, filename: String) {
    try {
        val exportsDir = File(context.cacheDir, "exports").apply { mkdirs() }
        val outFile = File(exportsDir, filename)
        outFile.writeBytes(bytes)
        val shareUri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            outFile,
        )
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/pgp-signature"
            putExtra(Intent.EXTRA_STREAM, shareUri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(send, context.getString(R.string.sign_file_share_button))
        chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(chooser)
    } catch (e: Exception) {
        // Best-effort: a share failure here is non-fatal; the user can retry.
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VerifyFileSheet(state: DecryptUiState, viewModel: EncryptDecryptViewModel) {
    val context = LocalContext.current
    val activity = context.findEncryptMainActivity()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    val pickInto: (isSignature: Boolean) -> Unit = { isSignature ->
        activity?.startDocumentPicker(arrayOf("*/*")) { uri ->
            if (uri != null) {
                try {
                    val (name, _) = queryDocumentMetadata(context, uri)
                    val bytes = context.contentResolver.openInputStream(uri)?.use {
                        it.readBytes()
                    } ?: ByteArray(0)
                    val fallback = uri.lastPathSegment?.substringAfterLast('/')
                    if (isSignature) {
                        viewModel.setVerifyFileSignature(name ?: fallback ?: "signature", bytes)
                    } else {
                        viewModel.setVerifyFileSigned(name ?: fallback ?: "file", bytes)
                    }
                } catch (e: Exception) {
                    // Silent — user taps the row again.
                }
            }
        }
    }

    ModalBottomSheet(
        onDismissRequest = { viewModel.dismissVerifyFileSheet() },
        sheetState = sheetState,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                stringResource(R.string.verify_file_sheet_title),
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                stringResource(R.string.verify_file_sheet_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            VerifyFilePickRow(
                label = stringResource(R.string.verify_file_pick_signed_label),
                filename = state.verifyFileSignedName,
                onPick = { pickInto(false) },
            )
            VerifyFilePickRow(
                label = stringResource(R.string.verify_file_pick_signature_label),
                filename = state.verifyFileSigName,
                onPick = { pickInto(true) },
            )

            state.verifyFileResult?.let { result ->
                VerificationBanner(
                    result = result,
                    onTapUnknownSigner = { viewModel.lookupSigner() },
                )
            }

            Button(
                onClick = { viewModel.runVerifyFile() },
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.verifyFileProcessing &&
                    state.verifyFileSignedBytes != null &&
                    state.verifyFileSigBytes != null,
            ) {
                if (state.verifyFileProcessing) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(stringResource(R.string.verify_file_verify_button))
            }
        }
    }
}

@Composable
private fun VerifyFilePickRow(label: String, filename: String?, onPick: () -> Unit) {
    OutlinedButton(onClick = onPick, modifier = Modifier.fillMaxWidth()) {
        Icon(
            Icons.Filled.AttachFile,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = filename ?: label,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun DecryptFileSection(state: DecryptUiState, viewModel: EncryptDecryptViewModel) {
    val context = LocalContext.current
    val activity = context.findEncryptMainActivity()

    val onPickFile: () -> Unit = {
        activity?.startDocumentPicker(arrayOf("*/*")) { uri ->
            if (uri != null) {
                try {
                    val (name, size) = queryDocumentMetadata(context, uri)
                    val bytes = context.contentResolver.openInputStream(uri)?.use {
                        it.readBytes()
                    } ?: ByteArray(0)
                    viewModel.setFileToDecrypt(
                        name = name ?: uri.lastPathSegment?.substringAfterLast('/') ?: "file",
                        size = size ?: bytes.size.toLong(),
                        bytes = bytes
                    )
                } catch (e: Exception) {
                    // Silent — user taps Browse again.
                }
            }
        }
    }

    if (state.selectedFileName != null) {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        // Lock-doc icon signals "this is the encrypted
                        // input, not the cleartext output yet".
                        Icons.Filled.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .size(40.dp)
                            .padding(8.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            state.selectedFileName,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            maxLines = 1
                        )
                        Text(
                            state.selectedFileSize?.let { formatFileSize(it) } ?: "—",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(onClick = { viewModel.clearDecryptFile() }) {
                        Icon(
                            Icons.Filled.Close,
                            contentDescription = stringResource(R.string.encrypt_file_remove),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Spacer(modifier = Modifier.height(4.dp))
                TextButton(
                    onClick = onPickFile,
                    modifier = Modifier.align(Alignment.End)
                ) {
                    Icon(
                        Icons.Filled.SwapHoriz,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.encrypt_file_choose_different), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    } else {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.primary.copy(alpha = 0.08f),
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onPickFile)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 28.dp, horizontal = 16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    Icons.Filled.Lock,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(36.dp)
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    stringResource(R.string.decrypt_file_choose),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    stringResource(R.string.decrypt_file_types),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// ── Decrypt Screen ─────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DecryptScreen(viewModel: EncryptDecryptViewModel) {
    val state by viewModel.decryptState.collectAsState()
    val clipboard = LocalClipboardManager.current
    val haptics = rememberHaptics()

    // HW Phase 3 — card-decrypt local state. When the input is encrypted to
    // a card key (state.isCardMessage), the passphrase field is replaced by
    // a PIN field and Decrypt runs an NFC operation instead of the software
    // path. Strings captured here because the NFC lambda runs on a binder
    // thread and can't call stringResource.
    var cardDecryptPin by remember { mutableStateOf("") }
    var cardDecryptWaiting by remember { mutableStateOf(false) }
    // Phase AU-1 — controls the searchable "Decrypt With" key picker sheet.
    var showDecryptKeyPicker by remember { mutableStateOf(false) }
    val cardDecPairFirstMsg = stringResource(R.string.card_sign_pair_first)
    val cardDecNfcUnavailMsg = stringResource(R.string.card_scan_nfc_unavailable)
    val cardDecFailedMsg = stringResource(R.string.card_sign_failed_generic)
    val cardDecNoKeyMsg = stringResource(R.string.card_sign_no_sig_key)

    // ── Phase A11: Biometric gate for the Decrypt action ─────────────
    //
    // When the user has enabled "Require for Decryption" in Settings,
    // tapping Decrypt prompts BiometricGate before running the actual
    // decrypt. Mirrors iOS DecryptView.swift:308-321 — biometric is
    // checked once at the initial tap; if a passphrase dialog later
    // surfaces, its confirm button calls viewModel.decrypt(passphrase)
    // directly without re-prompting biometric (matches iOS's
    // performDecrypt path).
    //
    // performDecrypt unifies the gate logic in one place so both the
    // bottom Decrypt button and any future Decrypt entry point in
    // this screen can reuse it. Reads requireBiometricForDecrypt
    // fresh each call so a Settings change is picked up without a
    // screen reload.
    val context = LocalContext.current
    val decryptActivity = context.findEncryptMainActivity()
    // 6.2.1 — shared per-action biometric gate for the Decrypt screen.
    // Honors "require biometric for decryption": runs [action] inside the
    // BiometricGate success callback when the setting is on and biometric is
    // available, otherwise runs it directly. Reused by both the software
    // decrypt button (performDecrypt) and the hardware-key (NFC card) decrypt
    // path, so the card flow no longer skips the gate. When the setting is
    // off, the card flow goes straight to PIN + tap as before.
    val gateDecryptBiometric: (() -> Unit) -> Unit = { action ->
        val activityLocal = decryptActivity
        val prefs = context.getSharedPreferences("pgpony_prefs", android.content.Context.MODE_PRIVATE)
        val requireBiometric = prefs.getBoolean("biometric_decrypt", false)
        if (requireBiometric && activityLocal != null &&
            BiometricGate.canAuthenticate(activityLocal) == BiometricAvailability.Available
        ) {
            BiometricGate.authenticate(
                activity = activityLocal,
                title = context.getString(R.string.decrypt_biometric_prompt_title),
                subtitle = context.getString(R.string.decrypt_biometric_prompt_subtitle),
                onSuccess = action,
                onError = { _, _ -> /* user cancelled / lockout — no-op, button stays tappable for retry */ }
            )
        } else {
            // Either the user hasn't opted in (most common path) or
            // biometric became unavailable mid-session (rare — user
            // disabled fingerprint in System Settings). Either way
            // we don't block the decrypt; security posture matches
            // the off-toggle case.
            action()
        }
    }
    val performDecrypt: () -> Unit = {
        gateDecryptBiometric {
            when (state.mode) {
                DecryptMode.TEXT -> viewModel.decrypt()
                DecryptMode.FILE -> viewModel.decryptFile()
            }
        }
    }

    // Refresh keys every time screen appears
    LaunchedEffect(Unit) { viewModel.refreshKeys() }

    // Fire success haptic exactly once per decrypt completion
    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            if (event is EncryptDecryptViewModel.Event.DecryptSuccess) {
                haptics.success()
            }
        }
    }

    Scaffold(
        topBar = { TopAppBar(
            title = { Text(stringResource(R.string.decrypt_screen_title)) },
            actions = {
                val hasContent = state.inputText.isNotBlank() ||
                    state.outputText.isNotBlank() || state.selectedFileBytes != null
                IconButton(onClick = { viewModel.clearDecrypt() }, enabled = hasContent) {
                    Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.common_clear))
                }
            }
        ) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(8.dp))

            // ── Phase A10c: Mode picker (Text / File) ──────────────────
            //
            // Same SingleChoiceSegmentedButtonRow shape as the encrypt
            // side, just with two segments instead of three (no sign-
            // only equivalent on the decrypt side — clear-signed
            // verification is auto-routed inside the text path).
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                DecryptMode.entries.forEachIndexed { index, m ->
                    SegmentedButton(
                        selected = state.mode == m,
                        onClick = { viewModel.setDecryptMode(m) },
                        shape = SegmentedButtonDefaults.itemShape(
                            index = index,
                            count = DecryptMode.entries.size
                        )
                    ) {
                        Text(m.displayName)
                    }
                }
            }
            Spacer(modifier = Modifier.height(12.dp))

            // Input — hidden in FILE mode; the picker chip below
            // takes its place.
            if (state.mode != DecryptMode.FILE) {
                OutlinedTextField(
                    value = state.inputText,
                    onValueChange = { viewModel.updateDecryptInput(it) },
                    // Phase A3: input may be an encrypted message OR a clear-signed
                    // text message. The Decrypt button auto-detects via
                    // VerifyService.detectInputType — single button covers both flows.
                    label = { Text(stringResource(R.string.decrypt_input_paste_label)) },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp),
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    maxLines = 15
                )
                // Phase AU-3 — paste the clipboard into the message field,
                // matching the Import and Encrypt tabs' paste affordance.
                Spacer(modifier = Modifier.height(8.dp))
                FilledTonalButton(
                    onClick = {
                        clipboard.getText()?.text?.let { viewModel.updateDecryptInput(it) }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.ContentPaste, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        stringResource(R.string.common_paste_from_clipboard),
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
            } else {
                DecryptFileSection(state = state, viewModel = viewModel)
                Spacer(modifier = Modifier.height(12.dp))
            }

            // HW Phase 3 — when the message is encrypted to a hardware key,
            // the private key never leaves the card: no passphrase applies,
            // so swap the key picker + passphrase field for a note and a PIN
            // field. The Decrypt button (below) runs the NFC PIN+tap flow.
            if (state.isCardMessage) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Nfc,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        stringResource(
                            R.string.decrypt_card_message_note,
                            state.cardMessageKeyName ?: stringResource(R.string.decrypt_card_message_fallback_name)
                        ),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = cardDecryptPin,
                    onValueChange = { cardDecryptPin = it },
                    label = { Text(stringResource(R.string.card_decrypt_pin_label)) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                Spacer(modifier = Modifier.height(12.dp))
            } else if (state.isPasswordMessage) {
                // Phase A1: password-encrypted (`gpg -c`) message — no keypair
                // applies, so swap the key picker for a note + the passphrase
                // field. The Decrypt button (below) runs the normal software
                // path, which reads state.passphrase.
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        stringResource(R.string.decrypt_password_message_note),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = state.passphrase,
                    onValueChange = { viewModel.updatePassphrase(it) },
                    label = { Text(stringResource(R.string.decrypt_password_passphrase_label)) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                Spacer(modifier = Modifier.height(12.dp))
            } else {
                // Key selector
                Text(stringResource(R.string.decrypt_with_key_label), style = MaterialTheme.typography.labelLarge)
                Spacer(modifier = Modifier.height(4.dp))
                if (state.availableKeys.isEmpty()) {
                    Text(
                        stringResource(R.string.decrypt_no_key_pairs),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    // Phase AU-1 — collapse the key list into a single selector
                    // that opens a searchable picker (hardware keys pinned
                    // first). The selected key's name + short fingerprint show
                    // on the button, with the NFC badge when it's card-backed.
                    val selectedKey = state.availableKeys
                        .firstOrNull { it.fingerprint == state.selectedKeyFingerprint }
                    OutlinedButton(
                        onClick = { showDecryptKeyPicker = true },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (selectedKey?.isCardBacked == true) {
                            Icon(
                                Icons.Filled.Nfc,
                                contentDescription = stringResource(R.string.decrypt_card_key_indicator),
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Text(
                            selectedKey?.let {
                                stringResource(
                                    R.string.decrypt_key_row_format,
                                    it.userName.ifBlank { it.userEmail },
                                    it.shortFingerprint
                                )
                            } ?: stringResource(R.string.decrypt_picker_choose),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.weight(1f)
                        )
                        Icon(Icons.Filled.ArrowDropDown, contentDescription = null)
                    }
                }
                if (showDecryptKeyPicker) {
                    DecryptKeyPickerSheet(
                        keys = state.availableKeys,
                        selectedFingerprint = state.selectedKeyFingerprint,
                        onSelect = { fp ->
                            viewModel.selectDecryptKey(fp)
                            showDecryptKeyPicker = false
                        },
                        onDismiss = { showDecryptKeyPicker = false }
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))

                // Passphrase
                OutlinedTextField(
                    value = state.passphrase,
                    onValueChange = { viewModel.updatePassphrase(it) },
                    label = { Text(stringResource(R.string.decrypt_passphrase_optional_label)) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                Spacer(modifier = Modifier.height(12.dp))
            }

            state.errorMessage?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                Spacer(modifier = Modifier.height(8.dp))
            }

            Button(
                onClick = {
                    // HW Phase 3 — card-encrypted message: run the NFC
                    // PIN+tap decrypt instead of the software/biometric
                    // path. The card's private key never leaves the device.
                    if (state.isCardMessage) {
                      // 6.2.1 — gate the hardware-key decrypt behind biometric
                      // when "require biometric for decryption" is on; otherwise
                      // straight to PIN + tap (the card is the primary factor).
                      gateDecryptBiometric {
                        val pin = cardDecryptPin
                        val cardFp = state.cardMessageKeyFingerprint
                        viewModel.onCardDecryptStarted()
                        cardDecryptWaiting = true
                        // FILE mode decrypts the picked bytes → file result
                        // sheet; TEXT mode decrypts the pasted message → text
                        // output. Op return types differ, so each takes its
                        // own startCardOperation call.
                        val started: Boolean? = if (state.mode == DecryptMode.FILE) {
                            val fileBytes = state.selectedFileBytes
                            decryptActivity?.startCardOperation({ session ->
                                session.select()
                                val fp = cardFp
                                    ?: session.getApplicationRelatedData().sigFingerprint
                                    ?: throw OpenPgpCardException.Malformed(cardDecNoKeyMsg)
                                val pubRing = PGPonyApp.instance.keyRepository.loadPublicKeyRing(fp)
                                    ?: throw OpenPgpCardException.Malformed(cardDecPairFirstMsg)
                                if (fileBytes == null) throw OpenPgpCardException.Malformed(cardDecNoKeyMsg)
                                CardDecryptService.shared.decryptBytes(
                                    session, pubRing, pin.toByteArray(Charsets.UTF_8), fileBytes,
                                    viewModel.cardVerificationRings()
                                )
                            }) { result ->
                                cardDecryptWaiting = false
                                decryptActivity?.stopCardScan()
                                result
                                    .onSuccess { viewModel.onCardDecryptFileSuccess(it) }
                                    .onFailure { e -> viewModel.onCardDecryptFailure(e.message ?: cardDecFailedMsg) }
                            }
                        } else {
                            val msg = state.inputText
                            decryptActivity?.startCardOperation({ session ->
                                session.select()
                                val fp = cardFp
                                    ?: session.getApplicationRelatedData().sigFingerprint
                                    ?: throw OpenPgpCardException.Malformed(cardDecNoKeyMsg)
                                val pubRing = PGPonyApp.instance.keyRepository.loadPublicKeyRing(fp)
                                    ?: throw OpenPgpCardException.Malformed(cardDecPairFirstMsg)
                                CardDecryptService.shared.decrypt(
                                    session, pubRing, pin.toByteArray(Charsets.UTF_8), msg,
                                    viewModel.cardVerificationRings()
                                )
                            }) { result ->
                                cardDecryptWaiting = false
                                decryptActivity?.stopCardScan()
                                result
                                    .onSuccess { viewModel.onCardDecryptSuccess(it) }
                                    .onFailure { e -> viewModel.onCardDecryptFailure(e.message ?: cardDecFailedMsg) }
                            }
                        }
                        if (started != true) {
                            cardDecryptWaiting = false
                            viewModel.onCardDecryptFailure(cardDecNfcUnavailMsg)
                        }
                      }
                    } else {
                        // Phase A10c: dispatch by mode. Text mode keeps
                        // the existing detectInputType auto-routing
                        // inside decrypt(); file mode calls decryptFile()
                        // which mirrors the encrypted-text path with
                        // bytes instead of armored text.
                        //
                        // Phase A11: dispatch routed through performDecrypt
                        // (declared at the top of DecryptScreen) so the
                        // "require biometric for decryption" setting
                        // is honored when enabled. performDecrypt either
                        // calls decrypt()/decryptFile() directly (when
                        // not gated) or runs them inside BiometricGate's
                        // onSuccess callback (when gated).
                        performDecrypt()
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.isProcessing && when {
                    state.isCardMessage -> cardDecryptPin.isNotEmpty() &&
                        (state.mode != DecryptMode.FILE || state.selectedFileBytes != null)
                    state.mode == DecryptMode.FILE -> state.selectedFileBytes != null
                    else -> true
                }
            ) {
                if (state.isProcessing) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(
                    when (state.mode) {
                        DecryptMode.FILE -> stringResource(R.string.decrypt_action_decrypt_file)
                        else -> stringResource(R.string.decrypt_action_decrypt)
                    }
                )
            }
            Spacer(modifier = Modifier.height(8.dp))

            // Phase A3 — "Verify a file" entry: pick an original file + its
            // detached .sig/.asc and check the signature. Opens a self-
            // contained sheet; independent of the decrypt path above.
            OutlinedButton(
                onClick = { viewModel.openVerifyFileSheet() },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Filled.VerifiedUser, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.verify_file_entry_button))
            }
            Spacer(modifier = Modifier.height(16.dp))

            // Output
            if (state.outputText.isNotBlank()) {
                Text(
                    // Phase A3: header text reflects which path produced the
                    // output. Clear-signed verification shows the verified
                    // cleartext; encrypted decryption shows decrypted plaintext.
                    when (state.verificationResult) {
                        is com.pgpony.android.crypto.VerificationResult.Verified,
                        is com.pgpony.android.crypto.VerificationResult.Invalid,
                        is com.pgpony.android.crypto.VerificationResult.UnknownSigner ->
                            if (state.signatureVerified) stringResource(R.string.decrypt_output_verified) else stringResource(R.string.decrypt_output_signed)
                        else -> stringResource(R.string.decrypt_output_decrypted)
                    },
                    style = MaterialTheme.typography.labelLarge
                )
                Spacer(modifier = Modifier.height(8.dp))

                // Phase A3: 4-state verification banner replaces the
                // single inline "Signature verified" check icon. Renders
                // green for verified, red for invalid, yellow (tappable)
                // for unknown signer, gray for unsigned. Tapping the
                // yellow banner opens the SignerLookupSheet.
                state.verificationResult?.let { result ->
                    VerificationBanner(
                        result = result,
                        onTapUnknownSigner = { viewModel.lookupSigner() }
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                }

                OutlinedTextField(
                    value = state.outputText,
                    onValueChange = {},
                    readOnly = true,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 100.dp),
                    maxLines = 15
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = {
                        // Phase A12: route through ClipboardService for
                        // auto-clear honoring. Label is "Decrypted message"
                        // — slightly leaky in system clipboard previews on
                        // Android 13+, but explicit context matters more
                        // here since the user explicitly chose to surface
                        // this text.
                        ClipboardService.copyText(context, state.outputText, label = context.getString(R.string.decrypt_clipboard_label))
                        haptics.tap()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.ContentCopy, stringResource(R.string.common_button_copy))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.common_button_copy_to_clipboard))
                }
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = { viewModel.clearDecrypt() },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.Clear, stringResource(R.string.common_clear))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.common_clear))
                }
            }
            Spacer(modifier = Modifier.height(24.dp))
        }
    }

    // Passphrase dialog
    //
    // Phase A10e: inline AlertDialog block extracted to
    // DecryptPassphraseDialog composable which adds key context
    // (name + fingerprint), a lock icon, descriptive body text, and
    // inline error message display. LegacyDecryptPassphraseDialog
    // preserves the previous body for revert-ability.
    if (state.showPassphraseDialog) {
        DecryptPassphraseDialog(state = state, viewModel = viewModel)
    }

    // Phase A3: SignerLookupSheet — shown when the user tapped the yellow
    // UnknownSigner verification banner. The sheet drives its own state
    // machine (Searching → Found → ImportSuccess, or NotFound/Failed)
    // via the ViewModel's lookupSigner/importDiscoveredSigner/dismiss
    // actions. After successful import the host re-verifies automatically
    // (importDiscoveredSigner re-runs decrypt() internally).
    if (state.showSignerLookup) {
        SignerLookupSheet(
            state = state.signerLookupState,
            claimedFingerprint = state.pendingUnknownClaimedFingerprint,
            onImport = { armoredKey -> viewModel.importDiscoveredSigner(armoredKey) },
            onDismiss = { viewModel.dismissSignerLookup() }
        )
    }

    // Phase A3 — "Verify a file" sheet.
    if (state.showVerifyFileSheet) {
        VerifyFileSheet(state = state, viewModel = viewModel)
    }

    // ── Phase A10c: file-decrypt result sheet ─────────────────────────
    //
    // Same pattern as the encrypt-side FileEncryptionResultScreen
    // (A10b): one-shot modal on success, dismissed via Done or back
    // gesture, dismiss action clears the decrypted bytes from state
    // so plaintext doesn't linger in memory longer than the user
    // chose to keep it open.
    if (state.showFileDecryptResultSheet && state.decryptedFileBytes != null) {
        FileDecryptionResultScreen(
            state = state,
            onDismiss = { viewModel.dismissFileDecryptResult() }
        )
    }

    // HW Phase 3 — card-decrypt waiting dialog (hold card to phone).
    if (cardDecryptWaiting) {
        AlertDialog(
            onDismissRequest = { },
            icon = { Icon(Icons.Filled.Contactless, contentDescription = null) },
            title = { Text(stringResource(R.string.card_decrypt_title)) },
            text = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(stringResource(R.string.card_decrypt_hold_card))
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    cardDecryptWaiting = false
                    decryptActivity?.stopCardScan()
                    viewModel.onCardDecryptFailure(cardDecFailedMsg)
                }) { Text(stringResource(R.string.common_button_cancel)) }
            }
        )
    }

    // ── First-visit tooltip (Phase 4) ───────────────────────────────────
    ScreenTooltip(
        tooltipKey = "decrypt_paste",
        message = stringResource(R.string.decrypt_tooltip_paste)
    )
}

// ── Decrypt "Decrypt With" key picker (Phase AU-1) ─────────────────────
//
// Searchable bottom-sheet replacement for the old inline RadioButton list.
// Hardware (card) keys are pinned into their own group above software keys;
// the current selection shows a check. Filtering matches name, email, or
// fingerprint. The caller (DecryptScreen) owns selection via
// viewModel.selectDecryptKey(), so card-vs-software routing is unchanged —
// this sheet only chooses which fingerprint to hand it.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DecryptKeyPickerSheet(
    keys: List<PGPKeyEntity>,
    selectedFingerprint: String?,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var query by remember { mutableStateOf("") }

    fun matches(key: PGPKeyEntity): Boolean {
        if (query.isBlank()) return true
        val q = query.trim().lowercase()
        return key.userName.lowercase().contains(q) ||
            key.userEmail.lowercase().contains(q) ||
            key.fingerprint.lowercase().contains(q)
    }

    val filtered = keys.filter { matches(it) }
    val hardwareKeys = filtered.filter { it.isCardBacked }
    val softwareKeys = filtered.filter { !it.isCardBacked }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .padding(bottom = 24.dp)
        ) {
            Text(
                stringResource(R.string.decrypt_picker_title),
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text(stringResource(R.string.decrypt_picker_search)) },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(12.dp))

            if (filtered.isEmpty()) {
                Text(
                    stringResource(R.string.decrypt_picker_none),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 16.dp)
                )
            } else {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 360.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    if (hardwareKeys.isNotEmpty()) {
                        DecryptPickerGroupLabel(stringResource(R.string.decrypt_picker_group_hardware))
                        hardwareKeys.forEach { key ->
                            DecryptKeyPickerRow(
                                key = key,
                                selected = key.fingerprint == selectedFingerprint,
                                onClick = { onSelect(key.fingerprint) }
                            )
                        }
                    }
                    if (softwareKeys.isNotEmpty()) {
                        DecryptPickerGroupLabel(stringResource(R.string.decrypt_picker_group_software))
                        softwareKeys.forEach { key ->
                            DecryptKeyPickerRow(
                                key = key,
                                selected = key.fingerprint == selectedFingerprint,
                                onClick = { onSelect(key.fingerprint) }
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DecryptPickerGroupLabel(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 8.dp, bottom = 4.dp)
    )
}

@Composable
private fun DecryptKeyPickerRow(
    key: PGPKeyEntity,
    selected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (key.isCardBacked) {
            Icon(
                Icons.Filled.Nfc,
                contentDescription = stringResource(R.string.decrypt_card_key_indicator),
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                key.userName.ifBlank { key.userEmail },
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                key.shortFingerprint,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (selected) {
            Icon(
                Icons.Filled.Check,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}
