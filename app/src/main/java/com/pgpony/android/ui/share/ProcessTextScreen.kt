// ProcessTextScreen.kt
// PGPony Android, 4.8.0 (#103): the screens behind the text selection menu's
// Encrypt and Sign entries, hosted by ProcessTextActivity.
//
// Built from the Quick Action's pieces so both read and behave the same: its
// scaffold, recipient rows, processing, error and result screens (Copy, Save,
// Share, Done), plus the Encrypt screen's "Also sign this message", Sign as,
// the Don't use confirmation and the post-quantum signature prompt.

package com.pgpony.android.ui.share

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.pgpony.android.MainActivity
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.i18n.ErrorText
import com.pgpony.android.ui.util.ObserveSafeSave
import com.pgpony.android.ui.util.SafeSave
import com.pgpony.android.ui.util.autofillPassword
import com.pgpony.android.ui.util.rememberSaveState

@Composable
fun ProcessTextScreen(
    vm: ProcessTextViewModel,
    /** The result is on its way back to the calling app; show progress, not the result. */
    returningResult: Boolean,
    onDismiss: () -> Unit,
) {
    val state by vm.state.collectAsState()
    val context = LocalContext.current
    val isSign = state.mode == ProcessText.Mode.SIGN

    // 4.7.0 (item 10): recipients marked Don't use, waiting on confirmation.
    var dontUsePrompt by remember { mutableStateOf<List<PGPKeyEntity>?>(null) }
    dontUsePrompt?.let { keys ->
        com.pgpony.android.ui.components.DontUseConfirmDialog(
            keys = keys,
            onConfirm = { dontUsePrompt = null; vm.start() },
            onDismiss = { dontUsePrompt = null }
        )
    }

    // 4.6.0 (item 14): the Encrypt screen's prompt, with its strings.
    if (state.showPqcPrompt) {
        AlertDialog(
            onDismissRequest = { vm.dismissPqcPrompt() },
            title = { Text(stringResource(R.string.pqc_v4_sign_title)) },
            text = { Text(stringResource(R.string.pqc_v4_sign_message)) },
            confirmButton = {
                TextButton(onClick = { vm.answerPqcPrompt(signAnyway = true) }) {
                    Text(stringResource(R.string.pqc_v4_sign_anyway))
                }
            },
            dismissButton = {
                TextButton(onClick = { vm.answerPqcPrompt(signAnyway = false) }) {
                    Text(stringResource(R.string.pqc_v4_send_unsigned))
                }
            },
        )
    }

    // Save for a result shown here, as the Quick Action does it (4.7.0 item 37).
    var saveNote by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(state.phase) { saveNote = null }
    var saveTask by remember { mutableStateOf<SafeSave.Task?>(SafeSave.running(SafeSave.KEY_QUICK)) }
    val saveState: SafeSave.State? = rememberSaveState(saveTask)
    ObserveSafeSave(SafeSave.KEY_QUICK)
    val savedNoteText = stringResource(R.string.result_save_saved_note)
    val failedNoteText = stringResource(R.string.result_save_failed_note)
    val cancelledNoteText = stringResource(R.string.save_cancelled)
    LaunchedEffect(saveState) {
        when (saveState) {
            is SafeSave.State.Done -> saveNote = savedNoteText
            is SafeSave.State.Failed -> saveNote = failedNoteText
            is SafeSave.State.Cancelled -> saveNote = cancelledNoteText
            is SafeSave.State.Running, null -> { }
        }
    }

    // Card strings, captured here: the card operation's callback cannot call stringResource.
    val cardNoSigKeyMsg = stringResource(R.string.card_sign_no_sig_key)
    val cardPairFirstMsg = stringResource(R.string.card_sign_pair_first)
    val cardFailedMsg = stringResource(R.string.card_sign_failed_generic)
    val cardNfcUnavailMsg = stringResource(R.string.card_scan_nfc_unavailable)
    var cardWaiting by remember { mutableStateOf(false) }
    LaunchedEffect(state.phase) {
        if (state.phase != ProcessTextPhase.Processing) cardWaiting = false
    }

    CompositionLocalProvider(
        LocalShareSaveState provides saveState,
        LocalShareSaveCancel provides { saveTask?.cancel() },
    ) {
        ShareScaffold(
            title = processTextTitle(state.phase, isSign),
            onDismiss = onDismiss,
        ) { padding ->
            Column(
                modifier = Modifier
                    .padding(padding)
                    .padding(horizontal = 20.dp)
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                if (state.phase in setOf(
                        ProcessTextPhase.PickRecipients,
                        ProcessTextPhase.PickSigner,
                        ProcessTextPhase.Passphrase,
                        ProcessTextPhase.CardPin,
                    )
                ) {
                    SelectionPreview(state.text)
                }

                when (state.phase) {
                    ProcessTextPhase.Loading -> ShareProcessingContent()

                    ProcessTextPhase.NoKeys -> {
                        // The Quick Action's empty-keyring card. In Sign mode with
                        // public keys only, say why first.
                        if (isSign && state.recipients.isNotEmpty()) {
                            Text(
                                text = stringResource(R.string.encdec_error_sign_no_signing_key),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                        ShareActionCard(
                            title = stringResource(R.string.share_target_open_full_app),
                            subtitle = stringResource(R.string.share_target_open_full_app_subtitle_setup),
                            icon = Icons.Default.OpenInNew,
                            onClick = {
                                context.startActivity(
                                    Intent(context, MainActivity::class.java).apply {
                                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                                    }
                                )
                                onDismiss()
                            },
                        )
                    }

                    ProcessTextPhase.PickRecipients -> RecipientStep(
                        state = state,
                        onToggle = vm::toggleRecipient,
                        onSignChange = vm::setSignMessage,
                        onSignAs = vm::openSignerPicker,
                        onEncrypt = {
                            // 4.7.0 (item 10): encrypting to, or signing with, a key marked
                            // Don't use asks first, as on the Encrypt screen.
                            val flagged = com.pgpony.android.ui.components.dontUseKeys(
                                state.recipients.filter { it.fingerprint in state.selectedRecipients } +
                                    listOfNotNull(state.signer?.takeIf { state.signMessage })
                            )
                            if (flagged.isEmpty()) vm.start() else dontUsePrompt = flagged
                        },
                        onCancel = onDismiss,
                    )

                    ProcessTextPhase.PickSigner -> SignerStep(
                        state = state,
                        onSelect = vm::selectSigner,
                        onSign = {
                            val flagged = com.pgpony.android.ui.components.dontUseKeys(listOf(state.signer))
                            if (flagged.isEmpty()) vm.start() else dontUsePrompt = flagged
                        },
                        onBack = { if (isSign) onDismiss() else vm.back() },
                    )

                    ProcessTextPhase.Passphrase -> PassphraseStep(
                        state = state,
                        onChange = vm::updatePassphrase,
                        onSubmit = { vm.submitPassphrase() },
                        onBack = { vm.back() },
                    )

                    ProcessTextPhase.CardPin -> CardPinStep(
                        state = state,
                        onChange = vm::updateCardPin,
                        onSubmit = {
                            val activity = context as? ProcessTextActivity
                            val op = vm.cardOperation(cardNoSigKeyMsg, cardPairFirstMsg)
                            if (op != null) {
                                if (activity == null) {
                                    vm.onCardFailure(cardNfcUnavailMsg)
                                } else {
                                    vm.onCardStarted()
                                    cardWaiting = true
                                    val started = activity.startCardOperation(op) { result ->
                                        // 4.0.5: the card is still in the field; see #7.
                                        activity.endCardOperation()
                                        result
                                            .onSuccess { vm.onCardSuccess(it) }
                                            .onFailure { e ->
                                                vm.onCardFailure(ErrorText.localize(context, e.message) ?: cardFailedMsg)
                                            }
                                    }
                                    if (!started) vm.onCardFailure(cardNfcUnavailMsg)
                                }
                            }
                        },
                        onBack = { vm.back() },
                    )

                    ProcessTextPhase.Processing -> if (cardWaiting) {
                        CardWaiting(onCancel = {
                            (context as? ProcessTextActivity)?.stopCardScan()
                            vm.back()
                        })
                    } else {
                        ShareProcessingContent()
                    }

                    ProcessTextPhase.Result -> if (returningResult) {
                        ShareProcessingContent()
                    } else {
                        Text(
                            text = stringResource(R.string.process_text_result_not_replaced),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        ShareCipherPreview(text = state.output)
                        ShareResultActionRow(
                            onCopy = { copyResult(context, state.output, isSign) },
                            onSave = {
                                saveResult(
                                    context,
                                    state.output.toByteArray(Charsets.UTF_8),
                                    null,
                                    if (isSign) "signed.asc" else "encrypted.asc",
                                    onTask = { task -> saveNote = null; saveTask = task },
                                ) { saveNote = it }
                            },
                            onShare = { shareResult(context, state.output, isSign) },
                            onDone = onDismiss,
                            saveNote = saveNote,
                        )
                    }

                    ProcessTextPhase.Error -> ShareErrorContent(
                        message = state.errorMessage,
                        onBack = { vm.back() },
                        onDismiss = onDismiss,
                    )
                }
            }
        }
    }
}

@Composable
private fun processTextTitle(phase: ProcessTextPhase, isSign: Boolean): String = when (phase) {
    ProcessTextPhase.PickRecipients -> stringResource(R.string.share_target_encrypt_title)
    ProcessTextPhase.PickSigner -> stringResource(R.string.sign_as_sheet_title)
    ProcessTextPhase.Passphrase ->
        if (isSign) stringResource(R.string.sign_as_sheet_title) else stringResource(R.string.share_target_encrypt_title)
    ProcessTextPhase.CardPin -> stringResource(R.string.card_sign_dialog_title)
    ProcessTextPhase.Loading,
    ProcessTextPhase.Processing -> stringResource(R.string.share_target_processing)
    ProcessTextPhase.Result ->
        if (isSign) stringResource(R.string.card_sign_result_title) else stringResource(R.string.share_target_encrypt_result_title)
    ProcessTextPhase.NoKeys,
    ProcessTextPhase.Error -> stringResource(R.string.app_name)
}

/** The selected text, as the Quick Action previews shared text. */
@Composable
private fun SelectionPreview(text: String) {
    val previewMaxChars = 240
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.process_text_input_label),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val truncated = text.length > previewMaxChars
            Text(
                text = if (truncated) text.take(previewMaxChars) else text,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 6,
                overflow = TextOverflow.Ellipsis,
            )
            if (truncated) {
                Text(
                    text = stringResource(R.string.share_target_input_truncated_format, text.length),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private fun signerName(key: PGPKeyEntity): String =
    key.userName.ifBlank { key.userEmail.ifBlank { key.shortFingerprint } }

@Composable
private fun RecipientStep(
    state: ProcessTextUiState,
    onToggle: (String) -> Unit,
    onSignChange: (Boolean) -> Unit,
    onSignAs: () -> Unit,
    onEncrypt: () -> Unit,
    onCancel: () -> Unit,
) {
    state.recipients.forEach { key ->
        ShareRecipientRow(
            key = key,
            selected = key.fingerprint in state.selectedRecipients,
            onClick = { onToggle(key.fingerprint) },
        )
    }

    // The Encrypt screen's "Also sign this message", with Sign as when
    // there is more than one key to sign with.
    val signer = state.signer
    if (signer != null) {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.encrypt_also_sign_message_title),
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.Medium,
                        )
                        Text(
                            text = stringResource(R.string.encrypt_also_sign_subtitle_format, signerName(signer)),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Switch(checked = state.signMessage, onCheckedChange = onSignChange)
                }
                if (state.signers.size > 1) {
                    TextButton(onClick = onSignAs) {
                        Text(stringResource(R.string.encrypt_sign_as_label))
                    }
                }
            }
        }
    }

    state.errorMessage?.let { msg ->
        Text(
            text = msg,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
            Text(stringResource(R.string.common_button_cancel))
        }
        Button(
            onClick = onEncrypt,
            modifier = Modifier.weight(1f),
            enabled = state.selectedRecipients.isNotEmpty(),
        ) {
            Text(stringResource(R.string.share_target_encrypt_button))
        }
    }
}

@Composable
private fun SignerStep(
    state: ProcessTextUiState,
    onSelect: (PGPKeyEntity) -> Unit,
    onSign: () -> Unit,
    onBack: () -> Unit,
) {
    val isSign = state.mode == ProcessText.Mode.SIGN
    state.signers.forEach { key ->
        ShareRecipientRow(
            key = key,
            selected = key.fingerprint == state.signer?.fingerprint,
            onClick = { onSelect(key) },
        )
    }
    state.errorMessage?.let { msg ->
        Text(
            text = msg,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) {
            Text(stringResource(if (isSign) R.string.common_button_cancel else R.string.common_button_back))
        }
        // Encrypt picks the signer by tapping a row and goes back on its own.
        if (isSign) {
            Button(
                onClick = onSign,
                modifier = Modifier.weight(1f),
                enabled = state.signer != null,
            ) {
                Text(stringResource(R.string.encrypt_action_sign))
            }
        }
    }
}

@Composable
private fun PassphraseStep(
    state: ProcessTextUiState,
    onChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onBack: () -> Unit,
) {
    state.signer?.let { key ->
        Text(
            text = stringResource(R.string.encrypt_also_sign_subtitle_format, signerName(key)),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    OutlinedTextField(
        value = state.passphrase,
        onValueChange = onChange,
        label = { Text(stringResource(R.string.share_target_decrypt_passphrase_label)) },
        visualTransformation = PasswordVisualTransformation(),
        // #105: the keyboard's Done runs the step's action.
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
        keyboardActions = KeyboardActions(onDone = { onSubmit() }),
        singleLine = true,
        modifier = Modifier
            .fillMaxWidth()
            .autofillPassword { onChange(it) },
    )
    state.errorMessage?.let { msg ->
        Text(
            text = msg,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) {
            Text(stringResource(R.string.common_button_back))
        }
        Button(onClick = onSubmit, modifier = Modifier.weight(1f)) {
            Text(
                stringResource(
                    if (state.mode == ProcessText.Mode.SIGN) R.string.encrypt_action_sign
                    else R.string.share_target_encrypt_button
                )
            )
        }
    }
}

@Composable
private fun CardPinStep(
    state: ProcessTextUiState,
    onChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onBack: () -> Unit,
) {
    Text(
        text = stringResource(R.string.card_sign_dialog_message),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    OutlinedTextField(
        value = state.cardPin,
        onValueChange = onChange,
        label = { Text(stringResource(R.string.card_decrypt_pin_label)) },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
        keyboardActions = KeyboardActions(onDone = { if (state.cardPin.isNotEmpty()) onSubmit() }),
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    state.errorMessage?.let { msg ->
        Text(
            text = msg,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) {
            Text(stringResource(R.string.common_button_back))
        }
        Button(
            onClick = onSubmit,
            modifier = Modifier.weight(1f),
            enabled = state.cardPin.isNotEmpty(),
        ) {
            Text(stringResource(R.string.card_sign_button))
        }
    }
}

@Composable
private fun CardWaiting(onCancel: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        CircularProgressIndicator()
        Text(
            text = stringResource(R.string.card_sign_hold_card),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        TextButton(onClick = onCancel) {
            Text(stringResource(R.string.common_button_cancel))
        }
    }
}

private fun copyResult(context: Context, text: String, signed: Boolean) {
    val clip = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    val label = context.getString(
        if (signed) R.string.card_sign_result_title else R.string.share_target_clip_label_encrypted
    )
    clip.setPrimaryClip(ClipData.newPlainText(label, text))
}

private fun shareResult(context: Context, text: String, signed: Boolean) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    val title = if (signed) null else context.getString(R.string.share_target_share_chooser_encrypted)
    val chooser = Intent.createChooser(send, title)
    chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(chooser)
}
