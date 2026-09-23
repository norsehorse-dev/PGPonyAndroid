// ShareTargetScreen.kt
// PGPony Android — Phase A15
//
// Root Composable hosted by ShareTargetActivity. Subscribes to
// ShareTargetViewModel.state and dispatches to one of:
//
//   ShareTargetPhase.PickAction      → ShareRootContent
//   ShareTargetPhase.PickRecipients  → ShareEncryptScreen
//   ShareTargetPhase.Processing      → ShareProcessingContent
//   ShareTargetPhase.EncryptResult   → ShareEncryptResultContent
//   ShareTargetPhase.PickDecryptKey  → ShareDecryptScreen
//   ShareTargetPhase.NeedPassphrase  → ShareDecryptScreen
//   ShareTargetPhase.DecryptResult   → ShareDecryptResultContent
//   ShareTargetPhase.Error           → ShareErrorContent
//
// The activity is intentionally a single-screen surface — every phase
// renders inside the same Scaffold so the user perceives one
// continuous task, not a deck of pushed views. iOS's Action
// Extension behaves the same way.
//
// Reusable bits live here (ShareScaffold, ShareInputPreview,
// ShareResultActionRow) because they are shared across encrypt and
// decrypt result phases.

package com.pgpony.android.ui.share

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.pgpony.android.MainActivity
import com.pgpony.android.R
import com.pgpony.android.intent.ShareIntentContent
import androidx.core.content.FileProvider
import com.pgpony.android.ui.util.ScratchFiles
import java.io.File
import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.card.CardDecryptService
import com.pgpony.android.crypto.card.OpenPgpCardException
import com.pgpony.android.saf.findDocumentCreatorHost
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ── Root Composable ────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareTargetScreen(
    vm: ShareTargetViewModel,
    onDismiss: () -> Unit,
) {
    val state by vm.state.collectAsState()
    val context = LocalContext.current

    // 4.1.0 Phase 7b — Save outcome, hoisted here because this is where the
    // result payload and the Context both are. Cleared whenever the phase
    // changes so a note from an earlier result cannot follow the user into
    // the next one.
    val saveScope = rememberCoroutineScope()
    var saveNote by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(state.phase) { saveNote = null }

    // HW Phase 3 — strings captured here; the NFC op lambda runs on a
    // binder thread and can't call stringResource.
    val cardNfcUnavailMsg = stringResource(R.string.card_scan_nfc_unavailable)
    val cardTooLargeMsg = stringResource(R.string.encdec_error_file_too_large_for_card)
    val cardPairFirstMsg = stringResource(R.string.card_sign_pair_first)
    val cardDecFailedMsg = stringResource(R.string.card_sign_failed_generic)

    ShareScaffold(
        title = ShareTitleForPhase(state.phase),
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
            // Input preview is shown on the picker screens (PickAction
            // / PickRecipients / PickDecryptKey / NeedPassphrase) so
            // the user can see what they're operating on. Hidden on
            // Processing / *Result / Error phases where it would just
            // be visual noise — the result IS the content there.
            if (state.phase in setOf(
                    ShareTargetPhase.PickAction,
                    ShareTargetPhase.PickRecipients,
                    ShareTargetPhase.PickDecryptKey,
                    ShareTargetPhase.NeedPassphrase,
                    ShareTargetPhase.CardPin,
                )
            ) {
                ShareInputPreview(content = state.content)
            }

            when (state.phase) {
                ShareTargetPhase.PickAction -> ShareRootContent(
                    state = state,
                    onEncrypt = { vm.beginEncrypt() },
                    onDecrypt = { vm.beginDecrypt() },
                    onOpenFullApp = { launchFullApp(context); onDismiss() },
                    onForwardKeyToMainApp = { armoredKey ->
                        launchFullAppWithForward(context, armoredKey)
                        onDismiss()
                    },
                )

                ShareTargetPhase.PickRecipients -> ShareEncryptPicker(
                    state = state,
                    onToggleRecipient = vm::toggleRecipient,
                    onConfirm = { vm.performEncrypt() },
                    onBack = { vm.goBackToActionPicker() },
                )

                ShareTargetPhase.PickDecryptKey -> ShareDecryptKeyPicker(
                    state = state,
                    onSelectKey = vm::selectDecryptKey,
                    onBack = { vm.goBackToActionPicker() },
                )

                ShareTargetPhase.NeedPassphrase -> ShareDecryptPassphrasePrompt(
                    state = state,
                    onPassphraseChange = vm::updatePassphrase,
                    onDecrypt = { vm.performDecrypt() },
                    onBack = { vm.goBackToActionPicker() },
                )

                ShareTargetPhase.CardPin -> {
                    val cardActivity = context as? ShareTargetActivity
                    ShareCardDecryptPrompt(
                        state = state,
                        onPinChange = vm::updateCardPin,
                        onDecrypt = {
                            val pin = state.cardPin
                            val cardFp = state.cardDecryptKeyFingerprint
                            val bytes = vm.encryptedBytesForCardDecrypt()
                            // 4.0.4 — a card operation holds the NFC session
                            // open throughout, so it cannot stream; a file
                            // too large to buffer has no bytes to give it.
                            val tooLargeForCard = bytes == null &&
                                (state.content as? ShareIntentContent.PgpFile)?.uri != null
                            if (cardActivity == null || cardFp == null || bytes == null) {
                                vm.onCardDecryptFailure(
                                    if (tooLargeForCard) cardTooLargeMsg else cardNfcUnavailMsg
                                )
                            } else {
                                vm.onCardDecryptStarted()
                                val started = cardActivity.startCardOperation({ session ->
                                    session.select()
                                    // 3.1.0 Phase 7 Fix1: tolerant loader (offline-primary cards).
                                    val pubRing = PGPonyApp.instance.keyRepository
                                        .loadPublicKeyRingByCardFingerprint(cardFp)
                                        ?: throw OpenPgpCardException.Malformed(cardPairFirstMsg)
                                    CardDecryptService.shared.decryptBytes(
                                        session, pubRing, pin.toByteArray(Charsets.UTF_8), bytes
                                    )
                                }) { result ->
                                    // 4.0.5 — card is still in the field; see
                                    // MainActivity.endCardOperation and #7.
                                    cardActivity.endCardOperation()
                                    result
                                        .onSuccess { vm.onCardDecryptSuccess(String(it.data, Charsets.UTF_8)) }
                                        .onFailure { e -> vm.onCardDecryptFailure(e.message ?: cardDecFailedMsg) }
                                }
                                if (!started) vm.onCardDecryptFailure(cardNfcUnavailMsg)
                            }
                        },
                        onBack = { vm.goBackToActionPicker() },
                    )
                }

                ShareTargetPhase.Processing -> ShareProcessingContent()

                ShareTargetPhase.EncryptResult -> ShareEncryptResultContent(
                    state = state,
                    onCopy = { copyToClipboard(context, state.outputText, encrypt = true) },
                    onSave = {
                        saveResult(
                            context, saveScope,
                            state.outputText.toByteArray(Charsets.UTF_8),
                            null, "encrypted.asc",
                        ) { saveNote = it }
                    },
                    onShare = { shareText(context, state.outputText, encrypt = true) },
                    onDone = onDismiss,
                    saveNote = saveNote,
                )

                ShareTargetPhase.EncryptFileResult -> ShareEncryptFileResultContent(
                    state = state,
                    // Issue #13, exactly: file shared in, encrypted, and
                    // previously no way to put it anywhere.
                    onSave = {
                        saveResult(
                            context, saveScope,
                            state.encryptedFileBytes,
                            state.encryptedFile,
                            state.encryptedFileName ?: "encrypted.gpg",
                        ) { saveNote = it }
                    },
                    saveNote = saveNote,
                    onShare = {
                        shareFile(
                            context,
                            state.encryptedFileBytes,
                            state.encryptedFile,
                            // 3.1.0 Phase 1 (C2) — .gpg fallback (was .pgp).
                            state.encryptedFileName ?: "encrypted.gpg",
                        )
                    },
                    onDone = onDismiss,
                )

                ShareTargetPhase.DecryptResult -> ShareDecryptResultContent(
                    state = state,
                    onCopy = { copyToClipboard(context, state.outputText, encrypt = false) },
                    onSave = {
                        saveResult(
                            context, saveScope,
                            state.outputText.toByteArray(Charsets.UTF_8),
                            null, "message.txt",
                        ) { saveNote = it }
                    },
                    onShare = { shareText(context, state.outputText, encrypt = false) },
                    onDone = onDismiss,
                    saveNote = saveNote,
                )

                ShareTargetPhase.DecryptFileResult -> ShareDecryptFileResultContent(
                    state = state,
                    // Not named in #13, but the identical gap: a decrypted
                    // file could only be shared back out, never kept.
                    onSave = {
                        saveResult(
                            context, saveScope,
                            state.decryptedFileBytes,
                            state.decryptedFile,
                            state.decryptedFileName ?: "decrypted_file",
                        ) { saveNote = it }
                    },
                    saveNote = saveNote,
                    onShare = {
                        val fname = state.decryptedFileName ?: "decrypted_file"
                        shareFile(
                            context,
                            state.decryptedFileBytes,
                            state.decryptedFile,
                            fname,
                            guessMimeType(fname),
                        )
                    },
                    onDone = onDismiss,
                )

                ShareTargetPhase.Error -> ShareErrorContent(
                    message = state.errorMessage,
                    onBack = { vm.goBackToActionPicker() },
                    onDismiss = onDismiss,
                )
            }
        }
    }
}

// ── Scaffold ───────────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ShareScaffold(
    title: String,
    onDismiss: () -> Unit,
    content: @Composable (PaddingValues) -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                actions = {
                    IconButton(onClick = onDismiss) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = stringResource(R.string.share_target_dismiss_cd),
                        )
                    }
                },
            )
        },
        content = content,
    )
}

@Composable
private fun ShareTitleForPhase(phase: ShareTargetPhase): String = when (phase) {
    ShareTargetPhase.PickAction -> stringResource(R.string.share_target_root_title)
    ShareTargetPhase.PickRecipients -> stringResource(R.string.share_target_encrypt_title)
    ShareTargetPhase.PickDecryptKey,
    ShareTargetPhase.NeedPassphrase,
    ShareTargetPhase.CardPin -> stringResource(R.string.share_target_decrypt_title)
    ShareTargetPhase.Processing -> stringResource(R.string.share_target_processing)
    ShareTargetPhase.EncryptResult -> stringResource(R.string.share_target_encrypt_result_title)
    ShareTargetPhase.EncryptFileResult -> stringResource(R.string.share_target_encrypt_file_result_title)
    ShareTargetPhase.DecryptResult -> stringResource(R.string.share_target_decrypt_result_title)
    ShareTargetPhase.DecryptFileResult -> stringResource(R.string.share_target_decrypt_file_result_title)
    ShareTargetPhase.Error -> stringResource(R.string.app_name)
}

// ── Input preview ──────────────────────────────────────────────────────

@Composable
fun ShareInputPreview(content: ShareIntentContent) {
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
            when (content) {
                is ShareIntentContent.Text -> {
                    Text(
                        text = stringResource(R.string.share_target_input_label_text),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    val truncated = content.text.length > previewMaxChars
                    Text(
                        text = if (truncated) content.text.take(previewMaxChars) else content.text,
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = if (content.looksLikePgpMessage || content.looksLikePgpKey)
                            FontFamily.Monospace else null,
                        maxLines = 6,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (truncated) {
                        Text(
                            text = stringResource(
                                R.string.share_target_input_truncated_format,
                                content.text.length,
                            ),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                is ShareIntentContent.PgpFile -> {
                    Text(
                        text = stringResource(
                            R.string.share_target_input_label_file_format,
                            content.filename ?: "(unnamed)",
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    val armoredText = content.armoredText
                    if (armoredText != null) {
                        val truncated = armoredText.length > previewMaxChars
                        Text(
                            text = if (truncated) armoredText.take(previewMaxChars) else armoredText,
                            style = MaterialTheme.typography.bodyMedium,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 6,
                            overflow = TextOverflow.Ellipsis,
                        )
                        if (truncated) {
                            Text(
                                text = stringResource(
                                    R.string.share_target_input_truncated_format,
                                    armoredText.length,
                                ),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    } else {
                        // 4.0.4 — a file too large to buffer has no bytes;
                        // ask the provider for its size instead. Remembered
                        // so the query doesn't run on every recomposition.
                        val previewCtx = LocalContext.current
                        val inputSize = remember(content) {
                            content.data?.size?.toLong()
                                ?: content.uri?.let {
                                    com.pgpony.android.intent.DocumentBytes
                                        .declaredSize(previewCtx.contentResolver, it)
                                }
                                ?: 0L
                        }
                        Text(
                            text = stringResource(
                                R.string.share_target_input_binary_format,
                                inputSize,
                            ),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                ShareIntentContent.Empty -> {
                    Text(
                        text = stringResource(R.string.share_target_error_no_input),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

// ── Root picker (Encrypt vs Decrypt vs Open Full App) ──────────────────

@Composable
private fun ShareRootContent(
    state: ShareTargetUiState,
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
    onOpenFullApp: () -> Unit,
    onForwardKeyToMainApp: (String) -> Unit,
) {
    val content = state.content
    val subtitle = when (content) {
        is ShareIntentContent.Text -> stringResource(R.string.share_target_root_subtitle_text)
        is ShareIntentContent.PgpFile -> stringResource(
            R.string.share_target_root_subtitle_file_format,
            content.filename ?: "(unnamed)",
        )
        ShareIntentContent.Empty -> ""
    }
    if (subtitle.isNotBlank()) {
        Text(
            text = subtitle,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    // Decide which actions to offer based on classification.
    val looksLikeKey = when (content) {
        is ShareIntentContent.Text -> content.looksLikePgpKey
        is ShareIntentContent.PgpFile -> content.looksLikePgpKey
        ShareIntentContent.Empty -> false
    }
    val looksLikeMessage = when (content) {
        is ShareIntentContent.Text -> content.looksLikePgpMessage
        is ShareIntentContent.PgpFile -> content.looksLikePgpMessage
        ShareIntentContent.Empty -> false
    }
    val noKeyPairs = state.availableKeyPairs.isEmpty()
    val noRecipients = state.availableRecipients.isEmpty()

    // Empty state: user has no keys at all → must launch full app to set up
    if (noKeyPairs && noRecipients) {
        ShareActionCard(
            title = stringResource(R.string.share_target_open_full_app),
            subtitle = stringResource(R.string.share_target_open_full_app_subtitle_setup),
            icon = Icons.Default.OpenInNew,
            onClick = onOpenFullApp,
        )
        return
    }

    // PGP key block → defer to main app (import flow lives there). We
    // forward the armored key text so the user lands directly in the
    // import sheet rather than an empty Keyring tab.
    if (looksLikeKey) {
        val armoredKey: String = when (content) {
            is ShareIntentContent.Text -> content.text
            is ShareIntentContent.PgpFile -> content.armoredText.orEmpty()
            ShareIntentContent.Empty -> ""
        }
        ShareActionCard(
            title = stringResource(R.string.share_target_open_full_app),
            subtitle = stringResource(R.string.share_target_open_full_app_subtitle_import),
            icon = Icons.Default.OpenInNew,
            onClick = {
                if (armoredKey.isNotBlank()) onForwardKeyToMainApp(armoredKey)
                else onOpenFullApp()
            },
        )
        return
    }

    // PGP message → primary action is Decrypt, encrypt is hidden
    // (re-encrypting a ciphertext is a weird user intent).
    if (looksLikeMessage) {
        ShareActionCard(
            title = stringResource(R.string.share_target_action_decrypt),
            subtitle = stringResource(R.string.share_target_action_decrypt_subtitle),
            icon = Icons.Default.LockOpen,
            onClick = onDecrypt,
            enabled = !noKeyPairs,
        )
        if (noKeyPairs) {
            Text(
                text = stringResource(R.string.share_target_decrypt_no_key_pairs),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        return
    }

    // Plain text → primary action is Encrypt. Also offer Decrypt as
    // a fallback in case the classifier missed (user pasted raw armor
    // without the BEGIN marker, edge case).
    ShareActionCard(
        title = stringResource(R.string.share_target_action_encrypt),
        subtitle = stringResource(R.string.share_target_action_encrypt_subtitle),
        icon = Icons.Default.Lock,
        onClick = onEncrypt,
        enabled = !noRecipients,
    )
    if (noRecipients) {
        Text(
            text = stringResource(R.string.share_target_encrypt_recipients_empty),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }
}

@Composable
fun ShareActionCard(
    title: String,
    subtitle: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: () -> Unit,
    enabled: Boolean = true,
) {
    val containerColor =
        if (enabled) MaterialTheme.colorScheme.surfaceContainerHigh
        else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (enabled) Modifier.clickable(onClick = onClick) else Modifier),
        shape = RoundedCornerShape(16.dp),
        color = containerColor,
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ── Processing ─────────────────────────────────────────────────────────

@Composable
private fun ShareProcessingContent() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 48.dp),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            CircularProgressIndicator()
            Text(
                text = stringResource(R.string.share_target_processing),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ── Encrypt result ─────────────────────────────────────────────────────

@Composable
private fun ShareEncryptResultContent(
    state: ShareTargetUiState,
    onCopy: () -> Unit,
    onSave: () -> Unit,
    onShare: () -> Unit,
    onDone: () -> Unit,
    saveNote: String?,
) {
    Text(
        text = stringResource(
            R.string.share_target_encrypt_result_subtitle_format,
            state.outputText.length,
        ),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    ShareCipherPreview(text = state.outputText)
    ShareResultActionRow(
        onCopy = onCopy,
        onSave = onSave,
        onShare = onShare,
        onDone = onDone,
        saveNote = saveNote,
    )
}

// ── Encrypt FILE result (Phase A2) ─────────────────────────────────────

@Composable
private fun ShareEncryptFileResultContent(
    state: ShareTargetUiState,
    onSave: () -> Unit,
    saveNote: String?,
    onShare: () -> Unit,
    onDone: () -> Unit,
) {
    // 3.1.0 Phase 1 (C2) — .gpg fallback (was .pgp).
    val name = state.encryptedFileName ?: "encrypted.gpg"
    // 4.0.4 — whichever carrier is populated.
    val size = state.encryptedFileBytes?.size?.toLong() ?: state.encryptedFile?.length() ?: 0L
    Text(
        text = stringResource(R.string.share_target_encrypt_file_result_subtitle),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
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
                imageVector = Icons.Filled.Lock,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = name,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = stringResource(
                        R.string.share_target_encrypt_file_result_size_format,
                        size,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
    // 4.1.0 Phase 7b (issue #13) — Save first, then Share, then Done on its
    // own row. Done used to sit where Save is now, which is part of why
    // "done button does nothing" was the way the report was phrased: the
    // primary-looking action closed the screen and lost the file.
    // RC5 follow-up (#13, CertainBot): the filled-Save-beside-outlined-
    // Share pair read as lopsided. Now stacked full-width like the
    // in-app result screen: filled primary Save on top, outlined Share
    // below, Done unchanged on its own row.
    Button(onClick = onSave, modifier = Modifier.fillMaxWidth()) {
        Icon(
            imageVector = Icons.Filled.SaveAlt,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(stringResource(R.string.common_button_save))
    }
    OutlinedButton(onClick = onShare, modifier = Modifier.fillMaxWidth()) {
        Icon(
            imageVector = Icons.Filled.Share,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(stringResource(R.string.share_target_encrypt_file_result_share_button))
    }
    ShareSaveNote(saveNote)
    TextButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.share_target_result_done))
    }
}

// ── Decrypt result ─────────────────────────────────────────────────────

@Composable
private fun ShareDecryptFileResultContent(
    state: ShareTargetUiState,
    onSave: () -> Unit,
    saveNote: String?,
    onShare: () -> Unit,
    onDone: () -> Unit,
) {
    val name = state.decryptedFileName ?: "decrypted_file"
    // 4.0.4 — whichever carrier is populated.
    val size = state.decryptedFileBytes?.size?.toLong() ?: state.decryptedFile?.length() ?: 0L
    val signerLabel = when {
        state.signatureVerified && state.signerName != null ->
            stringResource(R.string.share_target_decrypt_result_signed_format, state.signerName)
        state.signerKeyId != null && !state.signatureVerified ->
            stringResource(R.string.share_target_decrypt_result_unverified)
        else -> stringResource(R.string.share_target_decrypt_result_unsigned)
    }
    Text(
        text = signerLabel,
        style = MaterialTheme.typography.bodySmall,
        color = if (state.signatureVerified) MaterialTheme.colorScheme.primary
        else MaterialTheme.colorScheme.onSurfaceVariant,
    )
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
                imageVector = Icons.Filled.LockOpen,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = name,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = stringResource(
                        R.string.share_target_encrypt_file_result_size_format,
                        size,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
    // 4.1.0 Phase 7b — same shape as the encrypt side. A decrypted file
    // that can only be shared back out to another app is not much use to
    // someone who wanted the file.
    // RC5 follow-up (#13, CertainBot): the filled-Save-beside-outlined-
    // Share pair read as lopsided. Now stacked full-width like the
    // in-app result screen: filled primary Save on top, outlined Share
    // below, Done unchanged on its own row.
    Button(onClick = onSave, modifier = Modifier.fillMaxWidth()) {
        Icon(
            imageVector = Icons.Filled.SaveAlt,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(stringResource(R.string.common_button_save))
    }
    OutlinedButton(onClick = onShare, modifier = Modifier.fillMaxWidth()) {
        Icon(
            imageVector = Icons.Filled.Share,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(stringResource(R.string.share_target_decrypt_file_result_share_button))
    }
    ShareSaveNote(saveNote)
    TextButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.share_target_result_done))
    }
}

@Composable
private fun ShareDecryptResultContent(
    state: ShareTargetUiState,
    onCopy: () -> Unit,
    onSave: () -> Unit,
    onShare: () -> Unit,
    onDone: () -> Unit,
    saveNote: String?,
) {
    val signerLabel = when {
        state.signatureVerified && state.signerName != null ->
            stringResource(R.string.share_target_decrypt_result_signed_format, state.signerName)
        state.signerKeyId != null && !state.signatureVerified ->
            stringResource(R.string.share_target_decrypt_result_unverified)
        else -> stringResource(R.string.share_target_decrypt_result_unsigned)
    }
    Text(
        text = signerLabel,
        style = MaterialTheme.typography.bodySmall,
        color = if (state.signatureVerified) MaterialTheme.colorScheme.primary
        else MaterialTheme.colorScheme.onSurfaceVariant,
    )
    ShareCipherPreview(text = state.outputText, monospace = false)
    // 3.1.0 Phase 6 (J6): PGP/MIME bundle — attachment-count note; the
    // full attachment view (save/preview) lives in the main app.
    state.mimeAttachmentNote?.let { note ->
        Text(
            text = note,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    ShareResultActionRow(
        onCopy = onCopy,
        onSave = onSave,
        onShare = onShare,
        onDone = onDone,
        saveNote = saveNote,
    )
}

@Composable
private fun ShareCipherPreview(text: String, monospace: Boolean = true) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = text,
            modifier = Modifier.padding(12.dp),
            fontFamily = if (monospace) FontFamily.Monospace else null,
            style = MaterialTheme.typography.bodySmall,
            maxLines = 10,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

// ── Result action row (Copy / Share / Done) ────────────────────────────

@Composable
private fun ShareResultActionRow(
    onCopy: () -> Unit,
    onSave: () -> Unit,
    onShare: () -> Unit,
    onDone: () -> Unit,
    saveNote: String?,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(
            onClick = onCopy,
            modifier = Modifier.weight(1f),
        ) {
            Icon(
                imageVector = Icons.Default.ContentCopy,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.share_target_result_copy))
        }
        // 4.1.0 Phase 7b — Copy was the only way out of here for a text
        // result, which is fine for a paragraph and useless for a key.
        OutlinedButton(
            onClick = onSave,
            modifier = Modifier.weight(1f),
        ) {
            Icon(
                imageVector = Icons.Filled.SaveAlt,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.common_button_save))
        }
        OutlinedButton(
            onClick = onShare,
            modifier = Modifier.weight(1f),
        ) {
            Icon(
                imageVector = Icons.Default.Share,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.share_target_result_share))
        }
    }
    ShareSaveNote(saveNote)
    Button(
        onClick = onDone,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(stringResource(R.string.share_target_result_done))
    }
}

/**
 * 4.1.0 Phase 7b — the outcome of a Save, in the same place the main app
 * puts it. Absent until something has actually been saved or failed to
 * save; a cancelled picker leaves it absent.
 */
@Composable
private fun ShareSaveNote(note: String?) {
    if (note == null) return
    // RC5 P4 (#13, CertainBot): success note in the shared success green,
    // failure in the theme error color. Every caller assigns either
    // result_save_saved_note or result_save_failed_note, so the failed
    // resource fully discriminates the two outcomes.
    val failed = note == stringResource(R.string.result_save_failed_note)
    Text(
        text = note,
        style = MaterialTheme.typography.bodySmall,
        color = if (failed) MaterialTheme.colorScheme.error
                else androidx.compose.ui.graphics.Color(0xFF22C55E),
    )
}

// ── Error ──────────────────────────────────────────────────────────────

@Composable
private fun ShareErrorContent(
    message: String?,
    onBack: () -> Unit,
    onDismiss: () -> Unit,
) {
    Text(
        text = message ?: stringResource(R.string.share_target_error_generic_format, "unknown"),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.error,
    )
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(
            onClick = onBack,
            modifier = Modifier.weight(1f),
        ) {
            Text(stringResource(R.string.common_button_back))
        }
        Button(
            onClick = onDismiss,
            modifier = Modifier.weight(1f),
        ) {
            Text(stringResource(R.string.share_target_result_done))
        }
    }
}

// ── Helpers: clipboard + share intent + launch main app ────────────────

private fun copyToClipboard(context: Context, text: String, encrypt: Boolean) {
    val clip = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        ?: return
    val label = context.getString(
        if (encrypt) R.string.share_target_clip_label_encrypted
        else R.string.share_target_clip_label_decrypted
    )
    clip.setPrimaryClip(ClipData.newPlainText(label, text))
}

/**
 * Phase A2 — share the encrypted FILE bytes. Mirrors the in-app
 * FileEncryptionResultScreen idiom: write to cacheDir/exports/<name>, then
 * ACTION_SEND a FileProvider content:// URI with a one-shot read grant. The
 * cache dir is OS-cleaned; the grant ends when the receiver finishes.
 */
private fun shareFile(
    context: Context,
    bytes: ByteArray?,
    scratch: File?,
    filename: String,
    mimeType: String = "application/pgp-encrypted",
) {
    try {
        // 4.0.4 — a streamed result already sits in cacheDir/scratch,
        // which file_paths.xml exposes, so it is shared in place. Only
        // the buffered branch still needs a copy written for it.
        val shareUri = if (scratch != null) {
            ScratchFiles.uriFor(context, scratch)
        } else {
            val exportsDir = File(context.cacheDir, "exports").apply { mkdirs() }
            val outFile = com.pgpony.android.ui.util.ScratchFiles.safeChild(exportsDir, filename, "decrypted_file")
            outFile.writeBytes(bytes ?: ByteArray(0))
            FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                outFile,
            )
        }
        val send = Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_STREAM, shareUri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(
            send,
            context.getString(R.string.share_target_share_chooser_encrypted),
        )
        chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(chooser)
    } catch (e: Exception) {
        // Best-effort: a share failure here is non-fatal; the user can retry.
    }
}

/**
 * 4.1.0 Phase 7b (issue #13) — write a result to a destination the user
 * picks.
 *
 * Reaches the host through findDocumentCreatorHost() rather than casting to
 * an activity, which is the entire reason this works here at all: the same
 * call compiles and runs identically in the main app and in the share
 * target.
 *
 * mimeType is application/octet-stream and not a PGP type, deliberately.
 * SAF's document creator appends the MIME's canonical extension to any name
 * that does not already end in it, so application/pgp-encrypted turns the
 * suggested "notes.pdf.gpg" into "notes.pdf.gpg.pgp" on disk. octet-stream
 * has no canonical extension, so the name survives. Same reasoning, and the
 * same fix, as FileEncryptionResultScreen's 3.1.0 Phase 2 Fix1.
 *
 * The write itself runs on Dispatchers.IO. The main app's equivalent copies
 * a streamed ciphertext to the sink on the main thread; issue #10 is open
 * about exactly that kind of main-thread work, so new code does not repeat
 * it.
 *
 * A cancelled picker is silent — the user chose that, and reporting it as
 * an outcome reads like a failure.
 */
private fun saveResult(
    context: Context,
    scope: CoroutineScope,
    bytes: ByteArray?,
    scratch: File?,
    filename: String,
    onNote: (String) -> Unit,
) {
    val host = context.findDocumentCreatorHost()
    if (host == null) {
        onNote(context.getString(R.string.result_save_failed_note))
        return
    }
    host.startDocumentCreator("application/octet-stream", filename) { uri ->
        if (uri == null) return@startDocumentCreator
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                try {
                    val sink = context.contentResolver.openOutputStream(uri)
                        ?: return@withContext false
                    sink.use { out ->
                        // Exactly one carrier is ever populated: buffered
                        // bytes, or a scratch file from the streaming path.
                        if (scratch != null) {
                            scratch.inputStream().buffered().use { src ->
                                src.copyTo(out)
                            }
                        } else {
                            out.write(bytes ?: ByteArray(0))
                        }
                        out.flush()
                    }
                    true
                } catch (e: Exception) {
                    false
                }
            }
            onNote(
                context.getString(
                    if (ok) R.string.result_save_saved_note
                    else R.string.result_save_failed_note
                )
            )
        }
    }
}

/** Guess a MIME type from a filename extension; octet-stream fallback. */
private fun guessMimeType(filename: String): String {
    val ext = filename.substringAfterLast('.', "").lowercase()
    return android.webkit.MimeTypeMap.getSingleton()
        .getMimeTypeFromExtension(ext)
        ?: "application/octet-stream"
}

private fun shareText(context: Context, text: String, encrypt: Boolean) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    val chooser = Intent.createChooser(
        send,
        context.getString(
            if (encrypt) R.string.share_target_share_chooser_encrypted
            else R.string.share_target_share_chooser_decrypted,
        )
    )
    chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(chooser)
}

private fun launchFullApp(context: Context) {
    val intent = Intent(context, MainActivity::class.java).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
    }
    context.startActivity(intent)
}

/**
 * Forward the user's shared content into MainActivity so the import
 * flow (Keyring tab) picks it up. Used when ShareTargetActivity
 * classifies the payload as a PGP key — the standalone surface
 * doesn't run the import sheet, so we hand off.
 *
 * The forwarded intent reuses the same ACTION_SEND / EXTRA_TEXT shape
 * that MainActivity's IntentHandler.process() already recognizes, so
 * there's no parallel code path to maintain.
 */
@Suppress("unused")
private fun launchFullAppWithForward(context: Context, armoredKey: String) {
    val intent = Intent(context, MainActivity::class.java).apply {
        action = Intent.ACTION_SEND
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, armoredKey)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
    }
    context.startActivity(intent)
}
