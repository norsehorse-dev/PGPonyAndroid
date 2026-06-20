// EncryptionResultScreen.kt
// PGPony Android — Phase A10b
//
// Modal bottom sheet shown after a successful text-mode encrypt or
// sign-only operation. Mirrors iOS EncryptionResultView's shape:
//
//   1. Success header (icon + title) — icon and label adapt to sign-only
//   2. Status badges row (recipient count + Signed checkmark)
//   3. Encrypted/signed output preview (scrollable monospace card)
//   4. Recipients list — only shown for encrypt (skipped for sign-only)
//   5. Copy + Share buttons
//
// Triggered by EncryptUiState.showEncryptResultSheet flag, dismissed
// by calling viewModel.dismissEncryptResult(). The sheet doesn't own
// the output text — it reads it from state — so the inline output
// block in EncryptScreen continues to render the same content after
// dismissal, giving the user a second access point for copying.

package com.pgpony.android.ui.encrypt

import android.content.ClipData
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.getSystemService
import com.pgpony.android.R
import com.pgpony.android.MainActivity
import com.pgpony.android.ui.util.ClipboardService

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EncryptionResultScreen(state: EncryptUiState, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val signOnly = state.mode == EncryptMode.SIGN
    val signed = signOnly || (state.signMessage && state.signingKey != null)
    val output = state.outputText
    val detached = signOnly && state.detachedSignature
    val activity = context.findResultMainActivity()
    // One-shot save feedback (local UI flair, no business value).
    var savedNote by remember { mutableStateOf<String?>(null) }

    // One-shot "Copied!" feedback. The state lives in the sheet rather
    // than the ViewModel because it's pure UI flair — no business
    // value to remember across sheet dismissals. Mirrors iOS's
    // 3-second auto-revert behavior.
    var copied by remember { mutableStateOf(false) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 8.dp)
                .navigationBarsPadding(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // ── 1. Success header ────────────────────────────────────
            Icon(
                imageVector = if (signOnly) Icons.Filled.CheckCircle else Icons.Filled.Lock,
                contentDescription = null,
                tint = if (signOnly)
                    Color(0xFF22C55E)   // green — matches iOS sign-only success
                else
                    MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(56.dp)
            )
            Text(
                if (signOnly) stringResource(R.string.result_encrypt_header_signed) else stringResource(R.string.result_encrypt_header_encrypted),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )

            // ── 2. Status badges row ─────────────────────────────────
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (!signOnly) {
                    val count = state.selectedRecipients.size
                    StatusBadge(
                        icon = Icons.Filled.Person,
                        // iOS uses localized plurals here; we mimic the
                        // English version pending the localization phase.
                        label = if (count == 1) "1 recipient" else "$count recipients",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (signed) {
                    StatusBadge(
                        icon = Icons.Filled.VerifiedUser,
                        label = stringResource(R.string.result_encrypt_badge_signed),
                        tint = Color(0xFF22C55E)
                    )
                }
            }

            // ── 3. Output preview ────────────────────────────────────
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.Start
            ) {
                Text(
                    if (signOnly) stringResource(R.string.result_encrypt_output_signed) else stringResource(R.string.result_encrypt_output_encrypted),
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(6.dp))
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 200.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .verticalScroll(rememberScrollState())
                            .padding(12.dp)
                    ) {
                        Text(
                            output,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp
                        )
                    }
                }
            }

            // ── 4. Recipients list (encrypt-only) ────────────────────
            if (!signOnly && state.selectedRecipients.isNotEmpty()) {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.Start
                ) {
                    Text(
                        stringResource(R.string.result_encrypt_can_decrypt_label),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    state.selectedRecipients.forEach { key ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Filled.Person,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                key.userName.ifBlank { key.userEmail },
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.weight(1f),
                                maxLines = 1
                            )
                            Text(
                                key.shortFingerprint,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            // ── 5. Action buttons ────────────────────────────────────
            Button(
                onClick = {
                    // Phase A12: route through ClipboardService for
                    // auto-clear support. Label keeps the same "Signed
                    // message" / "Encrypted message" distinction shown
                    // in Android 13+ clipboard previews — armored
                    // ciphertext is by design safe to share publicly,
                    // so no EXTRA_IS_SENSITIVE marker needed (the
                    // previous direct-clipboard code also omitted it).
                    val label = if (signOnly) context.getString(R.string.result_encrypt_clipboard_label_signed) else context.getString(R.string.result_encrypt_clipboard_label_encrypted)
                    ClipboardService.copyText(context, output, label = label)
                    copied = true
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    if (copied) Icons.Filled.CheckCircle else Icons.Filled.ContentCopy,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(if (copied) stringResource(R.string.common_button_copied) else stringResource(R.string.common_button_copy_to_clipboard))
            }

            // ── Phase A12: live countdown ────────────────────────────
            //
            // Mirrors iOS Views/Encrypt/EncryptionResultView.swift:143-147
            // ("Clipboard will clear in Xs"). Only rendered when
            // ClipboardService has an active countdown — collected via
            // collectAsState off the service's StateFlow. The
            // countdown remains visible until it ticks to zero, then
            // disappears. Color-muted to keep it ambient rather than
            // alarming.
            val countdown by ClipboardService.countdownSeconds.collectAsState()
            if (copied && countdown > 0) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    stringResource(R.string.clipboard_will_clear_in_format, countdown),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
            }

            OutlinedButton(
                onClick = {
                    // ACTION_SEND with the armored text. Apps that
                    // accept text/plain can ingest the ciphertext
                    // directly; on API 26+ this surfaces the share
                    // sheet with Messages, Mail, etc. as targets.
                    val sendIntent = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, output)
                    }
                    context.startActivity(
                        Intent.createChooser(
                            sendIntent,
                            if (signOnly) context.getString(R.string.result_encrypt_share_chooser_signed) else context.getString(R.string.result_encrypt_share_chooser_encrypted)
                        )
                    )
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.Share, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.common_button_share))
            }

            // ── Save as file (SAF) ───────────────────────────────────
            // Reuses MainActivity.startDocumentCreator (same picker the
            // FILE-mode sheet uses). Suggested name + MIME adapt to the
            // output type.
            OutlinedButton(
                onClick = {
                    val suggestedName = when {
                        detached -> "signature.asc"
                        signOnly -> "signed-message.asc"
                        else -> "message.asc"
                    }
                    // Use octet-stream so the system picker preserves the
                    // suggested name verbatim. A typed PGP/text MIME makes
                    // SAF append its own extension (e.g. signature.asc.pgp).
                    val mime = "application/octet-stream"
                    activity?.startDocumentCreator(mime, suggestedName) { uri ->
                        if (uri == null) return@startDocumentCreator
                        try {
                            context.contentResolver.openOutputStream(uri)?.use {
                                it.write(output.toByteArray(Charsets.UTF_8)); it.flush()
                            }
                            savedNote = context.getString(R.string.result_save_saved_note)
                        } catch (e: Exception) {
                            savedNote = context.getString(R.string.result_save_failed_note)
                        }
                    }
                },
                enabled = activity != null,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.SaveAlt, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.result_save_as_file_button))
            }

            // For a detached signature, gpg --verify needs the exact
            // signed bytes too. Offer to save the message alongside so
            // the two files drop straight into `gpg --verify sig msg`.
            if (detached) {
                OutlinedButton(
                    onClick = {
                        activity?.startDocumentCreator("application/octet-stream", "message.txt") { uri ->
                            if (uri == null) return@startDocumentCreator
                            try {
                                context.contentResolver.openOutputStream(uri)?.use {
                                    it.write(state.inputText.toByteArray(Charsets.UTF_8)); it.flush()
                                }
                                savedNote = context.getString(R.string.result_save_message_saved_note)
                            } catch (e: Exception) {
                                savedNote = context.getString(R.string.result_save_failed_note)
                            }
                        }
                    },
                    enabled = activity != null,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.Description, null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.result_save_signed_message_button))
                }
            }

            savedNote?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

@Composable
private fun StatusBadge(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    tint: Color
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            icon,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(14.dp)
        )
        Spacer(modifier = Modifier.width(4.dp))
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = tint
        )
    }
}

private tailrec fun Context.findResultMainActivity(): MainActivity? = when (this) {
    is MainActivity -> this
    is ContextWrapper -> baseContext.findResultMainActivity()
    else -> null
}
