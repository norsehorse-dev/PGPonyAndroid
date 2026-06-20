// FileDecryptionResultScreen.kt
// PGPony Android — Phase A10c
//
// Modal bottom sheet shown after a successful file-mode decrypt.
// Mirrors iOS FileDecryptionResultView (DecryptView.swift:552):
//
//   1. Success icon (green lock-open) + "File Decrypted" title
//   2. Optional plaintext preview (if the decrypted bytes are
//      valid UTF-8 and short enough to render — < 5000 chars)
//   3. Output file card (suggested filename + size, green tint)
//   4. Save to Files (ACTION_CREATE_DOCUMENT) button
//   5. Share Decrypted File (FileProvider + ACTION_SEND) button
//   6. Copy to Clipboard button — only when the bytes are valid
//      UTF-8 (matching iOS's `if String(data:...) != nil` gate)
//   7. Done button
//
// The MIME type for save defaults to "application/octet-stream" —
// the decrypted plaintext might be anything, and we don't have
// enough information to guess. Users can edit the filename's
// extension in the system save dialog if they want a more specific
// type. (Future extension: detect MIME via the embedded literal-data
// filename's extension.)
//
// Verification banner from the existing VerificationBanner
// composable is shown above the file card when applicable —
// signature verification works the same for file mode as text mode
// since both share the DecryptResult.signerKeyID / signatureVerified
// path.

package com.pgpony.android.ui.encrypt

import android.content.ClipData
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import androidx.compose.foundation.background
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
import androidx.core.content.FileProvider
import androidx.core.content.getSystemService
import com.pgpony.android.MainActivity
import com.pgpony.android.R
import com.pgpony.android.ui.decrypt.VerificationBanner
import com.pgpony.android.ui.util.ClipboardService
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FileDecryptionResultScreen(state: DecryptUiState, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val activity = context.findDecryptResultMainActivity()
    val bytes = state.decryptedFileBytes ?: ByteArray(0)
    val outName = state.decryptedOutputFilename ?: stringResource(R.string.result_file_decrypt_default_filename)

    // Try to decode the decrypted bytes as UTF-8. Used both to
    // decide whether to show the preview block and to gate the
    // Copy-to-Clipboard button. Matches iOS's same gate.
    val asText = remember(bytes) {
        runCatching { String(bytes, Charsets.UTF_8) }
            .getOrNull()
            ?.takeIf { it.isNotEmpty() && it.toByteArray(Charsets.UTF_8).contentEquals(bytes) }
    }
    val asTextShort = asText?.takeIf { it.length < 5000 }

    var saveStatus by remember { mutableStateOf<DecryptSaveStatus>(DecryptSaveStatus.Idle) }
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
                Icons.Filled.LockOpen,
                contentDescription = null,
                tint = Color(0xFF22C55E),
                modifier = Modifier.size(56.dp)
            )
            Text(
                stringResource(R.string.result_file_decrypt_header),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )

            // ── Verification banner (when applicable) ────────────────
            state.verificationResult?.let { result ->
                VerificationBanner(
                    result = result,
                    onTapUnknownSigner = { /* not actionable from sheet — handled in main screen */ }
                )
            }

            // ── 2. Optional plaintext preview ────────────────────────
            asTextShort?.let { text ->
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.Start
                ) {
                    Text(
                        stringResource(R.string.result_file_decrypt_badge_preview),
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
                                text,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 13.sp
                            )
                        }
                    }
                }
            }

            // ── 3. Output file card ──────────────────────────────────
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Filled.Description,
                        contentDescription = null,
                        // Green to signal "this is the cleartext output,
                        // not the encrypted input" — same color choice as
                        // iOS doc.fill in FileDecryptionResultView.
                        tint = Color(0xFF22C55E),
                        modifier = Modifier.size(28.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            outName,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            maxLines = 1
                        )
                        Text(
                            formatFileSize(bytes.size.toLong()),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // ── 4. Save to Files ─────────────────────────────────────
            Button(
                onClick = {
                    activity?.startDocumentCreator(
                        mimeType = "application/octet-stream",
                        suggestedName = outName
                    ) { uri ->
                        if (uri == null) return@startDocumentCreator
                        try {
                            context.contentResolver.openOutputStream(uri)?.use {
                                it.write(bytes)
                                it.flush()
                            }
                            saveStatus = DecryptSaveStatus.Saved
                        } catch (e: Exception) {
                            saveStatus = DecryptSaveStatus.Error(e.message ?: context.getString(R.string.result_file_decrypt_save_failed_fallback))
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = activity != null
            ) {
                Icon(Icons.Filled.SaveAlt, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.result_file_decrypt_save_button))
            }

            // ── 5. Share Decrypted File ──────────────────────────────
            OutlinedButton(
                onClick = {
                    try {
                        val exportsDir = File(context.cacheDir, "exports").apply { mkdirs() }
                        val outFile = File(exportsDir, outName)
                        outFile.writeBytes(bytes)
                        val shareUri = FileProvider.getUriForFile(
                            context,
                            "${context.packageName}.fileprovider",
                            outFile
                        )
                        val send = Intent(Intent.ACTION_SEND).apply {
                            type = "application/octet-stream"
                            putExtra(Intent.EXTRA_STREAM, shareUri)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        context.startActivity(
                            Intent.createChooser(send, context.getString(R.string.result_file_decrypt_share_chooser))
                        )
                    } catch (e: Exception) {
                        saveStatus = DecryptSaveStatus.Error(e.message ?: context.getString(R.string.result_file_decrypt_share_failed_fallback))
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.Share, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.result_file_decrypt_share_button))
            }

            // ── 6. Copy to Clipboard (text-only) ─────────────────────
            asText?.let { text ->
                OutlinedButton(
                    onClick = {
                        // Phase A12: route through ClipboardService for
                        // auto-clear support. Decrypted text is more
                        // sensitive than encrypted output — the user
                        // explicitly opened it via successful decryption
                        // — so the auto-clear default of 60s is the
                        // right safety net.
                        ClipboardService.copyText(context, text, label = context.getString(R.string.decrypt_clipboard_label))
                        copied = true
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(
                        if (copied) Icons.Filled.CheckCircle else Icons.Filled.ContentCopy,
                        null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(if (copied) stringResource(R.string.common_button_copied) else stringResource(R.string.common_button_copy_to_clipboard))
                }
                // Phase A12: live countdown text, same pattern as
                // EncryptionResultScreen. Tied to copied=true so it
                // doesn't pop in unexpectedly if another part of the
                // app's clipboard write started a countdown while
                // this sheet was open.
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
            }

            // ── Status banner ────────────────────────────────────────
            when (val s = saveStatus) {
                DecryptSaveStatus.Idle -> { /* nothing */ }
                DecryptSaveStatus.Saved -> {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(
                                Color(0xFF22C55E).copy(alpha = 0.1f),
                                RoundedCornerShape(8.dp)
                            )
                            .padding(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Filled.CheckCircle,
                            contentDescription = null,
                            tint = Color(0xFF22C55E),
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            stringResource(R.string.result_file_decrypt_saved_status),
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF22C55E)
                        )
                    }
                }
                is DecryptSaveStatus.Error -> {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(
                                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.4f),
                                RoundedCornerShape(8.dp)
                            )
                            .padding(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Filled.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            s.message,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }

            // ── 7. Done ──────────────────────────────────────────────
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.common_button_done))
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

private sealed class DecryptSaveStatus {
    object Idle : DecryptSaveStatus()
    object Saved : DecryptSaveStatus()
    data class Error(val message: String) : DecryptSaveStatus()
}

/**
 * Same ContextWrapper unwrap pattern as the other ModalBottomSheet
 * hosts in this package. ModalBottomSheet uses a Dialog window with
 * its own context wrapper, so `LocalContext.current as? MainActivity`
 * returns null inside it — walk baseContext until we hit the real
 * activity.
 */
private tailrec fun Context.findDecryptResultMainActivity(): MainActivity? = when (this) {
    is MainActivity -> this
    is ContextWrapper -> baseContext.findDecryptResultMainActivity()
    else -> null
}
