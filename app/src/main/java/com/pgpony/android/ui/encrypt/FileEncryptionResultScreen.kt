// FileEncryptionResultScreen.kt
// PGPony Android — Phase A10b
//
// Modal bottom sheet shown after a successful file-mode encrypt.
// Mirrors iOS FileEncryptionResultView's shape:
//
//   1. Success icon + "File Encrypted" title
//   2. Status badges row (recipient count + Signed)
//   3. Output file card — name (<original>.pgp), size, lock icon
//   4. Recipients list
//   5. Save to Files button + Share button + Done
//
// Save flow: tapping Save opens ACTION_CREATE_DOCUMENT via
// MainActivity.startDocumentCreator (A10b helper), suggests
// "<originalName>.pgp" as the filename and "application/pgp-encrypted"
// as the MIME, then writes the encrypted bytes to the returned URI.
// Share flow: writes a temp file to the app cache directory, then
// shares via FileProvider — the FileProvider authority is the one
// set up in A7 Fix3 (file_paths.xml).
//
// On Save/Share success the sheet stays open so the user can do both
// — common pattern. Dismissal happens via the Done button or system
// back gesture, which calls viewModel.dismissFileEncryptResult() to
// clear the encrypted-bytes state and close the sheet.

package com.pgpony.android.ui.encrypt

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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.pgpony.android.R
import com.pgpony.android.MainActivity
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FileEncryptionResultScreen(state: EncryptUiState, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val activity = context.findFileResultMainActivity()
    val signed = state.signMessage && state.signingKey != null
    val origName = state.selectedFileName ?: "file"
    val encryptedName = "$origName.pgp"
    val encryptedBytes = state.encryptedFileBytes ?: ByteArray(0)

    // Save-status banner state. Same one-shot UI flair pattern as the
    // text-mode sheet — kept local since it has no business value.
    var saveStatus by remember { mutableStateOf<SaveStatus>(SaveStatus.Idle) }

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
                Icons.Filled.Lock,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(56.dp)
            )
            Text(
stringResource(R.string.file_enc_result_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )

            // ── 2. Status badges ─────────────────────────────────────
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                val count = state.selectedRecipients.size
                FileStatusBadge(
                    icon = Icons.Filled.Person,
                    label = if (count == 1) "1 recipient" else "$count recipients",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (signed) {
                    FileStatusBadge(
                        icon = Icons.Filled.VerifiedUser,
                        label = stringResource(R.string.file_enc_result_badge_signed),
                        tint = Color(0xFF22C55E)
                    )
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
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(28.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            encryptedName,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            maxLines = 1
                        )
                        Text(
                            formatFileSize(encryptedBytes.size.toLong()),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // ── 4. Recipients list ───────────────────────────────────
            if (state.selectedRecipients.isNotEmpty()) {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.Start
                ) {
                    Text(
stringResource(R.string.file_enc_result_badge_can_decrypt),
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
                    activity?.startDocumentCreator(
                        mimeType = "application/pgp-encrypted",
                        suggestedName = encryptedName
                    ) { uri ->
                        if (uri == null) {
                            // user cancelled — silent
                            return@startDocumentCreator
                        }
                        try {
                            context.contentResolver.openOutputStream(uri)?.use {
                                it.write(encryptedBytes)
                                it.flush()
                            }
                            saveStatus = SaveStatus.Saved
                        } catch (e: Exception) {
                            saveStatus = SaveStatus.Error(e.message ?: context.getString(R.string.file_enc_result_save_failed_default))
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = activity != null
            ) {
                Icon(Icons.Filled.SaveAlt, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.file_enc_result_save_button))
            }

            OutlinedButton(
                onClick = {
                    try {
                        // Write to app cache + share via FileProvider so
                        // other apps can read the file. Cache dir is
                        // OS-cleaned automatically; FileProvider grants
                        // one-shot read URIs via FLAG_GRANT_READ_URI_PERMISSION.
                        val exportsDir = File(context.cacheDir, "exports").apply { mkdirs() }
                        val outFile = File(exportsDir, encryptedName)
                        outFile.writeBytes(encryptedBytes)
                        val shareUri = FileProvider.getUriForFile(
                            context,
                            "${context.packageName}.fileprovider",
                            outFile
                        )
                        val send = Intent(Intent.ACTION_SEND).apply {
                            type = "application/pgp-encrypted"
                            putExtra(Intent.EXTRA_STREAM, shareUri)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        context.startActivity(
                            Intent.createChooser(send, context.getString(R.string.file_enc_result_share_chooser_title))
                        )
                    } catch (e: Exception) {
                        saveStatus = SaveStatus.Error(e.message ?: context.getString(R.string.file_enc_result_share_failed_default))
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.Share, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.file_enc_result_share_button))
            }

            // ── Status banner ────────────────────────────────────────
            when (val s = saveStatus) {
                SaveStatus.Idle -> { /* nothing */ }
                SaveStatus.Saved -> {
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
                            stringResource(R.string.file_enc_result_save_success),
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF22C55E)
                        )
                    }
                }
                is SaveStatus.Error -> {
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

@Composable
private fun FileStatusBadge(
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
        Text(label, style = MaterialTheme.typography.bodySmall, color = tint)
    }
}

private sealed class SaveStatus {
    object Idle : SaveStatus()
    object Saved : SaveStatus()
    data class Error(val message: String) : SaveStatus()
}

/**
 * Same ContextWrapper unwrap pattern as ImportKeyScreen Fix2 and
 * Screens.kt's findEncryptMainActivity(). FileEncryptionResultScreen
 * is rendered inside a ModalBottomSheet so the simple cast would
 * fail — must unwrap.
 */
private tailrec fun Context.findFileResultMainActivity(): MainActivity? = when (this) {
    is MainActivity -> this
    is ContextWrapper -> baseContext.findFileResultMainActivity()
    else -> null
}
