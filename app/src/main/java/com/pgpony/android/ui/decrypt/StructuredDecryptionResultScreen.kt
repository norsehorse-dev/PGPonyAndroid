// StructuredDecryptionResultScreen.kt
// PGPony Android — 3.1.0 Phase 4 (J1)
//
// The structured result for a decrypted PGP/MIME message: the body on
// top, then one row per attachment (thumbnail for images, type icon
// otherwise, name + type + size), each with Save (SAF) and Share
// (FileProvider). A bottom "Share all" uses ACTION_SEND_MULTIPLE.
//
// Port of iOS Views/Decrypt/StructuredDecryptionResultView.swift
// (7.1.x). Deviation from iOS noted: iOS offers "Save All"; Android's
// SAF has no multi-file create dialog, so "Share all" (→ Files app or
// any target) covers the bulk case and Save stays per-row.
//
// Tapping a row opens the attachment in a viewer app (ACTION_VIEW via
// a cache-dir FileProvider URI with a one-shot read grant — the same
// pattern FileEncryptionResultScreen A7 Fix3 established).

package com.pgpony.android.ui.decrypt

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Image as ImageIcon
import androidx.compose.material.icons.filled.IosShare
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.pgpony.android.MainActivity
import com.pgpony.android.R
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.mime.MimeAttachment
import com.pgpony.android.crypto.mime.MimeFileAttachment
import com.pgpony.android.ui.util.ScratchFiles
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StructuredDecryptionResultScreen(
    body: String?,
    attachments: List<MimeAttachment>,
    // 4.1.0 Phase 14 (issue #10): the streamed decrypt path extracts a
    // bundle to scratch files rather than to resident ByteArrays, so its
    // attachments arrive here as MimeFileAttachments. Exactly one of the
    // two lists is ever populated. Defaulted so the existing call sites
    // (text decrypt, card decrypt, buffered file decrypt) are unchanged.
    fileAttachments: List<MimeFileAttachment> = emptyList(),
    // 4.1.0 Phase 14b: this sheet never showed signature status.
    // FileDecryptionResultScreen has shown it since A10c, so a
    // bundle was the one decrypt result that told the user nothing
    // about who sent it. Defaulted, so nothing has to pass it.
    verificationResult: VerificationResult? = null,
    onTapUnknownSigner: () -> Unit = {},
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    // One row model for both carriers. Everything below this line stops
    // caring where the bytes live.
    val items = remember(attachments, fileAttachments) {
        attachments.map { AttachmentItem(it.filename, it.contentType, it.data.size.toLong(), it.data, null) } +
            fileAttachments.map { AttachmentItem(it.filename, it.contentType, it.size, null, it.file) }
    }
    val activity = context.findStructuredResultMainActivity()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 8.dp)
                .navigationBarsPadding()
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Icon(
                Icons.Filled.LockOpen,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(48.dp)
            )
            Text(
                stringResource(R.string.structured_result_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )

            // ── Verification banner (when applicable) ────────────────
            verificationResult?.let { result ->
                VerificationBanner(
                    result = result,
                    onTapUnknownSigner = onTapUnknownSigner
                )
            }

            // ── Body ─────────────────────────────────────────────────
            if (!body.isNullOrBlank()) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        body,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }

            // ── Attachments ──────────────────────────────────────────
            Text(
                stringResource(R.string.structured_result_attachments_format, items.size),
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp)
            )
            items.forEach { att ->
                AttachmentRow(
                    attachment = att,
                    onOpen = { openAttachment(context, att) },
                    onSave = {
                        activity?.startDocumentCreator(
                            // octet-stream: SAF appends typed MIMEs'
                            // canonical extensions (Phase 2 Fix1 lesson);
                            // the attachment's own name stays verbatim.
                            mimeType = "application/octet-stream",
                            suggestedName = att.filename
                        ) { uri ->
                            if (uri == null) return@startDocumentCreator
                            try {
                                context.contentResolver.openOutputStream(uri)?.use { out ->
                                    // 4.1.0 Phase 14: copy, do not read.
                                    // A file backed attachment can be tens
                                    // of megabytes and the whole point of
                                    // the streamed path is that it never
                                    // becomes a ByteArray.
                                    att.writeTo(out)
                                }
                            } catch (_: Exception) {
                                // Save failures surface as a missing file;
                                // the sheet stays up for a retry.
                            }
                        }
                    },
                    onShare = { shareAttachments(context, listOf(att)) }
                )
            }

            // ── Share all + Done ─────────────────────────────────────
            if (items.size > 1) {
                OutlinedButton(
                    onClick = { shareAttachments(context, items) },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.IosShare, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.structured_result_share_all))
                }
            }
            OutlinedButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.common_button_done))
            }
            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

/**
 * 4.1.0 Phase 14: one row, either carrier.
 *
 * [bytes] is set for the buffered decrypt paths, [file] for the streamed
 * one. Never both, never neither. Everything the sheet does (thumbnail,
 * save, share, open) goes through the two accessors below so no call
 * site has to branch.
 */
private class AttachmentItem(
    val filename: String,
    val contentType: String,
    val size: Long,
    val bytes: ByteArray?,
    val file: File?
) {
    /** Stream the payload out without materialising a file backed one. */
    fun writeTo(out: java.io.OutputStream) {
        val b = bytes
        if (b != null) out.write(b) else file?.inputStream()?.use { it.copyTo(out) }
    }
}

@Composable
private fun AttachmentRow(
    attachment: AttachmentItem,
    onOpen: () -> Unit,
    onSave: () -> Unit,
    onShare: () -> Unit
) {
    val isImage = attachment.contentType.startsWith("image/")
    // Thumbnail: decode once per attachment, downsampled so a large
    // photo doesn't hold a full-size Bitmap for a 44dp row. The file
    // backed branch uses decodeFile, which reads through the same
    // inSampleSize path without loading the original into memory first.
    val thumb: Bitmap? = remember(attachment) {
        if (!isImage) null else try {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            val data = attachment.bytes
            val path = attachment.file?.absolutePath
            if (data != null) {
                BitmapFactory.decodeByteArray(data, 0, data.size, bounds)
            } else {
                BitmapFactory.decodeFile(path, bounds)
            }
            val sample = maxOf(1, minOf(bounds.outWidth, bounds.outHeight) / 96)
            val opts = BitmapFactory.Options().apply { inSampleSize = sample }
            if (data != null) {
                BitmapFactory.decodeByteArray(data, 0, data.size, opts)
            } else {
                BitmapFactory.decodeFile(path, opts)
            }
        } catch (_: Exception) {
            null
        }
    }

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (thumb != null) {
                Image(
                    bitmap = thumb.asImageBitmap(),
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.size(44.dp)
                )
            } else {
                Icon(
                    if (isImage) Icons.Filled.ImageIcon else Icons.Filled.Description,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(36.dp)
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    attachment.filename,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1
                )
                Text(
                    "${attachment.contentType} · ${formatAttachmentSize(attachment.size)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1
                )
            }
            IconButton(onClick = onSave) {
                Icon(
                    Icons.Filled.Save,
                    contentDescription = stringResource(R.string.common_button_save),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(onClick = onShare) {
                Icon(
                    Icons.Filled.IosShare,
                    contentDescription = stringResource(R.string.common_button_share),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/**
 * FileProvider URIs for [attachments].
 *
 * 4.1.0 Phase 14: a file backed attachment already sits in the scratch
 * directory, which res/xml/file_paths.xml exposes, so it is handed
 * straight to the share target with no copy at all. Only the buffered
 * carrier still needs a spill to cacheDir/exports, and only because
 * there is nothing else on disk to point at.
 */
private fun exportUris(context: Context, attachments: List<AttachmentItem>): ArrayList<android.net.Uri> {
    val uris = ArrayList<android.net.Uri>(attachments.size)
    for (att in attachments) {
        val existing = att.file
        if (existing != null) {
            uris.add(ScratchFiles.uriFor(context, existing))
            continue
        }
        val exportsDir = File(context.cacheDir, "exports").apply { mkdirs() }
        val safeName = att.filename.replace('/', '_').ifBlank { "attachment" }
        val outFile = com.pgpony.android.ui.util.ScratchFiles.safeChild(exportsDir, safeName, "attachment")
        outFile.outputStream().use { att.writeTo(it) }
        uris.add(
            FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                outFile
            )
        )
    }
    return uris
}

private fun openAttachment(context: Context, att: AttachmentItem) {
    try {
        val uri = exportUris(context, listOf(att)).first()
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, att.contentType.ifBlank { "application/octet-stream" })
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, att.filename))
    } catch (_: Exception) {
        // No viewer for the type, or export failed — non-fatal; the row's
        // Save/Share remain available.
    }
}

private fun shareAttachments(context: Context, attachments: List<AttachmentItem>) {
    try {
        val uris = exportUris(context, attachments)
        val intent = if (uris.size == 1) {
            Intent(Intent.ACTION_SEND).apply {
                type = attachments.first().contentType.ifBlank { "application/octet-stream" }
                putExtra(Intent.EXTRA_STREAM, uris.first())
            }
        } else {
            Intent(Intent.ACTION_SEND_MULTIPLE).apply {
                type = "*/*"
                putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
            }
        }
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        context.startActivity(Intent.createChooser(intent, null))
    } catch (_: Exception) {
        // Share sheet unavailable — non-fatal.
    }
}

private fun formatAttachmentSize(bytes: Long): String = when {
    bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1_048_576.0)
    bytes >= 1024 -> "%.0f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

private tailrec fun Context.findStructuredResultMainActivity(): MainActivity? = when (this) {
    is MainActivity -> this
    is ContextWrapper -> baseContext.findStructuredResultMainActivity()
    else -> null
}
