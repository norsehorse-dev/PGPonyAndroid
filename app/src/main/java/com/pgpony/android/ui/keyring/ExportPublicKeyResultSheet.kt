// ExportPublicKeyResultSheet.kt
// PGPony Android — Phase A8.6
//
// Bottom sheet shown when the user taps "Share Public Key" in
// KeyDetailScreen's Actions section. Provides two delivery
// destinations:
//
//   1. Copy to clipboard — fast paste into Signal / Mastodon /
//      forums / messaging apps that prefer inline text. No
//      sensitive-content flag is set on the clip because public
//      keys are explicitly meant to be distributed — clipboard
//      preview should show what's being pasted.
//   2. Save as .asc file — durable backup or attachment via the
//      FileProvider-backed Intent shipped in A7 Fix3. Filename
//      shape: {owner}_{shortFP}_public.asc.
//
// Modeled on ExportPrivateKeyResultSheet but adjusted for the fact
// that public keys are NOT sensitive:
//
//   • No biometric or AlertDialog gate before opening the sheet.
//     Tap "Share Public Key" → sheet appears immediately.
//   • Header tint is primary (purple), not error (red). This is
//     a normal share, not a danger-zone action.
//   • Buttons use the default outlined-button tint, not the
//     red error tint reserved for destructive operations.
//   • No warning text about sensitivity / irreversibility.
//
// What stays the same as the private-key sheet:
//   • Metadata card (owner / email / fingerprint / length)
//     gives the user visual confirmation of which key they're
//     about to share without showing the armored bytes inline.
//   • Stacked vertical button layout for readability.
//   • Sheet stays open after Copy so the user can also Save
//     (or vice versa).

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.IosShare
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportPublicKeyResultSheet(
    keyOwnerLabel: String,
    keyEmail: String,
    shortFingerprint: String,
    armoredLength: Int,
    onCopy: () -> Unit,
    onSaveFile: () -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ── Header: share icon + title ────────────────────────────
            //
            // Share icon (not key icon like the private-key sheet) to
            // emphasize this is a routine distribute-it action, not a
            // sensitive export. Primary tint = the app's purple, the
            // "normal happy path" color.
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Share,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.export_public_sheet_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }

            // ── Subtitle ──────────────────────────────────────────────
            //
            // One-liner reminder of what the user is sharing. No
            // warnings, no admonitions — public keys are safe to share
            // by definition.
            Text(
                text = stringResource(R.string.export_public_sheet_explainer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // ── Metadata card ─────────────────────────────────────────
            //
            // Same shape as the private-key sheet's metadata card so
            // the two flows feel consistent. Shows enough to identify
            // the key without dumping the armored bytes on screen.
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(8.dp)
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    if (keyOwnerLabel.isNotBlank()) {
                        Text(
                            text = keyOwnerLabel,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    if (keyEmail.isNotBlank() && keyEmail != keyOwnerLabel) {
                        Text(
                            text = keyEmail,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Text(
                        text = stringResource(R.string.result_sheet_fingerprint_format, shortFingerprint),
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace
                        ),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = stringResource(R.string.result_sheet_armored_block_format, armoredLength),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // ── Action buttons (stacked, default tint) ────────────────
            //
            // Both buttons use the default outlined-button styling
            // (primary tint) — no error red, no danger-zone visual
            // weight. This is a routine action.
            OutlinedButton(
                onClick = onCopy,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Filled.ContentCopy,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.result_sheet_copy_button))
            }

            OutlinedButton(
                onClick = onSaveFile,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Filled.IosShare,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.result_sheet_save_button))
            }

            OutlinedButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.common_button_done))
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}
