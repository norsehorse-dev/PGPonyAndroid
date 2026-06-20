// RevocationResultSheet.kt
// PGPony Android — Phase A6 + A6 Fix4 + A8.6
//
// Shown immediately after a successful revocation AND when the user
// re-exports the revocation cert from Danger Zone later. Two
// purposes:
//
//   1. Confirm to the user that revocation was applied — the key in
//      their keyring now has the revoked banner and won't be selectable
//      as a signer or recipient anymore. (Both flows reach this sheet,
//      but the celebratory header is appropriate for both — post-revoke
//      because it just happened, and for re-export because the sheet
//      lets the user re-deliver the cert anywhere it might be needed.)
//
//   2. Give them the armored revocation certificate via Copy +
//      Save-as-file so they can:
//      - Paste into a group chat / forum to alert contacts
//      - Save offline as a backup
//      - Attach to email as a .asc file
//      - Upload to a keyserver (separate flow)
//
// Phase A8.6 rewrite: dropped the inline OutlinedTextField that
// previously showed the armored bytes; replaced the Share button
// (text/plain Intent) with Save-file (FileProvider .asc Intent).
// This brings the sheet into line with ExportPrivateKeyResultSheet
// + ExportPublicKeyResultSheet — Copy + Save + Done across all
// three result flows. Visual confirmation lives in the metadata
// card (owner / fingerprint / length); the raw armored block isn't
// useful to read on a phone screen and clutters the sheet.

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
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.IosShare
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RevocationResultSheet(
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
            // ── Header: success icon + title ──────────────────────────
            //
            // Green CheckCircle kept from the pre-A8.6 design — this is
            // an "operation completed" confirmation, distinct from the
            // public-key sheet's "share with anyone" framing or the
            // private-key sheet's "this is sensitive" warning.
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.CheckCircle,
                    contentDescription = null,
                    tint = Color(0xFF22C55E),
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.revocation_result_sheet_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }

            // ── Explanation text ──────────────────────────────────────
            //
            // Two sentences: what just happened, and what to do with
            // the certificate. Same content as pre-A8.6 — only the
            // formatting changed.
            Text(
                text = stringResource(R.string.revocation_result_sheet_explainer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // ── Metadata card ─────────────────────────────────────────
            //
            // Same shape as the other result sheets so all three
            // export flows feel consistent.
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
                        text = stringResource(R.string.result_sheet_revocation_block_format, armoredLength),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // ── Action buttons ────────────────────────────────────────
            //
            // Default outlined-button tint (primary purple). Revocation
            // certs are public material — they don't get the
            // error-red treatment the private key sheet uses.
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
