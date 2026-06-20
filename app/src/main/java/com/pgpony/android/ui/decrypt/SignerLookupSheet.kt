// SignerLookupSheet.kt
// PGPony Android — Phase A3
//
// Modal bottom sheet shown when the user taps the yellow "Unknown signer"
// verification banner. Walks the user through:
//
//   1. Searching — spinner + "Looking up 0x..." while the keyserver
//      query is in flight.
//   2. Found — preview of the discovered key (user ID, fingerprint,
//      algorithm) with an Import button. Tapping Import adds the key
//      to the local keyring and dismisses; the host screen then
//      re-verifies automatically and the banner flips to green.
//   3. NotFound — friendly message + Close button. The signer didn't
//      upload to keys.openpgp.org, or claimed a fingerprint that no
//      one knows about.
//   4. Failed — network/parse error. Close button.
//   5. ImportSuccess — brief confirmation before dismissal.
//
// Phase A8 will add WKD discovery in front of the Hagrid lookup; for
// A3, Hagrid is the only source (matches the existing Exchange tab's
// keyserver search). The state machine is shaped so adding WKD won't
// change anything sheet-side.

package com.pgpony.android.ui.decrypt

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.SearchOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
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

// ── State ─────────────────────────────────────────────────────────────

/**
 * Sheet state machine. Lives on DecryptUiState; the ViewModel transitions
 * between cases as the network call and import progress.
 */
sealed class SignerLookupState {
    object Searching : SignerLookupState()
    data class Found(
        /** Full armored public key block ready to hand to KeyRepository. */
        val armoredKey: String,
        val previewUserId: String,
        val previewFingerprint: String,
        val previewAlgorithm: String
    ) : SignerLookupState()
    data class NotFound(val searchedFingerprint: String) : SignerLookupState()
    data class Failed(val message: String) : SignerLookupState()
    data class ImportSuccess(val previewUserId: String) : SignerLookupState()
}

// ── Sheet ─────────────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SignerLookupSheet(
    state: SignerLookupState,
    claimedFingerprint: String?,
    onImport: (armoredKey: String) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState()
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                stringResource(R.string.signer_lookup_searching_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )

            when (state) {
                SignerLookupState.Searching -> SearchingBody(claimedFingerprint)
                is SignerLookupState.Found -> FoundBody(state, onImport, onDismiss)
                is SignerLookupState.NotFound -> NotFoundBody(state, onDismiss)
                is SignerLookupState.Failed -> FailedBody(state, onDismiss)
                is SignerLookupState.ImportSuccess -> ImportSuccessBody(state, onDismiss)
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

// ── State-specific bodies ─────────────────────────────────────────────

@Composable
private fun SearchingBody(claimedFingerprint: String?) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
        Spacer(modifier = Modifier.width(12.dp))
        Column {
            Text(
                stringResource(R.string.signer_lookup_searching_label),
                style = MaterialTheme.typography.bodyMedium
            )
            if (!claimedFingerprint.isNullOrBlank()) {
                Text(
                    formatFingerprint(claimedFingerprint),
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun FoundBody(
    state: SignerLookupState.Found,
    onImport: (String) -> Unit,
    onDismiss: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Filled.CloudDownload,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                stringResource(R.string.signer_lookup_found_title),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold
            )
        }

        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    state.previewUserId,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    formatFingerprint(state.previewFingerprint),
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    state.previewAlgorithm,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Text(
            stringResource(R.string.signer_lookup_found_body),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onDismiss,
                modifier = Modifier.weight(1f)
            ) {
                Text(stringResource(R.string.common_button_cancel))
            }
            Button(
                onClick = { onImport(state.armoredKey) },
                modifier = Modifier.weight(1f)
            ) {
                Text(stringResource(R.string.signer_lookup_import_button))
            }
        }
    }
}

@Composable
private fun NotFoundBody(state: SignerLookupState.NotFound, onDismiss: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Filled.SearchOff,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                stringResource(R.string.signer_lookup_not_found_title),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold
            )
        }
        Text(
            stringResource(R.string.signer_lookup_not_found_body_format, formatFingerprint(state.searchedFingerprint)),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedButton(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.common_button_close))
        }
    }
}

@Composable
private fun FailedBody(state: SignerLookupState.Failed, onDismiss: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Filled.ErrorOutline,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                stringResource(R.string.signer_lookup_failed_title),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.error
            )
        }
        Text(
            state.message,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedButton(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.common_button_close))
        }
    }
}

@Composable
private fun ImportSuccessBody(state: SignerLookupState.ImportSuccess, onDismiss: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Filled.CheckCircle,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                stringResource(R.string.signer_lookup_imported_title),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold
            )
        }
        Text(
            "${state.previewUserId} has been added to your keyring. " +
                    stringResource(R.string.signer_lookup_imported_body),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Button(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.common_button_done))
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────

/**
 * Render a 40-char (v4) or 64-char (v6) fingerprint as space-separated
 * groups of 4 hex chars for legibility. "B91A02D63E5CC09A3F4F87CAE6FB73E0E5C9F8A2"
 * → "B91A 02D6 3E5C C09A 3F4F 87CA E6FB 73E0 E5C9 F8A2".
 */
internal fun formatFingerprint(fp: String): String {
    return fp.uppercase().chunked(4).joinToString(" ")
}
