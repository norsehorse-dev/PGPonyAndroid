// RevokeKeySheet.kt
// PGPony Android — Phase A6
//
// Modal bottom sheet that drives the user through:
//   1. Picking a reason (5 RFC 4880 §5.2.3.23 codes — surfaced as
//      human-readable radio rows)
//   2. Optionally adding a comment
//   3. Optionally entering a passphrase (most PGPony keys are
//      unprotected, but imported keys may not be — field is always
//      visible to keep the flow consistent across protection states)
//   4. Tapping "Revoke Key" → fires the supplied callback which the
//      host hands off to KeyDetailViewModel.applyRevocation
//
// Reached from Danger Zone's "Revoke Key…" row in KeyDetailScreen.
// The host renders RevocationResultSheet after this completes
// successfully — the result sheet displays the generated cert with
// Copy / Share affordances.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.RadioButtonChecked
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.data.RevocationReason

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RevokeKeySheet(
    keyOwnerLabel: String,
    isProcessing: Boolean = false,
    /** When non-null, drives a red inline error message below the
     *  buttons (e.g. "Incorrect passphrase"). Cleared by the host when
     *  the user changes the form. */
    errorMessage: String? = null,
    onRevoke: (reason: RevocationReason, comment: String?, passphrase: String?) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var selectedReason by remember { mutableStateOf(RevocationReason.NO_REASON) }
    var comment by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }

    ModalBottomSheet(
        onDismissRequest = { if (!isProcessing) onDismiss() },
        sheetState = sheetState
    ) {
        // Phase A6 Fix4: the sheet's content (intro + 5 reason rows +
        // comment + passphrase + buttons) is taller than the viewport,
        // especially with the IME up — so the inner Column needs to
        // scroll. Drop the heightIn(max = 640.dp) cap that the prior
        // session added (it was strangling growth without solving
        // overflow), add verticalScroll for the overflow case, and
        // imePadding so the bottom of the content lifts above the
        // keyboard when the passphrase field is focused. navigationBars-
        // Padding keeps the buttons clear of the gesture-nav handle.
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = stringResource(R.string.revoke_sheet_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.error
            )
            Text(
                text = stringResource(R.string.revoke_sheet_explainer_format, keyOwnerLabel),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Text(
                text = stringResource(R.string.revoke_sheet_reason_label),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                RevocationReason.entries.forEach { reason ->
                    ReasonRow(
                        reason = reason,
                        isSelected = reason == selectedReason,
                        onClick = { selectedReason = reason }
                    )
                }
            }

            Text(
                text = stringResource(R.string.revoke_sheet_comment_label),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            OutlinedTextField(
                value = comment,
                onValueChange = { if (it.length <= 200) comment = it },
                placeholder = {
                    Text(
                        stringResource(R.string.revoke_sheet_comment_placeholder),
                        style = MaterialTheme.typography.bodySmall
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                maxLines = 3
            )

            Text(
                text = stringResource(R.string.revoke_sheet_passphrase_label),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                placeholder = {
                    Text(
                        stringResource(R.string.revoke_sheet_passphrase_placeholder),
                        style = MaterialTheme.typography.bodySmall
                    )
                },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            if (!errorMessage.isNullOrBlank()) {
                Text(
                    text = errorMessage,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = onDismiss,
                    enabled = !isProcessing,
                    modifier = Modifier.weight(1f)
                ) {
                    Text(stringResource(R.string.common_button_cancel))
                }
                Button(
                    onClick = {
                        onRevoke(
                            selectedReason,
                            comment.trim().ifBlank { null },
                            passphrase.ifBlank { null }
                        )
                    },
                    enabled = !isProcessing,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError
                    ),
                    modifier = Modifier.weight(1f)
                ) {
                    if (isProcessing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onError
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                    }
                    Text(stringResource(R.string.revoke_sheet_confirm))
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

@Composable
private fun ReasonRow(
    reason: RevocationReason,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .background(
                if (isSelected) MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
                else Color.Transparent
            )
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Icon(
            imageVector = if (isSelected) Icons.Filled.RadioButtonChecked
                          else Icons.Filled.RadioButtonUnchecked,
            contentDescription = null,
            tint = if (isSelected) MaterialTheme.colorScheme.error
                   else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier
                .size(20.dp)
                .padding(top = 2.dp)
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = reason.localizedName(),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = reason.localizedDescription(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}


/** Phase A13 — localized name + description for RevocationReason enum.
 *  Enum still exposes displayName/description as English for compat;
 *  UI call sites use these @Composable extensions instead. */
@androidx.compose.runtime.Composable
internal fun com.pgpony.android.data.RevocationReason.localizedName(): String = when (this) {
    com.pgpony.android.data.RevocationReason.NO_REASON       -> stringResource(R.string.revocation_reason_no_reason_name)
    com.pgpony.android.data.RevocationReason.SUPERSEDED      -> stringResource(R.string.revocation_reason_superseded_name)
    com.pgpony.android.data.RevocationReason.COMPROMISED     -> stringResource(R.string.revocation_reason_compromised_name)
    com.pgpony.android.data.RevocationReason.RETIRED         -> stringResource(R.string.revocation_reason_retired_name)
    com.pgpony.android.data.RevocationReason.USER_ID_INVALID -> stringResource(R.string.revocation_reason_user_id_invalid_name)
}

@androidx.compose.runtime.Composable
internal fun com.pgpony.android.data.RevocationReason.localizedDescription(): String = when (this) {
    com.pgpony.android.data.RevocationReason.NO_REASON       -> stringResource(R.string.revocation_reason_no_reason_description)
    com.pgpony.android.data.RevocationReason.SUPERSEDED      -> stringResource(R.string.revocation_reason_superseded_description)
    com.pgpony.android.data.RevocationReason.COMPROMISED     -> stringResource(R.string.revocation_reason_compromised_description)
    com.pgpony.android.data.RevocationReason.RETIRED         -> stringResource(R.string.revocation_reason_retired_description)
    com.pgpony.android.data.RevocationReason.USER_ID_INVALID -> stringResource(R.string.revocation_reason_user_id_invalid_description)
}
