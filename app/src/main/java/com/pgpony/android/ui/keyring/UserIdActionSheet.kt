// UserIdActionSheet.kt
// PGPony Android — 4.2.0 RC3 workstream I (#29 multiple identities)
//
// Shared passphrase-confirm sheet for the two lightweight User ID
// actions: revoke and make-primary. Both only need a passphrase and a
// confirmation, unlike Add User ID which needs the new identity's own
// fields — kept as one sheet with a title/subtitle/button-label that
// switches on [kind] rather than two near-identical files.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UserIdActionSheet(
    request: UserIdActionRequest,
    displayName: String,
    isProcessing: Boolean = false,
    errorMessage: String? = null,
    onApply: (passphrase: String?) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var passphrase by remember { mutableStateOf("") }

    val title = when (request.kind) {
        UserIdActionRequest.Kind.REVOKE -> stringResource(R.string.key_detail_userid_action_sheet_title_revoke)
        UserIdActionRequest.Kind.MAKE_PRIMARY -> stringResource(R.string.key_detail_userid_action_sheet_title_make_primary)
        UserIdActionRequest.Kind.REMOVE -> stringResource(R.string.key_detail_userid_action_sheet_title_remove)
    }
    val subtitle = when (request.kind) {
        UserIdActionRequest.Kind.REVOKE -> stringResource(R.string.key_detail_userid_action_sheet_subtitle_revoke, displayName)
        UserIdActionRequest.Kind.MAKE_PRIMARY -> stringResource(R.string.key_detail_userid_action_sheet_subtitle_make_primary, displayName)
        UserIdActionRequest.Kind.REMOVE -> stringResource(R.string.key_detail_userid_action_sheet_subtitle_remove, displayName)
    }
    val applyLabel = when (request.kind) {
        UserIdActionRequest.Kind.REVOKE -> stringResource(R.string.key_detail_userid_action_apply_revoke)
        UserIdActionRequest.Kind.MAKE_PRIMARY -> stringResource(R.string.key_detail_userid_action_apply_make_primary)
        UserIdActionRequest.Kind.REMOVE -> stringResource(R.string.key_detail_userid_action_apply_remove)
    }

    ModalBottomSheet(
        onDismissRequest = { if (!isProcessing) onDismiss() },
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(text = title, style = MaterialTheme.typography.headlineSmall)
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // Remove is structural (no signing), so it needs no passphrase.
            if (request.kind != UserIdActionRequest.Kind.REMOVE) {
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(stringResource(R.string.key_detail_userid_action_passphrase_label)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                    enabled = !isProcessing,
                    modifier = Modifier.fillMaxWidth()
                )
            }

            if (errorMessage != null) {
                Text(
                    text = errorMessage,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onDismiss,
                    enabled = !isProcessing,
                    modifier = Modifier.weight(1f)
                ) { Text(stringResource(R.string.common_button_cancel)) }
                Button(
                    onClick = { onApply(passphrase.ifBlank { null }) },
                    enabled = !isProcessing,
                    modifier = Modifier.weight(1f)
                ) {
                    if (isProcessing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                    } else {
                        Text(applyLabel)
                    }
                }
            }
        }
    }
}
