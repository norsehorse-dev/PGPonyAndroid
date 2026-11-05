// ChangePassphraseSheet.kt
// PGPony Android — 4.3.0 §1.1 (#26 change a key's passphrase)
//
// Modal bottom sheet to set, change, or remove the passphrase on a
// software key pair. Mirrors AddUserIdSheet. Card-backed and public-only
// keys never reach it (the action row is software-key-pair only; the card
// row points at the card PIN instead). Leaving the new passphrase blank
// removes protection, gated behind an explicit acknowledgement.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.ui.components.PassphraseVisibilityToggle
import com.pgpony.android.ui.util.dismissKeyboardOnTap
import com.pgpony.android.ui.util.keepsKeyboard
import androidx.compose.foundation.selection.toggleable
import androidx.compose.ui.semantics.Role

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChangePassphraseSheet(
    isProtected: Boolean,
    isProcessing: Boolean = false,
    errorMessage: String? = null,
    onApply: (oldPassphrase: String, newPassphrase: String) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    var current by remember { mutableStateOf("") }
    var newPass by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var ackRemove by remember { mutableStateOf(false) }
    var currentShown by remember { mutableStateOf(false) }
    var newShown by remember { mutableStateOf(false) }
    var confirmShown by remember { mutableStateOf(false) }

    val removing = newPass.isEmpty()
    val matches = newPass == confirm
    val canApply = !isProcessing &&
        matches &&
        (!isProtected || current.isNotEmpty()) &&
        (!removing || ackRemove) &&
        !(!isProtected && removing)

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
                .padding(bottom = 32.dp)
                .dismissKeyboardOnTap(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = stringResource(R.string.change_passphrase_sheet_title),
                style = MaterialTheme.typography.headlineSmall
            )
            Text(
                text = stringResource(R.string.change_passphrase_sheet_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (isProtected) {
                OutlinedTextField(
                    value = current,
                    onValueChange = { current = it },
                    label = { Text(stringResource(R.string.change_passphrase_current_label)) },
                    visualTransformation = if (currentShown) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = { PassphraseVisibilityToggle(currentShown) { currentShown = !currentShown } },
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                    enabled = !isProcessing,
                    modifier = Modifier.keepsKeyboard().fillMaxWidth()
                )
            }

            OutlinedTextField(
                value = newPass,
                onValueChange = { newPass = it },
                label = { Text(stringResource(R.string.change_passphrase_new_label)) },
                visualTransformation = if (newShown) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = { PassphraseVisibilityToggle(newShown) { newShown = !newShown } },
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                enabled = !isProcessing,
                modifier = Modifier.keepsKeyboard().fillMaxWidth()
            )
            OutlinedTextField(
                value = confirm,
                onValueChange = { confirm = it },
                label = { Text(stringResource(R.string.keyring_generate_passphrase_confirm_label)) },
                visualTransformation = if (confirmShown) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = { PassphraseVisibilityToggle(confirmShown) { confirmShown = !confirmShown } },
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                isError = !matches,
                enabled = !isProcessing,
                modifier = Modifier.keepsKeyboard().fillMaxWidth()
            )
            if (!matches) {
                Text(
                    text = stringResource(R.string.keyring_error_passphrase_mismatch),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }

            if (removing) {
                Text(
                    text = stringResource(R.string.change_passphrase_remove_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth().toggleable(
                        value = ackRemove,
                        enabled = !isProcessing,
                        role = Role.Checkbox,
                        onValueChange = { ackRemove = it }
                    )
                ) {
                    Checkbox(
                        checked = ackRemove,
                        onCheckedChange = null,
                        enabled = !isProcessing,
                        modifier = Modifier.minimumInteractiveComponentSize()
                    )
                    Text(
                        text = stringResource(R.string.change_passphrase_remove_ack),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }

            Text(
                text = stringResource(R.string.change_passphrase_backup_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

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
                    onClick = {
                        // 4.8.0 (item 4d): the current passphrase is used once; a retry starts empty.
                        val entered = if (isProtected) current else ""
                        current = ""
                        onApply(entered, newPass)
                    },
                    enabled = canApply,
                    modifier = Modifier.weight(1f)
                ) {
                    if (isProcessing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                    } else {
                        Text(stringResource(R.string.change_passphrase_apply))
                    }
                }
            }
        }
    }
}
