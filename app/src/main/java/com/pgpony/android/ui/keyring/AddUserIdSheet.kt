// AddUserIdSheet.kt
// PGPony Android — 4.2.0 RC3 workstream I (#29 multiple identities)
//
// Modal bottom sheet to add a new User ID to an existing software key
// pair. Name + email fields compose into the standard "Name <email>"
// UID string PGPCryptoService already uses at generation time. A
// primary toggle and passphrase field round it out. Card-backed and
// public-only keys never reach this sheet, same gating KeyDetailScreen
// already applies for Edit Expiry and Add Subkey.

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
fun AddUserIdSheet(
    keyOwnerLabel: String,
    isProcessing: Boolean = false,
    errorMessage: String? = null,
    onApply: (userId: String, makePrimary: Boolean, passphrase: String?) -> Unit,
    onDismiss: () -> Unit,
    /** 4.8.0 (#71): the primary is on the security key, so the field takes
     *  the card PIN and the self-certification is signed there. */
    cardPin: Boolean = false,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    var name by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var makePrimary by remember { mutableStateOf(false) }
    var passphrase by remember { mutableStateOf("") }
    var passphraseShown by remember { mutableStateOf(false) }

    fun composedUserId(): String {
        val trimmedName = name.trim()
        val trimmedEmail = email.trim()
        return when {
            trimmedName.isNotEmpty() && trimmedEmail.isNotEmpty() -> "$trimmedName <$trimmedEmail>"
            trimmedEmail.isNotEmpty() -> trimmedEmail
            else -> trimmedName
        }
    }

    val canApply = !isProcessing && composedUserId().isNotBlank() && (!cardPin || passphrase.isNotEmpty())

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
                text = stringResource(R.string.key_detail_add_userid_sheet_title),
                style = MaterialTheme.typography.headlineSmall
            )
            Text(
                text = stringResource(R.string.key_detail_add_userid_sheet_subtitle, keyOwnerLabel),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.key_detail_add_userid_name_label)) },
                singleLine = true,
                enabled = !isProcessing,
                modifier = Modifier.keepsKeyboard().fillMaxWidth()
            )
            OutlinedTextField(
                value = email,
                onValueChange = { email = it },
                label = { Text(stringResource(R.string.key_detail_add_userid_email_label)) },
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Email),
                singleLine = true,
                enabled = !isProcessing,
                modifier = Modifier.keepsKeyboard().fillMaxWidth()
            )

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().toggleable(
                    value = makePrimary,
                    enabled = !isProcessing,
                    role = Role.Checkbox,
                    onValueChange = { makePrimary = it }
                )
            ) {
                Checkbox(
                    checked = makePrimary,
                    onCheckedChange = null,
                    enabled = !isProcessing,
                    modifier = Modifier.minimumInteractiveComponentSize()
                )
                Text(
                    text = stringResource(R.string.key_detail_add_userid_make_primary_label),
                    style = MaterialTheme.typography.bodyMedium
                )
            }

            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = {
                    Text(
                        stringResource(
                            if (cardPin) R.string.card_decrypt_pin_label
                            else R.string.key_detail_add_userid_passphrase_label
                        )
                    )
                },
                // 4.8.0 (item 4d): show or hide for a passphrase only, never a card PIN.
                visualTransformation = if (passphraseShown && !cardPin) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = if (cardPin) null else ({ PassphraseVisibilityToggle(passphraseShown) { passphraseShown = !passphraseShown } }),
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                enabled = !isProcessing,
                modifier = Modifier.keepsKeyboard().fillMaxWidth()
            )
            if (cardPin) {
                Text(
                    text = stringResource(
                        if (isProcessing) R.string.card_decrypt_hold_card else R.string.key_detail_expiry_card_hint
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (isProcessing) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
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
                    onClick = {
                        // 4.8.0 (item 4d): the passphrase is used once; a retry starts empty.
                        val entered = passphrase
                        passphrase = ""
                        onApply(composedUserId(), makePrimary, entered.ifBlank { null })
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
                        Text(stringResource(R.string.key_detail_add_userid_apply))
                    }
                }
            }
        }
    }
}
