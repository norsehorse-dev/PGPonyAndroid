// EditNotationsSheet.kt
// PGPony Android — 4.3.0 RC4 §5.6.7 (Play review: editable key notations)
//
// Modal bottom sheet to edit the human-readable notations carried on a
// software key pair's primary self-cert. Rows of name=value, add/remove,
// then a passphrase field to re-sign. Names must contain '@' (RFC 9580
// requires the user-defined form user@example.com). Card-backed and
// public-only keys never reach this sheet, the same gating KeyDetailScreen
// already applies for Edit Expiry, Add Subkey, and Add User ID.

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
import com.pgpony.android.crypto.UserIdService

/** A single editable notation row. Both fields are observable so the
 *  text fields recompose as the user types without rebuilding the list. */
private class NotationDraft(name: String, value: String) {
    var name by mutableStateOf(name)
    var value by mutableStateOf(value)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditNotationsSheet(
    keyOwnerLabel: String,
    initialNotations: List<UserIdService.Notation>,
    showPassphraseField: Boolean = true,
    isProcessing: Boolean = false,
    errorMessage: String? = null,
    onApply: (notations: List<UserIdService.Notation>, passphrase: String?) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    val rows = remember {
        mutableStateListOf<NotationDraft>().apply {
            addAll(initialNotations.map { NotationDraft(it.name, it.value) })
        }
    }
    var passphrase by remember { mutableStateOf("") }
    var passphraseShown by remember { mutableStateOf(false) }

    // Rows the user actually meant: drop any left entirely blank.
    fun keptRows(): List<NotationDraft> =
        rows.filter { it.name.isNotBlank() || it.value.isNotBlank() }

    // Every kept row must be a full user-defined notation: a name that
    // contains '@' and a non-empty value.
    val hasInvalidRow = keptRows().any { !it.name.contains('@') || it.value.isBlank() }
    val canApply = !isProcessing && !hasInvalidRow

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
                text = stringResource(R.string.key_detail_notations_sheet_title),
                style = MaterialTheme.typography.headlineSmall
            )
            Text(
                text = stringResource(R.string.key_detail_notations_sheet_subtitle, keyOwnerLabel),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (rows.isEmpty()) {
                Text(
                    text = stringResource(R.string.key_detail_notations_sheet_empty),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            rows.forEachIndexed { index, row ->
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = row.name,
                            onValueChange = { row.name = it },
                            label = { Text(stringResource(R.string.key_detail_notations_name_label)) },
                            isError = row.name.isNotBlank() && !row.name.contains('@'),
                            singleLine = true,
                            enabled = !isProcessing,
                            modifier = Modifier.keepsKeyboard().weight(1f)
                        )
                        TextButton(
                            onClick = { rows.removeAt(index) },
                            enabled = !isProcessing
                        ) {
                            Text(
                                text = stringResource(R.string.key_detail_notations_remove_row),
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                    OutlinedTextField(
                        value = row.value,
                        onValueChange = { row.value = it },
                        label = { Text(stringResource(R.string.key_detail_notations_value_label)) },
                        singleLine = true,
                        enabled = !isProcessing,
                        modifier = Modifier.keepsKeyboard().fillMaxWidth()
                    )
                }
            }

            TextButton(
                onClick = { rows.add(NotationDraft("", "")) },
                enabled = !isProcessing
            ) {
                Text(stringResource(R.string.key_detail_notations_add_row))
            }

            if (hasInvalidRow) {
                Text(
                    text = stringResource(R.string.key_detail_notations_name_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }

            if (showPassphraseField) {
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(stringResource(R.string.key_detail_add_userid_passphrase_label)) },
                    visualTransformation = if (passphraseShown) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = { PassphraseVisibilityToggle(passphraseShown) { passphraseShown = !passphraseShown } },
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                    enabled = !isProcessing,
                    modifier = Modifier.keepsKeyboard().fillMaxWidth()
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
                        val notations = keptRows().map {
                            UserIdService.Notation(it.name.trim(), it.value)
                        }
                        // 4.8.0 (item 4d): the passphrase is used once; a retry starts empty.
                        val entered = passphrase
                        passphrase = ""
                        onApply(notations, entered.ifBlank { null })
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
                        Text(stringResource(R.string.key_detail_notations_apply))
                    }
                }
            }
        }
    }
}
