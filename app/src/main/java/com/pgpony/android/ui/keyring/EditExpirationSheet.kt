// EditExpirationSheet.kt
// PGPony Android — key expiration editor
//
// Modal bottom sheet to change a key's expiration. Presets (1y / 2y / 5y /
// Never) plus a custom date picker. For software key pairs it collects an
// optional passphrase; for card-backed keys it collects the PIN (the host
// runs the NFC op). Public-only keys never reach this sheet — the Expires
// row isn't tappable for them.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.ui.components.PassphraseVisibilityToggle
import com.pgpony.android.ui.util.dismissKeyboardOnTap
import com.pgpony.android.ui.util.keepsKeyboard
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditExpirationSheet(
    keyOwnerLabel: String,
    isCardBacked: Boolean,
    isProcessing: Boolean = false,
    errorMessage: String? = null,
    /** 4.7.0 (item 53, #86): the subkey being edited (its key ID), or null for
     *  the primary key. */
    subkeyLabel: String? = null,
    /** Offer "Also set it on subkeys that are still valid" (primary only, and
     *  only when the key has any). */
    offerCurrentSubkeys: Boolean = false,
    onApplySoftware: (expiresAtEpochSeconds: Long?, passphrase: String?, alsoCurrentSubkeys: Boolean) -> Unit,
    onApplyCard: (expiresAtEpochSeconds: Long?, pin: String, alsoCurrentSubkeys: Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    // null preset = custom-date mode.
    var selectedPreset by remember { mutableStateOf<ExpirationOption?>(ExpirationOption.ONE_YEAR) }
    var customMillis by remember { mutableStateOf<Long?>(null) }
    var showDatePicker by remember { mutableStateOf(false) }
    var passphrase by remember { mutableStateOf("") }
    var passphraseShown by remember { mutableStateOf(false) }
    var pin by remember { mutableStateOf("") }
    var alsoCurrentSubkeys by remember { mutableStateOf(false) }

    fun computeExpiresAtEpochSeconds(): Long? {
        val preset = selectedPreset
        return if (preset != null) {
            preset.seconds?.let { (System.currentTimeMillis() / 1000L) + it }  // null = Never
        } else {
            customMillis?.let { it / 1000L }
        }
    }

    val hasValidChoice = selectedPreset != null || customMillis != null
    val canApply = !isProcessing && hasValidChoice && (!isCardBacked || pin.isNotEmpty())

    ModalBottomSheet(
        onDismissRequest = { if (!isProcessing) onDismiss() },
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                // 4.1.0 — scroll was here already; the inset half was not,
                // and this sheet asks for a passphrase.
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp)
                .dismissKeyboardOnTap(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = stringResource(
                    if (subkeyLabel != null) R.string.key_detail_expiry_sheet_title_subkey
                    else R.string.key_detail_expiry_sheet_title
                ),
                style = MaterialTheme.typography.headlineSmall
            )
            Text(
                text = if (subkeyLabel != null) stringResource(R.string.key_detail_expiry_sheet_subtitle_subkey, subkeyLabel)
                else stringResource(R.string.key_detail_expiry_sheet_subtitle, keyOwnerLabel),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            FlowRowPresets(
                selectedPreset = selectedPreset,
                isCustom = selectedPreset == null,
                onPreset = { selectedPreset = it },
                onCustom = {
                    selectedPreset = null
                    showDatePicker = true
                }
            )

            if (selectedPreset == null) {
                val label = customMillis?.let {
                    DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(it))
                } ?: stringResource(R.string.key_detail_expiry_pick_date)
                OutlinedButton(
                    onClick = { showDatePicker = true },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(label) }
            }

            if (subkeyLabel == null && offerCurrentSubkeys) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .toggleable(
                            value = alsoCurrentSubkeys,
                            enabled = !isProcessing,
                            role = androidx.compose.ui.semantics.Role.Checkbox,
                            onValueChange = { alsoCurrentSubkeys = it }
                        )
                ) {
                    Checkbox(checked = alsoCurrentSubkeys, onCheckedChange = null, enabled = !isProcessing)
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text(stringResource(R.string.key_detail_expiry_also_subkeys), style = MaterialTheme.typography.bodyMedium)
                        Text(
                            stringResource(R.string.key_detail_expiry_also_subkeys_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            if (isCardBacked) {
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it },
                    label = { Text(stringResource(R.string.card_decrypt_pin_label)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                    enabled = !isProcessing,
                    modifier = Modifier.keepsKeyboard().fillMaxWidth()
                )
                Text(
                    text = stringResource(R.string.key_detail_expiry_card_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(stringResource(R.string.key_detail_expiry_passphrase_label)) },
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
                        val expiry = computeExpiresAtEpochSeconds()
                        val also = subkeyLabel == null && offerCurrentSubkeys && alsoCurrentSubkeys
                        if (isCardBacked) onApplyCard(expiry, pin, also)
                        else {
                            // 4.8.0 (item 4d): the passphrase is used once; a retry starts empty.
                            val entered = passphrase
                            passphrase = ""
                            onApplySoftware(expiry, entered.ifBlank { null }, also)
                        }
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
                        Text(stringResource(R.string.key_detail_expiry_apply))
                    }
                }
            }

            if (isCardBacked && isProcessing) {
                Text(
                    text = stringResource(R.string.card_decrypt_hold_card),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }
        }
    }

    if (showDatePicker) {
        val pickerState = rememberDatePickerState(
            initialSelectedDateMillis = customMillis ?: System.currentTimeMillis()
        )
        DatePickerDialog(
            onDismissRequest = { showDatePicker = false },
            confirmButton = {
                TextButton(onClick = {
                    customMillis = pickerState.selectedDateMillis
                    showDatePicker = false
                }) { Text(stringResource(R.string.common_button_ok)) }
            },
            dismissButton = {
                TextButton(onClick = { showDatePicker = false }) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        ) {
            DatePicker(state = pickerState)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun FlowRowPresets(
    selectedPreset: ExpirationOption?,
    isCustom: Boolean,
    onPreset: (ExpirationOption) -> Unit,
    onCustom: () -> Unit
) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        ExpirationOption.entries.forEach { opt ->
            val label = when (opt) {
                ExpirationOption.ONE_YEAR -> stringResource(R.string.expiration_one_year)
                ExpirationOption.TWO_YEARS -> stringResource(R.string.expiration_two_years)
                ExpirationOption.FIVE_YEARS -> stringResource(R.string.expiration_five_years)
                ExpirationOption.NEVER -> stringResource(R.string.expiration_never)
            }
            FilterChip(
                selected = selectedPreset == opt,
                onClick = { onPreset(opt) },
                label = { Text(label) }
            )
        }
        FilterChip(
            selected = isCustom,
            onClick = onCustom,
            label = { Text(stringResource(R.string.key_detail_expiry_custom)) }
        )
    }
}

/**
 * 4.7.0 RC6 (item 66, #86): the step between the sheet and the change. An
 * expiry edit re-signs a key that may already be published, so it says what
 * will change before anything is signed: the current and the new date, which
 * signatures are remade, and that others see it only after a publish. Confirm
 * then goes through the device-authentication gate (see
 * [deleteWithOptionalBiometricGate]).
 *
 * [currentExpiresAtMs] and [newExpiresAtEpochSeconds] are null for "never".
 * [subkeyLabel] is set when one subkey is the target; otherwise
 * [userIdCount] live User IDs are re-signed, plus [currentSubkeyCount]
 * subkeys when that option was ticked (0 when it was not).
 */
@Composable
internal fun ConfirmExpiryChangeDialog(
    currentExpiresAtMs: Long?,
    newExpiresAtEpochSeconds: Long?,
    subkeyLabel: String?,
    userIdCount: Int,
    currentSubkeyCount: Int,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    val never = stringResource(R.string.expiration_never)
    val fmt = DateFormat.getDateInstance(DateFormat.MEDIUM)
    val current = currentExpiresAtMs?.let { fmt.format(Date(it)) } ?: never
    val next = newExpiresAtEpochSeconds?.let { fmt.format(Date(it * 1000L)) } ?: never
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.key_detail_expiry_confirm_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.key_detail_expiry_confirm_current, current))
                Text(stringResource(R.string.key_detail_expiry_confirm_new, next))
                if (subkeyLabel != null) {
                    Text(stringResource(R.string.key_detail_expiry_confirm_subkey_only, subkeyLabel))
                } else {
                    Text(pluralStringResource(R.plurals.key_detail_expiry_confirm_user_ids, userIdCount, userIdCount))
                    if (currentSubkeyCount > 0) {
                        Text(
                            pluralStringResource(
                                R.plurals.key_detail_expiry_confirm_subkeys, currentSubkeyCount, currentSubkeyCount
                            )
                        )
                    }
                }
                Text(
                    stringResource(R.string.key_detail_expiry_confirm_publish),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text(stringResource(R.string.key_detail_expiry_confirm_action)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_button_cancel)) }
        }
    )
}
