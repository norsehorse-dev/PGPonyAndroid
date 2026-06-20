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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditExpirationSheet(
    keyOwnerLabel: String,
    isCardBacked: Boolean,
    isProcessing: Boolean = false,
    errorMessage: String? = null,
    onApplySoftware: (expiresAtEpochSeconds: Long?, passphrase: String?) -> Unit,
    onApplyCard: (expiresAtEpochSeconds: Long?, pin: String) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    // null preset = custom-date mode.
    var selectedPreset by remember { mutableStateOf<ExpirationOption?>(ExpirationOption.ONE_YEAR) }
    var customMillis by remember { mutableStateOf<Long?>(null) }
    var showDatePicker by remember { mutableStateOf(false) }
    var passphrase by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }

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
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = stringResource(R.string.key_detail_expiry_sheet_title),
                style = MaterialTheme.typography.headlineSmall
            )
            Text(
                text = stringResource(R.string.key_detail_expiry_sheet_subtitle, keyOwnerLabel),
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

            if (isCardBacked) {
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it },
                    label = { Text(stringResource(R.string.card_decrypt_pin_label)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                    enabled = !isProcessing,
                    modifier = Modifier.fillMaxWidth()
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
                    onClick = {
                        val expiry = computeExpiresAtEpochSeconds()
                        if (isCardBacked) onApplyCard(expiry, pin)
                        else onApplySoftware(expiry, passphrase.ifBlank { null })
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
