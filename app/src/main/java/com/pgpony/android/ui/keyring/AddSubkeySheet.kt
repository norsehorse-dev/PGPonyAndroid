// AddSubkeySheet.kt
// PGPony Android — 4.2.0 RC3 workstream H (§17.2)
//
// Modal bottom sheet to add a classical subkey (RSA 2048/4096,
// Ed25519, X25519) to an existing software key pair. Same shape as
// EditExpirationSheet: type chips, expiry presets + custom date,
// passphrase field. Card-backed and public-only keys never reach this
// sheet — KeyDetailScreen only wires the Add Subkey button for
// software key pairs, matching the Edit Expiry row's own gating.
//
// Composite (post-quantum) subkey types are intentionally not offered
// here yet; §17.2 H asks for them to be exposed "deliberately" from
// this same entry point, tracked as a follow-up once the type picker
// grows a second group of options.

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
import com.pgpony.android.crypto.ClassicalSubkeyGen
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddSubkeySheet(
    keyOwnerLabel: String,
    isProcessing: Boolean = false,
    errorMessage: String? = null,
    isV6: Boolean = false,
    onApply: (type: ClassicalSubkeyGen.ClassicalSubkeyType, expiresAtEpochSeconds: Long?, passphrase: String?) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    var selectedType by remember { mutableStateOf(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN) }
    var selectedPreset by remember { mutableStateOf<AddSubkeyExpiryOption?>(AddSubkeyExpiryOption.NEVER) }
    var customMillis by remember { mutableStateOf<Long?>(null) }
    var showDatePicker by remember { mutableStateOf(false) }
    var passphrase by remember { mutableStateOf("") }

    fun computeExpiresAtEpochSeconds(): Long? {
        val preset = selectedPreset
        return if (preset != null) {
            preset.seconds?.let { (System.currentTimeMillis() / 1000L) + it }
        } else {
            customMillis?.let { it / 1000L }
        }
    }

    val hasValidExpiry = selectedPreset != null || customMillis != null
    val canApply = !isProcessing && hasValidExpiry

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
            Text(
                text = stringResource(R.string.key_detail_add_subkey_sheet_title),
                style = MaterialTheme.typography.headlineSmall
            )
            Text(
                text = stringResource(R.string.key_detail_add_subkey_sheet_subtitle, keyOwnerLabel),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Text(
                text = stringResource(R.string.key_detail_add_subkey_type_label),
                style = MaterialTheme.typography.labelLarge
            )
            AddSubkeyTypeChips(
                selected = selectedType,
                isV6 = isV6,
                onSelect = { selectedType = it }
            )

            Text(
                text = stringResource(R.string.key_detail_add_subkey_expiry_label),
                style = MaterialTheme.typography.labelLarge
            )
            AddSubkeyExpiryChips(
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

            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = { Text(stringResource(R.string.key_detail_add_subkey_passphrase_label)) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                enabled = !isProcessing,
                modifier = Modifier.fillMaxWidth()
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
                        onApply(selectedType, computeExpiresAtEpochSeconds(), passphrase.ifBlank { null })
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
                        Text(stringResource(R.string.key_detail_add_subkey_apply))
                    }
                }
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

/**
 * Same shape as ExpirationOption (EditExpirationSheet.kt) but a
 * distinct type since "Never" is the sensible default here (a subkey
 * usually inherits the primary's own expiry policy rather than
 * forcing a one-year default the way primary-key generation does).
 */
private enum class AddSubkeyExpiryOption(val seconds: Long?) {
    NEVER(null),
    ONE_YEAR(365L * 24 * 60 * 60),
    TWO_YEARS(2 * 365L * 24 * 60 * 60),
    FIVE_YEARS(5 * 365L * 24 * 60 * 60)
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AddSubkeyExpiryChips(
    selectedPreset: AddSubkeyExpiryOption?,
    isCustom: Boolean,
    onPreset: (AddSubkeyExpiryOption) -> Unit,
    onCustom: () -> Unit
) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        AddSubkeyExpiryOption.entries.forEach { opt ->
            val label = when (opt) {
                AddSubkeyExpiryOption.NEVER -> stringResource(R.string.expiration_never)
                AddSubkeyExpiryOption.ONE_YEAR -> stringResource(R.string.expiration_one_year)
                AddSubkeyExpiryOption.TWO_YEARS -> stringResource(R.string.expiration_two_years)
                AddSubkeyExpiryOption.FIVE_YEARS -> stringResource(R.string.expiration_five_years)
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

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AddSubkeyTypeChips(
    selected: ClassicalSubkeyGen.ClassicalSubkeyType,
    isV6: Boolean,
    onSelect: (ClassicalSubkeyGen.ClassicalSubkeyType) -> Unit
) {
    // RC2: v6 keys take Ed25519/X25519 subkeys only; RSA is a v4 shape.
    val types = if (isV6) listOf(
        ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN,
        ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH,
        ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT
    ) else ClassicalSubkeyGen.ClassicalSubkeyType.entries
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        types.forEach { type ->
            val label = when (type) {
                ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_SIGN -> stringResource(R.string.key_detail_add_subkey_type_rsa_2048_sign)
                ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_ENCRYPT -> stringResource(R.string.key_detail_add_subkey_type_rsa_2048_encrypt)
                ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_SIGN -> stringResource(R.string.key_detail_add_subkey_type_rsa_4096_sign)
                ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_ENCRYPT -> stringResource(R.string.key_detail_add_subkey_type_rsa_4096_encrypt)
                ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_AUTH -> stringResource(R.string.key_detail_add_subkey_type_rsa_2048_auth)
                ClassicalSubkeyGen.ClassicalSubkeyType.RSA_4096_AUTH -> stringResource(R.string.key_detail_add_subkey_type_rsa_4096_auth)
                ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN -> stringResource(R.string.key_detail_add_subkey_type_ed25519_sign)
                ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH -> stringResource(R.string.key_detail_add_subkey_type_ed25519_auth)
                ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT -> stringResource(R.string.key_detail_add_subkey_type_x25519_encrypt)
            }
            FilterChip(
                selected = selected == type,
                onClick = { onSelect(type) },
                label = { Text(label) }
            )
        }
    }
}
