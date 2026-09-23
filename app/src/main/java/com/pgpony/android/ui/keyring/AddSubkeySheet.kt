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
// item 7 (#55): post-quantum subkey types are offered here too, in a
// second "Post-Quantum" group — ML-KEM encryption (768 on any key, 1024
// on v6) and, on a v6 key, ML-DSA signing. The sheet speaks a single
// AddSubkeyChoice, and the view model routes each kind to its generator.

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
import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddSubkeySheet(
    keyOwnerLabel: String,
    isProcessing: Boolean = false,
    errorMessage: String? = null,
    isV6: Boolean = false,
    /** 4.6.0 (item 21): a composite ML-DSA primary, which also takes RSA. */
    isCompositeSign: Boolean = false,
    onApply: (choice: AddSubkeyChoice, expiresAtEpochSeconds: Long?, passphrase: String?) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    var selectedChoice: AddSubkeyChoice by remember {
        mutableStateOf(AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN))
    }
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
                selected = selectedChoice,
                isV6 = isV6,
                isCompositeSign = isCompositeSign,
                onSelect = { selectedChoice = it }
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
                        onApply(selectedChoice, computeExpiresAtEpochSeconds(), passphrase.ifBlank { null })
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
    selected: AddSubkeyChoice,
    isV6: Boolean,
    isCompositeSign: Boolean,
    onSelect: (AddSubkeyChoice) -> Unit
) {
    val classical = AddSubkeyChoice.classicalFor(isV6, isCompositeSign)
    val postQuantum = AddSubkeyChoice.postQuantumFor(isV6)
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.key_detail_add_subkey_group_classical),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            classical.forEach { choice ->
                FilterChip(
                    selected = selected == choice,
                    onClick = { onSelect(choice) },
                    label = { Text(addSubkeyChoiceLabel(choice)) }
                )
            }
        }
        Text(
            text = stringResource(R.string.key_detail_add_subkey_group_pq),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            postQuantum.forEach { choice ->
                FilterChip(
                    selected = selected == choice,
                    onClick = { onSelect(choice) },
                    label = { Text(addSubkeyChoiceLabel(choice)) }
                )
            }
        }
    }
}

@Composable
fun addSubkeyChoiceLabel(choice: AddSubkeyChoice): String = when (choice) {
    is AddSubkeyChoice.Classical -> when (choice.type) {
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
    is AddSubkeyChoice.PqEncryption -> when (choice.suite) {
        CompositeSuite.IETF_1024 -> stringResource(R.string.key_detail_add_subkey_type_mlkem1024)
        else -> stringResource(R.string.key_detail_add_subkey_type_mlkem768)
    }
    is AddSubkeyChoice.PqSigning -> when (choice.suite) {
        CompositeSignSuite.MLDSA87_ED448 -> stringResource(R.string.key_detail_add_subkey_type_mldsa87)
        else -> stringResource(R.string.key_detail_add_subkey_type_mldsa65)
    }
}
