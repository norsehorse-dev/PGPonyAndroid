// AddSubkeySheet.kt
// PGPony Android — 4.2.0 RC3 workstream H (§17.2)
//
// Modal bottom sheet to add a classical subkey (RSA 2048/4096,
// Ed25519, X25519) to an existing software key pair. Same shape as
// EditExpirationSheet: type chips, expiry presets + custom date,
// passphrase field. Public-only keys never reach this sheet.
// 4.8.0 (#71): a key linked to a security key does (classical subkeys
// only, with a note), and when its primary is on the security key the
// sheet asks for the card PIN and the binding is signed there.
//
// item 7 (#55): post-quantum subkey types are offered here too, in a
// second "Post-Quantum" group — ML-KEM encryption (768 on any key, 1024
// on v6) and, on a v6 key, ML-DSA signing. The sheet speaks a single
// AddSubkeyChoice, and the view model routes each kind to its generator.
//
// 4.8.0 RC10 (#109): the types are grouped by what the subkey is for (Signing,
// Authentication, Encryption) from AddSubkeyChoice.optionsFor, the same list
// the composer in Generate Key shows. A v4 key also gets ECDSA and ECDH on a
// curve picked in a field (the key's own curve first, for an ECDSA key), so a
// brainpool key can take an Authenticate subkey for a security key's AUT slot.

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
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.ui.components.PassphraseVisibilityToggle
import com.pgpony.android.ui.util.dismissKeyboardOnTap
import com.pgpony.android.ui.util.keepsKeyboard
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.KeyAlgorithm
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
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
    /** 4.8.0 (#71): a key linked to a security key, which signs and decrypts
     *  there: classical subkeys only, and a note that the new one stays on
     *  this phone until it is moved. */
    cardLinked: Boolean = false,
    /** 4.8.0 (#71): the primary is on the security key, so its binding is
     *  signed there: ask for the card PIN, and the key's passphrase when
     *  [askPassphrase] (the key's secrets on this phone have one). Without
     *  it, a new passphrase is chosen (and confirmed) for the new subkey,
     *  whose secret is never stored unprotected. */
    onApplyCard: ((choice: AddSubkeyChoice, expiresAtEpochSeconds: Long?, pin: String, passphrase: String?) -> Unit)? = null,
    askPassphrase: Boolean = true,
    /** 4.8.0 RC10 (#109): the key's algorithm, so an ECDSA key starts on its own curve. */
    keyAlgorithm: KeyAlgorithm? = null,
) {
    val onCard = onApplyCard != null
    // 4.8.0 RC10 (#109): a swipe does not close this form; back and Cancel do.
    val sheetState = com.pgpony.android.ui.components.rememberFormSheetState()

    var selectedChoice: AddSubkeyChoice by remember {
        mutableStateOf(AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN))
    }
    // 4.8.0 RC10 (#109): the curve the ECDSA and ECDH types use.
    var curve by remember { mutableStateOf(AddSubkeyChoice.defaultCurve(keyAlgorithm)) }
    var selectedPreset by remember { mutableStateOf<AddSubkeyExpiryOption?>(AddSubkeyExpiryOption.NEVER) }
    var customMillis by remember { mutableStateOf<Long?>(null) }
    var showDatePicker by remember { mutableStateOf(false) }
    var passphrase by remember { mutableStateOf("") }
    var passphraseShown by remember { mutableStateOf(false) }
    var pin by remember { mutableStateOf("") }
    // 4.8.0 (#71): no protected secret on the phone, so the new subkey gets a new passphrase.
    val newPassphraseMode = onCard && !askPassphrase
    var confirm by remember { mutableStateOf("") }
    var confirmShown by remember { mutableStateOf(false) }
    val newPassphraseOk = !newPassphraseMode || (passphrase.isNotBlank() && passphrase == confirm)

    fun computeExpiresAtEpochSeconds(): Long? {
        val preset = selectedPreset
        return if (preset != null) {
            preset.seconds?.let { (System.currentTimeMillis() / 1000L) + it }
        } else {
            customMillis?.let { it / 1000L }
        }
    }

    val hasValidExpiry = selectedPreset != null || customMillis != null
    // 4.8.0 (#71): on the card path the key's own passphrase (when it has one)
    // is needed before the tap, so the card is not asked for nothing.
    val canApply = !isProcessing && hasValidExpiry && (!onCard || pin.isNotEmpty()) && newPassphraseOk &&
        (!onCard || !askPassphrase || passphrase.isNotEmpty())

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
                onSelect = { selectedChoice = it },
                showPostQuantum = !cardLinked,
                curve = curve,
                onCurve = { picked ->
                    curve = picked
                    // The same use on the new curve, when an ECDSA or ECDH type is selected.
                    val sel = selectedChoice
                    if (sel is AddSubkeyChoice.Classical && sel.type.curve != null) {
                        ClassicalSubkeyGen.ClassicalSubkeyType.ecdsa(picked, sel.type.capability)
                            ?.let { selectedChoice = AddSubkeyChoice.Classical(it) }
                    }
                }
            )
            if (cardLinked) {
                Text(
                    text = stringResource(R.string.key_detail_add_subkey_card_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary
                )
            }

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

            if (!onCard || askPassphrase) {
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(stringResource(R.string.key_detail_add_subkey_passphrase_label)) },
                    visualTransformation = if (passphraseShown) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = { PassphraseVisibilityToggle(passphraseShown) { passphraseShown = !passphraseShown } },
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                    enabled = !isProcessing,
                    modifier = Modifier.keepsKeyboard().fillMaxWidth()
                )
            }
            if (newPassphraseMode) {
                Text(
                    text = stringResource(R.string.key_detail_add_subkey_card_new_passphrase_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(stringResource(R.string.change_passphrase_new_label)) },
                    visualTransformation = if (passphraseShown) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = { PassphraseVisibilityToggle(passphraseShown) { passphraseShown = !passphraseShown } },
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
                    isError = passphrase != confirm,
                    enabled = !isProcessing,
                    modifier = Modifier.keepsKeyboard().fillMaxWidth()
                )
                if (passphrase != confirm) {
                    Text(
                        text = stringResource(R.string.keyring_error_passphrase_mismatch),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
            // 4.8.0 (#71): the binding is signed on the security key.
            if (onCard) {
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
                        confirm = ""
                        val cardApply = onApplyCard
                        if (cardApply != null) {
                            cardApply(selectedChoice, computeExpiresAtEpochSeconds(), pin, entered.ifBlank { null })
                        } else {
                            onApply(selectedChoice, computeExpiresAtEpochSeconds(), entered.ifBlank { null })
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
                        Text(stringResource(R.string.key_detail_add_subkey_apply))
                    }
                }
            }
            if (onCard && isProcessing) {
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
    onSelect: (AddSubkeyChoice) -> Unit,
    /** 4.8.0 (#71): false on a key linked to a security key. */
    showPostQuantum: Boolean = true,
    /** 4.8.0 RC10 (#109): the curve for the ECDSA and ECDH types (v4 keys). */
    curve: KeyAlgorithm = KeyAlgorithm.ECDSA_NIST_P256,
    onCurve: (KeyAlgorithm) -> Unit = {}
) {
    // 4.8.0 RC10 (#109): one list shared with the composer, grouped by use.
    val base = AddSubkeyChoice.baseFor(isV6, isCompositeSign)
    val options = AddSubkeyChoice.optionsFor(base, curve, postQuantum = showPostQuantum)
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (base == AddSubkeyChoice.Base.V4) {
            EcdsaCurveField(curve = curve, onSelect = onCurve)
        }
        SubkeyUsageGroups(options) { usage, choices ->
            Text(
                text = subkeyUsageLabel(usage),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                choices.forEach { choice ->
                    FilterChip(
                        selected = selected == choice,
                        onClick = { onSelect(choice) },
                        label = { Text(addSubkeyChoiceLabel(choice)) }
                    )
                }
            }
            if (usage == AddSubkeyChoice.Usage.AUTHENTICATE && base == AddSubkeyChoice.Base.V4 &&
                curve !in SSH_CURVES
            ) {
                Text(
                    text = stringResource(R.string.key_detail_add_subkey_ecdsa_ssh_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        // 4.6.0 (item 21): a classical subkey here still sits on a v6 key,
        // which Thunderbird and GnuPG cannot read yet.
        if (isCompositeSign) {
            Text(
                text = stringResource(R.string.key_detail_add_subkey_v6_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.tertiary
            )
        }
    }
}

/** 4.8.0 RC10 (#109): the curves SSH has an ECDSA key type for. */
private val SSH_CURVES = setOf(KeyAlgorithm.ECDSA_NIST_P256, KeyAlgorithm.ECDSA_NIST_P384, KeyAlgorithm.ECDSA_NIST_P521)

/**
 * 4.8.0 RC10 (#109): [options] split by use, in AddSubkeyChoice.Usage order,
 * empty groups left out. Shared by Add subkey and the composer's menu.
 */
@Composable
fun SubkeyUsageGroups(
    options: List<AddSubkeyChoice>,
    group: @Composable (AddSubkeyChoice.Usage, List<AddSubkeyChoice>) -> Unit
) {
    AddSubkeyChoice.Usage.entries.forEach { usage ->
        val choices = options.filter { AddSubkeyChoice.usageOf(it) == usage }
        if (choices.isNotEmpty()) group(usage, choices)
    }
}

@Composable
fun subkeyUsageLabel(usage: AddSubkeyChoice.Usage): String = when (usage) {
    AddSubkeyChoice.Usage.SIGN -> stringResource(R.string.key_detail_add_subkey_group_sign)
    AddSubkeyChoice.Usage.AUTHENTICATE -> stringResource(R.string.key_detail_add_subkey_group_auth)
    AddSubkeyChoice.Usage.ENCRYPT -> stringResource(R.string.key_detail_add_subkey_group_encrypt)
}

/**
 * 4.8.0 RC10 (#109): the curve for ECDSA and ECDH subkeys, a dropdown over
 * KeyAlgorithm.generatableEcdsa. Shared by Add subkey and the composer.
 */
@Composable
fun EcdsaCurveField(curve: KeyAlgorithm, onSelect: (KeyAlgorithm) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = stringResource(R.string.key_detail_add_subkey_curve_label),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Box {
            OutlinedButton(onClick = { open = true }) {
                Text(curve.shortName)
                Icon(Icons.Filled.ArrowDropDown, contentDescription = null)
            }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                KeyAlgorithm.generatableEcdsa.forEach { c ->
                    DropdownMenuItem(
                        text = { Text(c.shortName) },
                        onClick = {
                            open = false
                            onSelect(c)
                        }
                    )
                }
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
        // 4.8.0 RC10 (#109): ECDSA and ECDH, named with the curve.
        else -> {
            val curveName = choice.type.curve?.shortName.orEmpty()
            when (choice.type.capability) {
                ClassicalSubkeyGen.Capability.SIGN -> stringResource(R.string.key_detail_add_subkey_type_ecdsa_sign, curveName)
                ClassicalSubkeyGen.Capability.AUTHENTICATE -> stringResource(R.string.key_detail_add_subkey_type_ecdsa_auth, curveName)
                ClassicalSubkeyGen.Capability.ENCRYPT -> stringResource(R.string.key_detail_add_subkey_type_ecdh_encrypt, curveName)
            }
        }
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
