// ShareDecryptScreen.kt
// PGPony Android — Phase A15
//
// Decrypt-side flow inside ShareTargetActivity. Two phases:
//
//   1. PickDecryptKey — only reached when the user has 2+ key pairs.
//      Single-select list; tapping a row advances to NeedPassphrase.
//      For the common case (one key pair) the ViewModel skips this
//      phase entirely (beginDecrypt() auto-selects and jumps to
//      NeedPassphrase).
//
//   2. NeedPassphrase — passphrase text field + Decrypt button.
//      Passphrase is optional; if the chosen key has no passphrase,
//      leaving the field blank decrypts cleanly. BC will throw
//      PGPException for wrong/missing passphrase on a protected key,
//      which the ViewModel catches and surfaces as an error.
//
// Note: no biometric gate here. The main app's "Require biometric
// for decrypt" setting is honored only inside the main flow — the
// Quick Action surface lives behind a separate (in-future-phase)
// biometric lock; we don't double-prompt.

package com.pgpony.android.ui.share

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity

@Composable
fun ShareDecryptKeyPicker(
    state: ShareTargetUiState,
    onSelectKey: (PGPKeyEntity) -> Unit,
    onBack: () -> Unit,
) {
    state.availableKeyPairs.forEach { key ->
        ShareDecryptKeyRow(
            key = key,
            selected = state.selectedDecryptKey?.fingerprint == key.fingerprint,
            onClick = { onSelectKey(key) },
        )
    }

    OutlinedButton(
        onClick = onBack,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(stringResource(R.string.common_button_back))
    }
}

@Composable
private fun ShareDecryptKeyRow(
    key: PGPKeyEntity,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val containerColor =
        if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f)
        else MaterialTheme.colorScheme.surfaceContainerHigh
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        color = containerColor,
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Default.VpnKey,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp),
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = key.userID.ifBlank { key.fingerprint.take(16) },
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = key.longKeyId.chunked(4).joinToString(" "),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareDecryptPassphrasePrompt(
    state: ShareTargetUiState,
    onPassphraseChange: (String) -> Unit,
    onDecrypt: () -> Unit,
    onBack: () -> Unit,
) {
    val key = state.selectedDecryptKey
    if (key != null) {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(32.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Default.VpnKey,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp),
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.share_target_decrypt_auto_select_label),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = key.userID.ifBlank { key.fingerprint.take(16) },
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }

    OutlinedTextField(
        value = state.passphrase,
        onValueChange = onPassphraseChange,
        label = { Text(stringResource(R.string.share_target_decrypt_passphrase_label)) },
        placeholder = { Text(stringResource(R.string.share_target_decrypt_passphrase_optional)) },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )

    if (state.errorMessage != null) {
        Text(
            text = state.errorMessage,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) {
            Text(stringResource(R.string.common_button_back))
        }
        Button(
            onClick = onDecrypt,
            modifier = Modifier.weight(1f),
            enabled = state.selectedDecryptKey != null,
        ) {
            Text(stringResource(R.string.share_target_decrypt_button))
        }
    }
}

// ── HW Phase 3 — card (PIN + tap) decrypt prompt ───────────────────────
//
// Shown when the shared message is encrypted to a card key. No passphrase
// or software key pair applies; the user enters the card PIN and taps. The
// caller (ShareTargetScreen) supplies onDecrypt, which runs the NFC op via
// ShareTargetActivity and reports back to the ViewModel.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareCardDecryptPrompt(
    state: ShareTargetUiState,
    onPinChange: (String) -> Unit,
    onDecrypt: () -> Unit,
    onBack: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Default.VpnKey,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp),
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.share_target_card_label),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = state.cardDecryptKeyName
                        ?: stringResource(R.string.share_target_card_fallback_name),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }

    Text(
        text = stringResource(R.string.share_target_card_note),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    OutlinedTextField(
        value = state.cardPin,
        onValueChange = onPinChange,
        label = { Text(stringResource(R.string.card_decrypt_pin_label)) },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )

    if (state.errorMessage != null) {
        Text(
            text = state.errorMessage,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) {
            Text(stringResource(R.string.common_button_back))
        }
        Button(
            onClick = onDecrypt,
            modifier = Modifier.weight(1f),
            enabled = state.cardPin.isNotEmpty(),
        ) {
            Text(stringResource(R.string.card_decrypt_button))
        }
    }
}
