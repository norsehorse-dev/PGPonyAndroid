// DeleteKeySheet.kt
// PGPony Android — 4.2.0 RC3 workstream L (#21 delete safeguards)
//
// Replaces the bare AlertDialog for deleting a KEY PAIR with a sheet
// that (1) offers a backup export first, (2) requires an explicit
// acknowledgement checkbox before Delete enables, and (3) leaves the
// biometric gate to the HOST — applied only when the app's biometric
// lock is on, per the L plan — so this sheet never stacks prompts on
// its own. Public-only keys keep their lightweight dialog: they are
// re-importable; the safeguard exists for irreplaceable private
// material.
//
// No per-key backup state exists (the 8 August scope check: nothing
// records a backup timestamp, and PGPKeyEntity.isSynced is dead), so
// the sheet cannot know whether a backup already happened. The
// acknowledgement is therefore required ALWAYS and the backup offer is
// unconditional. Timestamped backup state is 4.3.0 work.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.pgpony.android.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeleteKeySheet(
    keyOwnerLabel: String,
    shortFingerprint: String,
    // §4.3: when this key was last backed up (epoch ms), or null for never.
    lastBackedUpAt: Long? = null,
    onSaveBackup: (exportPassphrase: String?) -> Unit,
    onDelete: () -> Unit,
    // #36 (CertainBot): offer a revoke path from the delete sheet. A revoke
    // cert can't be made after the key is gone, so this lets the user retire
    // it properly instead of a bare delete. Null hides the button.
    onRevokeInstead: (() -> Unit)? = null,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var acknowledged by remember { mutableStateOf(false) }
    // RC4 O5 (#16): optional passphrase on the backup copy. Confirm field
    // is non-negotiable here — a typo'd passphrase on the backup of a key
    // that is about to be DELETED is unrecoverable twice over. Ignored
    // when the key already carries its own passphrase (the repo exports
    // such rings as-is; the field subtitle says so).
    var backupPassphrase by remember { mutableStateOf("") }
    var backupPassphraseConfirm by remember { mutableStateOf("") }
    val backupMismatch =
        backupPassphrase.isNotEmpty() && backupPassphrase != backupPassphraseConfirm

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Warning,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.key_delete_sheet_title),
                    style = MaterialTheme.typography.headlineSmall
                )
            }

            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = MaterialTheme.shapes.medium
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    Text(keyOwnerLabel, style = MaterialTheme.typography.bodyMedium)
                    Text(
                        shortFingerprint,
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // §4.3: per-key backup status, so the user knows whether losing
            // this key is recoverable from a backup they already have.
            if (lastBackedUpAt != null) {
                val date = java.text.DateFormat.getDateInstance().format(java.util.Date(lastBackedUpAt))
                Text(
                    text = stringResource(R.string.key_delete_backed_up_on, date),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Text(
                    text = stringResource(R.string.key_delete_never_backed_up),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
            }

            // §5.6.1: delete now moves to Recently Deleted for a window, so
            // the language is a different promise than permanent destruction.
            Text(
                text = stringResource(
                    R.string.key_delete_sheet_body,
                    com.pgpony.android.data.repository.KeyRepository.RECYCLE_BIN_RETENTION_DAYS
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            OutlinedTextField(
                value = backupPassphrase,
                onValueChange = { backupPassphrase = it },
                label = { Text(stringResource(R.string.export_passphrase_backup_label)) },
                visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            if (backupPassphrase.isNotEmpty()) {
                OutlinedTextField(
                    value = backupPassphraseConfirm,
                    onValueChange = { backupPassphraseConfirm = it },
                    label = { Text(stringResource(R.string.export_passphrase_confirm_label)) },
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    singleLine = true,
                    isError = backupMismatch,
                    modifier = Modifier.fillMaxWidth()
                )
                if (backupMismatch) {
                    Text(
                        text = stringResource(R.string.export_passphrase_mismatch),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }

            OutlinedButton(
                onClick = {
                    onSaveBackup(backupPassphrase.ifBlank { null })
                },
                enabled = !backupMismatch,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Filled.SaveAlt,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.key_delete_backup_button))
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { acknowledged = !acknowledged },
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(
                    checked = acknowledged,
                    onCheckedChange = { acknowledged = it }
                )
                Text(
                    text = stringResource(R.string.key_delete_ack_label),
                    style = MaterialTheme.typography.bodyMedium
                )
            }

            if (onRevokeInstead != null) {
                Text(
                    text = stringResource(R.string.key_delete_revoke_instead_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutlinedButton(
                    onClick = onRevokeInstead,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(
                        imageVector = Icons.Filled.Block,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.key_delete_revoke_instead_button))
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f)
                ) { Text(stringResource(R.string.common_button_cancel)) }
                Button(
                    onClick = onDelete,
                    enabled = acknowledged,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error
                    )
                ) { Text(stringResource(R.string.key_delete_confirm_button)) }
            }
        }
    }
}
