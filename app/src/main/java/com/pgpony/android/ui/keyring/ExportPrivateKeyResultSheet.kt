// ExportPrivateKeyResultSheet.kt
// PGPony Android — Phase A7 Fix4
//
// Shown after a successful biometric-gated private-key export. Two
// destinations from one share moment:
//
//   1. Copy to clipboard — fast path for piping into a password
//      manager (1Password, Bitwarden, KeePass) as a secure note,
//      which is a common PGP-key backup pattern that file-share
//      doesn't serve well.
//   2. Save as .asc file — durable backup to Drive/Files/email via
//      the FileProvider-backed Intent shipped in Fix3.
//
// Deliberate design choices:
//
//   • The armored text is NOT displayed in the sheet. The user has
//     already passed the AlertDialog warning + biometric prompt, so
//     visual verification of the bytes adds nothing — and avoids
//     exposing the secret to shoulder-surfing, screen recording, or
//     a misclicked screenshot. The metadata (owner, fingerprint,
//     length) is enough confirmation that the right key is loaded.
//
//   • Buttons are stacked vertically (not in a Row), forcing each
//     destructive action to be a single deliberate tap. Matches the
//     "this is serious" affordance the AlertDialog set up.
//
//   • Both action buttons use error-color tinting — the same red as
//     the AlertDialog Continue button. Visual consistency: red means
//     "you're about to produce sensitive material that will live
//     somewhere PGPony can't reach."
//
//   • Sheet stays open after Copy so the user can also Save (or vice
//     versa). Done dismisses; tapping outside dismisses; either path
//     clears the armored material from the VM.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.IosShare
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.ui.components.PassphraseVisibilityToggle
import com.pgpony.android.ui.util.dismissKeyboardOnTap
import com.pgpony.android.ui.util.keepsKeyboard
import androidx.compose.foundation.selection.toggleable
import androidx.compose.ui.semantics.Role
import androidx.compose.material3.minimumInteractiveComponentSize

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportPrivateKeyResultSheet(
    keyOwnerLabel: String,
    keyEmail: String,
    shortFingerprint: String,
    armoredLength: Int,
    // RC4 O5 (#16, CertainBot): the ring already has its own passphrase —
    // hide the export-passphrase fields and say so instead.
    alreadyProtected: Boolean = false,
    onCopy: (exportPassphrase: String?, gpgCompat: Boolean) -> Unit,
    onSaveFile: (exportPassphrase: String?, gpgCompat: Boolean) -> Unit,
    onShare: (exportPassphrase: String?, gpgCompat: Boolean) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    // RC4 O5: optional passphrase applied to the EXPORT COPY only. A
    // mismatch disables every delivery button — a typo here on top of a
    // deleted original would make the backup unreadable forever.
    var exportPassphrase by remember { mutableStateOf("") }
    var exportPassphraseConfirm by remember { mutableStateOf("") }
    var exportShown by remember { mutableStateOf(false) }
    var exportConfirmShown by remember { mutableStateOf(false) }
    val passphraseMismatch =
        exportPassphrase.isNotEmpty() && exportPassphrase != exportPassphraseConfirm
    val effectivePassphrase: String? =
        if (alreadyProtected || exportPassphrase.isBlank()) null else exportPassphrase
    // issue #2 symptom D: emit GnuPG's native composite-secret format.
    var gpgCompat by remember { mutableStateOf(false) }
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        // Same scroll/IME treatment as the other result sheets — the
        // metadata card + warning text + 3 stacked buttons can run
        // tall on small screens.
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp, vertical = 8.dp)
                .dismissKeyboardOnTap(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ── Header: key icon + title ──────────────────────────────
            //
            // Key icon (not CheckCircle green like the revocation result)
            // because this isn't a "done, success!" moment — it's a
            // "you've produced sensitive material, now decide what to
            // do with it" moment. Different vibe, different icon.
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Key,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.export_private_sheet_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }

            // ── Warning text ──────────────────────────────────────────
            //
            // Brief recap of the AlertDialog's main point. Sheet is
            // shown AFTER the dialog + biometric, but the user might
            // have tapped through the dialog quickly — this is a
            // last visual reminder before they pick a destination.
            Text(
                text = stringResource(R.string.export_private_sheet_warning),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // ── Metadata card ─────────────────────────────────────────
            //
            // Displays owner / email / fingerprint / length so the
            // user can visually confirm that the right key is loaded
            // before producing its private material. Deliberately
            // NOT showing the armored text itself — see file header.
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(8.dp)
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    if (keyOwnerLabel.isNotBlank()) {
                        Text(
                            text = keyOwnerLabel,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    if (keyEmail.isNotBlank() && keyEmail != keyOwnerLabel) {
                        Text(
                            text = keyEmail,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Text(
                        text = stringResource(R.string.result_sheet_fingerprint_format, shortFingerprint),
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace
                        ),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = stringResource(R.string.result_sheet_armored_block_format, armoredLength),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // ── Subtle clipboard caveat (API 33+ context) ─────────────
            //
            // On Android 13+ the clipboard auto-purges any "sensitive"
            // payload after ~1 hour and Android's clipboard-preview
            // overlay is suppressed (we pass EXTRA_IS_SENSITIVE when
            // setting the clip). On older Android the clip persists
            // until cleared. Either way it's worth one line of caution
            // before the buttons.
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Warning,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = stringResource(R.string.result_sheet_clipboard_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // ── Action buttons (stacked, error-tinted) ────────────────
            //
            // Stacked vertically so each is a deliberate single tap.
            // Both use error-color tinting (red) — same visual weight
            // as the AlertDialog Continue button that brought us here.
            // Done is neutral outline.
            if (alreadyProtected) {
                Text(
                    text = stringResource(R.string.export_passphrase_already_protected_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                OutlinedTextField(
                    value = exportPassphrase,
                    onValueChange = { exportPassphrase = it },
                    label = { Text(stringResource(R.string.export_passphrase_label)) },
                    visualTransformation = if (exportShown) VisualTransformation.None else androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    trailingIcon = { PassphraseVisibilityToggle(exportShown) { exportShown = !exportShown } },
                    singleLine = true,
                    modifier = Modifier.keepsKeyboard().fillMaxWidth()
                )
                if (exportPassphrase.isNotEmpty()) {
                    OutlinedTextField(
                        value = exportPassphraseConfirm,
                        onValueChange = { exportPassphraseConfirm = it },
                        label = { Text(stringResource(R.string.export_passphrase_confirm_label)) },
                        visualTransformation = if (exportConfirmShown) VisualTransformation.None else androidx.compose.ui.text.input.PasswordVisualTransformation(),
                        trailingIcon = { PassphraseVisibilityToggle(exportConfirmShown) { exportConfirmShown = !exportConfirmShown } },
                        singleLine = true,
                        isError = passphraseMismatch,
                        modifier = Modifier.keepsKeyboard().fillMaxWidth()
                    )
                    if (passphraseMismatch) {
                        Text(
                            text = stringResource(R.string.export_passphrase_mismatch),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .toggleable(value = gpgCompat, role = Role.Switch, onValueChange = { gpgCompat = it })
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.export_private_gpg_compat_label),
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = stringResource(R.string.export_private_gpg_compat_caption),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(checked = gpgCompat, onCheckedChange = null, modifier = Modifier.minimumInteractiveComponentSize())
            }

            OutlinedButton(
                enabled = !passphraseMismatch,
                onClick = { onCopy(effectivePassphrase, gpgCompat) },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Icon(
                    imageVector = Icons.Filled.ContentCopy,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.result_sheet_copy_button))
            }

            // RC3 §J: real ACTION_CREATE_DOCUMENT save; share chooser
            // moved to its own button (see ExportPublicKeyResultSheet).
            // Both keep the error-red tint — this is secret material
            // whichever way it leaves the app.
            OutlinedButton(
                enabled = !passphraseMismatch,
                onClick = { onSaveFile(effectivePassphrase, gpgCompat) },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Icon(
                    imageVector = Icons.Filled.SaveAlt,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.result_sheet_save_button))
            }

            OutlinedButton(
                enabled = !passphraseMismatch,
                onClick = { onShare(effectivePassphrase, gpgCompat) },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Icon(
                    imageVector = Icons.Filled.IosShare,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.result_sheet_share_button))
            }

            OutlinedButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.common_button_done))
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

// ── Default error tint for the action buttons ─────────────────────────
//
// Used as a typed alias to avoid Color(0xFFEF4444) littering the
// component. The actual value comes from MaterialTheme.colorScheme.error
// declared in MainActivity.kt's PGPonyTheme block.
@Suppress("unused")
private val DangerZoneTint = Color(0xFFEF4444)
