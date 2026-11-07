// SshKeysScreen.kt
// PGPony Android, 4.8.0 RC7 (item 1): Settings > SSH keys.
//
// Experimental ssh-mldsa44-ed25519 keys (OpenSSH 10.6 and later), held on
// the phone outside the OpenPGP keyring. The screen generates, imports,
// renames and deletes them, copies or shares the authorized_keys line, and
// exports the private key as a passphrase-protected OpenSSH key file. It never
// signs: logins go through the SSH provider, like the OpenPGP SSH keys.
//
// A pushed page under Settings (the "ssh_keys" route in MainActivity), the
// same way Pair and the recycle bin are. Exporting asks for the same device
// check as Export Private Key, and every passphrase dialog sets FLAG_SECURE.

package com.pgpony.android.ui.settings

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.os.Build
import android.view.WindowManager
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.lifecycle.viewmodel.compose.viewModel
import com.pgpony.android.MainActivity
import com.pgpony.android.R
import com.pgpony.android.data.ssh.SshKeyEntry
import com.pgpony.android.data.ssh.SshKeyStore
import com.pgpony.android.saf.findDocumentCreatorHost
import com.pgpony.android.ui.components.PassphraseVisibilityToggle
import com.pgpony.android.ui.keyring.BiometricAvailability
import com.pgpony.android.ui.keyring.BiometricGate
import com.pgpony.android.ui.util.keepsKeyboard
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SshKeysScreen(onBack: () -> Unit) {
    val vm: SshKeysViewModel = viewModel()
    val state by vm.state.collectAsState()
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val snackbarHostState = remember { SnackbarHostState() }

    var showGenerate by remember { mutableStateOf(false) }
    var showTermuxHelp by remember { mutableStateOf(false) }
    var renameTarget by remember { mutableStateOf<SshKeyEntry?>(null) }
    var deleteTarget by remember { mutableStateOf<SshKeyEntry?>(null) }
    var exportTarget by remember { mutableStateOf<SshKeyEntry?>(null) }

    LaunchedEffect(state.message) {
        state.message?.let {
            snackbarHostState.showSnackbar(it)
            vm.consumeMessage()
        }
    }

    val copiedNote = stringResource(R.string.key_detail_ssh_key_copied)
    val onCopy: (SshKeyEntry) -> Unit = { entry ->
        clipboard.setText(AnnotatedString(entry.publicKeyLine))
        // Android 13 and later confirm a copy themselves.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) vm.showMessage(copiedNote)
    }
    val onShare: (SshKeyEntry) -> Unit = { entry ->
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, entry.publicKeyLine)
        }
        runCatching { context.startActivity(Intent.createChooser(send, null)) }
    }
    // Same device check as Export Private Key, with the same fall-through
    // when no biometric or screen lock is set up.
    val onExport: (SshKeyEntry) -> Unit = { entry ->
        val activity = context.findFragmentActivity()
        if (activity != null &&
            BiometricGate.canAuthenticate(context) == BiometricAvailability.Available
        ) {
            BiometricGate.authenticate(
                activity = activity,
                title = context.getString(R.string.key_detail_export_biometric_title),
                subtitle = context.getString(R.string.key_detail_export_biometric_subtitle),
                onSuccess = { exportTarget = entry },
                onError = { _, _ -> }
            )
        } else {
            exportTarget = entry
        }
    }
    val onImport: () -> Unit = {
        val activity = context.findSshKeysMainActivity()
        activity?.startDocumentPicker(arrayOf("*/*")) { uri ->
            if (uri != null) vm.importFrom(uri, context.contentResolver)
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ssh_keys_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.common_button_back)
                        )
                    }
                }
            )
        }
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (state.working) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            } else {
                Spacer(modifier = Modifier.height(4.dp))
            }
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 24.dp)
            ) {
                item(key = "intro") {
                    IntroBlock(onOpenTermuxHelp = { showTermuxHelp = true })
                }
                item(key = "actions") {
                    Column {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 16.dp),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { showGenerate = true },
                                enabled = !state.working,
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(stringResource(R.string.ssh_keys_generate))
                            }
                            OutlinedButton(
                                onClick = onImport,
                                enabled = !state.working,
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Filled.FileOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(stringResource(R.string.ssh_keys_import))
                            }
                        }
                        HorizontalDivider()
                    }
                }
                when {
                    !state.loaded -> item(key = "loading") {
                        Box(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 32.dp),
                            contentAlignment = Alignment.Center
                        ) { CircularProgressIndicator() }
                    }
                    state.loadFailed -> item(key = "failed") {
                        StateText(stringResource(R.string.ssh_keys_load_failed))
                    }
                    state.keys.isEmpty() -> item(key = "empty") {
                        StateText(stringResource(R.string.ssh_keys_empty))
                    }
                    else -> itemsIndexed(state.keys, key = { _, k -> k.id }) { index, entry ->
                        Column {
                            SshKeyRow(
                                entry = entry,
                                enabled = !state.working,
                                onCopy = { onCopy(entry) },
                                onShare = { onShare(entry) },
                                onExport = { onExport(entry) },
                                onRename = { renameTarget = entry },
                                onDelete = { deleteTarget = entry }
                            )
                            if (index != state.keys.lastIndex) HorizontalDivider()
                        }
                    }
                }
            }
        }
    }

    if (showTermuxHelp) {
        SshTermuxSheet(onDismiss = { showTermuxHelp = false })
    }

    if (showGenerate) {
        LabelDialog(
            title = stringResource(R.string.ssh_keys_generate_title),
            initial = "",
            confirmLabel = stringResource(R.string.onboarding_generate_button),
            onConfirm = { label ->
                showGenerate = false
                vm.generate(label)
            },
            onDismiss = { showGenerate = false }
        )
    }

    renameTarget?.let { target ->
        LabelDialog(
            title = stringResource(R.string.ssh_keys_rename_title),
            initial = target.label,
            confirmLabel = stringResource(R.string.common_button_save),
            onConfirm = { label ->
                renameTarget = null
                vm.rename(target.id, label)
            },
            onDismiss = { renameTarget = null }
        )
    }

    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(stringResource(R.string.ssh_keys_delete_title)) },
            text = { Text(stringResource(R.string.ssh_keys_delete_body, displayLabel(target))) },
            confirmButton = {
                TextButton(onClick = {
                    deleteTarget = null
                    vm.delete(target.id)
                }) {
                    Text(
                        stringResource(R.string.common_button_delete),
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        )
    }

    exportTarget?.let { target ->
        ExportPassphraseDialog(
            onConfirm = { passphrase ->
                exportTarget = null
                val host = context.findDocumentCreatorHost()
                if (host == null) {
                    vm.showMessage(context.getString(R.string.result_save_failed_note))
                } else {
                    val chars = passphrase.toCharArray()
                    host.startDocumentCreator(
                        "application/octet-stream",
                        SshKeyForm.exportFileName(target.label)
                    ) { uri ->
                        if (uri == null) {
                            chars.fill('\u0000')
                        } else {
                            vm.exportTo(target.id, chars, uri, context.contentResolver)
                        }
                    }
                }
            },
            onDismiss = { exportTarget = null }
        )
    }

    state.importPrompt?.let { prompt ->
        ImportPassphraseDialog(
            wrongPassphrase = prompt.wrongPassphrase,
            working = state.working,
            onConfirm = { passphrase -> vm.submitImportPassphrase(passphrase.toCharArray()) },
            onDismiss = { vm.cancelImport() }
        )
    }
}

// ── Pieces ─────────────────────────────────────────────────────────────

@Composable
private fun IntroBlock(onOpenTermuxHelp: () -> Unit) {
    Column {
        Text(
            stringResource(R.string.ssh_keys_intro),
            style = MaterialTheme.typography.bodyMedium
        )
        // A callout, not a badge: neutral border, plain bold label.
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp)
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, MaterialTheme.shapes.small)
                .padding(12.dp)
        ) {
            Text(
                stringResource(R.string.ssh_keys_experimental_label),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                stringResource(R.string.ssh_keys_experimental_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        TextButton(onClick = onOpenTermuxHelp, modifier = Modifier.padding(top = 4.dp)) {
            Text(stringResource(R.string.ssh_help_title))
        }
    }
}

@Composable
private fun StateText(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp)
    )
}

@Composable
private fun displayLabel(entry: SshKeyEntry): String =
    entry.label.ifBlank { stringResource(R.string.sign_as_sheet_no_name) }

@Composable
private fun SshKeyRow(
    entry: SshKeyEntry,
    enabled: Boolean,
    onCopy: () -> Unit,
    onShare: () -> Unit,
    onExport: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit
) {
    var menuOpen by remember { mutableStateOf(false) }
    val created = remember(entry.createdAt) {
        DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(entry.createdAt))
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled) { menuOpen = true }
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.Top
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(displayLabel(entry), style = MaterialTheme.typography.bodyLarge)
            Text(
                entry.keyType,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                entry.fingerprint,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                stringResource(R.string.ssh_keys_created_format, created),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Box {
            IconButton(onClick = { menuOpen = true }, enabled = enabled) {
                Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.key_detail_actions_menu_cd))
            }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.ssh_keys_copy_public)) },
                    leadingIcon = { Icon(Icons.Filled.ContentCopy, null) },
                    onClick = { menuOpen = false; onCopy() }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.ssh_keys_share_public)) },
                    leadingIcon = { Icon(Icons.Filled.Share, null) },
                    onClick = { menuOpen = false; onShare() }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.ssh_keys_export_private)) },
                    leadingIcon = { Icon(Icons.Filled.SaveAlt, null) },
                    onClick = { menuOpen = false; onExport() }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.ssh_keys_rename)) },
                    leadingIcon = { Icon(Icons.Filled.Edit, null) },
                    onClick = { menuOpen = false; onRename() }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.common_button_delete), color = MaterialTheme.colorScheme.error) },
                    leadingIcon = { Icon(Icons.Filled.Delete, null, tint = MaterialTheme.colorScheme.error) },
                    onClick = { menuOpen = false; onDelete() }
                )
            }
        }
    }
}

/** Generate and Rename: one label field, refused when blank. */
@Composable
private fun LabelDialog(
    title: String,
    initial: String,
    confirmLabel: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var label by remember { mutableStateOf(initial) }
    val usable = SshKeyForm.isLabelUsable(label)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = label,
                onValueChange = { if (it.length <= SshKeyStore.MAX_LABEL_LENGTH) label = it },
                label = { Text(stringResource(R.string.ssh_keys_label_field)) },
                supportingText = { Text(stringResource(R.string.ssh_keys_label_hint)) },
                singleLine = true,
                modifier = Modifier.keepsKeyboard().fillMaxWidth()
            )
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(label) }, enabled = usable) { Text(confirmLabel) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_button_cancel)) }
        }
    )
}

/** Keeps a passphrase out of screenshots and the screen recorder while it is shown. */
@Composable
private fun SecureWindowWhileShown() {
    val context = LocalContext.current
    DisposableEffect(Unit) {
        val window = context.findActivity()?.window
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
}

private val secureDialog = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)

/** The passphrase that protects an exported private key, asked twice. */
@Composable
private fun ExportPassphraseDialog(onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    SecureWindowWhileShown()
    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var shown by remember { mutableStateOf(false) }
    var attempted by remember { mutableStateOf(false) }
    val problem = SshKeyForm.passphraseProblem(passphrase, confirm)
    val transformation = if (shown) VisualTransformation.None else PasswordVisualTransformation()
    AlertDialog(
        onDismissRequest = onDismiss,
        properties = secureDialog,
        title = { Text(stringResource(R.string.ssh_keys_export_private)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.ssh_keys_export_body), style = MaterialTheme.typography.bodyMedium)
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(stringResource(R.string.encrypt_password_passphrase_label)) },
                    visualTransformation = transformation,
                    trailingIcon = { PassphraseVisibilityToggle(shown) { shown = !shown } },
                    singleLine = true,
                    isError = attempted && problem == SshKeyForm.PassphraseProblem.EMPTY,
                    modifier = Modifier.keepsKeyboard().fillMaxWidth()
                )
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { confirm = it },
                    label = { Text(stringResource(R.string.encrypt_password_confirm_label)) },
                    visualTransformation = transformation,
                    singleLine = true,
                    isError = attempted && problem == SshKeyForm.PassphraseProblem.MISMATCH,
                    modifier = Modifier.keepsKeyboard().fillMaxWidth()
                )
                if (attempted && problem != null) {
                    Text(
                        stringResource(
                            if (problem == SshKeyForm.PassphraseProblem.EMPTY) R.string.encdec_error_password_required
                            else R.string.export_passphrase_mismatch
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                attempted = true
                if (problem == null) onConfirm(passphrase)
            }) { Text(stringResource(R.string.common_button_save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_button_cancel)) }
        }
    )
}

/** The passphrase of a protected key file being imported. */
@Composable
private fun ImportPassphraseDialog(
    wrongPassphrase: Boolean,
    working: Boolean,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit
) {
    SecureWindowWhileShown()
    var passphrase by remember { mutableStateOf("") }
    var shown by remember { mutableStateOf(false) }
    // 4.8.0 RC7 (item 1): Cancel (and Back) stay usable while bcrypt_pbkdf
    // runs; the view model drops the result (SshKeysViewModel.cancelImport).
    AlertDialog(
        onDismissRequest = onDismiss,
        properties = secureDialog,
        title = { Text(stringResource(R.string.ssh_keys_import_pass_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(stringResource(R.string.encrypt_password_passphrase_label)) },
                    visualTransformation = if (shown) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = { PassphraseVisibilityToggle(shown) { shown = !shown } },
                    singleLine = true,
                    isError = wrongPassphrase,
                    enabled = !working,
                    modifier = Modifier.keepsKeyboard().fillMaxWidth()
                )
                if (wrongPassphrase) {
                    Text(
                        stringResource(R.string.provider_passphrase_wrong),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                if (working) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(passphrase) },
                enabled = passphrase.isNotEmpty() && !working
            ) { Text(stringResource(R.string.signer_lookup_import_button)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.common_button_cancel))
            }
        }
    )
}

// ── Context walks ──────────────────────────────────────────────────────

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

private fun Context.findFragmentActivity(): androidx.fragment.app.FragmentActivity? =
    findActivity() as? androidx.fragment.app.FragmentActivity

/** Walk the ContextWrapper chain to the hosting MainActivity (matches
 *  BackupScreen: a bare `as? MainActivity` fails inside dialogs and sheets). */
private tailrec fun Context.findSshKeysMainActivity(): MainActivity? = when (this) {
    is MainActivity -> this
    is ContextWrapper -> baseContext.findSshKeysMainActivity()
    else -> null
}
