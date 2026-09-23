// BackupScreen.kt
// PGPony Android — 4.0.0 Phase 3 (encrypted keyring backup UI)
//
// Full-screen overlay (shown from Settings) hosting the backup and
// restore flows. File save/open go through MainActivity's SAF helpers
// (the same path ImportKeyScreen/FileEncryptionResultScreen use, which
// dodge the broken Compose launcher on the FragmentActivity host).

package com.pgpony.android.ui.backup

import android.content.Context
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.pgpony.android.MainActivity
import com.pgpony.android.R
import com.pgpony.android.backup.MergeReport
import com.pgpony.android.intent.DocumentBytes
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupScreen(
    onDismiss: () -> Unit,
    initialRestoreBytes: ByteArray? = null,
    onRestored: () -> Unit = {}
) {
    val vm: BackupViewModel = viewModel()
    val state by vm.state.collectAsState()
    val context = LocalContext.current
    val activity = context.findMainActivityForBackup()
    val clipboard = LocalClipboardManager.current

    // A restore imported keys through the repository, but the keyring list
    // loads via a one-shot query (no reactive Flow), so tell it to reload
    // once the merge completes — otherwise the new keys don't appear until
    // the app is relaunched.
    LaunchedEffect(state.phase) {
        if (state.phase == BackupViewModel.Phase.RestoreDone) onRestored()
    }

    // Opened by tapping a .pgpony file: jump straight into the restore
    // flow with the file already loaded (keyed on identity so it fires
    // once per delivered file, not on every recomposition).
    LaunchedEffect(initialRestoreBytes) {
        if (initialRestoreBytes != null && initialRestoreBytes.isNotEmpty()) {
            vm.beginRestore(initialRestoreBytes)
        }
    }

    val onBack: () -> Unit = {
        if (state.phase == BackupViewModel.Phase.Menu) onDismiss() else vm.reset()
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(stringResource(R.string.backup_screen_title)) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.backup_done))
                        }
                    }
                )
            }
        ) { padding ->
            Column(
                modifier = Modifier
                    .padding(padding)
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 12.dp)
            ) {
                when (state.phase) {
                    BackupViewModel.Phase.Menu -> MenuBody(
                        onBackup = { vm.beginBackup() },
                        onRestore = {
                            activity?.startDocumentPicker(
                                arrayOf("application/octet-stream", "text/plain", "*/*")
                            ) { uri ->
                                // Read synchronously in the picker callback
                                // (matches ImportKeyScreen). Backup files are
                                // small, and a coroutine scope tied to this
                                // composition may already be gone by the time
                                // the picker returns — which silently dropped
                                // beginRestore and bounced back to the menu.
                                if (uri != null) {
                                    val bytes = DocumentBytes.read(context.contentResolver, uri)
                                    if (bytes != null && bytes.isNotEmpty()) vm.beginRestore(bytes)
                                }
                            }
                        }
                    )

                    BackupViewModel.Phase.ShowCode -> ShowCodeBody(
                        state = state,
                        onCopy = {
                            state.recoveryGrouped?.let {
                                clipboard.setText(AnnotatedString(it))
                            }
                        },
                        onConfirmChange = vm::updateConfirm,
                        onSave = {
                            if (vm.confirmMatches()) {
                                val stamp = SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date())
                                activity?.startDocumentCreator(
                                    mimeType = "application/octet-stream",
                                    suggestedName = vm.suggestedFileName(stamp)
                                ) { uri ->
                                    uri?.let { vm.writeBackup(it, context.contentResolver) }
                                }
                            } else {
                                vm.flagConfirmMismatch()
                            }
                        }
                    )

                    BackupViewModel.Phase.EnterCode -> EnterCodeBody(
                        state = state,
                        onCodeChange = vm::updateRestoreCode,
                        onRestore = vm::runRestore
                    )

                    BackupViewModel.Phase.BackupDone -> DoneBody(
                        title = stringResource(R.string.backup_saved_title),
                        body = stringResource(R.string.backup_saved_body),
                        onDone = onDismiss
                    )

                    BackupViewModel.Phase.RestoreDone -> RestoreReportBody(
                        report = state.report,
                        onDone = onDismiss,
                        onApplySettings = { vm.applyRestoredSettings() },
                        onSkipSettings = { vm.skipRestoredSettings() }
                    )
                }

                state.error?.let {
                    Spacer(Modifier.height(12.dp))
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                }
                if (state.working) {
                    Spacer(Modifier.height(16.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(10.dp))
                        Text(stringResource(R.string.backup_working))
                    }
                }
            }
        }
    }
}

@Composable
private fun MenuBody(onBackup: () -> Unit, onRestore: () -> Unit) {
    ActionCard(
        icon = { Icon(Icons.Filled.CloudUpload, null, tint = Color(0xFF8B5CF6), modifier = Modifier.size(28.dp)) },
        title = stringResource(R.string.backup_menu_backup_title),
        subtitle = stringResource(R.string.backup_menu_backup_subtitle),
        onClick = onBackup
    )
    Spacer(Modifier.height(12.dp))
    ActionCard(
        icon = { Icon(Icons.Filled.Download, null, tint = Color(0xFF22C55E), modifier = Modifier.size(28.dp)) },
        title = stringResource(R.string.backup_menu_restore_title),
        subtitle = stringResource(R.string.backup_menu_restore_subtitle),
        onClick = onRestore
    )
}

@Composable
private fun ShowCodeBody(
    state: BackupViewModel.UiState,
    onCopy: () -> Unit,
    onConfirmChange: (String) -> Unit,
    onSave: () -> Unit
) {
    Text(stringResource(R.string.backup_code_heading), style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(8.dp))

    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            state.recoveryGrouped ?: "",
            style = MaterialTheme.typography.titleLarge.copy(fontFamily = FontFamily.Monospace),
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth().padding(vertical = 18.dp, horizontal = 8.dp)
        )
    }
    Spacer(Modifier.height(8.dp))
    TextButton(onClick = onCopy) {
        Icon(Icons.Filled.ContentCopy, null, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text(stringResource(R.string.backup_code_copy))
    }

    Spacer(Modifier.height(4.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Filled.Warning, null, tint = Color(0xFFF59E0B), modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(
            stringResource(R.string.backup_code_explain),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }

    Spacer(Modifier.height(20.dp))
    OutlinedTextField(
        value = state.confirmInput,
        onValueChange = onConfirmChange,
        label = { Text(stringResource(R.string.backup_confirm_label)) },
        supportingText = { Text(stringResource(R.string.backup_confirm_hint)) },
        isError = state.confirmMismatch,
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, capitalization = KeyboardCapitalization.Characters),
        modifier = Modifier.fillMaxWidth()
    )
    if (state.confirmMismatch) {
        Text(
            stringResource(R.string.backup_confirm_mismatch),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall
        )
    }

    Spacer(Modifier.height(16.dp))
    Button(
        onClick = onSave,
        enabled = state.confirmInput.isNotBlank() && !state.working,
        modifier = Modifier.fillMaxWidth()
    ) {
        Icon(Icons.Filled.CloudUpload, null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(stringResource(R.string.backup_continue))
    }
}

@Composable
private fun EnterCodeBody(
    state: BackupViewModel.UiState,
    onCodeChange: (String) -> Unit,
    onRestore: () -> Unit
) {
    Text(
        stringResource(
            if (state.okcBackup) R.string.restore_code_heading_okc else R.string.restore_code_heading
        ),
        style = MaterialTheme.typography.titleMedium
    )
    Spacer(Modifier.height(6.dp))
    Text(
        stringResource(
            if (state.okcBackup) R.string.restore_code_explain_okc else R.string.restore_code_explain
        ),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(Modifier.height(16.dp))
    OutlinedTextField(
        value = state.restoreCode,
        onValueChange = onCodeChange,
        label = { Text(stringResource(R.string.restore_code_label)) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, capitalization = KeyboardCapitalization.Characters),
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(Modifier.height(16.dp))
    Button(
        onClick = onRestore,
        enabled = state.restoreCode.isNotBlank() && !state.working,
        modifier = Modifier.fillMaxWidth()
    ) {
        Icon(Icons.Filled.Download, null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(stringResource(R.string.restore_run))
    }
}

@Composable
private fun RestoreReportBody(
    report: MergeReport?,
    onDone: () -> Unit,
    onApplySettings: () -> Unit = {},
    onSkipSettings: () -> Unit = {}
) {
    Text(stringResource(R.string.restore_done_title), style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(12.dp))
    if (report == null) {
        Text(stringResource(R.string.restore_nothing))
    } else {
        ReportLine(stringResource(R.string.restore_added), report.added.size, Color(0xFF22C55E))
        ReportLine(stringResource(R.string.restore_upgraded), report.upgraded.size, Color(0xFF8B5CF6))
        ReportLine(stringResource(R.string.restore_updated), report.updated.size, Color(0xFF3B82F6))
        ReportLine(stringResource(R.string.restore_unchanged), report.unchanged.size, MaterialTheme.colorScheme.onSurfaceVariant)
        if (report.failed.isNotEmpty()) {
            ReportLine(stringResource(R.string.restore_failed), report.failed.size, MaterialTheme.colorScheme.error)
        }
        if (report.settingsApplied) {
            Spacer(Modifier.height(8.dp))
            Text(stringResource(R.string.restore_settings_applied),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        // 4.6.0 (item 17.9): the backup's proxy and key-server settings are
        // only applied when the user says so here.
        if (report.pendingSettings != null) {
            Spacer(Modifier.height(12.dp))
            Text(stringResource(R.string.restore_settings_ask),
                style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(onClick = onSkipSettings, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.restore_settings_skip))
                }
                Button(onClick = onApplySettings, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.restore_settings_apply))
                }
            }
        }
    }
    Spacer(Modifier.height(20.dp))
    Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.backup_done))
    }
}

@Composable
private fun ReportLine(label: String, count: Int, tint: Color) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text("$count", style = MaterialTheme.typography.titleMedium, color = tint)
    }
}

@Composable
private fun DoneBody(title: String, body: String, onDone: () -> Unit) {
    Text(title, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(8.dp))
    Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(20.dp))
    Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.backup_done))
    }
}

@Composable
private fun ActionCard(
    icon: @Composable () -> Unit,
    title: String,
    subtitle: String,
    onClick: () -> Unit
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .clickable(onClick = onClick)
                .padding(16.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            icon()
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Text(subtitle, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

/** Walk the ContextWrapper chain to the hosting MainActivity (matches
 *  ImportKeyScreen — a bare `as? MainActivity` fails inside dialogs/sheets). */
private tailrec fun Context.findMainActivityForBackup(): MainActivity? = when (this) {
    is MainActivity -> this
    is android.content.ContextWrapper -> baseContext.findMainActivityForBackup()
    else -> null
}
