// ExchangeScreen.kt
// PGPony Android
//
// Exchange tab UI with 3 sections: Show My Key (QR), Scan Key, Key Server.
// Matches iOS ExchangeView layout with segmented picker.

package com.pgpony.android.ui.exchange

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FastForward
import androidx.compose.material.icons.filled.FastRewind
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import com.pgpony.android.qr.QrAnimation
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.ui.components.ScreenTooltip
import com.pgpony.android.ui.keyring.ImportMethod
import com.pgpony.android.ui.keyring.ImportMethodBody
import com.pgpony.android.ui.keyring.KeyringUiState
import com.pgpony.android.ui.keyring.KeyringViewModel
import androidx.compose.ui.platform.LocalContext
import com.pgpony.android.ui.util.rememberHaptics

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExchangeScreen(viewModel: ExchangeViewModel, keyringViewModel: KeyringViewModel) {
    val state by viewModel.state.collectAsState()
    // 4.7.0 RC6 (item 64, #92): Scan Key and Key Server run the Import flow
    // (preview with fingerprints, then import) on the Keyring's view model,
    // the same one the Import sheet uses, so both pages import the same way.
    val importState by keyringViewModel.state.collectAsState()
    val clipboard = LocalClipboardManager.current
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    // Refresh keys whenever this screen enters composition. The ViewModel
    // is scoped to the activity / nav entry and survives tab switches, so
    // its init-time load can be stale by the time the user navigates here
    // after generating or importing keys on another screen.
    LaunchedEffect(Unit) { viewModel.loadKeys() }

    LaunchedEffect(state.errorMessage) {
        state.errorMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearError() }
    }
    LaunchedEffect(state.successMessage) {
        state.successMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearSuccess() }
    }
    // The import outcome, shown here since the Keyring screen is not.
    LaunchedEffect(importState.successMessage) {
        importState.successMessage?.let { snackbarHostState.showSnackbar(it); keyringViewModel.clearSuccess() }
    }
    LaunchedEffect(importState.duplicateImportResult) {
        importState.duplicateImportResult?.let {
            keyringViewModel.dismissDuplicateAlert()
            snackbarHostState.showSnackbar(context.getString(R.string.import_result_already_in_keyring))
        }
    }

    if (importState.showImportQRScanner) {
        com.pgpony.android.ui.scanner.QRScannerScreen(
            onScanned = { text -> keyringViewModel.onImportQRScanned(text) },
            onScannedWithTiming = { text, timing -> keyringViewModel.onImportQRScanned(text, timing) },
            onDismiss = { keyringViewModel.dismissImportQRScanner() }
        )
        return
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = { TopAppBar(title = { Text(stringResource(R.string.exchange_screen_title)) }) }
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding)
        ) {
            // Segmented tab bar
            TabRow(
                selectedTabIndex = state.section.ordinal,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
            ) {
                ExchangeSection.entries.filterNot {
                    it == ExchangeSection.KEY_SERVER &&
                        com.pgpony.android.network.OfflineMode.enabled
                }.forEach { section ->
                    Tab(
                        selected = state.section == section,
                        onClick = {
                            viewModel.setSection(section)
                            // A new tab starts without the last tab's preview.
                            when (section) {
                                ExchangeSection.SCAN_KEY -> keyringViewModel.setImportMethod(ImportMethod.QR_CODE)
                                ExchangeSection.KEY_SERVER -> keyringViewModel.setImportMethod(ImportMethod.KEY_SERVER)
                                ExchangeSection.SHOW_KEY -> Unit
                            }
                        },
                        text = {
                            Text(when (section) {
                                ExchangeSection.SHOW_KEY -> stringResource(R.string.exchange_section_show_key)
                                ExchangeSection.SCAN_KEY -> stringResource(R.string.exchange_section_scan_key)
                                ExchangeSection.KEY_SERVER -> stringResource(R.string.exchange_section_key_server)
                            })
                        }
                    )
                }
            }
            // Section content
            when (state.section) {
                ExchangeSection.SHOW_KEY -> ShowKeySection(state, viewModel, clipboard)
                ExchangeSection.SCAN_KEY -> ImportPane {
                    ImportMethodBody(importState, keyringViewModel, ImportMethod.QR_CODE)
                }
                ExchangeSection.KEY_SERVER ->
                    // RC1 offline switch: no keyserver section while offline.
                    if (com.pgpony.android.network.OfflineMode.enabled) {
                        ShowKeySection(state, viewModel, clipboard)
                    } else {
                        KeyLookupPane(importState, keyringViewModel)
                    }
            }
        }
    }
}

// ââ Show Key Section âââââââââââââââââââââââââââââââââââââââââââââââââââ

@Composable
private fun ShowKeySection(
    state: ExchangeUiState,
    viewModel: ExchangeViewModel,
    clipboard: androidx.compose.ui.platform.ClipboardManager
) {
    val haptics = rememberHaptics()
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(8.dp))
        if (state.myKeyPairs.isEmpty()) {
            Spacer(modifier = Modifier.height(48.dp))
            Text(stringResource(R.string.exchange_no_key_pairs_title), style = MaterialTheme.typography.titleMedium)
            Text(
                stringResource(R.string.exchange_no_keys),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            // Key selector
            if (state.myKeyPairs.size > 1) {
                Text(stringResource(R.string.exchange_select_key_label), style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.fillMaxWidth())
                Spacer(modifier = Modifier.height(4.dp))
                state.myKeyPairs.forEach { key ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = state.selectedKey?.fingerprint == key.fingerprint,
                            onClick = { viewModel.selectKey(key) }
                        )
                        // 4.7.0 (item 35): name, email and short fingerprint.
                        Text(key.pickerLabel, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                Spacer(modifier = Modifier.height(12.dp))
            }
            com.pgpony.android.ui.components.PublicKeyQrDisplay(
                store = state.qrStore, mode = state.qrMode, policy = state.qrPolicy,
                onModeChange = viewModel::setQrMode, onPolicyChange = viewModel::setQrPolicy, errorMessage = state.qrError,
                fingerprint = state.selectedKey?.formattedFingerprint)
            if (state.qrStore != null) {
                state.selectedKey?.let { key ->
                    Text(key.userName.ifBlank { key.userEmail.ifBlank { key.userID } }, style = MaterialTheme.typography.titleSmall)
                    // 4.7.0 (item 35): the email too, so the shown key is unmistakable.
                    if (key.userName.isNotBlank() && key.userEmail.isNotBlank()) {
                        Text(key.userEmail, style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Text(key.formattedFingerprint,
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Spacer(modifier = Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        state.armoredPublicKey?.let {
                            clipboard.setText(AnnotatedString(it))
                            haptics.tap()
                        }
                    }) {
                        Icon(Icons.Filled.ContentCopy, null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(stringResource(R.string.exchange_copy_key_button))
                    }
                    OutlinedButton(onClick = { viewModel.uploadToKeyServer() },
                        enabled = !state.isUploading) {
                        Icon(Icons.Filled.CloudUpload, null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(if (state.isUploading) stringResource(R.string.exchange_upload_button_in_progress) else stringResource(R.string.exchange_upload_button))
                    }
                }
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
    }
}

// ── Scan Key and Key Server (4.7.0 RC6, item 64) ───────────────────────

@Composable
private fun ImportPane(content: @Composable () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .imePadding(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        content()
        Spacer(modifier = Modifier.height(24.dp))
    }
}

/**
 * The Key Server tab: a key server or WKD lookup, or a GitHub user's keys
 * (item 42), each with the Import flow's preview.
 */
@Composable
private fun KeyLookupPane(importState: KeyringUiState, keyringViewModel: KeyringViewModel) {
    val method = if (importState.importMethod == ImportMethod.GITHUB) ImportMethod.GITHUB else ImportMethod.KEY_SERVER
    ImportPane {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = method == ImportMethod.KEY_SERVER,
                onClick = { if (method != ImportMethod.KEY_SERVER) keyringViewModel.setImportMethod(ImportMethod.KEY_SERVER) },
                leadingIcon = { Icon(Icons.Filled.Public, null, modifier = Modifier.size(FilterChipDefaults.IconSize)) },
                label = { Text(stringResource(R.string.import_method_key_server)) }
            )
            FilterChip(
                selected = method == ImportMethod.GITHUB,
                onClick = { if (method != ImportMethod.GITHUB) keyringViewModel.setImportMethod(ImportMethod.GITHUB) },
                leadingIcon = { Icon(Icons.Filled.Code, null, modifier = Modifier.size(FilterChipDefaults.IconSize)) },
                label = { Text(stringResource(R.string.import_method_github)) }
            )
        }
        ImportMethodBody(importState, keyringViewModel, method)
    }

    // First-visit tooltip (Phase 4)
    ScreenTooltip(
        tooltipKey = "exchange_qr",
        message = stringResource(R.string.exchange_tooltip_qr)
    )
}
