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
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
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
import com.pgpony.android.ui.util.rememberHaptics

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExchangeScreen(viewModel: ExchangeViewModel) {
    val state by viewModel.state.collectAsState()
    val clipboard = LocalClipboardManager.current
    val snackbarHostState = remember { SnackbarHostState() }

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
                ExchangeSection.entries.forEach { section ->
                    Tab(
                        selected = state.section == section,
                        onClick = { viewModel.setSection(section) },
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
                ExchangeSection.SCAN_KEY -> ScanKeySection(state, viewModel)
                ExchangeSection.KEY_SERVER -> KeyServerSection(state, viewModel)
            }
        }
    }
    // Import confirm dialog
    if (state.showImportConfirm) {
        AlertDialog(
            onDismissRequest = { viewModel.dismissImportConfirm() },
            title = { Text(stringResource(R.string.exchange_import_dialog_title)) },
            text = { Text(stringResource(R.string.exchange_import_dialog_body)) },
            confirmButton = {
                TextButton(onClick = { viewModel.importScannedKey() }) { Text("Import") }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissImportConfirm() }) { Text(stringResource(R.string.common_button_cancel)) }
            }
        )
    }
}

// ── Show Key Section ───────────────────────────────────────────────────

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
            Text("No key pairs", style = MaterialTheme.typography.titleMedium)
            Text(
                stringResource(R.string.exchange_no_keys),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            // Key selector
            if (state.myKeyPairs.size > 1) {
                Text("Select Key", style = MaterialTheme.typography.labelMedium,
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
                        Text("${key.userName} (${key.shortFingerprint})",
                            style = MaterialTheme.typography.bodyMedium)
                    }
                }
                Spacer(modifier = Modifier.height(12.dp))
            }
            // QR code
            state.qrBitmap?.let { bitmap ->
                Card(
                    modifier = Modifier.size(280.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Box(
                        modifier = Modifier.fillMaxSize().padding(16.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Image(
                            bitmap = bitmap.asImageBitmap(),
                            contentDescription = stringResource(R.string.exchange_qr_cd),
                            modifier = Modifier.fillMaxSize()
                        )
                    }
                }
                Spacer(modifier = Modifier.height(12.dp))
                state.selectedKey?.let { key ->
                    Text(key.userName, style = MaterialTheme.typography.titleSmall)
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

// ── Scan Key Section ───────────────────────────────────────────────────

@Composable
private fun ScanKeySection(state: ExchangeUiState, viewModel: ExchangeViewModel) {
    var showScanner by remember { mutableStateOf(false) }

    if (showScanner) {
        com.pgpony.android.ui.scanner.QRScannerScreen(
            onScanned = { text ->
                showScanner = false
                viewModel.onQRScanned(text)
            },
            onDismiss = { showScanner = false }
        )
    } else {
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                Icons.Filled.QrCodeScanner,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.7f)
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text("Scan QR Code", style = MaterialTheme.typography.titleMedium)
            Text(
                "Scan a PGP public key QR code to import it",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(24.dp))
            Button(onClick = { showScanner = true }) {
                Icon(Icons.Filled.CameraAlt, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.exchange_scan_button))
            }
        }
    }
}

// ── Key Server Section ─────────────────────────────────────────────────

@Composable
private fun KeyServerSection(state: ExchangeUiState, viewModel: ExchangeViewModel) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
    ) {
        Spacer(modifier = Modifier.height(8.dp))
        Text("Search keys.openpgp.org", style = MaterialTheme.typography.labelLarge)
        Spacer(modifier = Modifier.height(4.dp))
        OutlinedTextField(
            value = state.searchQuery,
            onValueChange = { viewModel.updateSearchQuery(it) },
            label = { Text(stringResource(R.string.exchange_keyserver_query_label)) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            trailingIcon = {
                if (state.isSearching) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    IconButton(onClick = { viewModel.searchKeyServer() }) {
                        Icon(Icons.Filled.Search, stringResource(R.string.exchange_keyserver_search_cd))
                    }
                }
            }
        )
        Spacer(modifier = Modifier.height(12.dp))
        // Search result
        state.searchResult?.let { armored ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                )
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Key Found", style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.primary)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        armored.take(120) + "...",
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        maxLines = 4
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = { viewModel.importSearchResult() },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Filled.Download, null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(stringResource(R.string.exchange_keyserver_import_button))
                    }
                }
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
    }

    // ── First-visit tooltip (Phase 4) ───────────────────────────────────
    ScreenTooltip(
        tooltipKey = "exchange_qr",
        message = stringResource(R.string.exchange_tooltip_qr)
    )
}
