// ImportKeyScreen.kt
// PGPony Android — Phase A10a
//
// 4-method import sheet matching iOS ImportKeyView. Replaces the
// pre-A10a paste-only ImportKeySheet inline composable that lived
// inside KeyringScreen.kt.
//
// Layout (top to bottom):
//   1. Title row ("Import Key" + Cancel)
//   2. Segmented method picker — Paste / File / QR / Key Server
//   3. Method-specific section:
//        Paste      → multiline TextField + "Preview" button
//        File       → "Choose Key File" button → ACTION_OPEN_DOCUMENT
//        QR Code    → "Scan QR Code" button → QRScannerScreen overlay
//        Key Server → search field + "Search" button (WKD → Hagrid)
//   4. Error banner (if any)
//   5. Preview card (only if importPreview != null):
//        owner / fingerprint / algorithm / Pair-vs-Public-Only
//        "Found via <source>" badge if importLookupSource != null
//        "From file: <name>" badge if importSourceFilename != null
//        Duplicate warning if isDuplicate (with upgrade-promise text
//        if willUpgradeToKeyPair)
//        [Cancel] [Import]
//
// QR scanning uses the existing ui/scanner/QRScannerScreen, displayed
// full-screen above the import sheet when showImportQRScanner is true.
//
// Phase A10a Fix1 — File method now routes through
// MainActivity.startDocumentPicker() instead of
// rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()).
// Same FragmentActivity 16-bit requestCode crash that A9 Fix1 hit
// with permission requests, but this time from startActivityForResult.
// The Compose launcher comment in this file ("Doesn't hit the
// FragmentActivity 16-bit limit because it's a startActivityForResult
// path, not a requestPermissions path") was wrong — FragmentActivity
// applies the 16-bit check to both. See MainActivity Phase A10a Fix1
// notes for the full story.
//
// Phase A10a Fix2 — initial Fix1 made the Browse button a no-op.
// `LocalContext.current` inside a ModalBottomSheet is wrapped (the
// sheet renders inside a Dialog window with its own context), so
// `context as? MainActivity` returned null and the `activity?.…`
// safe-call dropped on the floor. ContactsScreen worked because it's
// hosted directly in the NavHost without a dialog wrapper. Fix:
// walk up ContextWrapper.baseContext via findMainActivity() until
// we hit the real activity.

package com.pgpony.android.ui.keyring

import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.MainActivity
import com.pgpony.android.network.KeyLookupSource
import com.pgpony.android.ui.scanner.QRScannerScreen

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportKeyScreen(state: KeyringUiState, viewModel: KeyringViewModel) {
    // QR scanner is rendered as a full-screen overlay above the sheet;
    // when active, the sheet is hidden behind it so the scanner has
    // the full viewport.
    if (state.showImportQRScanner) {
        QRScannerScreen(
            onScanned = { text -> viewModel.onImportQRScanned(text) },
            onDismiss = { viewModel.dismissImportQRScanner() }
        )
        return
    }

    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = { viewModel.dismissImport() },
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 8.dp)
                .imePadding()
                .navigationBarsPadding(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ── Header ────────────────────────────────────────────────
            Text(
                stringResource(R.string.import_screen_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold
            )

            // ── Method picker (segmented) ─────────────────────────────
            //
            // Material 3's SingleChoiceSegmentedButtonRow gives the
            // closest analogue to iOS's .pickerStyle(.segmented).
            // Switching method clears any in-flight preview because
            // the new method may have a totally different data source.
            ImportMethodPicker(
                selected = state.importMethod,
                onSelect = { viewModel.setImportMethod(it) }
            )

            // ── Method-specific section ───────────────────────────────
            when (state.importMethod) {
                ImportMethod.PASTE      -> PasteSection(state, viewModel)
                ImportMethod.FILE       -> FileSection(state, viewModel)
                ImportMethod.QR_CODE    -> QrSection(state, viewModel)
                ImportMethod.KEY_SERVER -> KeyServerSection(state, viewModel)
            }

            // ── Error banner ──────────────────────────────────────────
            state.errorMessage?.let { msg ->
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        msg,
                        modifier = Modifier.padding(12.dp),
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }

            // ── Preview + Import buttons ──────────────────────────────
            state.importPreview?.let { preview ->
                ImportPreviewCard(
                    preview = preview,
                    lookupSource = state.importLookupSource,
                    sourceFilename = state.importSourceFilename
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { viewModel.clearImportPreview() },
                        modifier = Modifier.weight(1f),
                        enabled = !state.isImporting
                    ) {
                        Text(stringResource(R.string.common_button_cancel))
                    }
                    Button(
                        onClick = { viewModel.confirmImportPreview() },
                        modifier = Modifier.weight(1f),
                        // Block re-commit during the in-flight import,
                        // and disable when the existing key isn't a
                        // candidate for upgrade — confirmImportPreview
                        // would throw AlreadyExists anyway.
                        // HW Phase 1.5 — a card-pairing duplicate is also
                        // a valid commit (folds the public key onto the
                        // card record), so keep the button live for it.
                        enabled = !state.isImporting
                                && (!preview.isDuplicate
                                    || preview.willUpgradeToKeyPair
                                    || preview.willPairWithCard)
                    ) {
                        if (state.isImporting) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Text(
                            when {
                                preview.willPairWithCard -> stringResource(R.string.import_button_pair_card)
                                preview.willUpgradeToKeyPair -> stringResource(R.string.import_button_upgrade_key)
                                else -> stringResource(R.string.import_button_import_key)
                            }
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

// ── Method picker ──────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ImportMethodPicker(
    selected: ImportMethod,
    onSelect: (ImportMethod) -> Unit
) {
    val methods = ImportMethod.entries
    SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
        methods.forEachIndexed { index, method ->
            SegmentedButton(
                selected = selected == method,
                onClick = { onSelect(method) },
                shape = SegmentedButtonDefaults.itemShape(
                    index = index,
                    count = methods.size
                ),
                icon = {
                    Icon(
                        imageVector = iconForMethod(method),
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                },
                label = {
                    Text(
                        text = when (method) {
                            ImportMethod.PASTE -> stringResource(R.string.import_method_paste)
                            ImportMethod.FILE -> stringResource(R.string.import_method_file)
                            ImportMethod.QR_CODE -> stringResource(R.string.import_method_qr_code)
                            ImportMethod.KEY_SERVER -> stringResource(R.string.import_method_key_server)
                        },
                        style = MaterialTheme.typography.labelMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            )
        }
    }
}

private fun iconForMethod(method: ImportMethod) = when (method) {
    ImportMethod.PASTE      -> Icons.Filled.ContentPaste
    ImportMethod.FILE       -> Icons.Filled.FolderOpen
    ImportMethod.QR_CODE    -> Icons.Filled.QrCodeScanner
    ImportMethod.KEY_SERVER -> Icons.Filled.Public
}

// ── Per-method sections ────────────────────────────────────────────────

@Composable
private fun PasteSection(state: KeyringUiState, viewModel: KeyringViewModel) {
    val clipboard = LocalClipboardManager.current
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = state.importArmoredText,
            onValueChange = { viewModel.updateImportText(it) },
            label = { Text(stringResource(R.string.import_paste_label)) },
            placeholder = { Text(stringResource(R.string.import_paste_placeholder)) },
            modifier = Modifier.fillMaxWidth().heightIn(min = 140.dp),
            maxLines = 12,
            textStyle = MaterialTheme.typography.bodySmall
                .copy(fontFamily = FontFamily.Monospace)
        )
        // Phase AU-2 — prominent "Paste from Clipboard" action that fills the
        // field above from the system clipboard, matching the deliberate
        // paste affordance on the iOS Import screen. Filled-tonal so it reads
        // as the primary action here; Preview stays a secondary OutlinedButton.
        FilledTonalButton(
            onClick = {
                clipboard.getText()?.text?.let { viewModel.updateImportText(it) }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Filled.ContentPaste, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                stringResource(R.string.import_paste_from_clipboard),
                fontWeight = FontWeight.SemiBold
            )
        }
        OutlinedButton(
            onClick = { viewModel.previewArmoredKey(state.importArmoredText) },
            modifier = Modifier.fillMaxWidth(),
            enabled = !state.isPreviewing && state.importArmoredText.isNotBlank()
        ) {
            if (state.isPreviewing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp
                )
                Spacer(modifier = Modifier.width(8.dp))
            }
            Text(stringResource(R.string.import_preview_button))
        }
    }
}

@Composable
private fun FileSection(state: KeyringUiState, viewModel: KeyringViewModel) {
    val context = LocalContext.current
    // Phase A10a Fix1 — file picker now routes through MainActivity
    // because Compose's rememberLauncherForActivityResult is broken on
    // FragmentActivity-hosted activities (request codes generated by
    // the registry exceed FragmentActivity's 16-bit check —
    // checkForValidRequestCode applies to startActivityForResult, not
    // just requestPermissions, contrary to the original A9 Fix1
    // comment). The helper calls ActivityCompat.startActivityForResult
    // with a known small request code and dispatches the result via
    // onActivityResult.
    //
    // Phase A10a Fix2 — must unwrap ContextWrapper chain. The cast
    // `context as? MainActivity` returns null inside a
    // ModalBottomSheet because the sheet's dialog wraps the context.
    // findMainActivity() walks up baseContext until it finds the
    // real activity, matching the standard Compose idiom.
    val activity = context.findMainActivity()

    val onPickFile: () -> Unit = {
        activity?.startDocumentPicker(
            arrayOf(
                "text/plain",
                "application/pgp-keys",
                "application/octet-stream",
                "*/*"
            )
        ) { uri ->
            if (uri != null) {
                val filename = uri.lastPathSegment?.substringAfterLast('/')
                    ?: uri.toString().substringAfterLast('/')
                val text = try {
                    context.contentResolver.openInputStream(uri)?.use {
                        it.readBytes().toString(Charsets.UTF_8)
                    } ?: ""
                } catch (e: Exception) {
                    ""
                }
                if (text.isNotBlank()) {
                    viewModel.previewArmoredKey(text, sourceFilename = filename)
                } else {
                    // The error message routing is via previewArmoredKey
                    // when text is blank — call it with the empty string
                    // to consistently set "No key data" via that path.
                    viewModel.previewArmoredKey("")
                }
            }
            // uri == null means the user cancelled or there was no
            // DocumentsUI activity. Cancel is silent (matches iOS);
            // ActivityNotFoundException is rare enough that we don't
            // surface a banner.
        }
    }

    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.FolderOpen,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.import_file_choose_title),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        stringResource(R.string.import_file_choose_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
            // OpenDocument with multiple MIME types — armored PGP
            // files use text/plain in practice; application/pgp-keys
            // is the IANA-registered type some tools set. Wildcard
            // */* catches everything else (e.g. .key from older
            // GnuPG installs that didn't register a MIME).
            Button(
                onClick = onPickFile,
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.isPreviewing
            ) {
                Icon(Icons.Filled.UploadFile, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.import_file_browse_button))
            }
        }
    }
}

@Composable
private fun QrSection(state: KeyringUiState, viewModel: KeyringViewModel) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.QrCodeScanner,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.import_qr_title),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        stringResource(R.string.import_qr_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = { viewModel.showImportQRScanner() },
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.isPreviewing
            ) {
                Icon(Icons.Filled.PhotoCamera, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.import_qr_open_camera_button))
            }
        }
    }
}

@Composable
private fun KeyServerSection(state: KeyringUiState, viewModel: KeyringViewModel) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = state.importSearchQuery,
            onValueChange = { viewModel.updateImportSearchQuery(it) },
            label = { Text(stringResource(R.string.import_keyserver_query_label)) },
            placeholder = { Text(stringResource(R.string.import_keyserver_query_placeholder)) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            leadingIcon = {
                Icon(Icons.Filled.Search, null, modifier = Modifier.size(18.dp))
            },
            trailingIcon = {
                if (state.isSearchingKeyServer) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp).padding(end = 4.dp),
                        strokeWidth = 2.dp
                    )
                }
            }
        )
        Button(
            onClick = { viewModel.searchKeyServerForImport() },
            modifier = Modifier.fillMaxWidth(),
            enabled = !state.isSearchingKeyServer
                    && !state.isPreviewing
                    && state.importSearchQuery.isNotBlank()
        ) {
            Icon(Icons.Filled.Search, null, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text(if (state.isSearchingKeyServer) stringResource(R.string.import_keyserver_search_button_in_progress) else stringResource(R.string.import_keyserver_search_button))
        }
        Text(
            stringResource(R.string.import_keyserver_help),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

// ── Preview card ───────────────────────────────────────────────────────

@Composable
private fun ImportPreviewCard(
    preview: com.pgpony.android.data.repository.ImportPreview,
    lookupSource: KeyLookupSource?,
    sourceFilename: String?
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Header — Key Pair vs Public Only, with key icon tinted
            // to match (indigo for pair, gray for public-only).
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.VpnKey,
                    contentDescription = null,
                    tint = if (preview.hasPrivateKey) Color(0xFF8B5CF6)
                           else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (preview.hasPrivateKey) stringResource(R.string.import_preview_type_key_pair)
                           else stringResource(R.string.import_preview_type_public_only),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = if (preview.hasPrivateKey) Color(0xFF8B5CF6)
                            else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            HorizontalDivider()

            DetailRow(stringResource(R.string.import_preview_detail_user_label), preview.userId.ifBlank { stringResource(R.string.import_preview_detail_user_empty) })
            DetailRow(stringResource(R.string.import_preview_detail_fingerprint_label), preview.shortFingerprint, mono = true)
            DetailRow(stringResource(R.string.import_preview_detail_algorithm_label), preview.algorithmShortName)

            // ── Source badges ─────────────────────────────────────────
            //
            // KEY_SERVER imports surface the lookup source with a
            // green/blue badge — WKD authoritative because the
            // recipient's own domain hosted it; Hagrid less so.
            //
            // FILE imports surface the source filename so the user
            // can verify they grabbed the right file. .asc files
            // commonly have similar names (alice_pub.asc,
            // alice_priv.asc — easy to mix up).
            lookupSource?.let { src ->
                HorizontalDivider()
                LookupSourceBadge(src)
            }
            sourceFilename?.let { name ->
                HorizontalDivider()
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Description,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = stringResource(R.string.import_preview_source_file_format, name),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            // ── Duplicate warnings ────────────────────────────────────
            if (preview.isDuplicate) {
                HorizontalDivider()
                DuplicateBanner(
                    willUpgrade = preview.willUpgradeToKeyPair,
                    willPairWithCard = preview.willPairWithCard
                )
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String, mono: Boolean = false) {
    Row(verticalAlignment = Alignment.Top) {
        Text(
            "$label:",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(96.dp)
        )
        Text(
            value,
            style = if (mono) MaterialTheme.typography.bodySmall
                .copy(fontFamily = FontFamily.Monospace)
                    else MaterialTheme.typography.bodySmall,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun LookupSourceBadge(source: KeyLookupSource) {
    val (tint, label) = when (source) {
        KeyLookupSource.WKD_ADVANCED -> Color(0xFF22C55E) to stringResource(R.string.import_preview_source_wkd_advanced)
        KeyLookupSource.WKD_DIRECT   -> Color(0xFF22C55E) to stringResource(R.string.import_preview_source_wkd_direct)
        KeyLookupSource.HAGRID       -> Color(0xFF3B82F6) to stringResource(R.string.import_preview_source_hagrid)
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            Icons.Filled.Public,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(14.dp)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = tint
        )
    }
}

@Composable
private fun DuplicateBanner(willUpgrade: Boolean, willPairWithCard: Boolean = false) {
    val (tint, icon, text) = when {
        willPairWithCard -> Triple(
            Color(0xFF22C55E),
            Icons.Filled.Nfc,
            stringResource(R.string.import_duplicate_will_pair_card)
        )
        willUpgrade -> Triple(
            Color(0xFF22C55E),
            Icons.Filled.Upgrade,
            stringResource(R.string.import_duplicate_will_upgrade)
        )
        else -> Triple(
            Color(0xFFEAB308),
            Icons.Filled.Warning,
            stringResource(R.string.import_duplicate_no_change)
        )
    }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .background(tint.copy(alpha = 0.1f), RoundedCornerShape(8.dp))
            .padding(8.dp)
    ) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(16.dp))
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text,
            style = MaterialTheme.typography.bodySmall,
            color = tint
        )
    }
}

// ── Phase A10a Fix2: ContextWrapper unwrapper ───────────────────────────
//
// LocalContext.current inside a ModalBottomSheet returns a wrapped
// context (the sheet uses a Dialog window with its own context theme
// wrapper), so a direct `as? MainActivity` cast fails and the activity
// helper call drops on the floor. Walk up baseContext until we hit
// the real activity, or null if we don't find one (shouldn't happen
// in production — the file picker would just be a no-op rather than
// a crash).
private tailrec fun Context.findMainActivity(): MainActivity? = when (this) {
    is MainActivity -> this
    is ContextWrapper -> baseContext.findMainActivity()
    else -> null
}
