// KeyringScreen.kt
// PGPony Android
//
// Keyring tab UI — shows key list split into "My Keys" and "Contact Keys",
// with FAB menu for generate/import. Matches iOS KeyringListView layout.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.PointerEventPass
import kotlinx.coroutines.delay
import sh.calvin.reorderable.ReorderableItem
import sh.calvin.reorderable.rememberReorderableLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.LocalBillingService
import com.pgpony.android.billing.ProGuard
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.ui.components.KeyCard
import com.pgpony.android.ui.components.ScreenTooltip
import com.pgpony.android.ui.pro.ProFeature
import com.pgpony.android.ui.pro.ProGateSheet

// Auto-hiding keyring FAB: idle timeout before the "+" fades out, and the
// fade duration. Single tunable constants per the spec.
private const val FAB_IDLE_TIMEOUT_MS = 2500L
private const val FAB_FADE_MS = 250

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyringScreen(
    viewModel: KeyringViewModel,
    // Phase A4a: parent (MainActivity) supplies the navigation handler so
    // KeyringScreen stays NavController-agnostic. The previous "TODO: nav
    // to KeyDetailScreen" inline comments are replaced by this hook.
    onKeyClick: (fingerprint: String) -> Unit = {},
    // HW Phase 1: parent supplies the navigation handler to the hardware-
    // key NFC scan screen. Defaulted so existing call sites / previews
    // that don't pass it still compile.
    onScanCard: () -> Unit = {}
) {
    val state by viewModel.state.collectAsState()
    val billingService = LocalBillingService.current
    val billingState by billingService.state.collectAsState()
    var proGateFeature by remember { mutableStateOf<ProFeature?>(null) }

    // Snackbar for success/error
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(state.errorMessage) {
        state.errorMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearError() }
    }
    LaunchedEffect(state.successMessage) {
        state.successMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearSuccess() }
    }

    // ── Auto-hiding FAB ────────────────────────────────────────────────
    // The "+" FAB fades out after FAB_IDLE_TIMEOUT_MS of no interaction and
    // fades back in on any tap (handled by the content pointerInput below)
    // or list scroll (snapshotFlow inside PullToRefreshBox). fabExpanded is
    // hoisted so the auto-hide effect can keep the FAB visible while the add
    // menu is open. While fully hidden (alpha 0) the FAB is not composed, so
    // it neither handles its own click nor blocks the list underneath.
    var fabShown by remember { mutableStateOf(true) }
    var fabExpanded by remember { mutableStateOf(false) }
    var lastFabInteraction by remember { mutableLongStateOf(System.currentTimeMillis()) }
    val fabAlpha by animateFloatAsState(
        targetValue = if (fabShown) 1f else 0f,
        animationSpec = tween(FAB_FADE_MS),
        label = "keyringFabAlpha"
    )
    val bumpFab: () -> Unit = {
        lastFabInteraction = System.currentTimeMillis()
        fabShown = true
    }
    LaunchedEffect(lastFabInteraction, fabExpanded) {
        // Stay visible while the add menu is expanded; otherwise restart the
        // idle countdown on every interaction and fade out when it elapses.
        if (fabExpanded) return@LaunchedEffect
        fabShown = true
        delay(FAB_IDLE_TIMEOUT_MS)
        fabShown = false
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.keyring_title)) },
                actions = {
                    var sortMenuOpen by remember { mutableStateOf(false) }
                    IconButton(onClick = { sortMenuOpen = true }) {
                        Icon(Icons.Filled.Sort, stringResource(R.string.keyring_sort_cd))
                    }
                    DropdownMenu(
                        expanded = sortMenuOpen,
                        onDismissRequest = { sortMenuOpen = false }
                    ) {
                        SortMenuItem(
                            label = stringResource(R.string.keyring_sort_alpha_asc),
                            selected = state.sortMode == SortMode.ALPHA_ASC,
                            onClick = { viewModel.setSortMode(SortMode.ALPHA_ASC); sortMenuOpen = false }
                        )
                        SortMenuItem(
                            label = stringResource(R.string.keyring_sort_alpha_desc),
                            selected = state.sortMode == SortMode.ALPHA_DESC,
                            onClick = { viewModel.setSortMode(SortMode.ALPHA_DESC); sortMenuOpen = false }
                        )
                        SortMenuItem(
                            label = stringResource(R.string.keyring_sort_manual),
                            selected = state.sortMode == SortMode.MANUAL,
                            onClick = { viewModel.setSortMode(SortMode.MANUAL); sortMenuOpen = false }
                        )
                    }
                }
            )
        },
        floatingActionButton = {
            // Only compose the FAB while it has any opacity. At alpha 0 it is
            // absent from the tree, so it cannot catch touches or block the
            // list beneath it; a tap in that region falls through to the
            // content pointerInput, which reveals it.
            if (fabShown || fabAlpha > 0f) {
                Column(
                    horizontalAlignment = Alignment.End,
                    modifier = Modifier.alpha(fabAlpha)
                ) {
                    if (fabExpanded) {
                        SmallFloatingActionButton(
                            onClick = { fabExpanded = false; bumpFab(); onScanCard() },
                            containerColor = MaterialTheme.colorScheme.secondaryContainer
                        ) { Icon(Icons.Filled.Nfc, stringResource(R.string.keyring_fab_hardware_key)) }
                        Spacer(modifier = Modifier.height(8.dp))
                        SmallFloatingActionButton(
                            onClick = { fabExpanded = false; bumpFab(); viewModel.showImport() },
                            containerColor = MaterialTheme.colorScheme.secondaryContainer
                        ) { Icon(Icons.Filled.Download, "Import Key") }
                        Spacer(modifier = Modifier.height(8.dp))
                        SmallFloatingActionButton(
                            onClick = {
                                fabExpanded = false
                                bumpFab()
                                if (ProGuard.canGenerateKey(state.myKeys.size, billingState.isPro)) {
                                    viewModel.showGenerate()
                                } else {
                                    proGateFeature = ProFeature.UNLIMITED_KEYS
                                }
                            },
                            containerColor = MaterialTheme.colorScheme.secondaryContainer
                        ) { Icon(Icons.Filled.Add, "Generate Key") }
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                    FloatingActionButton(
                        onClick = {
                            // Capture visibility BEFORE bumping. A tap while
                            // hidden (mid fade-out) only reveals; add-key /
                            // menu toggle fires only when already visible.
                            val wasShown = fabShown
                            bumpFab()
                            if (wasShown) fabExpanded = !fabExpanded
                        },
                        containerColor = Color(0xFF8B5CF6)
                    ) {
                        Icon(
                            if (fabExpanded) Icons.Filled.Close else Icons.Filled.Add,
                            contentDescription = stringResource(R.string.keyring_add_key_cd)
                        )
                    }
                }
            }
        }
    ) { padding ->
        // Observe taps anywhere on the screen WITHOUT consuming them
        // (Initial pass), so a tap reveals the FAB but KeyCard clicks still
        // work. This also catches taps in the bottom-end corner when the
        // FAB is hidden/uncomposed, revealing it.
        Box(
            modifier = Modifier
                .fillMaxSize()
                .pointerInput(Unit) {
                    awaitPointerEventScope {
                        while (true) {
                            val event = awaitPointerEvent(PointerEventPass.Initial)
                            if (event.changes.any { it.pressed }) bumpFab()
                        }
                    }
                }
        ) {
        if (state.allKeys.isEmpty() && !state.isLoading) {
            // Empty state
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Filled.VpnKey,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text("No keys yet", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Tap + to generate or import a key",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            // Phase A8.5: PullToRefreshBox wraps the list so users can
            // swipe down to refresh. The padding from Scaffold is moved
            // to the Box (so the indicator floats at the top of the
            // content area, not under the system status bar), and the
            // LazyColumn no longer takes the padding directly.
            PullToRefreshBox(
                isRefreshing = state.isRefreshing,
                onRefresh = { viewModel.refresh() },
                modifier = Modifier.fillMaxSize().padding(padding)
            ) {
                val lazyListState = rememberLazyListState()
                // Reveal the FAB on any scroll (either direction): track
                // scroll-in-progress plus first-visible index/offset changes.
                LaunchedEffect(lazyListState) {
                    snapshotFlow {
                        Triple(
                            lazyListState.isScrollInProgress,
                            lazyListState.firstVisibleItemIndex,
                            lazyListState.firstVisibleItemScrollOffset
                        )
                    }.collect { bumpFab() }
                }
                val reorderableState = rememberReorderableLazyListState(lazyListState) { from, to ->
                    val f = from.key as? String
                    val t = to.key as? String
                    if (f != null && t != null) viewModel.moveManual(f, t)
                }
                val manualMode = state.sortMode == SortMode.MANUAL
                LazyColumn(
                    state = lazyListState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    if (state.myKeys.isNotEmpty()) {
                        item {
                            Text(
                                stringResource(R.string.keyring_section_my_keys),
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(top = 8.dp, bottom = 4.dp)
                            )
                        }
                        items(state.myKeys, key = { it.id }) { key ->
                            ReorderableItem(reorderableState, key = key.id) { _ ->
                                KeyCard(
                                    key = key,
                                    onClick = { onKeyClick(key.fingerprint) },
                                    trailing = if (manualMode) {
                                        {
                                            Icon(
                                                Icons.Filled.DragHandle,
                                                contentDescription = stringResource(R.string.keyring_drag_handle_cd),
                                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                                modifier = Modifier.draggableHandle()
                                            )
                                        }
                                    } else null
                                )
                            }
                        }
                    }
                    if (state.contactKeys.isNotEmpty()) {
                        item {
                            Text(
                                stringResource(R.string.keyring_section_contact_keys),
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.secondary,
                                modifier = Modifier.padding(top = 16.dp, bottom = 4.dp)
                            )
                        }
                        items(state.contactKeys, key = { it.id }) { key ->
                            ReorderableItem(reorderableState, key = key.id) { _ ->
                                KeyCard(
                                    key = key,
                                    onClick = { onKeyClick(key.fingerprint) },
                                    trailing = if (manualMode) {
                                        {
                                            Icon(
                                                Icons.Filled.DragHandle,
                                                contentDescription = stringResource(R.string.keyring_drag_handle_cd),
                                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                                modifier = Modifier.draggableHandle()
                                            )
                                        }
                                    } else null
                                )
                            }
                        }
                    }
                }
            }
        }
        }
    }

    // ── Generate Sheet ─────────────────────────────────────────────────
    if (state.showGenerateSheet) {
        GenerateKeySheet(state = state, viewModel = viewModel)
    }

    // ── Import Sheet ───────────────────────────────────────────────────
    // Phase A10a — replaced the inline single-method ImportKeySheet
    // with ImportKeyScreen, which surfaces all four iOS methods
    // (Paste / File / QR / Key Server) and an inline preview card.
    if (state.showImportSheet) {
        ImportKeyScreen(state = state, viewModel = viewModel)
    }

    // ── Delete Confirm ─────────────────────────────────────────────────
    state.keyToDelete?.let { key ->
        AlertDialog(
            onDismissRequest = { viewModel.cancelDelete() },
            title = { Text(stringResource(R.string.keyring_delete_dialog_title)) },
            text = {
                Text(stringResource(R.string.keyring_delete_dialog_body_format, key.userName.ifBlank { key.userEmail }, key.shortFingerprint))
            },
            confirmButton = {
                TextButton(
                    onClick = { viewModel.deleteKey() },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                ) { Text(stringResource(R.string.keyring_delete_dialog_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.cancelDelete() }) { Text(stringResource(R.string.common_button_cancel)) }
            }
        )
    }

    // ── Pro Gate Sheet ──────────────────────────────────────────────────
    proGateFeature?.let { feature ->
        ProGateSheet(
            feature = feature,
            billingService = billingService,
            onDismiss = { proGateFeature = null }
        )
    }

    // ── First-visit tooltip (Phase 4) ───────────────────────────────────
    ScreenTooltip(
        tooltipKey = "keyring_fab",
        message = stringResource(R.string.keyring_tooltip_fab),
        enabled = state.allKeys.isEmpty()
    )
}

// ── Generate Key Bottom Sheet ──────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun GenerateKeySheet(state: KeyringUiState, viewModel: KeyringViewModel) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(
        onDismissRequest = { viewModel.dismissGenerate() },
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
                .fillMaxWidth()
        ) {
            Text(stringResource(R.string.keyring_generate_title), style = MaterialTheme.typography.headlineSmall)
            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = state.generateName,
                onValueChange = { viewModel.updateGenerateName(it) },
                label = { Text(stringResource(R.string.keyring_generate_name_label)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = state.generateEmail,
                onValueChange = { viewModel.updateGenerateEmail(it) },
                label = { Text(stringResource(R.string.keyring_generate_email_label)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(12.dp))

            // Algorithm picker
            Text(stringResource(R.string.keyring_generate_algorithm_label), style = MaterialTheme.typography.labelMedium)
            Spacer(modifier = Modifier.height(4.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                KeyAlgorithm.generatable.forEach { algo ->
                    FilterChip(
                        selected = state.generateAlgorithm == algo,
                        onClick = { viewModel.updateGenerateAlgorithm(algo) },
                        label = { Text(algo.shortName) }
                    )
                }
            }
            Spacer(modifier = Modifier.height(6.dp))
            // V6-6: explain the selected algorithm so the v4-vs-v6 choice is
            // legible at generation time — the v6 option produces an RFC 9580
            // key (signing subkey + hardware-key support); v4 stays maximally
            // compatible with older OpenPGP software.
            Text(
                text = when {
                    state.generateAlgorithm.isV6 ->
                        stringResource(R.string.keyring_generate_algorithm_caption_v6)
                    state.generateAlgorithm == KeyAlgorithm.ED25519_CV25519 ->
                        stringResource(R.string.keyring_generate_algorithm_caption_ed25519)
                    else ->
                        stringResource(R.string.keyring_generate_algorithm_caption_rsa)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(12.dp))

            // Expiration picker
            Text(stringResource(R.string.keyring_generate_expiration_label), style = MaterialTheme.typography.labelMedium)
            Spacer(modifier = Modifier.height(4.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ExpirationOption.entries.forEach { exp ->
                    // Phase A13: enum displayName is still on the enum for
                    // compatibility, but the UI label resolves through
                    // string resources for localization.
                    val expLabel = when (exp) {
                        ExpirationOption.ONE_YEAR -> stringResource(R.string.expiration_one_year)
                        ExpirationOption.TWO_YEARS -> stringResource(R.string.expiration_two_years)
                        ExpirationOption.FIVE_YEARS -> stringResource(R.string.expiration_five_years)
                        ExpirationOption.NEVER -> stringResource(R.string.expiration_never)
                    }
                    FilterChip(
                        selected = state.generateExpiration == exp,
                        onClick = { viewModel.updateGenerateExpiration(exp) },
                        label = { Text(expLabel) }
                    )
                }
            }
            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = state.generatePassphrase,
                onValueChange = { viewModel.updateGeneratePassphrase(it) },
                label = { Text(stringResource(R.string.keyring_generate_passphrase_label)) },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = state.generateConfirmPassphrase,
                onValueChange = { viewModel.updateGenerateConfirmPassphrase(it) },
                label = { Text(stringResource(R.string.keyring_generate_passphrase_confirm_label)) },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(16.dp))

            state.errorMessage?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                Spacer(modifier = Modifier.height(8.dp))
            }

            Button(
                onClick = { viewModel.generateKey() },
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.isGenerating
            ) {
                if (state.isGenerating) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(if (state.isGenerating) stringResource(R.string.keyring_generate_button_in_progress) else stringResource(R.string.keyring_generate_button))
            }
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

// ── Import Key Bottom Sheet ────────────────────────────────────────────

/**
 * Pre-A10a single-method paste-only import sheet. Replaced by
 * ImportKeyScreen in A10a (4-method picker + preview). Kept private
 * and suppressed for additive integrity — no external callers
 * remain.
 */
@Suppress("unused")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ImportKeySheet(state: KeyringUiState, viewModel: KeyringViewModel) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(
        onDismissRequest = { viewModel.dismissImport() },
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
                .fillMaxWidth()
        ) {
            Text("Import Key", style = MaterialTheme.typography.headlineSmall)
            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = state.importArmoredText,
                onValueChange = { viewModel.updateImportText(it) },
                label = { Text("Paste armored PGP key") },
                modifier = Modifier.fillMaxWidth().heightIn(min = 150.dp),
                maxLines = 15
            )
            Spacer(modifier = Modifier.height(12.dp))

            state.errorMessage?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                Spacer(modifier = Modifier.height(8.dp))
            }

            Button(
                onClick = { viewModel.importKey() },
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.isImporting
            ) {
                if (state.isImporting) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(if (state.isImporting) "Importing..." else "Import Key")
            }
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
private fun SortMenuItem(
    label: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    DropdownMenuItem(
        text = { Text(label) },
        onClick = onClick,
        trailingIcon = {
            if (selected) {
                Icon(Icons.Filled.Check, contentDescription = null)
            }
        }
    )
}
