// KeyringScreen.kt
// PGPony Android
//
// Keyring tab UI — shows key list split into "My Keys" and "Contact Keys",
// with FAB menu for generate/import. Matches iOS KeyringListView layout.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.PointerEventPass
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import sh.calvin.reorderable.ReorderableItem
import sh.calvin.reorderable.ReorderableLazyListState
import sh.calvin.reorderable.rememberReorderableLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Sort
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.PGPKeyEntity
import androidx.compose.ui.unit.Dp
import com.pgpony.android.ui.components.KeyCard
import com.pgpony.android.ui.components.ScreenTooltip

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
    onScanCard: () -> Unit = {},
    onOpenRecycleBin: () -> Unit = {}
) {
    val state by viewModel.state.collectAsState()

    // CertainBot (RC4): a delete or trust change made on the Key Detail
    // screen left this list stale until an app reload. The Keyring leaves
    // composition when Key Detail is pushed, so re-querying on each entry
    // (including the pop back) reflects those changes at once.
    LaunchedEffect(Unit) { viewModel.reloadSilently() }

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
                        Icon(Icons.AutoMirrored.Filled.Sort, stringResource(R.string.keyring_sort_cd))
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
                    var moreMenuOpen by remember { mutableStateOf(false) }
                    IconButton(onClick = { moreMenuOpen = true }) {
                        Icon(Icons.Filled.MoreVert, stringResource(R.string.keyring_more_cd))
                    }
                    DropdownMenu(
                        expanded = moreMenuOpen,
                        onDismissRequest = { moreMenuOpen = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.settings_recycle_bin_title)) },
                            onClick = { moreMenuOpen = false; onOpenRecycleBin() }
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
                                viewModel.showGenerate()
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
                // Colours read here rather than inside keySection: a
                // LazyListScope builder is not a composable and cannot
                // reach MaterialTheme.
                val mineColor = MaterialTheme.colorScheme.primary
                val contactColor = MaterialTheme.colorScheme.secondary
                val publicColor = MaterialTheme.colorScheme.tertiary
                LazyColumn(
                    state = lazyListState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // 4.2.0 RC2 workstream F — one-time, dismissible hint for
                    // LibrePGP composite keys generated before the wire
                    // fixes. Sits above My Keys since it always concerns
                    // the user's own key pairs.
                    if (state.regenHintKeys.isNotEmpty()) {
                        item(key = "regen_hint_banner") {
                            RegenHintBanner(
                                count = state.regenHintKeys.size,
                                onDismiss = {
                                    state.regenHintKeys.forEach { viewModel.dismissRegenHint(it.fingerprint) }
                                }
                            )
                        }
                    }
                    // 4.1.0 Phase 12b — three sections through one builder.
                    // The first two were already identical apart from the
                    // list, the heading and the colour; a third copy is not
                    // how you want to discover that.
                    keySection(
                        keys = state.myKeys,
                        titleRes = R.string.keyring_section_my_keys,
                        titleColor = mineColor,
                        topPadding = 8.dp,
                        reorderableState = reorderableState,
                        manualMode = manualMode,
                        onKeyClick = onKeyClick,
                    )
                    keySection(
                        keys = state.contactKeys,
                        titleRes = R.string.keyring_section_contacts,
                        titleColor = contactColor,
                        topPadding = 16.dp,
                        reorderableState = reorderableState,
                        manualMode = manualMode,
                        onKeyClick = onKeyClick,
                    )
                    keySection(
                        keys = state.publicKeys,
                        titleRes = R.string.keyring_section_public_keys,
                        titleColor = publicColor,
                        topPadding = 16.dp,
                        reorderableState = reorderableState,
                        manualMode = manualMode,
                        onKeyClick = onKeyClick,
                    )
                }
            }
        }
        }
    }

    // ── Generate Sheet ─────────────────────────────────────────────────
    if (state.showGenerateSheet) {
        GenerateKeySheet(state = state, viewModel = viewModel)
    }

    // ── Post-generation publish prompt (4.0.0 Phase 5a, §6 Q6) ─────────
    // After a key is generated (in-app OR onboarding — both route through
    // KeyringViewModel.generateKey), offer to publish it: the same
    // multi-server PublishSheet with both servers pre-checked. Skippable
    // (dismiss). iOS parity — the verified-badge / board-trust funnel.
    state.pendingPublishFingerprint?.let { fp ->
        com.pgpony.android.ui.keydetail.PublishSheet(
            fingerprint = fp,
            onDismiss = { viewModel.dismissPublishPrompt() }
        )
    }

    // ── Import Sheet ───────────────────────────────────────────────────
    // Phase A10a — replaced the inline single-method ImportKeySheet
    // with ImportKeyScreen, which surfaces all four iOS methods
    // (Paste / File / QR / Key Server) and an inline preview card.
    if (state.showImportSheet) {
        ImportKeyScreen(state = state, viewModel = viewModel)
    }

    // ── 4.0.0 Phase 1 (iOS v7.1.1 F3): duplicate-import alert ──────────
    // Raised when an import commit resolved ALREADY_IN_KEYRING. Hosted
    // here (not in ImportKeyScreen) because the sheet has already been
    // dismissed by the time the dialog shows, and because View Key
    // needs this screen's onKeyClick hook to push KeyDetail — the
    // Android shape of iOS's pendingShowKeyFingerprint handoff.
    state.duplicateImportResult?.let { dup ->
        AlertDialog(
            onDismissRequest = { viewModel.dismissDuplicateAlert() },
            title = { Text(stringResource(R.string.import_duplicate_alert_title)) },
            text = {
                Text(stringResource(R.string.import_duplicate_alert_body_format, dup.keyName))
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.dismissDuplicateAlert()
                        onKeyClick(dup.fingerprint)
                    }
                ) { Text(stringResource(R.string.import_duplicate_view_key)) }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissDuplicateAlert() }) { Text(stringResource(R.string.common_button_ok)) }
            }
        )
    }

    // ── Delete Confirm ─────────────────────────────────────────────────
    //
    // RC3 §L (#21): key pairs get the same DeleteKeySheet as Key Detail
    // (backup offer + acknowledgement + optional biometric gate);
    // public-only keys keep the lightweight dialog.
    state.keyToDelete?.let { key ->
        if (key.isKeyPair) {
            val deleteOwnerLabel = key.userName.ifBlank {
                key.userEmail.ifBlank { key.shortFingerprint }
            }
            val deleteScope = rememberCoroutineScope()
            val deleteContext = androidx.compose.ui.platform.LocalContext.current
            DeleteKeySheet(
                keyOwnerLabel = deleteOwnerLabel,
                shortFingerprint = key.shortFingerprint,
                lastBackedUpAt = key.lastBackedUpAt,
                onSaveBackup = { backupPass ->
                    val armored = viewModel.armoredPrivateFor(key, backupPass)
                    if (armored == null) {
                        deleteScope.launch {
                            snackbarHostState.showSnackbar(
                                deleteContext.getString(R.string.key_detail_status_priv_file_failed)
                            )
                        }
                    } else {
                        saveArmoredToFile(
                            context = deleteContext,
                            scope = deleteScope,
                            snackbarHostState = snackbarHostState,
                            armored = armored,
                            suggestedName = KeyShareIntents.buildExportFilename(
                                ownerLabel = deleteOwnerLabel,
                                shortFingerprint = key.shortFingerprint,
                                suffix = "_private"
                            )
                        )
                    }
                },
                onDelete = {
                    deleteWithOptionalBiometricGate(deleteContext) { viewModel.deleteKey() }
                },
                onDismiss = { viewModel.cancelDelete() }
            )
        } else {
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
    }

    // ── First-visit tooltip (Phase 4) ───────────────────────────────────
    ScreenTooltip(
        tooltipKey = "keyring_fab",
        message = stringResource(R.string.keyring_tooltip_fab),
        enabled = state.allKeys.isEmpty()
    )
}

// ── Keyring sections ───────────────────────────────────────────────────

/**
 * 4.2.0 RC2 workstream F — banner listing how many keys carry the pre-fix
 * LibrePGP composite encoding gpg cannot encrypt to. Dismissing it dismisses
 * every currently-listed fingerprint at once (the caller passes the exact
 * set backing [count]); a NEW affected key imported later still surfaces
 * its own hint since its fingerprint isn't in the dismissed set yet.
 */
@Composable
private fun RegenHintBanner(count: Int, onDismiss: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f)
        )
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.Top
        ) {
            Icon(
                Icons.Filled.Warning,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(top = 2.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = pluralStringResource(R.plurals.keyring_regen_hint_title, count, count),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = stringResource(R.string.keyring_regen_hint_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(onClick = onDismiss) {
                Icon(
                    Icons.Filled.Close,
                    contentDescription = stringResource(R.string.keyring_regen_hint_dismiss_cd)
                )
            }
        }
    }
}

/**
 * 4.1.0 Phase 12b — one keyring section: a heading, then its keys.
 *
 * Emits nothing at all when the list is empty, so an empty section leaves no
 * stray heading behind. Drag handles appear only in MANUAL sort, unchanged.
 *
 * [titleColor] is passed in because a LazyListScope builder is not a
 * composable and cannot read MaterialTheme; the caller reads the three
 * colours once, just above the LazyColumn.
 */
private fun LazyListScope.keySection(
    keys: List<PGPKeyEntity>,
    titleRes: Int,
    titleColor: Color,
    topPadding: Dp,
    reorderableState: ReorderableLazyListState,
    manualMode: Boolean,
    onKeyClick: (String) -> Unit,
) {
    if (keys.isEmpty()) return
    item {
        Text(
            stringResource(titleRes),
            style = MaterialTheme.typography.titleSmall,
            color = titleColor,
            modifier = Modifier.padding(top = topPadding, bottom = 4.dp)
        )
    }
    items(keys, key = { it.id }) { key ->
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

// ── Generate Key Bottom Sheet ──────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun GenerateKeySheet(state: KeyringUiState, viewModel: KeyringViewModel) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(
        onDismissRequest = { viewModel.dismissGenerate() },
        sheetState = sheetState
    ) {
        // 4.1.0 — this sheet had no scroll at all, so once the form grew
        // taller than the viewport the passphrase fields and the Generate
        // button were simply unreachable and swiping did nothing. It fit on a
        // 720x1600 reference device at fontScale 1.0 with almost no margin,
        // which is why it survived review; Samsung's system font has wider
        // metrics than Roboto, so One UI devices overflowed at what the user
        // experiences as default settings. Reported as "I cant scroll down
        // pass the expiration portion", on a Galaxy Note 10+, and it made key
        // generation impossible with no workaround.
        //
        // Same modifier order as RevokeKeySheet: scroll first, then insets,
        // padding last. imePadding matters because MainActivity calls
        // enableEdgeToEdge(), so the window never resizes for the keyboard and
        // Material3 1.3.1 does not apply IME insets to ModalBottomSheet
        // content itself.
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp, vertical = 16.dp)
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
                    state.generateAlgorithm.isComposite && state.generateAlgorithm.isV6 ->
                        stringResource(R.string.keyring_generate_algorithm_caption_pqc_ietf)
                    state.generateAlgorithm.isComposite ->
                        stringResource(R.string.keyring_generate_algorithm_caption_pqc_librepgp)
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
            // 4.1.0 — was a fixed Row. Four chips do not fit one line on a
            // narrow or large-text screen, and Compose measures the fourth
            // with maxWidth = 0: the "Never" label then wraps one character
            // per line and the chip renders ~120dp tall instead of ~32dp,
            // adding roughly 90dp of dead vertical space. That is what tipped
            // an already-marginal form into hard overflow. The Algorithm
            // picker above already used FlowRow; this one was missed.
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = state.generateConfirmPassphrase,
                onValueChange = { viewModel.updateGenerateConfirmPassphrase(it) },
                label = { Text(stringResource(R.string.keyring_generate_passphrase_confirm_label)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
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
