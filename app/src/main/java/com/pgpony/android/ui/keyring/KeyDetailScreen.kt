// KeyDetailScreen.kt
// PGPony Android — Phase A4a + A4b + A6 + A7 + A7 Fix4
//
// Key-detail surface with full action wiring. Phase A4a built the
// read-only layout and stubbed all actions through a "Coming in next
// update" snackbar; Phase A4b replaced those stubs with real handlers
// (Trust, Contacts, Notes, Share, Default, Upload, Delete); Phase A6
// added the revocation flow; Phase A7 closed out the Export Private
// Key stub with an AlertDialog + biometric gate; Phase A7 Fix4 adds
// the post-biometric result sheet:
//
//   • Export Private Key → AlertDialog warns user about the
//     sensitivity → BiometricGate.authenticate (if available, with
//     PIN/credential fallback on API 30+) → ExportPrivateKeyResultSheet
//     opens with Copy + Save-as-file + Done. Sheet stays open across
//     Copy so users can also Save (or vice versa); Done clears the
//     cached armored bytes from VM state.
//
// MainActivity bumped from ComponentActivity to FragmentActivity in
// A7 to support BiometricPrompt; non-biometric flows are unaffected
// (FragmentActivity extends ComponentActivity).
//
// No stubs remain in KeyDetailScreen after A7.
//
// Navigation:
//   • Entered via route "keyring/{fingerprint}" from MainActivity.
//   • Back arrow dismisses to the Keyring tab.
//   • Delete confirmation → KeyDetailEvent.KeyDeleted → onBack().

package com.pgpony.android.ui.keyring

import android.Manifest
import android.content.pm.PackageManager
// ── A15 preflight fix ──────────────────────────────────────────────
//
// KeyDetailScreen has ~30 R.string.* call sites added during A13
// extraction, but the file's import block was never updated to bring
// `com.pgpony.android.R` into scope, so every R reference came up
// unresolved at compile time. Adding the import here is purely
// additive and gives all existing call sites a working symbol.
import com.pgpony.android.R
import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.KeyExpirationService
import com.pgpony.android.crypto.card.OpenPgpCardException
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Surface
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.IosShare
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.Report
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import com.pgpony.android.saf.findDocumentCreatorHost
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyDetailScreen(
    fingerprint: String,
    viewModel: KeyDetailViewModel,
    onBack: () -> Unit,
    onChangeCardPin: () -> Unit = {},
    onEncryptToKey: (String) -> Unit = {},
    onDecryptWithKey: (String) -> Unit = {}
) {
    val state by viewModel.state.collectAsState()
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val snackbarHostState = remember { SnackbarHostState() }
    // Phase A4b — scope for one-off snackbar emissions from non-suspend
    // Composable callbacks (e.g. the QR copy button: we want feedback
    // immediately after writing to the clipboard without round-tripping
    // through the VM's state machine).
    val scope = rememberCoroutineScope()
    // #63 (CertainBot): one-time hint that the header avatar is a shortcut.
    LaunchedEffect(state.key?.fingerprint) {
        val k = state.key ?: return@LaunchedEffect
        val prefs = context.getSharedPreferences("pgpony_prefs", android.content.Context.MODE_PRIVATE)
        if (!prefs.getBoolean("kd_avatar_shortcut_hint_shown", false)) {
            prefs.edit().putBoolean("kd_avatar_shortcut_hint_shown", true).apply()
            snackbarHostState.showSnackbar(
                context.getString(
                    if (k.isKeyPair) R.string.kd_avatar_hint_decrypt else R.string.kd_avatar_hint_encrypt
                )
            )
        }
    }
    // 4.0.0 Phase 5a — multi-server publish sheet overlay flag.
    var showPublish by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }

    // Phase A9 Fix1 — pendingContactAction + contactPermissionLauncher
    // removed. The Compose launcher crashed on FragmentActivity-hosted
    // activities due to the 16-bit request code limit. Each call site
    // now passes its own follow-up action as a closure to
    // MainActivity.requestRuntimePermission, so the
    // shared-launcher-with-state-flag pattern isn't needed.
    val activity = context as? com.pgpony.android.MainActivity

    // Fire the initial load whenever the fingerprint arg changes.
    LaunchedEffect(fingerprint) {
        viewModel.load(fingerprint)
    }

    // Phase A4b — pop the back stack after delete confirmation succeeds.
    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                KeyDetailEvent.KeyDeleted -> onBack()
            }
        }
    }

    // Surface coming-soon stubs (Export Private Key + Revoke Key in A4b)
    // as transient snackbars.
    LaunchedEffect(state.comingSoonLabel) {
        val label = state.comingSoonLabel ?: return@LaunchedEffect
        snackbarHostState.showSnackbar("$label — coming in a later update")
        viewModel.dismissComingSoon()
    }

    // Phase A4b — success snackbar surface for write actions.
    LaunchedEffect(state.successMessage) {
        val msg = state.successMessage ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(msg)
        viewModel.clearSuccess()
    }

    // Surface any error from key-load / QR-encode / write actions.
    LaunchedEffect(state.errorMessage) {
        val msg = state.errorMessage ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(msg)
        viewModel.clearError()
    }

    // 4.5.3 (#57): offer to restore a key whose secure storage the OS wiped.
    // Re-offered each time the screen is opened while the key still needs it.
    LaunchedEffect(state.needsRecovery, state.showRecoveryDialog) {
        if (state.needsRecovery && !state.showRecoveryDialog) {
            val res = snackbarHostState.showSnackbar(
                message = "This key's secure storage was reset by the device. Restore access?",
                actionLabel = "Restore",
                duration = SnackbarDuration.Long
            )
            if (res == SnackbarResult.ActionPerformed) viewModel.showRecoveryDialog()
        }
    }

    // Phase A4b — central action dispatcher. The section composables
    // unchanged from A4a still emit string labels via their
    // onComingSoon callbacks; this dispatcher maps those labels to
    // the appropriate real handler. Remaining stubs (Export, Revoke)
    // route back to viewModel.showComingSoon for the snackbar.
    val dispatchAction: (String) -> Unit = { actionId ->
        // Phase A13: action IDs are now stable English routing keys
        // (KeyDetailActionIds.*) rather than user-facing labels. The
        // displayed labels come from stringResource() in the action-row
        // call sites; the routing key passed here is decoupled from
        // the display label so localization doesn't break dispatch.
        when (actionId) {
            KeyDetailActionIds.CHANGE_TRUST -> viewModel.showTrustSheet()
            KeyDetailActionIds.ADD_NOTES, KeyDetailActionIds.EDIT_NOTES -> viewModel.showNotesSheet()
            KeyDetailActionIds.LINK_CONTACT -> ensureContactsPermission(
                context,
                onAlreadyGranted = { viewModel.showContactPicker() },
                onNeedRequest = {
                    // A9 Fix1 — use MainActivity helper with the Link
                    // follow-up captured as a closure. Replaces the
                    // broken Compose-launcher + pendingContactAction
                    // dispatch pattern.
                    activity?.requestRuntimePermission(
                        Manifest.permission.READ_CONTACTS
                    ) { granted ->
                        if (granted) {
                            viewModel.showContactPicker()
                        } else {
                            viewModel.reportContactsPermissionDenied()
                        }
                    }
                }
            )
            KeyDetailActionIds.AUTO_MATCH_EMAIL -> ensureContactsPermission(
                context,
                onAlreadyGranted = { viewModel.autoMatchByEmail() },
                onNeedRequest = {
                    // A9 Fix1 — same pattern as Link to Contact above.
                    activity?.requestRuntimePermission(
                        Manifest.permission.READ_CONTACTS
                    ) { granted ->
                        if (granted) {
                            viewModel.autoMatchByEmail()
                        } else {
                            viewModel.reportContactsPermissionDenied()
                        }
                    }
                }
            )
            KeyDetailActionIds.UNLINK_CONTACT      -> viewModel.showUnlinkConfirm()
            // Phase A8.6 — Share Public Key now opens a result sheet
            // with Copy + Save-as-file options (matching the private
            // key flow's UX shape minus the warning + biometric gate).
            KeyDetailActionIds.SHARE_PUBLIC_KEY    -> {
                val armored = viewModel.armoredPublicKeyForShare()
                if (armored != null) {
                    viewModel.showExportPublicResult(armored)
                } else {
                    scope.launch {
                        snackbarHostState.showSnackbar(
                            context.getString(R.string.key_detail_status_pub_export_failed)
                        )
                    }
                }
            }
            KeyDetailActionIds.SET_AS_DEFAULT  -> viewModel.setAsDefault()
            KeyDetailActionIds.CHANGE_CARD_PIN -> onChangeCardPin()
            // 4.0.0 Phase 5a — the old single-server upload is replaced
            // by the multi-server PublishSheet (per-server checkboxes,
            // verification status, key-type compat warnings).
            KeyDetailActionIds.UPLOAD_TO_KEY_SERVER -> showPublish = true
            KeyDetailActionIds.CHECK_KEY_SERVER -> viewModel.checkKeyServer()
            // 4.0.0 Phase 2 (iOS v7.1.1 F5) — keyserver refresh-and-merge.
            KeyDetailActionIds.REFRESH_KEY_SERVER -> viewModel.refreshFromKeyServer()
            KeyDetailActionIds.DELETE_KEY          -> viewModel.showDeleteConfirm()
            // Phase A6 — Revoke Key now wires to the real flow. Pre-A6
            // this was a stub routing to viewModel.showComingSoon.
            KeyDetailActionIds.REVOKE_KEY          -> viewModel.showRevokeSheet()
            // Phase A8.6 — Export Revocation Certificate now goes
            // through the same RevocationResultSheet as the
            // post-revoke flow, so both entry points produce the same
            // Copy + Save-As-File UX. The VM helper fetches the
            // stored cert and toggles the sheet state in one call.
            KeyDetailActionIds.EXPORT_REVOCATION_CERT -> {
                scope.launch {
                    val opened = viewModel.showRevocationCertResult()
                    if (!opened) {
                        snackbarHostState.showSnackbar(
                            context.getString(R.string.key_detail_status_no_revocation_cert)
                        )
                    }
                }
            }
            // Phase A7 — Export Private Key now wires to the real flow.
            // showExportPrivateConfirm flips the state flag; the actual
            // AlertDialog is rendered below alongside the other dialogs,
            // and confirms route through BiometricGate before the Intent.
            KeyDetailActionIds.EXPORT_PRIVATE_KEY -> viewModel.showExportPrivateConfirm()
            KeyDetailActionIds.CHANGE_PASSPHRASE -> viewModel.showChangePassphraseSheet()
            // Fallback — non-routing IDs (shouldn't happen since the
            // action menu only emits known IDs, but kept for safety).
            // showComingSoon receives the raw ID rather than a localized
            // label because routing IDs are intentionally English.
            else -> viewModel.showComingSoon(actionId)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.key_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.key_detail_back_cd)
                        )
                    }
                },
                // §5.6.2 (#36): QR + overflow menu replace the QR/Actions/Danger
                // scroll sections. Menu items reuse the same dispatchAction ids.
                actions = {
                    val menuKey = state.key
                    var menuOpen by remember { mutableStateOf(false) }
                    IconButton(onClick = { viewModel.showQR() }) {
                        Icon(Icons.Filled.QrCode2, contentDescription = stringResource(R.string.key_detail_show_qr_cd))
                    }
                    if (menuKey != null) {
                        IconButton(onClick = { menuOpen = true }) {
                            Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.key_detail_actions_menu_cd))
                        }
                        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                            if (menuKey.isCardBacked) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.key_detail_action_change_card_pin)) },
                                    leadingIcon = { Icon(Icons.Filled.Password, null) },
                                    onClick = { menuOpen = false; dispatchAction(KeyDetailActionIds.CHANGE_CARD_PIN) }
                                )
                            }
                            if (menuKey.isKeyPair) {
                                // #45: yellow warning signal on the sensitive export.
                                DropdownMenuItem(
                                    text = {
                                        Text(
                                            stringResource(R.string.key_detail_action_export_private_key),
                                            color = androidx.compose.ui.graphics.Color(0xFFF59E0B)
                                        )
                                    },
                                    leadingIcon = {
                                        Icon(
                                            Icons.Filled.VpnKey,
                                            null,
                                            tint = androidx.compose.ui.graphics.Color(0xFFF59E0B)
                                        )
                                    },
                                    onClick = { menuOpen = false; dispatchAction(KeyDetailActionIds.EXPORT_PRIVATE_KEY) }
                                )
                            }
                            if (menuKey.isKeyPair && !menuKey.isCardBacked) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.key_detail_action_change_passphrase)) },
                                    leadingIcon = { Icon(Icons.Filled.Password, null) },
                                    onClick = { menuOpen = false; dispatchAction(KeyDetailActionIds.CHANGE_PASSPHRASE) }
                                )
                            }
                            // 4.6.0 (item 16): the authorized_keys line for the
                            // key's SSH authentication subkey.
                            state.sshPublicKey?.let { line ->
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.key_detail_action_copy_ssh_key)) },
                                    leadingIcon = { Icon(Icons.Filled.Terminal, null) },
                                    onClick = {
                                        menuOpen = false
                                        clipboard.setText(AnnotatedString(line))
                                        scope.launch {
                                            snackbarHostState.showSnackbar(context.getString(R.string.key_detail_ssh_key_copied))
                                        }
                                    }
                                )
                            }
                            if (menuKey.isKeyPair && !menuKey.isDefault) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.key_detail_action_set_as_default)) },
                                    leadingIcon = { Icon(Icons.Filled.Star, null) },
                                    onClick = { menuOpen = false; dispatchAction(KeyDetailActionIds.SET_AS_DEFAULT) }
                                )
                            }
                            // 4.6.0 (item 10): every key-server item is hidden
                            // while offline, like the ActionRows it replaced.
                            val online = !com.pgpony.android.network.OfflineMode.enabled
                            // 4.6.0 (item 9): stays after the first upload, as
                            // "Update on Key Servers", so later edits can be published.
                            if (menuKey.isKeyPair && online) {
                                DropdownMenuItem(
                                    text = {
                                        Text(stringResource(
                                            if (menuKey.keyServerUploaded) R.string.key_detail_action_update_key_servers
                                            else R.string.key_detail_action_upload_to_key_server
                                        ))
                                    },
                                    leadingIcon = { Icon(Icons.Filled.CloudUpload, null) },
                                    onClick = { menuOpen = false; dispatchAction(KeyDetailActionIds.UPLOAD_TO_KEY_SERVER) }
                                )
                            }
                            if (online) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.key_detail_action_check_key_server)) },
                                    leadingIcon = { Icon(Icons.Filled.CloudDownload, null) },
                                    onClick = { menuOpen = false; dispatchAction(KeyDetailActionIds.CHECK_KEY_SERVER) }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.key_detail_action_refresh_key_server)) },
                                    leadingIcon = { Icon(Icons.Filled.Sync, null) },
                                    onClick = { menuOpen = false; dispatchAction(KeyDetailActionIds.REFRESH_KEY_SERVER) }
                                )
                            }
                            HorizontalDivider()
                            if (menuKey.isKeyPair && menuKey.isRevoked) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.key_detail_action_export_revocation_cert)) },
                                    leadingIcon = { Icon(Icons.Filled.IosShare, null) },
                                    onClick = { menuOpen = false; dispatchAction(KeyDetailActionIds.EXPORT_REVOCATION_CERT) }
                                )
                            } else if (menuKey.isKeyPair) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.key_detail_action_revoke_key), color = MaterialTheme.colorScheme.error) },
                                    leadingIcon = { Icon(Icons.Filled.Report, null, tint = MaterialTheme.colorScheme.error) },
                                    onClick = { menuOpen = false; dispatchAction(KeyDetailActionIds.REVOKE_KEY) }
                                )
                            }
                            if (!DestructiveActionsDisabled.isEnabled(context)) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.key_detail_action_delete_key), color = MaterialTheme.colorScheme.error) },
                                    leadingIcon = { Icon(Icons.Filled.Delete, null, tint = MaterialTheme.colorScheme.error) },
                                    onClick = { menuOpen = false; dispatchAction(KeyDetailActionIds.DELETE_KEY) }
                                )
                            }
                        }
                    }
                }
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { padding ->
        when {
            state.isLoading -> LoadingBody(padding = padding)
            state.notFound  -> NotFoundBody(padding = padding)
            state.key != null -> LoadedBody(
                padding = padding,
                state = state,
                onCopyFingerprint = {
                    clipboard.setText(AnnotatedString(state.key!!.fingerprint))
                    viewModel.copyFingerprintFeedback()
                },
                onCopyEmail = { email ->
                    clipboard.setText(AnnotatedString(email))
                    scope.launch { snackbarHostState.showSnackbar(context.getString(R.string.key_detail_email_copied)) }
                },
                onShowQR = { viewModel.showQR() },
                // Phase A4b — dispatcher replaces the bare onComingSoon
                onComingSoon = dispatchAction,
                onEditExpiry = { viewModel.showExpirySheet() },
                onAddSubkey = { viewModel.showAddSubkeySheet() },
                onRevokeSubkey = { viewModel.showSubkeyRevokeSheet(it) },
                onRemoveSubkey = { viewModel.requestSubkeyRemove(it) },
                onAddUserId = { viewModel.showAddUserIdSheet() },
                onMakePrimaryUserId = { uid -> viewModel.requestUserIdAction(uid, UserIdActionRequest.Kind.MAKE_PRIMARY) },
                onRevokeUserId = { uid -> viewModel.requestUserIdAction(uid, UserIdActionRequest.Kind.REVOKE) },
                onRemoveUserId = { uid -> viewModel.requestUserIdAction(uid, UserIdActionRequest.Kind.REMOVE) },
                onEncryptToKey = onEncryptToKey,
                onDecryptWithKey = onDecryptWithKey,
                onEditNotations = { viewModel.showNotationsSheet() },
                // RC3 §N (#34)
                onToggleFallback = { fp -> viewModel.toggleFallback(fp) },
                onMoveFallback = { fp, delta -> viewModel.moveFallback(fp, delta) },
                onPickSigningDefault = { slot, fp -> viewModel.setSigningDefault(slot, fp) },
                onStrictFallbacksChange = { enabled -> viewModel.setStrictFallbacks(enabled) }
            )
        }
    }

    // 4.0.0 Phase 5a — multi-server publish sheet. Top-level sibling of
    // the other sheet overlays (was mistakenly nested inside the QR
    // sheet's conditional, so it only rendered while the QR sheet showed
    // — the "upload does nothing" bug).
    if (showPublish) {
        com.pgpony.android.ui.keydetail.PublishSheet(
            fingerprint = fingerprint,
            onDismiss = { showPublish = false }
        )
    }

    // QR sheet — overlaid on top of the screen content.
    val keyForSheet = state.key
    if (state.showQRSheet && keyForSheet != null) {
        KeyDetailQRSheet(
            key = keyForSheet,
            qrFrames = state.qrFrames,
            qrIndex = state.qrIndex,
            onPrevFrame = { viewModel.qrPrev() },
            onNextFrame = { viewModel.qrNext() },
            // Phase A4b — wire real copy: armored public key to clipboard.
            onCopyArmored = {
                val armored = viewModel.armoredPublicKeyForShare()
                if (armored != null) {
                    clipboard.setText(AnnotatedString(armored))
                    scope.launch {
                        snackbarHostState.showSnackbar(context.getString(R.string.key_detail_status_pub_copied))
                    }
                }
                viewModel.hideQR()
            },
            // Phase A8.6 — QR sheet's Share button now routes through
            // the result sheet so the user gets Copy + Save-as-file
            // options instead of going straight to a text share. The
            // QR sheet itself dismisses; the result sheet takes over.
            onShare = {
                val armored = viewModel.armoredPublicKeyForShare()
                if (armored != null) {
                    viewModel.showExportPublicResult(armored)
                }
                viewModel.hideQR()
            },
            onDismiss = { viewModel.hideQR() }
        )
    }

    // ── Phase A4b: Trust Level sheet ──────────────────────────────────
    val keyForTrust = state.key
    if (state.showTrustSheet && keyForTrust != null) {
        TrustLevelSheet(
            currentTrust = keyForTrust.trustLevel,
            onSelect = { level -> viewModel.setTrustLevel(level) },
            onDismiss = { viewModel.dismissTrustSheet() }
        )
    }

    // ── Phase A4b: Notes editor sheet ─────────────────────────────────
    val keyForNotes = state.key
    if (state.showNotesSheet && keyForNotes != null) {
        NotesEditorSheet(
            initialNotes = keyForNotes.notes,
            onSave = { notes -> viewModel.saveNotes(notes) },
            onDismiss = { viewModel.dismissNotesSheet() }
        )
    }

    // ── Phase A4b: Contact link sheet ─────────────────────────────────
    if (state.showContactSheet) {
        ContactLinkSheet(
            contacts = state.deviceContacts,
            filterEmail = state.contactFilterEmail,
            onSelect = { contact -> viewModel.selectContact(contact) },
            onDismiss = { viewModel.dismissContactSheet() }
        )
    }

    // ── Phase A4b: Unlink contact confirmation ────────────────────────
    if (state.showUnlinkConfirm) {
        val contactName = state.key?.contactName.orEmpty()
        AlertDialog(
            onDismissRequest = { viewModel.dismissUnlinkConfirm() },
            title = { Text(stringResource(R.string.key_detail_unlink_dialog_title)) },
            text = {
                Text(
                    stringResource(
                        R.string.key_detail_unlink_dialog_body_format,
                        contactName.ifBlank { stringResource(R.string.key_detail_unlink_dialog_this_contact_fallback) }
                    )
                )
            },
            confirmButton = {
                TextButton(onClick = { viewModel.unlinkContact() }) {
                    Text(stringResource(R.string.key_detail_unlink_dialog_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissUnlinkConfirm() }) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        )
    }

    // ── Phase A4b: Delete confirmation ────────────────────────────────
    //
    // RC3 §L (#21): a KEY PAIR now gets DeleteKeySheet — backup offer,
    // required acknowledgement, and (only when the app's biometric lock
    // is on) a biometric gate on the final Delete. Public-only keys are
    // re-importable and keep the lightweight dialog.
    if (state.showDeleteConfirm) {
        val key = state.key
        if (key?.isKeyPair == true) {
            val deleteOwnerLabel = key.userName.ifBlank {
                key.userEmail.ifBlank { key.shortFingerprint }
            }
            DeleteKeySheet(
                keyOwnerLabel = deleteOwnerLabel,
                shortFingerprint = key.shortFingerprint,
                lastBackedUpAt = key.lastBackedUpAt,
                onSaveBackup = { backupPass ->
                    val armored = viewModel.armoredPrivateKeyForShare(backupPass)
                    if (armored == null) {
                        scope.launch {
                            snackbarHostState.showSnackbar(
                                context.getString(R.string.key_detail_status_priv_file_failed)
                            )
                        }
                    } else {
                        saveArmoredToFile(
                            context = context,
                            scope = scope,
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
                    deleteWithOptionalBiometricGate(context) { viewModel.deleteKey() }
                },
                // #36 (CertainBot): revoke instead of a bare delete. Closes
                // the delete sheet and opens the existing revoke flow. Hidden
                // for an already-revoked key, where there is nothing to retire.
                onRevokeInstead = if (!key.isRevoked) {
                    {
                        viewModel.dismissDeleteConfirm()
                        viewModel.showRevokeSheet()
                    }
                } else null,
                onDismiss = { viewModel.dismissDeleteConfirm() }
            )
        } else {
            AlertDialog(
                onDismissRequest = { viewModel.dismissDeleteConfirm() },
                title = { Text(stringResource(R.string.key_detail_delete_dialog_title)) },
                text = {
                    Text(
                        stringResource(R.string.key_detail_delete_dialog_intro) +
                                stringResource(R.string.key_detail_delete_dialog_body_public_only)
                    )
                },
                confirmButton = {
                    TextButton(
                        onClick = { viewModel.deleteKey() },
                        colors = ButtonDefaults.textButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Text(stringResource(R.string.key_detail_delete_dialog_confirm))
                    }
                },
                dismissButton = {
                    TextButton(onClick = { viewModel.dismissDeleteConfirm() }) {
                        Text(stringResource(R.string.common_button_cancel))
                    }
                }
            )
        }
    }

    // ── Phase A6: Revoke Key sheet ────────────────────────────────────
    //
    // Driven entirely by VM state. The sheet is "smart" in that its
    // Revoke button calls back here, but it doesn't do any DB or crypto
    // work itself — applyRevocation() on the VM is the single chokepoint.
    val keyForRevoke = state.key
    if (state.showRevokeSheet && keyForRevoke != null) {
        val ownerLabel = keyForRevoke.userName.ifBlank {
            keyForRevoke.userEmail.ifBlank { keyForRevoke.shortFingerprint }
        }
        RevokeKeySheet(
            keyOwnerLabel = ownerLabel,
            isProcessing = state.isRevoking,
            errorMessage = state.revokeError,
            onRevoke = { reason, comment, passphrase ->
                viewModel.applyRevocation(reason, comment, passphrase)
            },
            onDismiss = { viewModel.dismissRevokeSheet() }
        )
    }

    // ── item 16 (#54): subkey revoke sheet (reuses RevokeKeySheet) ─────
    val subkeyRevokeTarget = state.subkeyRevokeTarget
    if (state.showSubkeyRevokeSheet && subkeyRevokeTarget != null) {
        RevokeKeySheet(
            keyOwnerLabel = subkeyRevokeTarget.algorithmLabel + " · " + subkeyRevokeTarget.keyId,
            isProcessing = state.subkeyRevokeInFlight,
            errorMessage = state.subkeyRevokeError,
            onRevoke = { reason, comment, passphrase ->
                viewModel.revokeSubkey(reason, comment, passphrase)
            },
            onDismiss = { viewModel.dismissSubkeyRevokeSheet() }
        )
    }

    // ── item 16 (#54): local remove confirmation ──────────────────────
    val subkeyRemoveTarget = state.subkeyRemoveTarget
    if (subkeyRemoveTarget != null) {
        AlertDialog(
            onDismissRequest = { viewModel.dismissSubkeyRemove() },
            title = { Text(stringResource(R.string.key_detail_subkey_remove_confirm_title)) },
            text = {
                Column {
                    Text(stringResource(R.string.key_detail_subkey_remove_confirm_body))
                    if (!subkeyRemoveTarget.isRevoked) {
                        Spacer(Modifier.height(8.dp))
                        TextButton(
                            onClick = { viewModel.revokeSubkeyInstead() },
                            enabled = !state.subkeyRemoveInFlight
                        ) {
                            Text(
                                stringResource(R.string.key_detail_subkey_revoke_instead_button),
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        deleteWithOptionalBiometricGate(
                            context,
                            title = context.getString(R.string.key_detail_subkey_remove_biometric_title),
                            subtitle = context.getString(R.string.key_detail_subkey_remove_biometric_subtitle)
                        ) { viewModel.confirmSubkeyRemove() }
                    },
                    enabled = !state.subkeyRemoveInFlight
                ) {
                    Text(stringResource(R.string.key_detail_subkey_remove_confirm_action))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { viewModel.dismissSubkeyRemove() },
                    enabled = !state.subkeyRemoveInFlight
                ) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        )
    }

    // ── item 16 (#54): last-encryption-subkey warning ─────────────────
    if (state.lastEncryptionWarning != null) {
        AlertDialog(
            onDismissRequest = { viewModel.dismissLastEncryptionSubkey() },
            title = { Text(stringResource(R.string.key_detail_subkey_last_enc_title)) },
            text = { Text(stringResource(R.string.key_detail_subkey_last_enc_body)) },
            confirmButton = {
                TextButton(onClick = { viewModel.confirmLastEncryptionSubkey() }) {
                    Text(stringResource(R.string.key_detail_subkey_last_enc_action))
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissLastEncryptionSubkey() }) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        )
    }

    // ── Expiration editor sheet ───────────────────────────────────────
    val keyForExpiry = state.key
    if (state.showExpirySheet && keyForExpiry != null) {
        val ownerLabel = keyForExpiry.userName.ifBlank {
            keyForExpiry.userEmail.ifBlank { keyForExpiry.shortFingerprint }
        }
        val cardNfcUnavail = stringResource(R.string.card_scan_nfc_unavailable)
        val cardPairFirst = stringResource(R.string.card_sign_pair_first)
        val cardExpiryFailed = stringResource(R.string.key_detail_expiry_failed)
        EditExpirationSheet(
            keyOwnerLabel = ownerLabel,
            isCardBacked = keyForExpiry.isCardBacked,
            isProcessing = state.expiryInFlight,
            errorMessage = state.expiryError,
            onApplySoftware = { expiresAt, passphrase ->
                viewModel.applyExpirationSoftware(expiresAt, passphrase)
            },
            onApplyCard = { expiresAt, pin ->
                val fp = keyForExpiry.fingerprint
                viewModel.onCardExpiryStarted()
                val started = activity?.startCardOperation({ session ->
                    session.select()
                    val ring = PGPonyApp.instance.keyRepository.loadPublicKeyRing(fp)
                        ?: throw OpenPgpCardException.Malformed(cardPairFirst)
                    KeyExpirationService.shared.setExpirationCard(
                        session, ring, expiresAt, pin.toByteArray(Charsets.UTF_8)
                    )
                }) { result ->
                    activity.stopCardScan()
                    result
                        .onSuccess { viewModel.persistCardExpiry(it.publicRing, expiresAt) }
                        .onFailure { e -> viewModel.onCardExpiryFailure(e.message ?: cardExpiryFailed) }
                }
                if (started != true) viewModel.onCardExpiryFailure(cardNfcUnavail)
            },
            onDismiss = { viewModel.dismissExpirySheet() }
        )
    }

    // ── RC3 §17.2 H: Add Subkey sheet ──────────────────────────────────
    val keyForAddSubkey = state.key
    if (state.showAddSubkeySheet && keyForAddSubkey != null) {
        val addSubkeyOwnerLabel = keyForAddSubkey.userName.ifBlank {
            keyForAddSubkey.userEmail.ifBlank { keyForAddSubkey.shortFingerprint }
        }
        AddSubkeySheet(
            keyOwnerLabel = addSubkeyOwnerLabel,
            isProcessing = state.addSubkeyInFlight,
            errorMessage = state.addSubkeyError,
            isV6 = keyForAddSubkey.isV6Key,
            isCompositeSign = keyForAddSubkey.algorithm.isCompositeSign,
            onApply = { choice, expiresAt, passphrase ->
                viewModel.addSubkey(choice, expiresAt, passphrase)
            },
            onDismiss = { viewModel.dismissAddSubkeySheet() }
        )
    }

    // ── RC3 §17.2 I (#29): Add User ID sheet ────────────────────────────
    val keyForAddUserId = state.key
    if (state.showAddUserIdSheet && keyForAddUserId != null) {
        val addUserIdOwnerLabel = keyForAddUserId.userName.ifBlank {
            keyForAddUserId.userEmail.ifBlank { keyForAddUserId.shortFingerprint }
        }
        AddUserIdSheet(
            keyOwnerLabel = addUserIdOwnerLabel,
            isProcessing = state.addUserIdInFlight,
            errorMessage = state.addUserIdError,
            onApply = { userId, makePrimary, passphrase ->
                viewModel.addUserId(userId, makePrimary, passphrase)
            },
            onDismiss = { viewModel.dismissAddUserIdSheet() }
        )
    }

    if (state.showChangePassphraseSheet && state.key != null) {
        ChangePassphraseSheet(
            isProtected = state.privateKeyIsProtected,
            isProcessing = state.changePassphraseInFlight,
            errorMessage = state.changePassphraseError,
            onApply = { oldPass, newPass ->
                viewModel.changePassphrase(oldPass, newPass)
            },
            onDismiss = { viewModel.dismissChangePassphraseSheet() }
        )
    }

    // ── §5.6.7 (Play review): edit key notations sheet ──────────────────
    val keyForNotations = state.key
    if (state.showNotationsSheet && keyForNotations != null) {
        val notationsOwnerLabel = keyForNotations.userName.ifBlank {
            keyForNotations.userEmail.ifBlank { keyForNotations.shortFingerprint }
        }
        EditNotationsSheet(
            keyOwnerLabel = notationsOwnerLabel,
            initialNotations = state.notations,
            showPassphraseField = state.privateKeyIsProtected,
            isProcessing = state.notationsInFlight,
            errorMessage = state.notationsError,
            onApply = { notations, passphrase ->
                viewModel.saveNotations(notations, passphrase)
            },
            onDismiss = { viewModel.dismissNotationsSheet() }
        )
    }

    // ── RC3 §17.2 I (#29): revoke / make-primary User ID sheet ──────────
    val pendingUserIdAction = state.userIdAction
    if (pendingUserIdAction != null) {
        val parsedUserId = com.pgpony.android.data.PGPKeyEntity.parseUserID(pendingUserIdAction.userId)
        val userIdDisplayName = parsedUserId.first.ifBlank { parsedUserId.second.ifBlank { pendingUserIdAction.userId } }
        UserIdActionSheet(
            request = pendingUserIdAction,
            displayName = userIdDisplayName,
            isProcessing = state.userIdActionInFlight,
            errorMessage = state.userIdActionError,
            onApply = { passphrase -> viewModel.confirmUserIdAction(passphrase) },
            onDismiss = { viewModel.dismissUserIdAction() }
        )
    }

    // ── Phase A6 + A8.6: Revocation result sheet ──────────────────────
    //
    // Renders after applyRevocation succeeds AND when the user
    // taps "Export Revocation Certificate" in Danger Zone for an
    // already-revoked key (Phase A8.6 unification — both flows now
    // produce the same Copy + Save-As-File UX).
    //
    // The cert is stored on PGPKeyEntity.revocationCertificate by
    // applyRevocation; the re-export entry point via
    // viewModel.showRevocationCertResult() pulls it back into state
    // and toggles the sheet.
    val pendingCert = state.pendingRevocationCert
    if (state.showRevocationResultSheet && pendingCert != null && keyForRevoke != null) {
        val ownerLabel = keyForRevoke.userName.ifBlank {
            keyForRevoke.userEmail.ifBlank { keyForRevoke.shortFingerprint }
        }
        RevocationResultSheet(
            keyOwnerLabel = ownerLabel,
            keyEmail = keyForRevoke.userEmail,
            shortFingerprint = keyForRevoke.shortFingerprint,
            armoredLength = pendingCert.length,
            onCopy = {
                val ok = KeyShareIntents.copyRevocationCertToClipboard(
                    context = context,
                    armoredCert = pendingCert
                )
                scope.launch {
                    snackbarHostState.showSnackbar(
                        if (ok) context.getString(R.string.key_detail_status_rev_copied)
                        else context.getString(R.string.key_detail_status_clip_unavailable)
                    )
                }
                // Sheet stays open so user can also Save if they want.
            },
            // RC3 §J (NorseHorse device testing): onSaveFile is a real
            // ACTION_CREATE_DOCUMENT save now; the share chooser it used
            // to open lives on onShare. Same split on all three export
            // sheets below.
            onSaveFile = {
                saveArmoredToFile(
                    context = context,
                    scope = scope,
                    snackbarHostState = snackbarHostState,
                    armored = pendingCert,
                    suggestedName = KeyShareIntents.buildExportFilename(
                        ownerLabel = ownerLabel,
                        shortFingerprint = keyForRevoke.shortFingerprint,
                        suffix = "_revocation"
                    )
                )
            },
            onShare = {
                val launched = KeyShareIntents.shareRevocationCertificate(
                    context = context,
                    armoredCert = pendingCert,
                    keyOwnerLabel = ownerLabel,
                    shortFingerprint = keyForRevoke.shortFingerprint
                )
                if (!launched) {
                    scope.launch {
                        snackbarHostState.showSnackbar(
                            context.getString(R.string.key_detail_status_rev_file_failed)
                        )
                    }
                }
            },
            onDismiss = { viewModel.dismissRevocationResultSheet() },
            onPublish = if (com.pgpony.android.network.OfflineMode.enabled) null else ({
                viewModel.dismissRevocationResultSheet()
                showPublish = true
            })
        )
    }

    // ── Phase A7: Export Private Key confirmation ─────────────────────
    //
    // Two-step gate: AlertDialog warns about sensitivity, then on
    // confirm we invoke BiometricGate (if the device can authenticate)
    // and only on biometric success surface the share Intent.
    //
    // For devices with no biometric / no screen lock, the dialog itself
    // is the gate — proceeding straight to the Intent after Continue.
    // This matches typical Android export-sensitive-data UX and avoids
    // forcing the user to set up biometric in Android Settings just to
    // export a key they already own.
    val keyForExport = state.key
    if (state.showRecoveryDialog) {
        val recoveryPass = remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { if (!state.isRecovering) viewModel.dismissRecoveryDialog() },
            title = { Text("Restore key access") },
            text = {
                Column {
                    Text(
                        "This key's secure storage was reset by the device, so the app " +
                            "can't read the key right now. Enter the key's passphrase to " +
                            "restore access. This does not change your key."
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = recoveryPass.value,
                        onValueChange = { recoveryPass.value = it },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        label = { Text("Passphrase") }
                    )
                    state.recoveryError?.let {
                        Spacer(Modifier.height(8.dp))
                        Text(it, color = MaterialTheme.colorScheme.error)
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = recoveryPass.value.isNotEmpty() && !state.isRecovering,
                    onClick = { viewModel.submitRecovery(recoveryPass.value) }
                ) { Text(if (state.isRecovering) "Restoring\u2026" else "Restore") }
            },
            dismissButton = {
                TextButton(
                    onClick = { viewModel.dismissRecoveryDialog() },
                    enabled = !state.isRecovering
                ) { Text(stringResource(R.string.common_button_cancel)) }
            }
        )
    }

    if (state.showExportPrivateConfirm && keyForExport != null) {
        // Compute the owner label outside the callbacks so both the
        // dialog body and the share Intent use the same string.
        val ownerLabel = keyForExport.userName.ifBlank {
            keyForExport.userEmail.ifBlank { keyForExport.shortFingerprint }
        }
        AlertDialog(
            onDismissRequest = { viewModel.dismissExportPrivateConfirm() },
            title = { Text(stringResource(R.string.key_detail_export_private_dialog_title)) },
            text = {
                Text(
                    stringResource(R.string.key_detail_export_private_dialog_body_format, ownerLabel)
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.dismissExportPrivateConfirm()
                        // Dispatch the share, gated by biometric if
                        // available. On success the helper opens the
                        // ExportPrivateKeyResultSheet via the VM; the
                        // sheet itself owns the Copy / Save-file
                        // actions. See Fix4 notes.
                        doExportPrivateWithBiometric(
                            context = context,
                            viewModel = viewModel,
                            onError = { msg ->
                                scope.launch { snackbarHostState.showSnackbar(msg) }
                            }
                        )
                    },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text(stringResource(R.string.common_button_continue))
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissExportPrivateConfirm() }) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        )
    }

    // ── Phase A7 Fix4: Export Private Key result sheet ────────────────
    //
    // Renders after biometric success. Hosts two delivery options
    // (Copy to clipboard, Save as .asc file) plus Done. Sheet stays
    // open after Copy so the user can also Save (or vice versa);
    // Done — or tap-outside — dismisses and clears the cached armored
    // material from VM state.
    //
    // The armored text itself is held in state.pendingExportedPrivate;
    // we read state.key for the metadata card so the sheet shows owner
    // / email / fingerprint / length without needing the secret bytes
    // on screen.
    val pendingPrivate = state.pendingExportedPrivate
    val keyForResultSheet = state.key
    if (state.showExportPrivateResultSheet && pendingPrivate != null && keyForResultSheet != null) {
        val ownerLabel = keyForResultSheet.userName.ifBlank {
            keyForResultSheet.userEmail.ifBlank { keyForResultSheet.shortFingerprint }
        }
        ExportPrivateKeyResultSheet(
            keyOwnerLabel = ownerLabel,
            keyEmail = keyForResultSheet.userEmail,
            shortFingerprint = keyForResultSheet.shortFingerprint,
            armoredLength = pendingPrivate.length,
            alreadyProtected = state.privateKeyIsProtected,
            onCopy = { exportPass, gpgCompat ->
                // RC4 O5: re-export per action so the chosen passphrase
                // lands on the delivered copy. Falls back to the cached
                // plain armored on export failure (never silently drops
                // the action).
                val armoredForCopy = (if (gpgCompat) viewModel.armoredPrivateKeyGpgCompatForShare(exportPass) else viewModel.armoredPrivateKeyForShare(exportPass)) ?: pendingPrivate
                val ok = KeyShareIntents.copyPrivateKeyToClipboard(
                    context = context,
                    armoredPrivate = armoredForCopy
                )
                scope.launch {
                    snackbarHostState.showSnackbar(
                        if (ok) context.getString(R.string.key_detail_status_priv_copied)
                        else context.getString(R.string.key_detail_status_clip_unavailable)
                    )
                }
                // Deliberately NOT dismissing the sheet — user may
                // also want to save the file.
            },
            onSaveFile = { exportPass, gpgCompat ->
                saveArmoredToFile(
                    context = context,
                    scope = scope,
                    snackbarHostState = snackbarHostState,
                    armored = (if (gpgCompat) viewModel.armoredPrivateKeyGpgCompatForShare(exportPass) else viewModel.armoredPrivateKeyForShare(exportPass)) ?: pendingPrivate,
                    suggestedName = KeyShareIntents.buildExportFilename(
                        ownerLabel = ownerLabel,
                        shortFingerprint = keyForResultSheet.shortFingerprint,
                        suffix = "_private"
                    )
                )
            },
            onShare = { exportPass, gpgCompat ->
                val launched = KeyShareIntents.shareArmoredPrivateKey(
                    context = context,
                    armoredPrivate = (if (gpgCompat) viewModel.armoredPrivateKeyGpgCompatForShare(exportPass) else viewModel.armoredPrivateKeyForShare(exportPass)) ?: pendingPrivate,
                    keyOwnerLabel = ownerLabel,
                    shortFingerprint = keyForResultSheet.shortFingerprint
                )
                if (!launched) {
                    scope.launch {
                        snackbarHostState.showSnackbar(
                            context.getString(R.string.key_detail_status_priv_file_failed)
                        )
                    }
                }
                // Sheet stays open behind the share chooser; if the
                // user cancels the chooser they're back to the sheet
                // and can pick Copy or Done.
            },
            onDismiss = { viewModel.dismissExportPrivateResult() }
        )
    }

    // ── Phase A8.6: Export Public Key result sheet ────────────────────
    //
    // Renders when the user taps "Share Public Key" (or hits Share
    // from the QR sheet). Hosts Copy + Save-As-File + Done. No
    // biometric / warning gate — public keys are meant to be
    // distributed. Sheet stays open after Copy so the user can also
    // Save (or vice versa); Done dismisses and clears the cached
    // armored bytes.
    val pendingPublic = state.pendingExportedPublic
    val keyForPublicSheet = state.key
    if (state.showExportPublicResultSheet && pendingPublic != null && keyForPublicSheet != null) {
        val ownerLabel = keyForPublicSheet.userName.ifBlank {
            keyForPublicSheet.userEmail.ifBlank { keyForPublicSheet.shortFingerprint }
        }
        ExportPublicKeyResultSheet(
            keyOwnerLabel = ownerLabel,
            keyEmail = keyForPublicSheet.userEmail,
            shortFingerprint = keyForPublicSheet.shortFingerprint,
            armoredLength = pendingPublic.length,
            onCopy = {
                val ok = KeyShareIntents.copyPublicKeyToClipboard(
                    context = context,
                    armoredPublic = pendingPublic
                )
                scope.launch {
                    snackbarHostState.showSnackbar(
                        if (ok) context.getString(R.string.key_detail_status_pub_copied)
                        else context.getString(R.string.key_detail_status_clip_unavailable)
                    )
                }
            },
            onSaveFile = {
                saveArmoredToFile(
                    context = context,
                    scope = scope,
                    snackbarHostState = snackbarHostState,
                    armored = pendingPublic,
                    suggestedName = KeyShareIntents.buildExportFilename(
                        ownerLabel = ownerLabel,
                        shortFingerprint = keyForPublicSheet.shortFingerprint,
                        suffix = "_public"
                    )
                )
            },
            onShare = {
                val launched = KeyShareIntents.sharePublicKey(
                    context = context,
                    armored = pendingPublic,
                    keyOwnerLabel = ownerLabel,
                    shortFingerprint = keyForPublicSheet.shortFingerprint
                )
                if (!launched) {
                    scope.launch {
                        snackbarHostState.showSnackbar(
                            context.getString(R.string.key_detail_status_pub_file_failed)
                        )
                    }
                }
            },
            onDismiss = { viewModel.dismissExportPublicResult() }
        )
    }
}

// ── Phase A4b helpers ──────────────────────────────────────────────────

/**
 * Two contact-related actions share the same READ_CONTACTS gate. The
 * enum lets the permission launcher's callback resume the right one.
 */
/**
 * Two contact-related actions share the same READ_CONTACTS gate. The
 * enum was used by the pre-A9-Fix1 pending-action pattern to dispatch
 * the right follow-up after a permission grant. The Fix1 closure-based
 * dispatch made the enum unused, but it's kept as a private definition
 * for any future shared-launcher reintroduction.
 */
@Suppress("unused")
private enum class ContactAction { Link, AutoMatch }

/**
 * Check the current READ_CONTACTS state and either fire the
 * "already granted" path immediately, or fire the "need to ask"
 * path which arms the launcher. Caller is responsible for remembering
 * which action (Link vs AutoMatch) initiated the request so the
 * launcher's grant callback can resume the right one.
 */
private fun ensureContactsPermission(
    context: android.content.Context,
    onAlreadyGranted: () -> Unit,
    onNeedRequest: () -> Unit
) {
    val granted = ContextCompat.checkSelfPermission(
        context, Manifest.permission.READ_CONTACTS
    ) == PackageManager.PERMISSION_GRANTED
    if (granted) onAlreadyGranted() else onNeedRequest()
}

/**
 * Build and launch the share-public-key intent directly (file-based
 * via FileProvider as of A8.6). Reads the armored key + fingerprint
 * out of the VM and hands them to KeyShareIntents.
 *
 * Currently unused — the "Share Public Key" dispatcher routes
 * through ExportPublicKeyResultSheet instead — but kept as a
 * convenience for any future direct-share entry point that wants to
 * bypass the result sheet.
 */
/**
 * RC3 §J (NorseHorse device testing) — write armored key material to a
 * destination the user picks via ACTION_CREATE_DOCUMENT. The export
 * sheets' "Save as .asc file" buttons used to open the system-share
 * chooser, which on many devices has no local save-to-Files target at
 * all — a save button that couldn't save. Same SAF idiom as
 * ShareTargetScreen.saveResult / FileEncryptionResultScreen.
 *
 * MIME is application/octet-stream, not application/pgp-keys: SAF
 * appends the MIME's canonical extension to any suggested name that
 * lacks it, which would mangle the "_public.asc" convention gpg users
 * expect (same reasoning as FileEncryptionResultScreen 3.1.0 Ph2 Fix1).
 * A cancelled picker is silent — the user chose that.
 */
/**
 * RC3 §L (#21): run [onConfirmed] behind the biometric prompt ONLY when
 * the app's biometric lock is enabled (the L plan's rule — deletion gets
 * no extra gate for users who never asked for biometrics). Falls through
 * to [onConfirmed] when the lock is off, biometrics are unavailable, or
 * the activity cast fails — the acknowledgement checkbox is the primary
 * safeguard; this is a second factor for users who opted into one.
 */
internal fun deleteWithOptionalBiometricGate(
    context: android.content.Context,
    title: String = context.getString(R.string.key_delete_biometric_title),
    subtitle: String = context.getString(R.string.key_delete_biometric_subtitle),
    onConfirmed: () -> Unit
) {
    val activity = context as? androidx.fragment.app.FragmentActivity
    // RC5 follow-up (#36, Araaf): the gate used to apply only when the
    // app's Biometric Lock setting was on (the original L design), so a
    // user running with the lock off deleted key pairs with no device
    // auth at all. The P2 clear-all gauntlet already reversed that
    // reasoning — destroying private key material justifies the prompt
    // regardless of the lock setting — and single-key deletion is the
    // same stakes at smaller scope. Now gated purely on device
    // capability, same rule as the gauntlet.
    if (activity != null &&
        DestructiveActionLock.isEnabled(context) &&
        BiometricGate.canAuthenticate(context) == BiometricAvailability.Available
    ) {
        BiometricGate.authenticate(
            activity = activity,
            title = title,
            subtitle = subtitle,
            onSuccess = onConfirmed,
            onError = { _, _ -> /* cancelled — the sheet stays open */ }
        )
    } else {
        onConfirmed()
    }
}

internal fun saveArmoredToFile(
    context: android.content.Context,
    scope: kotlinx.coroutines.CoroutineScope,
    snackbarHostState: SnackbarHostState,
    armored: String,
    suggestedName: String,
) {
    val host = context.findDocumentCreatorHost()
    if (host == null) {
        scope.launch {
            snackbarHostState.showSnackbar(context.getString(R.string.result_save_failed_note))
        }
        return
    }
    host.startDocumentCreator("application/octet-stream", suggestedName) { uri ->
        if (uri == null) return@startDocumentCreator
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                try {
                    context.contentResolver.openOutputStream(uri)?.use { out ->
                        out.write(armored.toByteArray(Charsets.UTF_8))
                        out.flush()
                    } != null
                } catch (e: Exception) {
                    false
                }
            }
            snackbarHostState.showSnackbar(
                context.getString(
                    if (ok) R.string.result_save_saved_note
                    else R.string.result_save_failed_note
                )
            )
        }
    }
}

@Suppress("unused")
private fun doSharePublicKey(viewModel: KeyDetailViewModel, context: android.content.Context) {
    val armored = viewModel.armoredPublicKeyForShare() ?: return
    val key = viewModel.state.value.key ?: return
    val label = key.userName.ifBlank { key.userEmail.ifBlank { "Key" } }
    KeyShareIntents.sharePublicKey(context, armored, label, key.shortFingerprint)
}

/**
 * Phase A7 — gate the private-key share Intent behind device
 * authentication when possible. Three branches:
 *
 *   • BiometricAvailability.Available: show the BiometricPrompt with
 *     PIN/credential fallback on API 30+, biometric-only on 28-29,
 *     weak-biometric on 26-27 (see BiometricGate file header).
 *   • BiometricAvailability.NoneEnrolled / Unavailable: skip the
 *     biometric prompt and proceed straight to the result sheet. The
 *     AlertDialog confirm that brought us here is the only gate.
 *     Forcing the user to set up biometric in Android Settings just to
 *     export their own key would be hostile UX for a feature they
 *     already confirmed they want.
 *
 * Fix4: on biometric success, opens the ExportPrivateKeyResultSheet
 * via viewModel.showExportPrivateResult(armored) instead of firing
 * the share Intent directly. The sheet hosts Copy + Save-as-file
 * actions so the user can pick the destination (or do both).
 *
 * The activity-cast is defensive — PGPony's only Activity is
 * MainActivity, which extends FragmentActivity from A7 forward. If the
 * cast somehow fails we proceed without the biometric gate (the
 * AlertDialog confirm still happened).
 */
private fun doExportPrivateWithBiometric(
    context: android.content.Context,
    viewModel: KeyDetailViewModel,
    onError: (String) -> Unit
) {
    // Helper that opens the result sheet. Invoked either directly
    // (no biometric available) or from the BiometricGate onSuccess
    // callback.
    val openResultSheet: () -> Unit = open@{
        val armored = viewModel.armoredPrivateKeyForShare()
        if (armored == null) {
            onError(context.getString(R.string.key_detail_status_priv_missing))
            return@open
        }
        viewModel.showExportPrivateResult(armored)
    }

    when (BiometricGate.canAuthenticate(context)) {
        BiometricAvailability.Available -> {
            val activity = context as? androidx.fragment.app.FragmentActivity
            if (activity == null) {
                // Should never happen — MainActivity IS a FragmentActivity
                // post-A7 — but if the cast fails we still honor the
                // user's intent rather than dead-end.
                openResultSheet()
                return
            }
            BiometricGate.authenticate(
                activity = activity,
                title = context.getString(R.string.key_detail_export_biometric_title),
                subtitle = context.getString(R.string.key_detail_export_biometric_subtitle),
                onSuccess = openResultSheet,
                onError = { _, message ->
                    // BiometricPrompt's localized "Authentication
                    // cancelled" / "Too many attempts" / etc. — pass
                    // straight through so the user sees the same
                    // language Android already used in the prompt.
                    onError(message)
                }
            )
        }
        // No biometric / no screen lock — the AlertDialog confirm was
        // the gate. Proceed to result sheet.
        BiometricAvailability.NoneEnrolled,
        BiometricAvailability.Unavailable -> {
            openResultSheet()
        }
    }
}

// ── State-specific bodies ──────────────────────────────────────────────

@Composable
private fun LoadingBody(padding: PaddingValues) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding),
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator()
    }
}

@Composable
private fun NotFoundBody(padding: PaddingValues) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = stringResource(R.string.key_detail_error_key_not_found),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun LoadedBody(
    padding: PaddingValues,
    state: KeyDetailUiState,
    onCopyFingerprint: () -> Unit,
    onCopyEmail: (String) -> Unit,
    onShowQR: () -> Unit,
    onComingSoon: (String) -> Unit,
    onEditExpiry: () -> Unit,
    onAddSubkey: () -> Unit,
    onRevokeSubkey: (SubkeyDisplayInfo) -> Unit,
    onRemoveSubkey: (SubkeyDisplayInfo) -> Unit,
    onAddUserId: () -> Unit,
    onMakePrimaryUserId: (String) -> Unit,
    onRevokeUserId: (String) -> Unit,
    onRemoveUserId: (String) -> Unit,
    onEncryptToKey: (String) -> Unit,
    onDecryptWithKey: (String) -> Unit,
    onEditNotations: () -> Unit,
    // RC3 §N (#34)
    onToggleFallback: (String) -> Unit,
    onMoveFallback: (String, Int) -> Unit,
    onPickSigningDefault: (Int, String?) -> Unit,
    onStrictFallbacksChange: (Boolean) -> Unit
) {
    val key = state.key ?: return  // Defensive — caller already filtered
    val hideDestructiveActions = DestructiveActionsDisabled.isEnabled(androidx.compose.ui.platform.LocalContext.current)
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding),
        contentPadding = PaddingValues(bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            KeyHeaderSection(
                key = key,
                onCopyEmail = onCopyEmail,
                onAvatarClick = { if (key.isKeyPair) onDecryptWithKey(key.fingerprint) else onEncryptToKey(key.fingerprint) },
                onEditLabel = {
                    onComingSoon(if (key.notes.isNullOrBlank()) KeyDetailActionIds.ADD_NOTES else KeyDetailActionIds.EDIT_NOTES)
                }
            )
        }
        // Phase A6 — Revoked banner directly under the header so it's
        // the first thing the user sees on a revoked key without having
        // to scroll to Danger Zone. RevokedBanner internally no-ops when
        // !key.isRevoked, so unconditional inclusion is safe.
        item { RevokedBanner(key = key) }
        // 4.6.0 (item 11): a published key edited since its last upload.
        if (key.isKeyPair && key.hasUnpublishedChanges && !com.pgpony.android.network.OfflineMode.enabled) {
            item {
                UnpublishedChangesRow(onUpdate = { onComingSoon(KeyDetailActionIds.UPLOAD_TO_KEY_SERVER) })
            }
        }
        item {
            FingerprintSection(
                key = key,
                copiedRecently = state.copiedFingerprint,
                onCopy = onCopyFingerprint,
                onShare = { onComingSoon(KeyDetailActionIds.SHARE_PUBLIC_KEY) }
            )
        }
        // 4.0.0 Phase 2 (iOS v7.1.1 F4) — every User ID on the key.
        // Rendered when there's more than one, or when the key can add
        // one (RC3 §17.2 I / #29) — software key pairs only, same
        // gating as the Subkeys section's Add button.
        val canEditUserIds = key.isKeyPair && !key.isCardBacked
        if (state.userIds.size > 1 || canEditUserIds) {
            item {
                UserIdsSection(
                    userIds = state.userIds,
                    canEdit = canEditUserIds,
                    onMakePrimary = onMakePrimaryUserId,
                    onRevoke = onRevokeUserId,
                    onRemove = if (hideDestructiveActions) null else onRemoveUserId,
                    onAddUserId = onAddUserId,
                    onCopyEmail = onCopyEmail
                )
            }
        }
        // §5.6.7 (Play review) — editable primary-UID notations.
        // Same software-key-pair gating as the UID and subkey edit
        // surfaces; the section self-hides when empty and read-only.
        if (state.notations.isNotEmpty() || canEditUserIds) {
            item {
                NotationsSection(
                    notations = state.notations,
                    canEdit = canEditUserIds,
                    onEdit = onEditNotations
                )
            }
        }
        item {
            DetailsSection(
                key = key,
                onTrustTap = { onComingSoon(KeyDetailActionIds.CHANGE_TRUST) },
                onEditExpiry = if (key.isKeyPair || key.isCardBacked) onEditExpiry else null
            )
        }
        // 4.2.0 RC3 workstream G (§11.2) — read-only subkey list.
        // Rendered when the ring has subkeys, or when the key can add
        // one (RC3 §17.2 H) — software key pairs only, matching the
        // Edit Expiry row's own gating (card-backed keys use the NFC
        // flow, public-only keys have no private material to sign
        // the binding with).
        val canAddSubkey = key.isKeyPair && !key.isCardBacked
        if (state.subkeys.isNotEmpty() || canAddSubkey) {
            item {
                SubkeysSection(
                    subkeys = state.subkeys,
                    canAddSubkey = canAddSubkey,
                    onAddSubkey = onAddSubkey,
                    canManageSubkeys = canAddSubkey,
                    onRevokeSubkey = onRevokeSubkey,
                    onRemoveSubkey = if (hideDestructiveActions) null else onRemoveSubkey
                )
            }
        }
        // ── RC3 §N (#34): fallbacks + signing defaults ─────────────
        // Software key pairs only — same gating rationale as Add Subkey
        // (card-backed keys can't trial-decrypt in software; public-only
        // keys decrypt nothing).
        if (key.isKeyPair && !key.isCardBacked) {
            item {
                FallbackKeysSection(
                    rows = state.fallbackKeys,
                    strictMode = state.strictFallbacks,
                    onToggle = onToggleFallback,
                    onMove = onMoveFallback,
                    onStrictModeChange = onStrictFallbacksChange
                )
            }
            item {
                SigningDefaultsSection(
                    openKey = key,
                    defaults = state.signingDefaults,
                    choices = state.signerChoices,
                    onPick = onPickSigningDefault
                )
            }
        }
        item {
            ContactSection(
                key = key,
                onComingSoon = onComingSoon
            )
        }
        item {
            NotesSection(
                key = key,
                onComingSoon = onComingSoon
            )
        }
        // §5.6.2 (#36): QR, Actions, and Danger Zone moved to the top-bar
        // overflow menu; Share Public Key moved into the fingerprint card.
    }
}

/** 4.6.0 (item 11): one-tap update for a published key whose server copy is behind. */
@Composable
private fun UnpublishedChangesRow(onUpdate: () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
        color = MaterialTheme.colorScheme.secondaryContainer,
        shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Filled.CloudUpload, null,
                tint = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.size(20.dp)
            )
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(R.string.key_detail_unpublished_changes_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.weight(1f)
            )
            TextButton(onClick = onUpdate) {
                Text(stringResource(R.string.key_detail_unpublished_changes_action))
            }
        }
    }
}
