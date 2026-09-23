// SettingsScreen.kt
// PGPony Android
//
// Settings tab UI with sections: Security, Clipboard, Key Management,
// Data, Support, and About. Matches iOS SettingsView layout.
//
// Phase 1 additions (v1.1.0): Support section with Rate, Send Feedback,
// Privacy Policy, and Security & Encryption rows. Compatibility row added
// to About section. SecurityInfoScreen wired up as overlay.
//
// Phase 2 additions (v1.2.0): Help & FAQ row added at the top of the
// Support section. HelpScreen wired up as overlay.
//
// Phase 3 additions (v1.3.0): "Show Welcome Tour Again" row in About
// section that calls back into MainActivity to re-trigger onboarding.
//
// Phase 4 additions (v1.4.0): "Reset Tips" row in About section that
// clears all tooltip_shown_* SharedPreferences flags so coach-mark
// tooltips reappear on next visit to each main tab.

package com.pgpony.android.ui.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.*
// 3.1.0 Phase 7 (B3) — card PIN cache section imports.
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.TextButton
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.*
import androidx.compose.runtime.*
import kotlinx.coroutines.launch
import com.pgpony.android.update.UpdateCheckService
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.browser.customtabs.CustomTabsIntent

import com.pgpony.android.R
import com.pgpony.android.data.ArmorCommentDefaults
import com.pgpony.android.BuildConfig
import com.pgpony.android.data.ArmorCommentValidator
import com.pgpony.android.ui.components.rememberTooltipState
import com.pgpony.android.ui.help.HelpScreen
import com.pgpony.android.ui.theme.AppTheme

// Version display reads BuildConfig.VERSION_NAME, generated from versionName in
// app/build.gradle.kts, so it can never drift out of sync again.

/**
 * RC3 §J (#20): the six top-level Settings categories. Each value maps to
 * one when-branch of the sub-page renderer in SettingsScreen; the sections
 * inside each branch are the pre-#20 sections, moved verbatim.
 */
private enum class SettingsCategory {
    SECURITY, ENCRYPTION, KEYS, APPEARANCE, BACKUP_DATA, HELP_ABOUT
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    onReplayOnboarding: () -> Unit = {},
    onOpenPassStore: () -> Unit = {},
    onKeysChanged: () -> Unit = {},
    onOpenRecycleBin: () -> Unit = {}
) {
    val state by viewModel.state.collectAsState()
    // RC3 §J (#20): which category sub-page is open; null = the top-level
    // category list. Plain remember to match the sibling overlay flags —
    // a rotation pops back to the list, same as every overlay here.
    var openCategory by remember { mutableStateOf<SettingsCategory?>(null) }
    var showSecurityInfo by remember { mutableStateOf(false) }
    // A14 Picker — Settings → Language sub-screen overlay flag. Mirrors the
    // showSecurityInfo pattern used for the security-info modal.
    var showLanguagePicker by remember { mutableStateOf(false) }
    var showHelp by remember { mutableStateOf(false) }
    // 4.0.0 Phase 9b — About → Licenses overlay flag, same pattern as
    // the security-info and language-picker overlays above.
    var showLicenses by remember { mutableStateOf(false) }
    // 4.0.0 Succession Phase 1 — OpenPGP provider → Connected apps
    // overlay flag, same pattern as the overlays above.
    var showApiClients by remember { mutableStateOf(false) }
    // 4.0.0 Phase 5a — Key servers directory overlay flag.
    var showKeyservers by remember { mutableStateOf(false) }
    var showBackup by remember { mutableStateOf(false) }

    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = context as? android.app.Activity
    // #50: turning a security setting on or off is itself a security action,
    // so gate both directions behind a biometric check when the device has one.
    // Falls through only where no biometric is enrolled (matching the clear-all
    // path), so a user without biometrics is never locked out of their own switch.
    val guardSecurityChange: (String, String, () -> Unit) -> Unit = { confirmTitle, confirmSubtitle, action ->
        val fragmentActivity = context as? androidx.fragment.app.FragmentActivity
        if (fragmentActivity != null &&
            com.pgpony.android.ui.keyring.BiometricGate.canAuthenticate(context) ==
            com.pgpony.android.ui.keyring.BiometricAvailability.Available
        ) {
            com.pgpony.android.ui.keyring.BiometricGate.authenticate(
                activity = fragmentActivity,
                title = confirmTitle,
                subtitle = confirmSubtitle,
                onSuccess = { action() },
                onError = { _, _ -> }
            )
        } else {
            action()
        }
    }
    val tooltipState = rememberTooltipState()

    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(state.errorMessage) {
        state.errorMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearError() }
    }
    LaunchedEffect(state.successMessage) {
        state.successMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearSuccess() }
    }

    // Refresh stats when screen appears
    // RC5 P3 (#23): loadPreferences() re-syncs pref-backed switches with
    // what is actually persisted. Covers the onboarding biometric toggle,
    // which writes the pref directly before this ViewModel ever re-reads.
    LaunchedEffect(Unit) {
        viewModel.loadPreferences()
        viewModel.loadKeyStats()
    }
    // RC5 (Kevin): a completed clear-all behaves like a reinstall — the
    // gauntlet is already dismissed (state reset in the ViewModel), the
    // keyring reloads empty, and the app returns to onboarding.
    LaunchedEffect(state.clearCompleted) {
        if (state.clearCompleted) {
            viewModel.consumeClearCompleted()
            onKeysChanged()
            onReplayOnboarding()
        }
    }

    // RC3 §J (#20): system back pops a category sub-page back to the
    // category list instead of leaving Settings.
    androidx.activity.compose.BackHandler(enabled = openCategory != null) {
        openCategory = null
    }

    // ── Phase A12: probe notification permission on appear ───────────
    //
    // On API 33+ POST_NOTIFICATIONS is a runtime grant the user can
    // revoke at any time from System Settings. Reading the current
    // state on view appear lets the Reminders section render a
    // "Permission needed" inline hint when the toggle is on but the
    // grant has been revoked — gives the user a clear path back to
    // a working state. Pre-API 33, NotificationManagerCompat falls
    // back to the per-app toggle in System Settings, which is what
    // we want.
    LaunchedEffect(Unit) {
        viewModel.updateNotificationPermissionGranted(
            com.pgpony.android.notifications.KeyExpirationService
                .areNotificationsEnabled(context)
        )
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        when (openCategory) {
                            null -> stringResource(R.string.settings_title)
                            SettingsCategory.SECURITY -> stringResource(R.string.settings_category_security_title)
                            SettingsCategory.ENCRYPTION -> stringResource(R.string.settings_category_encryption_title)
                            SettingsCategory.KEYS -> stringResource(R.string.settings_category_keys_title)
                            SettingsCategory.APPEARANCE -> stringResource(R.string.settings_category_appearance_title)
                            SettingsCategory.BACKUP_DATA -> stringResource(R.string.settings_category_backup_title)
                            SettingsCategory.HELP_ABOUT -> stringResource(R.string.settings_category_help_title)
                        }
                    )
                },
                navigationIcon = {
                    if (openCategory != null) {
                        IconButton(onClick = { openCategory = null }) {
                            Icon(
                                Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = stringResource(R.string.common_button_back)
                            )
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
        ) {
            when (openCategory) {
                null -> {
            // ── RC3 §J (#20): category list ────────────────────────────
            //
            // The single 19-section scroll is now six category rows, each
            // opening a sub-page rendered by the when-branches below —
            // same Composable scope, so every section keeps direct access
            // to state / viewModel / the overlay flags with zero
            // parameter threading. Android-Settings-style sub-screens per
            // the 4.2.0 plan (#20); iOS keeps its one Form because that
            // is the iOS convention — this is the Android one.
            SettingsAction(
                title = stringResource(R.string.settings_category_security_title),
                subtitle = stringResource(R.string.settings_category_security_subtitle),
                icon = Icons.Filled.Shield,
                iconTint = Color(0xFF8B5CF6),
                onClick = { openCategory = SettingsCategory.SECURITY }
            )
            SettingsAction(
                title = stringResource(R.string.settings_category_encryption_title),
                subtitle = stringResource(R.string.settings_category_encryption_subtitle),
                icon = Icons.Filled.Lock,
                iconTint = Color(0xFF10B981),
                onClick = { openCategory = SettingsCategory.ENCRYPTION }
            )
            SettingsAction(
                title = stringResource(R.string.settings_category_keys_title),
                subtitle = stringResource(R.string.settings_category_keys_subtitle),
                icon = Icons.Filled.VpnKey,
                iconTint = Color(0xFFF59E0B),
                onClick = { openCategory = SettingsCategory.KEYS }
            )
            SettingsAction(
                title = stringResource(R.string.settings_category_appearance_title),
                subtitle = stringResource(R.string.settings_category_appearance_subtitle),
                icon = Icons.Filled.Palette,
                iconTint = Color(0xFF3B82F6),
                onClick = { openCategory = SettingsCategory.APPEARANCE }
            )
            SettingsAction(
                title = stringResource(R.string.settings_category_backup_title),
                subtitle = stringResource(R.string.settings_category_backup_subtitle),
                icon = Icons.Filled.Backup,
                iconTint = Color(0xFF8B5CF6),
                onClick = { openCategory = SettingsCategory.BACKUP_DATA }
            )
            SettingsAction(
                title = stringResource(R.string.settings_category_help_title),
                subtitle = stringResource(R.string.settings_category_help_subtitle),
                icon = Icons.AutoMirrored.Filled.HelpOutline,
                iconTint = Color(0xFF6366F1),
                onClick = { openCategory = SettingsCategory.HELP_ABOUT }
            )
            Spacer(modifier = Modifier.height(16.dp))

            // Footer
            Text(
                stringResource(R.string.settings_about_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                modifier = Modifier.fillMaxWidth().padding(bottom = 24.dp)
            )
                }
                SettingsCategory.SECURITY -> {
            // ── Security Section ───────────────────────────────────────
            SectionHeader(stringResource(R.string.settings_section_security))
            // item 10 (user request): offline mode leads the Security section so the
            // privacy-hardening switch is the first row a user sees.
            // RC1 offline switch: privacy hardening, grouped with Security.
            SettingsToggle(
                title = stringResource(R.string.settings_offline_toggle_title),
                subtitle = stringResource(R.string.settings_offline_toggle_subtitle),
                icon = Icons.Filled.CloudOff,
                iconTint = Color(0xFF8B5CF6),
                checked = com.pgpony.android.network.OfflineMode.enabled,
                onCheckedChange = {
                    com.pgpony.android.network.OfflineMode.set(it)
                    com.pgpony.android.sync.KeyRefreshScheduler.apply(context)
                }
            )
            SettingsToggle(
                title = stringResource(R.string.settings_biometric_lock_title),
                subtitle = stringResource(R.string.settings_biometric_lock_subtitle),
                icon = Icons.Filled.Fingerprint,
                iconTint = Color(0xFF8B5CF6),
                checked = state.biometricLockEnabled,
                onCheckedChange = { target ->
                    guardSecurityChange(
                        context.getString(R.string.settings_security_confirm_lock_title),
                        context.getString(if (target) R.string.settings_security_confirm_enable_subtitle else R.string.settings_security_confirm_disable_subtitle)
                    ) { viewModel.setBiometricLock(context, target) }
                }
            )
            if (state.biometricLockEnabled) {
                SettingsToggle(
                    title = stringResource(R.string.settings_biometric_decrypt_title),
                    subtitle = stringResource(R.string.settings_biometric_decrypt_subtitle),
                    icon = Icons.Filled.Shield,
                    iconTint = Color(0xFF8B5CF6),
                    checked = state.requireBiometricForDecrypt,
                    onCheckedChange = { viewModel.setRequireBiometricForDecrypt(it) }
                )
            }
            // Independent of the app-open lock: "fingerprint to sign" can
            // be on without locking app open (per user request).
            SettingsToggle(
                title = stringResource(R.string.settings_biometric_sign_title),
                subtitle = stringResource(R.string.settings_biometric_sign_subtitle),
                icon = Icons.Filled.Fingerprint,
                iconTint = Color(0xFF8B5CF6),
                checked = state.requireBiometricForSign,
                onCheckedChange = { target ->
                    guardSecurityChange(
                        context.getString(R.string.settings_security_confirm_sign_title),
                        context.getString(if (target) R.string.settings_security_confirm_enable_subtitle else R.string.settings_security_confirm_disable_subtitle)
                    ) { viewModel.setRequireBiometricForSign(target) }
                }
            )
            // ── #36 (Araaf): global destructive-action lock ─────────────
            SettingsToggle(
                title = stringResource(R.string.settings_protect_destructive_title),
                subtitle = stringResource(R.string.settings_protect_destructive_subtitle),
                icon = Icons.Filled.Shield,
                iconTint = Color(0xFF8B5CF6),
                checked = state.protectDestructiveActions,
                onCheckedChange = { target ->
                    guardSecurityChange(
                        context.getString(R.string.settings_security_confirm_destructive_title),
                        context.getString(if (target) R.string.settings_security_confirm_enable_subtitle else R.string.settings_security_confirm_disable_subtitle)
                    ) { viewModel.setProtectDestructiveActions(target) }
                }
            )
            // ── #36 (Araaf, 4.5.1): opt-in hide of destructive actions ──
            SettingsToggle(
                title = stringResource(R.string.settings_disable_destructive_title),
                subtitle = stringResource(R.string.settings_disable_destructive_subtitle),
                icon = Icons.Filled.Shield,
                iconTint = Color(0xFF8B5CF6),
                checked = state.destructiveActionsDisabled,
                onCheckedChange = { target ->
                    guardSecurityChange(
                        context.getString(R.string.settings_security_confirm_destructive_title),
                        context.getString(if (target) R.string.settings_security_confirm_enable_subtitle else R.string.settings_security_confirm_disable_subtitle)
                    ) { viewModel.setDestructiveActionsDisabled(target) }
                }
            )
            // ── 3.1.0 Phase 8 (E5 F-item): sign-by-default ──────────────
            SignByDefaultToggle()
            // ── 3.1.0 Phase 7 (B1/B2/B3): Remember Card PIN ─────────────
            CardPinCacheSection()
            // ── RC3 §J (#15): passphrase-cache duration picker ──────────
            PassphraseCacheSection()
            // ── 4.0.0 Phase 9b (iOS v7.1.1 parity): auto-wipe toggle ────
            //
            // The wipe behavior itself shipped in 3.1.0 Phase 5
            // (always-on); this makes it a setting. Default ON preserves
            // what every existing install does today.
            SettingsToggle(
                title = stringResource(R.string.settings_clear_inputs_title),
                subtitle = stringResource(R.string.settings_clear_inputs_subtitle),
                icon = Icons.Filled.CleaningServices,
                iconTint = Color(0xFFF59E0B),
                checked = state.clearInputsAfterEncrypt,
                onCheckedChange = { viewModel.setClearInputsAfterEncrypt(it) }
            )
            // darkvegas interop: passphrase encryption uses gpg-compatible S2K
            // by default; this opts into Argon2id (needs GnuPG 2.4+).
            SettingsToggle(
                title = stringResource(R.string.settings_argon2_title),
                subtitle = stringResource(R.string.settings_argon2_subtitle),
                icon = Icons.Filled.Lock,
                iconTint = Color(0xFF8B5CF6),
                checked = state.useArgon2,
                onCheckedChange = { viewModel.setUseArgon2(it) }
            )
            SettingsToggle(
                title = stringResource(R.string.settings_allow_expired_title),
                subtitle = stringResource(R.string.settings_allow_expired_subtitle),
                icon = Icons.Filled.Lock,
                iconTint = Color(0xFF8B5CF6),
                checked = state.allowExpiredKeys,
                onCheckedChange = { viewModel.setAllowExpiredKeys(it) }
            )
            Spacer(modifier = Modifier.height(16.dp))
            SectionHeader(stringResource(R.string.settings_section_pass_store))
            SettingsToggle(
                title = stringResource(R.string.settings_pass_store_enable_title),
                subtitle = stringResource(R.string.settings_pass_store_enable_subtitle),
                icon = Icons.Filled.Lock,
                iconTint = Color(0xFF8B5CF6),
                checked = state.passStoreEnabled,
                onCheckedChange = { viewModel.setPassStoreEnabled(it) }
            )
            if (state.passStoreEnabled) {
                SettingsToggle(
                    title = stringResource(R.string.settings_pass_store_biometric_title),
                    subtitle = stringResource(R.string.settings_pass_store_biometric_subtitle),
                    icon = Icons.Filled.Fingerprint,
                    iconTint = Color(0xFF8B5CF6),
                    checked = state.requireBiometricForPassStore,
                    onCheckedChange = { viewModel.setRequireBiometricForPassStore(it) }
                )
                SettingsAction(
                    title = stringResource(R.string.settings_pass_store_open_title),
                    subtitle = stringResource(R.string.settings_pass_store_open_subtitle),
                    icon = Icons.Filled.FolderOpen,
                    iconTint = Color(0xFF8B5CF6),
                    onClick = onOpenPassStore
                )
            }
            Spacer(modifier = Modifier.height(16.dp))
            SectionHeader(stringResource(R.string.settings_section_clipboard))
            SettingsToggle(
                title = stringResource(R.string.settings_clipboard_autoclear_title),
                subtitle = stringResource(R.string.settings_clipboard_autoclear_subtitle),
                icon = Icons.Filled.Timer,
                iconTint = Color(0xFFF59E0B),
                checked = state.clipboardAutoClear,
                onCheckedChange = { viewModel.setClipboardAutoClear(it) }
            )
            if (state.clipboardAutoClear) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(stringResource(R.string.settings_clipboard_clear_after_label), style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(start = 40.dp))
                Row(
                    modifier = Modifier.padding(start = 40.dp, top = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Phase A13: labels come from string resources so the
                    // 30s/1m/2m/5m suffixes can be localized if a language
                    // uses a different abbreviation convention. The seconds
                    // value stays an Int constant — not user-facing.
                    val intervalLabels = listOf(
                        30 to stringResource(R.string.settings_clipboard_interval_30s),
                        60 to stringResource(R.string.settings_clipboard_interval_1m),
                        120 to stringResource(R.string.settings_clipboard_interval_2m),
                        300 to stringResource(R.string.settings_clipboard_interval_5m)
                    )
                    intervalLabels.forEach { (sec, label) ->
                        FilterChip(
                            selected = state.clipboardClearSeconds == sec,
                            onClick = { viewModel.setClipboardClearSeconds(sec) },
                            label = { Text(label) }
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(16.dp))

                }
                SettingsCategory.ENCRYPTION -> {
            // ── 3.1.0 Phase 8 (E4 F-item): email send format ────────────
            SectionHeader(stringResource(R.string.settings_section_email))
            EmailFormatSection()
            Spacer(modifier = Modifier.height(16.dp))
            // ── §5.5.1 (board t/1): default sharing method ──────────────
            SectionHeader(stringResource(R.string.settings_section_sharing))
            DefaultShareFormatSection()
            Spacer(modifier = Modifier.height(16.dp))
            // ── PGP Output Section: customizable armor comment ─────────
            //
            // One setting with two parts:
            //   1. A master toggle ("Include comment in PGP output",
            //      default ON).
            //   2. An editable text field, enabled only when the toggle
            //      is ON, pre-filled with the default string.
            // Below the field, a live preview renders the EXACT line that
            // will be embedded, computed with the same validator the
            // crypto layer uses (ArmorCommentValidator.validate), so the
            // preview can never disagree with the output. When the
            // validated result is null (toggle off, or field cleared /
            // sanitized to empty) we show a "no comment" hint instead.
            //
            // Scope reminder for future edits: this only affects
            // encrypt / sign / encrypt-and-sign. Exported keys are kept
            // comment-free in PGPCryptoService (stripVersionClean).
            SectionHeader(stringResource(R.string.settings_section_pgp_output))
            SettingsToggle(
                title = stringResource(R.string.settings_armor_comment_toggle_title),
                subtitle = stringResource(R.string.settings_armor_comment_toggle_subtitle),
                icon = Icons.Filled.Comment,
                iconTint = Color(0xFF10B981),
                checked = state.armorCommentInclude,
                onCheckedChange = { viewModel.setArmorCommentInclude(it) }
            )
            if (state.armorCommentInclude) {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = state.armorCommentText,
                    onValueChange = { viewModel.setArmorCommentText(it) },
                    label = { Text(stringResource(R.string.settings_armor_comment_field_label)) },
                    placeholder = { Text(ArmorCommentDefaults.DEFAULT_COMMENT) },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 40.dp)
                )
                Spacer(modifier = Modifier.height(6.dp))
                // Live preview — the actual embedded line, or a hint that
                // no Comment header will be written.
                val previewValue = ArmorCommentValidator.validate(
                    include = state.armorCommentInclude,
                    raw = state.armorCommentText
                )
                if (previewValue != null) {
                    Text(
                        text = stringResource(
                            R.string.settings_armor_comment_preview_format,
                            previewValue
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 40.dp)
                    )
                } else {
                    Text(
                        text = stringResource(R.string.settings_armor_comment_preview_none),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 40.dp)
                    )
                }
            }
            // ── 4.0.0 Phase 9b (iOS 7.1.x parity): pubkey export comment ──
            //
            // Independent toggle for the Comment header on user-facing
            // public key exports (Key Detail → Share Public Key: copy,
            // save-as-file, share sheet). Shares the comment text above.
            // Keyserver uploads and QR codes stay comment-free regardless
            // — same exemption as iOS.
            SettingsToggle(
                title = stringResource(R.string.settings_armor_comment_pubkey_title),
                subtitle = stringResource(R.string.settings_armor_comment_pubkey_subtitle),
                icon = Icons.Filled.QrCode2,
                iconTint = Color(0xFF10B981),
                checked = state.armorCommentPubkeyInclude,
                onCheckedChange = { viewModel.setArmorCommentPubkeyInclude(it) }
            )
            Spacer(modifier = Modifier.height(16.dp))
            // ── Default recipient (Phase A4) ───────────────────────────
            //
            // Pre-select the encrypt recipient so it isn't re-picked every
            // time (main case: encrypting to oneself). Three modes; PINNED
            // reveals a key dropdown. Persisted via DefaultRecipientPrefs and
            // applied in EncryptDecryptViewModel.loadKeys + ShareTargetViewModel.
            SectionHeader(stringResource(R.string.settings_section_default_recipient))
            Text(
                stringResource(R.string.settings_default_recipient_label),
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.padding(start = 16.dp, top = 4.dp)
            )
            Row(
                modifier = Modifier.padding(start = 16.dp, top = 8.dp, end = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                DefaultRecipientMode.entries.forEach { mode ->
                    val label = when (mode) {
                        DefaultRecipientMode.NONE ->
                            stringResource(R.string.settings_default_recipient_none)
                        DefaultRecipientMode.PINNED ->
                            stringResource(R.string.settings_default_recipient_pinned)
                        DefaultRecipientMode.REMEMBER_LAST ->
                            stringResource(R.string.settings_default_recipient_last)
                    }
                    FilterChip(
                        selected = state.defaultRecipientMode == mode,
                        onClick = { viewModel.setDefaultRecipientMode(mode) },
                        label = { Text(label) }
                    )
                }
            }
            if (state.defaultRecipientMode == DefaultRecipientMode.PINNED) {
                var recipientMenuExpanded by remember { mutableStateOf(false) }
                val pinned = state.recipientKeyChoices.firstOrNull {
                    it.fingerprint == state.defaultRecipientFingerprint
                }
                Box(modifier = Modifier.padding(start = 16.dp, top = 8.dp, end = 16.dp)) {
                    OutlinedButton(onClick = { recipientMenuExpanded = true }) {
                        Text(
                            text = pinned?.let {
                                it.userName.ifBlank { it.userEmail }.ifBlank { it.userID }
                            } ?: stringResource(R.string.settings_default_recipient_choose),
                            maxLines = 1,
                        )
                        Icon(Icons.Filled.ArrowDropDown, contentDescription = null)
                    }
                    DropdownMenu(
                        expanded = recipientMenuExpanded,
                        onDismissRequest = { recipientMenuExpanded = false }
                    ) {
                        state.recipientKeyChoices.forEach { key ->
                            DropdownMenuItem(
                                text = {
                                    Text(key.userName.ifBlank { key.userEmail }.ifBlank { key.userID })
                                },
                                onClick = {
                                    viewModel.setDefaultRecipientKey(key.fingerprint)
                                    recipientMenuExpanded = false
                                }
                            )
                        }
                    }
                }
            }
            Spacer(modifier = Modifier.height(16.dp))

                }
                SettingsCategory.KEYS -> {
            // ── Reminders Section (Phase A12) ──────────────────────────
            //
            // Toggle for key-expiration reminders. When enabled,
            // KeyExpirationService schedules AlarmManager wake-ups at
            // -30d, -7d, -1d, and day-of expiration for every key that
            // has an expiresAt timestamp. KeyExpirationReceiver posts
            // a notification when each alarm fires.
            //
            // Permission handling:
            //   • Pre-API 33: POST_NOTIFICATIONS is install-time
            //     granted, no runtime prompt needed. The toggle flow
            //     just persists and schedules.
            //   • API 33+: POST_NOTIFICATIONS is runtime. On toggle-on,
            //     we use MainActivity.requestRuntimePermission (the
            //     same helper A9/A10a uses for CAMERA + file picker
            //     work-arounds) to surface the system dialog. If the
            //     user denies, we revert the toggle and surface a
            //     snackbar explaining why.
            //
            // Permission-revoked inline hint:
            //   If the toggle is on but areNotificationsEnabled returns
            //   false at SettingsScreen appearance (user disabled
            //   notifications in System Settings between sessions),
            //   render an inline "Notifications disabled — open System
            //   Settings to re-enable" hint below the toggle.
            SectionHeader(stringResource(R.string.settings_section_reminders))
            SettingsToggle(
                title = stringResource(R.string.settings_reminders_key_expiration_title),
                subtitle = stringResource(R.string.settings_reminders_key_expiration_subtitle),
                icon = Icons.Filled.Notifications,
                iconTint = Color(0xFF8B5CF6),
                checked = state.keyExpirationRemindersEnabled,
                onCheckedChange = { newState ->
                    if (newState) {
                        // Phase A12 — toggling ON.
                        // API 33+ → request runtime POST_NOTIFICATIONS first.
                        val mainActivity = context as? com.pgpony.android.MainActivity
                        val needsRuntimeGrant =
                            android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU
                        if (needsRuntimeGrant && mainActivity != null) {
                            mainActivity.requestRuntimePermission(
                                android.Manifest.permission.POST_NOTIFICATIONS
                            ) { granted ->
                                viewModel.updateNotificationPermissionGranted(granted)
                                if (granted) {
                                    viewModel.setKeyExpirationReminders(context, true)
                                } else {
                                    viewModel.showError(
                                        context.getString(R.string.settings_reminders_permission_denied_error)
                                    )
                                }
                            }
                        } else {
                            viewModel.setKeyExpirationReminders(context, true)
                        }
                    } else {
                        viewModel.setKeyExpirationReminders(context, false)
                    }
                }
            )
            // Inline permission-revoked hint. Only renders when the
            // toggle is on but the system says notifications aren't
            // currently allowed — a state the user can fix by opening
            // System Settings → Apps → PGPony → Notifications.
            if (state.keyExpirationRemindersEnabled && !state.notificationPermissionGranted) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 56.dp, end = 16.dp, top = 4.dp)
                ) {
                    Text(
                        stringResource(R.string.settings_reminders_notifications_disabled_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
            // ── Key Management Section ─────────────────────────────────
            SectionHeader(stringResource(R.string.settings_section_key_management))
            // #63 (CertainBot): the Default Key is pickable from here, not just
            // shown. Reuses the same dropdown pattern as the default recipient.
            if (state.signingKeyChoices.isNotEmpty()) {
                Text(
                    text = stringResource(R.string.settings_key_default_label),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(start = 16.dp, top = 8.dp)
                )
                var defaultKeyMenuExpanded by remember { mutableStateOf(false) }
                Box(modifier = Modifier.padding(start = 16.dp, top = 4.dp, end = 16.dp)) {
                    OutlinedButton(onClick = { defaultKeyMenuExpanded = true }) {
                        Text(
                            text = state.defaultKeyName
                                ?: stringResource(R.string.settings_key_default_choose),
                            maxLines = 1,
                        )
                        Icon(Icons.Filled.ArrowDropDown, contentDescription = null)
                    }
                    DropdownMenu(
                        expanded = defaultKeyMenuExpanded,
                        onDismissRequest = { defaultKeyMenuExpanded = false }
                    ) {
                        state.signingKeyChoices.forEach { key ->
                            DropdownMenuItem(
                                text = {
                                    Text(key.userName.ifBlank { key.userEmail }.ifBlank { key.userID })
                                },
                                onClick = {
                                    viewModel.setDefaultSigningKey(key.fingerprint)
                                    defaultKeyMenuExpanded = false
                                }
                            )
                        }
                    }
                }
            }
            SettingsRow(
                title = stringResource(R.string.settings_key_total_keys_label),
                value = "${state.totalKeys}",
                icon = Icons.Filled.VpnKey,
                iconTint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            SettingsRow(
                title = stringResource(R.string.settings_key_total_pairs_label),
                value = "${state.totalKeyPairs}",
                icon = Icons.Filled.Key,
                iconTint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            // item 8 (#request): opt out of the post-keygen publish suggestion
            // (which points at key servers, keys.pgpony.app included).
            SettingsToggle(
                title = stringResource(R.string.settings_offer_publish_title),
                subtitle = stringResource(R.string.settings_offer_publish_subtitle),
                icon = Icons.Filled.CloudUpload,
                iconTint = Color(0xFF8B5CF6),
                checked = state.offerPublishAfterKeygen,
                onCheckedChange = { viewModel.setOfferPublishAfterKeygen(it) }
            )
            Spacer(modifier = Modifier.height(16.dp))
            // ── OpenPGP Provider Section (4.0.0 Succession Phase 1) ────
            //
            // Management surface for the OpenPGP API provider: which
            // apps (Thunderbird for Android, K-9, Password Store, …)
            // may use PGPony as their crypto engine. The revocation UI
            // is a plan §5 non-negotiable for the exported service.
            SectionHeader(stringResource(R.string.settings_section_provider))
            SettingsAction(
                title = stringResource(R.string.settings_provider_clients_title),
                subtitle = stringResource(R.string.settings_provider_clients_subtitle),
                icon = Icons.Filled.Link,
                iconTint = Color(0xFF8B5CF6),
                onClick = { showApiClients = true }
            )
            Spacer(modifier = Modifier.height(16.dp))
            // RC1 offline switch (hard gate): the network surfaces below are
            // hidden while offline mode is on. The toggle itself lives in the
            // Security & Privacy category.
            if (!com.pgpony.android.network.OfflineMode.enabled) {
            // ── Key Servers Section (4.0.0 Phase 5a) ───────────────────
            SectionHeader(stringResource(R.string.settings_section_keyservers))
            SettingsAction(
                title = stringResource(R.string.settings_keyservers_title),
                subtitle = stringResource(R.string.settings_keyservers_subtitle),
                icon = Icons.Filled.Dns,
                iconTint = Color(0xFF8B5CF6),
                onClick = { showKeyservers = true }
            )
            Spacer(modifier = Modifier.height(16.dp))
            // ── Key Refresh Section (4.0.0 Phase 5) ────────────────────
            SectionHeader(stringResource(R.string.settings_section_key_refresh))
            BackgroundRefreshSection()
            Spacer(modifier = Modifier.height(16.dp))
            // ── Proxy / Tor Section (4.0.0 Phase 6) ────────────────────
            SectionHeader(stringResource(R.string.settings_section_proxy))
            ProxySection()
            Spacer(modifier = Modifier.height(16.dp))
            }
            // ── §5.6.1 (#36 part 1): recycle bin ───────────────────────
            SettingsAction(
                title = stringResource(R.string.settings_recycle_bin_title),
                subtitle = stringResource(R.string.settings_recycle_bin_subtitle),
                icon = Icons.Filled.Delete,
                iconTint = Color(0xFF8B5CF6),
                onClick = onOpenRecycleBin
            )
            Spacer(modifier = Modifier.height(16.dp))

                }
                SettingsCategory.APPEARANCE -> {
            // ── Appearance Section (Phase A12) ─────────────────────────
            //
            // Three FilterChips mirroring iOS's Picker(selection:
            // $appState.selectedTheme). System follows the device-level
            // dark/light toggle; Light/Dark force the respective mode
            // regardless of system. Selection persists via
            // SettingsViewModel.setTheme which writes the storageKey
            // ("system"/"light"/"dark") to SharedPreferences key
            // "selected_theme". MainActivity.PGPonyTheme reads the same
            // pref reactively, so picking a different chip recomposes
            // the entire UI with the new color scheme without an app
            // relaunch.
            //
            // Phase A13: theme.displayName is still the English string
            // baked into the AppTheme enum. For localization we resolve
            // it through a `themeLabel(theme)` helper that maps the enum
            // to its R.string entry — defined locally below since this
            // is the only place a theme picker UI exists.
            SectionHeader(stringResource(R.string.settings_section_appearance))
            Text(
                stringResource(R.string.settings_appearance_theme_label),
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.padding(start = 16.dp, top = 4.dp)
            )
            Row(
                modifier = Modifier.padding(start = 16.dp, top = 8.dp, end = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                AppTheme.entries.forEach { theme ->
                    val themeLabel = when (theme) {
                        AppTheme.System -> stringResource(R.string.settings_appearance_theme_system)
                        AppTheme.Light -> stringResource(R.string.settings_appearance_theme_light)
                        AppTheme.Dark -> stringResource(R.string.settings_appearance_theme_dark)
                    }
                    FilterChip(
                        selected = state.selectedTheme == theme,
                        onClick = { viewModel.setTheme(theme) },
                        label = { Text(themeLabel) }
                    )
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
            // A14 Picker — Language row.
            //
            // Tapping opens LanguagePickerScreen as a full-screen overlay
            // (same pattern as SecurityInfoScreen below). The current
            // language's nativeName is shown as the row subtitle so the
            // user can tell which one is active at a glance — no need
            // to drill in just to check.
            //
            // Why we read LanguageManager.current() rather than the
            // observable LanguageState.current directly: the row is
            // only rendered once per Settings appearance, and the
            // Activity recreation triggered by the picker will rebuild
            // the entire SettingsScreen anyway. Subscribing to a
            // MutableState here would just trigger a recompose twice
            // in quick succession for the same change.
            SettingsAction(
                title = stringResource(R.string.settings_language_row_title),
                subtitle = com.pgpony.android.i18n.LanguageManager.current().nativeName,
                icon = androidx.compose.material.icons.Icons.Filled.Language,
                iconTint = Color(0xFF3B82F6),
                onClick = { showLanguagePicker = true },
            )

            Spacer(modifier = Modifier.height(16.dp))

                }
                SettingsCategory.BACKUP_DATA -> {
            // ── Backup Section (4.0.0 Phase 3) ─────────────────────────
            SectionHeader(stringResource(R.string.settings_section_backup))
            SettingsAction(
                title = stringResource(R.string.settings_backup_title),
                subtitle = stringResource(R.string.settings_backup_subtitle),
                icon = Icons.Filled.Backup,
                iconTint = Color(0xFF8B5CF6),
                onClick = { showBackup = true }
            )
            Spacer(modifier = Modifier.height(16.dp))
            // ── Data Section ───────────────────────────────────────────
            SectionHeader(stringResource(R.string.settings_section_data))
            if (!state.destructiveActionsDisabled) {
                TextButton(
                    onClick = { viewModel.showClearConfirm() },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                ) {
                    Icon(Icons.Filled.Delete, null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.settings_data_clear_all_button))
                }
            }
            Spacer(modifier = Modifier.height(16.dp))

                }
                SettingsCategory.HELP_ABOUT -> {
            // ── Support Section (Phase 1, Help & FAQ added Phase 2) ────
            SectionHeader(stringResource(R.string.settings_section_support))
            SettingsAction(
                title = stringResource(R.string.settings_support_help_title),
                subtitle = stringResource(R.string.settings_support_help_subtitle),
                icon = Icons.AutoMirrored.Filled.HelpOutline,
                iconTint = Color(0xFF6366F1),
                onClick = { showHelp = true }
            )
            SettingsAction(
                title = stringResource(R.string.settings_support_rate_title),
                subtitle = stringResource(R.string.settings_support_rate_subtitle),
                icon = Icons.Filled.Star,
                iconTint = Color(0xFFF59E0B),
                onClick = {
                    val act = activity
                    if (act != null) {
                        RateAppHelper.requestReview(act)
                    } else {
                        viewModel.showError(context.getString(R.string.settings_support_rate_error))
                    }
                }
            )
            SettingsAction(
                title = stringResource(R.string.settings_support_feedback_title),
                subtitle = stringResource(R.string.settings_support_feedback_subtitle),
                icon = Icons.Filled.Email,
                iconTint = Color(0xFF8B5CF6),
                onClick = {
                    val opened = FeedbackIntent.launch(context, BuildConfig.VERSION_NAME)
                    if (!opened) {
                        viewModel.showError(
                            context.getString(R.string.settings_support_feedback_no_email_error, FeedbackIntent.FEEDBACK_EMAIL)
                        )
                    }
                }
            )
            SettingsAction(
                title = stringResource(R.string.settings_support_privacy_title),
                subtitle = stringResource(R.string.settings_support_privacy_subtitle),
                icon = Icons.Filled.PrivacyTip,
                iconTint = Color(0xFF22C55E),
                trailingIcon = Icons.AutoMirrored.Filled.OpenInNew,
                onClick = {
                    try {
                        val tab = CustomTabsIntent.Builder().build()
                        tab.launchUrl(
                            context,
                            android.net.Uri.parse("https://pgpony.app/privacy")
                        )
                    } catch (e: Exception) {
                        viewModel.showError(context.getString(R.string.settings_support_browser_error))
                    }
                }
            )
            SettingsAction(
                title = stringResource(R.string.settings_support_security_title),
                subtitle = stringResource(R.string.settings_support_security_subtitle),
                icon = Icons.Filled.Shield,
                iconTint = Color(0xFF8B5CF6),
                onClick = { showSecurityInfo = true }
            )
            // §5.55 (Kevin): PGPony for Desktop. The same product, not a
            // sibling app, so it sits ABOVE the More-from list rather than
            // in it. Opens the product site in a Custom Tab.
            SettingsAction(
                title = stringResource(R.string.settings_desktop_title),
                subtitle = stringResource(R.string.settings_desktop_subtitle),
                icon = Icons.Filled.Computer,
                iconTint = Color(0xFF8B5CF6),
                trailingIcon = Icons.AutoMirrored.Filled.OpenInNew,
                onClick = {
                    try {
                        CustomTabsIntent.Builder().build().launchUrl(
                            context,
                            android.net.Uri.parse("https://pgpony.app/desktop")
                        )
                    } catch (e: Exception) {
                        viewModel.showError(
                            context.getString(R.string.settings_support_browser_error)
                        )
                    }
                }
            )
            Spacer(modifier = Modifier.height(16.dp))
            // ── More from NorseHorse ───────────────────────────────────
            // Every sibling app links to its product site (see the list
            // below). The full app source and the open-source crypto
            // engine (PGPonyCore-Kotlin) both open on GitHub in a
            // Custom Tab.
            SectionHeader(stringResource(R.string.settings_section_more))
            // RC3 §J, per NorseHorse: the sibling apps all link straight
            // to their product sites now, in BOTH flavors — the old row
            // routed AgePony through the flavor-split MoreLinks helper
            // (Play listing on play, website on foss). With no store
            // links left at all, FD2's link-hygiene concern is moot and
            // the MoreLinks flavor pair is retired.
            listOf(
                Triple(R.string.settings_more_ponyfamily_title, R.string.settings_more_ponyfamily_subtitle, "https://pony.norsehor.se"),
                Triple(R.string.settings_more_agepony_title, R.string.settings_more_agepony_subtitle, "https://agepony.com"),
                Triple(R.string.settings_more_quorumpony_title, R.string.settings_more_quorumpony_subtitle, "https://quorumpony.com"),
                Triple(R.string.settings_more_carrierpony_title, R.string.settings_more_carrierpony_subtitle, "https://carrierpony.com"),
                Triple(R.string.settings_more_burnpony_title, R.string.settings_more_burnpony_subtitle, "https://burnpony.app"),
                Triple(R.string.settings_more_vaultpony_title, R.string.settings_more_vaultpony_subtitle, "https://vaultpony.app"),
                Triple(R.string.settings_more_passpony_title, R.string.settings_more_passpony_subtitle, "https://passpony.app"),
                Triple(R.string.settings_more_relaypony_title, R.string.settings_more_relaypony_subtitle, "https://relaypony.app"),
                Triple(R.string.settings_more_scrubpony_title, R.string.settings_more_scrubpony_subtitle, "https://scrubpony.app"),
            ).forEach { (titleRes, subtitleRes, url) ->
                SettingsAction(
                    title = stringResource(titleRes),
                    subtitle = stringResource(subtitleRes),
                    icon = Icons.Filled.Lock,
                    iconTint = Color(0xFF22C55E),
                    trailingIcon = Icons.AutoMirrored.Filled.OpenInNew,
                    onClick = {
                        try {
                            CustomTabsIntent.Builder().build().launchUrl(
                                context,
                                android.net.Uri.parse(url)
                            )
                        } catch (e: Exception) {
                            viewModel.showError(
                                context.getString(R.string.settings_support_browser_error)
                            )
                        }
                    }
                )
            }
            SettingsAction(
                title = stringResource(R.string.settings_more_appsource_title),
                subtitle = stringResource(R.string.settings_more_appsource_subtitle),
                icon = Icons.Filled.Code,
                iconTint = Color(0xFF8B5CF6),
                trailingIcon = Icons.AutoMirrored.Filled.OpenInNew,
                onClick = {
                    try {
                        CustomTabsIntent.Builder().build().launchUrl(
                            context,
                            android.net.Uri.parse(
                                // FD3: full app repo. Swap this if the public
                                // repo lands under a different name or host.
                                "https://github.com/norsehorse-dev/PGPonyAndroid"
                            )
                        )
                    } catch (e: Exception) {
                        viewModel.showError(
                            context.getString(R.string.settings_support_browser_error)
                        )
                    }
                }
            )
            SettingsAction(
                title = stringResource(R.string.settings_more_source_title),
                subtitle = stringResource(R.string.settings_more_source_subtitle),
                icon = Icons.Filled.Code,
                iconTint = Color(0xFF8B5CF6),
                trailingIcon = Icons.AutoMirrored.Filled.OpenInNew,
                onClick = {
                    try {
                        CustomTabsIntent.Builder().build().launchUrl(
                            context,
                            android.net.Uri.parse(
                                "https://github.com/norsehorse-dev/PGPonyCore-Kotlin"
                            )
                        )
                    } catch (e: Exception) {
                        viewModel.showError(
                            context.getString(R.string.settings_support_browser_error)
                        )
                    }
                }
            )
            // ── §5.6.9 (Piotr): update check, offered only on sideloads ──
            if (UpdateCheckService.isEligible(context) &&
                !com.pgpony.android.network.OfflineMode.enabled) {
                Spacer(modifier = Modifier.height(16.dp))
                SectionHeader(stringResource(R.string.settings_section_updates))
                UpdateCheckSection()
            }
            Spacer(modifier = Modifier.height(16.dp))
            // ── About Section ──────────────────────────────────────────
            SectionHeader(stringResource(R.string.settings_section_about))
            SettingsRow(
                title = stringResource(R.string.settings_about_version_label),
                value = BuildConfig.VERSION_NAME,
                icon = Icons.Filled.Info,
                iconTint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            SettingsRow(
                title = stringResource(R.string.settings_about_compat_label),
                value = stringResource(R.string.settings_about_compat_value),
                icon = Icons.Filled.PhoneAndroid,
                iconTint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            SettingsRow(
                title = stringResource(R.string.settings_about_openpgp_label),
                value = stringResource(R.string.settings_about_openpgp_value),
                icon = Icons.Filled.Description,
                iconTint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            SettingsRow(
                title = stringResource(R.string.settings_about_crypto_label),
                value = stringResource(R.string.settings_about_crypto_value),
                icon = Icons.Filled.Security,
                iconTint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            // 4.0.0 Phase 9b — open-source attributions (iOS parity;
            // Bouncy Castle's MIT-style license requires the notice).
            SettingsAction(
                title = stringResource(R.string.settings_about_licenses_title),
                subtitle = stringResource(R.string.settings_about_licenses_subtitle),
                icon = Icons.Filled.Description,
                iconTint = MaterialTheme.colorScheme.onSurfaceVariant,
                onClick = { showLicenses = true }
            )
            SettingsAction(
                title = stringResource(R.string.settings_about_replay_onboarding_title),
                subtitle = stringResource(R.string.settings_about_replay_onboarding_subtitle),
                icon = Icons.Filled.Replay,
                iconTint = MaterialTheme.colorScheme.onSurfaceVariant,
                onClick = { onReplayOnboarding() }
            )
            SettingsAction(
                title = stringResource(R.string.settings_about_reset_tips_title),
                subtitle = stringResource(R.string.settings_about_reset_tips_subtitle),
                icon = Icons.Filled.Lightbulb,
                iconTint = Color(0xFFFBBF24),
                onClick = {
                    tooltipState.resetAll()
                    viewModel.showSuccess(context.getString(R.string.settings_about_reset_tips_success))
                }
            )
            Spacer(modifier = Modifier.height(32.dp))

                }
            }
        }
    }

    // ── Clear Data Gauntlet ────────────────────────────────────────────
    //
    // RC5 P2 (#16): RC4's single dialog + checkbox cost AraafRoyall his
    // three keys. Per Kevin's decision (committed publicly in the #16
    // reply), the feature stays but fires only through consecutive
    // confirmations: step 1 = warning + a save-a-backup-first offer +
    // acknowledgement; step 2 = consequences restated + a second, more
    // explicit acknowledgement; then a biometric check whenever the
    // device supports one (NOT gated on the app-lock setting — the
    // stakes justify it; falls through only where no biometrics exist).
    // This deliberately reverses O6's one-dialog consolidation for this
    // ONE action: the incident is the evidence that prompt stacking is a
    // feature here.
    if (state.showClearConfirm) {
        var clearStep by remember { mutableStateOf(1) }
        var clearAck1 by remember { mutableStateOf(false) }
        var clearAck2 by remember { mutableStateOf(false) }
        val runClearWithBiometric = {
            val fragmentActivity = context as? androidx.fragment.app.FragmentActivity
            // #36 (Araaf): the global destructive-action lock governs the
            // biometric layer here too. The two-step confirm gauntlet below
            // stays regardless; this only skips the device-auth prompt when
            // the user has turned the lock off.
            if (fragmentActivity != null &&
                com.pgpony.android.ui.keyring.DestructiveActionLock.isEnabled(context) &&
                com.pgpony.android.ui.keyring.BiometricGate.canAuthenticate(context) ==
                com.pgpony.android.ui.keyring.BiometricAvailability.Available
            ) {
                com.pgpony.android.ui.keyring.BiometricGate.authenticate(
                    activity = fragmentActivity,
                    title = context.getString(R.string.settings_data_clear_biometric_title),
                    subtitle = context.getString(R.string.settings_data_clear_biometric_subtitle),
                    onSuccess = { viewModel.clearAllData() },
                    onError = { _, _ -> /* cancelled — the dialog stays */ }
                )
            } else {
                viewModel.clearAllData()
            }
        }
        if (clearStep == 1) {
            AlertDialog(
                onDismissRequest = { viewModel.dismissClear() },
                title = { Text(stringResource(R.string.settings_data_clear_step1_title)) },
                text = {
                    Column {
                        Text(stringResource(R.string.settings_data_clear_step1_body))
                        // RC5 escalation: name every key about to be
                        // destroyed, revoked ones included, so the stakes
                        // are concrete losses rather than an abstract
                        // warning. Scroll-capped so a large keyring
                        // doesn't push the buttons off screen.
                        if (state.clearKeysPreview.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(12.dp))
                            Text(
                                stringResource(
                                    R.string.settings_data_clear_key_list_header_format,
                                    state.clearKeysPreview.size
                                ),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.error
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Column(
                                modifier = Modifier
                                    .heightIn(max = 160.dp)
                                    .verticalScroll(rememberScrollState())
                            ) {
                                state.clearKeysPreview.forEach { key ->
                                    val label = key.userName.ifBlank { key.userEmail }
                                    Text(
                                        "\u2022 " + label +
                                            (if (key.userEmail.isNotBlank() && label != key.userEmail) " (" + key.userEmail + ")" else "") +
                                            " \u00b7 " + key.shortFingerprint,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        OutlinedButton(
                            onClick = {
                                viewModel.dismissClear()
                                showBackup = true
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) { Text(stringResource(R.string.settings_data_clear_backup_button)) }
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { clearAck1 = !clearAck1 },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(checked = clearAck1, onCheckedChange = { clearAck1 = it })
                            Text(
                                stringResource(R.string.key_delete_ack_label),
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                },
                confirmButton = {
                    TextButton(
                        onClick = { clearStep = 2 },
                        enabled = clearAck1,
                        colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                    ) { Text(stringResource(R.string.common_button_continue)) }
                },
                dismissButton = {
                    TextButton(onClick = { viewModel.dismissClear() }) { Text(stringResource(R.string.common_button_cancel)) }
                }
            )
        } else {
            // RC5 escalation: on top of the second acknowledgement, the
            // user must type the confirmation word exactly (case and
            // all — muscle memory can't do it), and the final button
            // then holds a 5-second countdown before it arms. Breaking
            // any precondition resets the countdown.
            var clearTyped by remember { mutableStateOf("") }
            val clearTypeWord = stringResource(R.string.settings_data_clear_type_word)
            val clearArmed = clearAck2 && clearTyped.trim() == clearTypeWord
            var clearCountdown by remember { mutableStateOf(5) }
            LaunchedEffect(clearArmed) {
                if (clearArmed) {
                    clearCountdown = 5
                    while (clearCountdown > 0) {
                        kotlinx.coroutines.delay(1000)
                        clearCountdown--
                    }
                } else {
                    clearCountdown = 5
                }
            }
            AlertDialog(
                onDismissRequest = { viewModel.dismissClear() },
                title = { Text(stringResource(R.string.settings_data_clear_step2_title)) },
                text = {
                    Column {
                        Text(stringResource(R.string.settings_data_clear_step2_body))
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { clearAck2 = !clearAck2 },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(checked = clearAck2, onCheckedChange = { clearAck2 = it })
                            Text(
                                stringResource(R.string.settings_data_clear_ack2_label),
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(
                            value = clearTyped,
                            onValueChange = { clearTyped = it },
                            label = {
                                Text(
                                    stringResource(
                                        R.string.settings_data_clear_type_label_format,
                                        clearTypeWord
                                    )
                                )
                            },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                },
                confirmButton = {
                    TextButton(
                        onClick = { runClearWithBiometric() },
                        enabled = clearArmed && clearCountdown == 0,
                        colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                    ) {
                        Text(
                            if (clearArmed && clearCountdown > 0)
                                stringResource(R.string.settings_data_clear_step2_confirm) + " (" + clearCountdown + ")"
                            else
                                stringResource(R.string.settings_data_clear_step2_confirm)
                        )
                    }
                },
                dismissButton = {
                    TextButton(onClick = { viewModel.dismissClear() }) { Text(stringResource(R.string.common_button_cancel)) }
                }
            )
        }
    }

    // ── Security & Encryption Info (Phase 1) ────────────────────────────
    if (showSecurityInfo) {
        SecurityInfoScreen(onDismiss = { showSecurityInfo = false })
    }
    // A14 Picker — Language picker overlay. Rendered alongside the
    // existing security-info overlay; only one can be visible at a
    // time per the state-machine guarantees of remember/mutableStateOf.
    if (showLanguagePicker) {
        LanguagePickerScreen(onDismiss = { showLanguagePicker = false })
    }

    // ── Help & FAQ (Phase 2) ────────────────────────────────────────────
    if (showHelp) {
        HelpScreen(onDismiss = { showHelp = false })
    }

    // ── Licenses (4.0.0 Phase 9b) ───────────────────────────────────────
    if (showLicenses) {
        LicensesScreen(onDismiss = { showLicenses = false })
    }

    // ── Connected apps (4.0.0 Succession Phase 1) ───────────────────────
    if (showApiClients) {
        ApiClientsScreen(onDismiss = { showApiClients = false })
    }

    // ── Key servers (4.0.0 Phase 5a) ────────────────────────────────────
    if (showKeyservers) {
        KeyserversScreen(onDismiss = { showKeyservers = false })
    }
    if (showBackup) {
        com.pgpony.android.ui.backup.BackupScreen(
            onDismiss = { showBackup = false },
            onRestored = onKeysChanged
        )
    }
}

// ── Reusable Setting Components ────────────────────────────────────────

@Composable
private fun SectionHeader(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 8.dp, bottom = 8.dp)
    )
}

// §5.6.9 (Piotr): sideload update-check control. Rendered only when the
// build is a sideload (see UpdateCheckService.isEligible). Opt-in switch
// plus a manual "Check now" that toasts the outcome. Notify-and-link only;
// no download happens here or in the service.
@Composable
private fun UpdateCheckSection() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var enabled by remember { mutableStateOf(UpdateCheckService.isEnabled(context)) }
    var checking by remember { mutableStateOf(false) }
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
        SettingsToggle(
            title = stringResource(R.string.settings_updates_toggle_title),
            subtitle = stringResource(R.string.settings_updates_toggle_subtitle),
            icon = Icons.Filled.SystemUpdate,
            iconTint = Color(0xFF8B5CF6),
            checked = enabled,
            onCheckedChange = {
                enabled = it
                UpdateCheckService.setEnabled(context, it)
            }
        )
        if (enabled) {
            TextButton(
                onClick = {
                    if (checking) return@TextButton
                    checking = true
                    scope.launch {
                        val result = UpdateCheckService.checkForUpdate(context, force = true)
                        val msg = when (result) {
                            is UpdateCheckService.CheckResult.UpdateAvailable ->
                                context.getString(R.string.settings_updates_found, result.version)
                            UpdateCheckService.CheckResult.UpToDate ->
                                context.getString(R.string.settings_updates_uptodate)
                            else ->
                                context.getString(R.string.settings_updates_failed)
                        }
                        android.widget.Toast.makeText(
                            context, msg, android.widget.Toast.LENGTH_SHORT
                        ).show()
                        checking = false
                    }
                }
            ) {
                Text(stringResource(R.string.settings_updates_check_now))
            }
        }
    }
}

@Composable
private fun SettingsToggle(
    title: String,
    subtitle: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    iconTint: Color,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, tint = iconTint, modifier = Modifier.size(24.dp))
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(subtitle, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun SettingsRow(
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    iconTint: Color,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth().padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, tint = iconTint, modifier = Modifier.size(24.dp))
        Spacer(modifier = Modifier.width(12.dp))
        Text(title, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun SettingsAction(
    title: String,
    subtitle: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    iconTint: Color,
    onClick: () -> Unit,
    trailingIcon: androidx.compose.ui.graphics.vector.ImageVector = Icons.Filled.ChevronRight
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, tint = iconTint, modifier = Modifier.size(24.dp))
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Icon(
            trailingIcon,
            null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
            modifier = Modifier.size(20.dp)
        )
    }
}


// ── 3.1.0 Phase 7 (B1/B2/B3): card PIN cache settings ──────────────────
//
// Toggle (default OFF), duration choice, LIVE countdown while a PIN is
// held, and a manual Clear. The countdown reads
// CardPinCache.remainingMs() on a 1-second ticker; because the cache
// recomputes expiry from the CURRENT duration preference on every
// read, changing the duration updates both the held PIN's lifetime and
// the visible countdown immediately (the 7.1.x recompute F-item).
// ── 4.0.0 Phase 5 — background keyserver refresh settings ──────────────
//
// Self-contained (reads/writes SharedPreferences directly, same pattern
// as CardPinCacheSection), so no SettingsViewModel change. Every toggle
// re-applies the WorkManager schedule immediately via
// KeyRefreshScheduler.apply. §6 Q4: the enable default is play=ON /
// foss=OFF (KeyRefreshScheduler.defaultEnabled), and the foss build
// shows a one-line "turn it on" nudge when off. The privacy disclosure
// (plan §5) sits under the toggle whenever it's enabled.
@Composable
private fun BackgroundRefreshSection() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val prefs = remember {
        context.getSharedPreferences(
            com.pgpony.android.sync.KeyRefreshScheduler.PREFS, android.content.Context.MODE_PRIVATE
        )
    }
    var enabled by remember {
        mutableStateOf(com.pgpony.android.sync.KeyRefreshScheduler.isEnabled(context))
    }
    var wifiOnly by remember {
        mutableStateOf(com.pgpony.android.sync.KeyRefreshScheduler.isWifiOnly(context))
    }

    SettingsToggle(
        title = stringResource(R.string.settings_key_refresh_title),
        subtitle = stringResource(R.string.settings_key_refresh_subtitle),
        icon = Icons.Filled.Sync,
        iconTint = Color(0xFF8B5CF6),
        checked = enabled,
        onCheckedChange = {
            enabled = it
            prefs.edit().putBoolean(
                com.pgpony.android.sync.KeyRefreshScheduler.KEY_ENABLED, it
            ).apply()
            com.pgpony.android.sync.KeyRefreshScheduler.apply(context)
        }
    )

    if (!enabled && com.pgpony.android.BuildConfig.FLAVOR == "foss") {
        Text(
            stringResource(R.string.settings_key_refresh_foss_enable),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 36.dp, bottom = 8.dp)
        )
    }

    if (enabled) {
        SettingsToggle(
            title = stringResource(R.string.settings_key_refresh_wifi_title),
            subtitle = stringResource(R.string.settings_key_refresh_wifi_subtitle),
            icon = Icons.Filled.Wifi,
            iconTint = MaterialTheme.colorScheme.onSurfaceVariant,
            checked = wifiOnly,
            onCheckedChange = {
                wifiOnly = it
                prefs.edit().putBoolean(
                    com.pgpony.android.sync.KeyRefreshScheduler.KEY_WIFI_ONLY, it
                ).apply()
                com.pgpony.android.sync.KeyRefreshScheduler.apply(context)
            }
        )
        Text(
            stringResource(R.string.settings_key_refresh_disclosure),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 36.dp, top = 4.dp)
        )
    }
}

// ── 4.0.0 Phase 6 — SOCKS/Tor proxy settings ───────────────────────────
//
// Self-contained (SharedPreferences via ProxyPrefs). Mode chips
// Off / Orbot / Custom; custom host+port fields; the onion-mirror
// toggle and the fail-closed note when a proxy is active. Changing the
// mode invalidates the shared client so the next request uses the new
// route.
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ProxySection() {
    val context = androidx.compose.ui.platform.LocalContext.current
    var mode by remember {
        mutableStateOf(com.pgpony.android.network.ProxyPrefs.config(context).mode)
    }
    var onion by remember {
        mutableStateOf(com.pgpony.android.network.ProxyPrefs.onionMirror(context))
    }
    var customHost by remember {
        mutableStateOf(
            context.getSharedPreferences(
                com.pgpony.android.network.ProxyPrefs.PREFS, android.content.Context.MODE_PRIVATE
            ).getString(com.pgpony.android.network.ProxyPrefs.KEY_CUSTOM_HOST, "") ?: ""
        )
    }
    var customPort by remember {
        mutableStateOf(
            context.getSharedPreferences(
                com.pgpony.android.network.ProxyPrefs.PREFS, android.content.Context.MODE_PRIVATE
            ).getInt(
                com.pgpony.android.network.ProxyPrefs.KEY_CUSTOM_PORT,
                com.pgpony.android.network.ProxyPrefs.ORBOT_PORT
            ).toString()
        )
    }
    // proxy stream isolation: SOCKS5 user/pass.
    var proxyUser by remember {
        mutableStateOf(com.pgpony.android.network.ProxyPrefs.username(context))
    }
    var proxyPass by remember {
        mutableStateOf(com.pgpony.android.network.ProxyPrefs.password(context))
    }

    Text(
        stringResource(R.string.settings_proxy_subtitle),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(bottom = 8.dp)
    )

    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        data class ModeOpt(val id: String, val labelRes: Int)
        listOf(
            ModeOpt(com.pgpony.android.network.ProxyPrefs.MODE_OFF, R.string.settings_proxy_mode_off),
            ModeOpt(com.pgpony.android.network.ProxyPrefs.MODE_ORBOT, R.string.settings_proxy_mode_orbot),
            ModeOpt(com.pgpony.android.network.ProxyPrefs.MODE_CUSTOM, R.string.settings_proxy_mode_custom)
        ).forEach { opt ->
            FilterChip(
                selected = mode == opt.id,
                onClick = {
                    mode = opt.id
                    com.pgpony.android.network.ProxyPrefs.setMode(context, opt.id)
                    com.pgpony.android.network.HttpClientFactory.invalidate()
                },
                label = { Text(stringResource(opt.labelRes)) }
            )
        }
    }

    if (mode == com.pgpony.android.network.ProxyPrefs.MODE_ORBOT &&
        !com.pgpony.android.network.ProxyPrefs.isOrbotInstalled(context)
    ) {
        Text(
            stringResource(R.string.settings_proxy_orbot_missing),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(top = 8.dp)
        )
    }

    if (mode == com.pgpony.android.network.ProxyPrefs.MODE_CUSTOM) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedTextField(
                value = customHost,
                onValueChange = {
                    customHost = it
                    com.pgpony.android.network.ProxyPrefs.setCustom(
                        context, it, customPort.toIntOrNull()
                            ?: com.pgpony.android.network.ProxyPrefs.ORBOT_PORT
                    )
                    com.pgpony.android.network.HttpClientFactory.invalidate()
                },
                singleLine = true,
                label = { Text(stringResource(R.string.settings_proxy_custom_host)) },
                modifier = Modifier.weight(2f)
            )
            OutlinedTextField(
                value = customPort,
                onValueChange = {
                    val digits = it.filter { c -> c.isDigit() }.take(5)
                    customPort = digits
                    com.pgpony.android.network.ProxyPrefs.setCustom(
                        context, customHost,
                        digits.toIntOrNull()
                            ?: com.pgpony.android.network.ProxyPrefs.ORBOT_PORT
                    )
                    com.pgpony.android.network.HttpClientFactory.invalidate()
                },
                singleLine = true,
                label = { Text(stringResource(R.string.settings_proxy_custom_port)) },
                modifier = Modifier.weight(1f)
            )
        }
    }

    if (mode != com.pgpony.android.network.ProxyPrefs.MODE_OFF) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedTextField(
                value = proxyUser,
                onValueChange = {
                    proxyUser = it
                    com.pgpony.android.network.ProxyPrefs.setCredentials(context, it, proxyPass)
                    com.pgpony.android.network.HttpClientFactory.invalidate()
                },
                singleLine = true,
                label = { Text(stringResource(R.string.settings_proxy_socks_user)) },
                modifier = Modifier.weight(1f)
            )
            OutlinedTextField(
                value = proxyPass,
                onValueChange = {
                    proxyPass = it
                    com.pgpony.android.network.ProxyPrefs.setCredentials(context, proxyUser, it)
                    com.pgpony.android.network.HttpClientFactory.invalidate()
                },
                singleLine = true,
                visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                label = { Text(stringResource(R.string.settings_proxy_socks_pass)) },
                modifier = Modifier.weight(1f)
            )
        }
        Text(
            stringResource(R.string.settings_proxy_socks_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp)
        )
    }

    if (mode != com.pgpony.android.network.ProxyPrefs.MODE_OFF) {
        SettingsToggle(
            title = stringResource(R.string.settings_proxy_onion_title),
            subtitle = stringResource(R.string.settings_proxy_onion_subtitle),
            icon = Icons.Filled.Lock,
            iconTint = Color(0xFF8B5CF6),
            checked = onion,
            onCheckedChange = {
                onion = it
                com.pgpony.android.network.ProxyPrefs.setOnionMirror(context, it)
            }
        )
        Text(
            stringResource(R.string.settings_proxy_failclosed_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 36.dp, top = 4.dp)
        )
    }
}

/**
 * RC3 §J (#15) — duration picker for the provider passphrase cache,
 * ported from CardPinCacheSection below (same chips, same countdown,
 * same clear-now, same recompute-on-read semantics — see
 * ProviderPassphraseCache's header). Differences from the card
 * section, both deliberate:
 *   • No enable toggle. The cache has been unconditionally on at a
 *     fixed 5 minutes since 4.0.0 P2a-2; #15 only makes the duration
 *     a choice, and a default-off toggle would regress users relying
 *     on it (explicit plan constraint).
 *   • Clear now clears ALL held entries — the cache is per-key, and
 *     "clear" from Settings should mean everything, not the newest.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PassphraseCacheSection() {
    var durationSec by remember {
        mutableStateOf(com.pgpony.android.provider.ProviderPassphraseCache.durationSec())
    }
    var remainingMs by remember {
        mutableStateOf(com.pgpony.android.provider.ProviderPassphraseCache.remainingMs())
    }
    LaunchedEffect(Unit) {
        while (true) {
            remainingMs = com.pgpony.android.provider.ProviderPassphraseCache.remainingMs()
            kotlinx.coroutines.delay(1000)
        }
    }

    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.Password,
            contentDescription = null,
            tint = Color(0xFF0EA5E9),
            modifier = Modifier.size(24.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                stringResource(R.string.settings_passphrase_cache_title),
                style = MaterialTheme.typography.bodyLarge
            )
            Text(
                stringResource(R.string.settings_passphrase_cache_subtitle),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
        Text(
            stringResource(R.string.settings_card_pin_cache_duration_label),
            style = MaterialTheme.typography.labelLarge
        )
        Spacer(modifier = Modifier.height(6.dp))
        val choices = listOf(
            60 to stringResource(R.string.settings_card_pin_cache_1min),
            300 to stringResource(R.string.settings_card_pin_cache_5min),
            900 to stringResource(R.string.settings_card_pin_cache_15min),
            3600 to stringResource(R.string.settings_card_pin_cache_1hr),
            com.pgpony.android.provider.ProviderPassphraseCache.DURATION_UNTIL_CLEARED to
                stringResource(R.string.settings_card_pin_cache_until_cleared),
            com.pgpony.android.session.SessionPolicy.DURATION_UNTIL_LOCKED to
                stringResource(R.string.settings_session_until_locked)
        )
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            choices.forEach { (secs, label) ->
                FilterChip(
                    selected = durationSec == secs,
                    onClick = {
                        durationSec = secs
                        com.pgpony.android.provider.ProviderPassphraseCache.setDurationSec(secs)
                        remainingMs = com.pgpony.android.provider.ProviderPassphraseCache.remainingMs()
                    },
                    label = { Text(label, maxLines = 1) }
                )
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
        if (remainingMs > 0) {
            if (com.pgpony.android.session.SessionPolicy.isLifecycleHeld()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        stringResource(R.string.settings_passphrase_cache_held_until_cleared),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = {
                        com.pgpony.android.provider.ProviderPassphraseCache.clearAll()
                        // 4.6.0 (item 17.10): the in-app prompt cache shares this duration and
                        // this button; it was never cleared here.
                        com.pgpony.android.session.InAppPassphraseCache.clearAll()
                        com.pgpony.android.provider.ProviderCacheClearReceiver.requestClearAll()
                        remainingMs = 0
                    }) {
                        Text(stringResource(R.string.settings_card_pin_cache_clear))
                    }
                }
            } else {
                val totalSec = remainingMs / 1000
                val mm = totalSec / 60
                val ss = totalSec % 60
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        stringResource(
                            R.string.settings_passphrase_cache_countdown_format,
                            String.format("%d:%02d", mm, ss)
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = {
                        com.pgpony.android.provider.ProviderPassphraseCache.clearAll()
                        // 4.6.0 (item 17.10): the in-app prompt cache shares this duration and
                        // this button; it was never cleared here.
                        com.pgpony.android.session.InAppPassphraseCache.clearAll()
                        com.pgpony.android.provider.ProviderCacheClearReceiver.requestClearAll()
                        remainingMs = 0
                    }) {
                        Text(stringResource(R.string.settings_card_pin_cache_clear))
                    }
                }
            }
        } else {
            Text(
                stringResource(R.string.settings_passphrase_cache_none_held),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CardPinCacheSection() {
    var enabled by remember {
        mutableStateOf(com.pgpony.android.crypto.card.CardPinCache.isEnabled())
    }
    var durationSec by remember {
        mutableStateOf(com.pgpony.android.crypto.card.CardPinCache.durationSec())
    }
    var remainingMs by remember {
        mutableStateOf(com.pgpony.android.crypto.card.CardPinCache.remainingMs())
    }
    LaunchedEffect(enabled) {
        while (enabled) {
            remainingMs = com.pgpony.android.crypto.card.CardPinCache.remainingMs()
            kotlinx.coroutines.delay(1000)
        }
    }

    SettingsToggle(
        title = stringResource(R.string.settings_card_pin_cache_title),
        subtitle = stringResource(R.string.settings_card_pin_cache_subtitle),
        icon = Icons.Filled.Contactless,
        iconTint = Color(0xFF0EA5E9),
        checked = enabled,
        onCheckedChange = {
            enabled = it
            com.pgpony.android.crypto.card.CardPinCache.setEnabled(it)
            remainingMs = com.pgpony.android.crypto.card.CardPinCache.remainingMs()
        }
    )
    if (enabled) {
        Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
            Text(
                stringResource(R.string.settings_card_pin_cache_duration_label),
                style = MaterialTheme.typography.labelLarge
            )
            Spacer(modifier = Modifier.height(6.dp))
            val choices = listOf(
                60 to stringResource(R.string.settings_card_pin_cache_1min),
                300 to stringResource(R.string.settings_card_pin_cache_5min),
                900 to stringResource(R.string.settings_card_pin_cache_15min),
                3600 to stringResource(R.string.settings_card_pin_cache_1hr),
                // 4.0.0 Phase 9 — iOS-parity superset: hold with no
                // timer. Wrong-PIN / manual Clear / process death still
                // clear it; only the countdown goes away.
                com.pgpony.android.crypto.card.CardPinCache.DURATION_UNTIL_CLEARED to
                    stringResource(R.string.settings_card_pin_cache_until_cleared),
                com.pgpony.android.session.SessionPolicy.DURATION_UNTIL_LOCKED to
                    stringResource(R.string.settings_session_until_locked)
            )
            // 4.0.0 Phase 9 — five choices no longer fit a segmented row
            // ("1 hour" already ellipsized on narrow devices with four).
            // FilterChips in a FlowRow wrap naturally and survive longer
            // locale strings; selection semantics are unchanged.
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                choices.forEach { (secs, label) ->
                    FilterChip(
                        selected = durationSec == secs,
                        onClick = {
                            durationSec = secs
                            com.pgpony.android.crypto.card.CardPinCache.setDurationSec(secs)
                            // B2/B3: the boundary and the countdown both
                            // honor the new duration on the next tick.
                            remainingMs = com.pgpony.android.crypto.card.CardPinCache.remainingMs()
                        },
                        label = { Text(label, maxLines = 1) }
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            if (remainingMs > 0) {
                // 4.0.0 Phase 9 — under the "Until I clear it" sentinel a
                // held PIN reports Long.MAX_VALUE, so show the held state
                // instead of a (nonsense) countdown. Clear now works the
                // same in both branches.
                if (com.pgpony.android.session.SessionPolicy.isLifecycleHeld()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            stringResource(R.string.settings_card_pin_cache_held_until_cleared),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.weight(1f)
                        )
                        TextButton(onClick = {
                            com.pgpony.android.crypto.card.CardPinCache.clear()
                            // 4.6.0 (item 17.10): also drop the PIN held by the :remote_api
                            // process (ProviderCardOpActivity caches it there).
                            com.pgpony.android.provider.ProviderCacheClearReceiver.requestClearAll()
                            remainingMs = 0
                        }) {
                            Text(stringResource(R.string.settings_card_pin_cache_clear))
                        }
                    }
                } else {
                    val totalSec = remainingMs / 1000
                    val mm = totalSec / 60
                    val ss = totalSec % 60
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            stringResource(
                                R.string.settings_card_pin_cache_countdown_format,
                                String.format("%d:%02d", mm, ss)
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.weight(1f)
                        )
                        TextButton(onClick = {
                            com.pgpony.android.crypto.card.CardPinCache.clear()
                            // 4.6.0 (item 17.10): also drop the PIN held by the :remote_api
                            // process (ProviderCardOpActivity caches it there).
                            com.pgpony.android.provider.ProviderCacheClearReceiver.requestClearAll()
                            remainingMs = 0
                        }) {
                            Text(stringResource(R.string.settings_card_pin_cache_clear))
                        }
                    }
                }
            } else {
                Text(
                    stringResource(R.string.settings_card_pin_cache_none_held),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
        }
    }
}


// ── 3.1.0 Phase 8 (E5 F-item): sign-by-default toggle ──────────────────
//
// Distinct from the default SIGNER (the isDefault key drives which key
// signs): this decides whether the Encrypt screen's "Also sign" toggle
// starts ON for a fresh session. Applied once at
// EncryptDecryptViewModel init, so flipping it off for one message
// doesn't snap back.
@Composable
private fun SignByDefaultToggle() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val prefs = remember {
        context.getSharedPreferences("pgpony_prefs", android.content.Context.MODE_PRIVATE)
    }
    var enabled by remember { mutableStateOf(prefs.getBoolean("sign_by_default", false)) }
    SettingsToggle(
        title = stringResource(R.string.settings_sign_by_default_title),
        subtitle = stringResource(R.string.settings_sign_by_default_subtitle),
        icon = Icons.Filled.Draw,
        iconTint = Color(0xFF10B981),
        checked = enabled,
        onCheckedChange = {
            enabled = it
            prefs.edit().putBoolean("sign_by_default", it).apply()
        }
    )
}

// ── 3.1.0 Phase 8 (E4 F-item): email send format ───────────────────────
//
// How "Send as Email" packages the armored output: inline in the body
// (PGP-aware desktop clients auto-decrypt), as a .asc attachment, or
// both. "Send from" account selection is the mail client's own chooser
// on Android — satisfied by the platform, nothing to configure here.
@Composable
private fun EmailFormatSection() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val prefs = remember {
        context.getSharedPreferences("pgpony_prefs", android.content.Context.MODE_PRIVATE)
    }
    var format by remember {
        mutableStateOf(prefs.getString("email_send_format", "inline") ?: "inline")
    }
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
        Text(
            stringResource(R.string.settings_email_format_label),
            style = MaterialTheme.typography.labelLarge
        )
        Spacer(modifier = Modifier.height(6.dp))
        val choices = listOf(
            "inline" to stringResource(R.string.settings_email_format_inline),
            "attachment" to stringResource(R.string.settings_email_format_attachment),
            "both" to stringResource(R.string.settings_email_format_both)
        )
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            choices.forEachIndexed { index, (value, label) ->
                SegmentedButton(
                    selected = format == value,
                    onClick = {
                        format = value
                        prefs.edit().putString("email_send_format", value).apply()
                    },
                    shape = SegmentedButtonDefaults.itemShape(index = index, count = choices.size)
                ) {
                    Text(label, maxLines = 1)
                }
            }
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            stringResource(R.string.settings_email_format_subtitle),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

// §5.5.1 (board t/1): default packaging for the result Share button —
// inline armored text vs a .asc file. Generalizes the email-format idea to
// the general share sheet.
@Composable
private fun DefaultShareFormatSection() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val prefs = remember {
        context.getSharedPreferences("pgpony_prefs", android.content.Context.MODE_PRIVATE)
    }
    var format by remember {
        mutableStateOf(prefs.getString("default_share_format", "text") ?: "text")
    }
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
        Text(
            stringResource(R.string.settings_share_format_label),
            style = MaterialTheme.typography.labelLarge
        )
        Spacer(modifier = Modifier.height(6.dp))
        val choices = listOf(
            "text" to stringResource(R.string.settings_share_format_inline),
            "file" to stringResource(R.string.settings_share_format_file)
        )
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            choices.forEachIndexed { index, (value, label) ->
                SegmentedButton(
                    selected = format == value,
                    onClick = {
                        format = value
                        prefs.edit().putString("default_share_format", value).apply()
                    },
                    shape = SegmentedButtonDefaults.itemShape(index = index, count = choices.size)
                ) {
                    Text(label, maxLines = 1)
                }
            }
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            stringResource(R.string.settings_share_format_subtitle),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
