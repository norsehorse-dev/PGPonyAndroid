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
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.browser.customtabs.CustomTabsIntent

import com.pgpony.android.LocalBillingService
import com.pgpony.android.R
import com.pgpony.android.data.ArmorCommentDefaults
import com.pgpony.android.BuildConfig
import com.pgpony.android.data.ArmorCommentValidator
import com.pgpony.android.ui.components.rememberTooltipState
import com.pgpony.android.ui.help.HelpScreen
import com.pgpony.android.ui.pro.ProBadge
import com.pgpony.android.ui.pro.ProFeature
import com.pgpony.android.ui.pro.ProGateSheet
import com.pgpony.android.ui.theme.AppTheme

// Version display reads BuildConfig.VERSION_NAME, generated from versionName in
// app/build.gradle.kts, so it can never drift out of sync again.

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    onReplayOnboarding: () -> Unit = {},
    onOpenPassStore: () -> Unit = {}
) {
    val state by viewModel.state.collectAsState()
    val billingService = LocalBillingService.current
    val billingState by billingService.state.collectAsState()
    var proGateFeature by remember { mutableStateOf<ProFeature?>(null) }
    var showSecurityInfo by remember { mutableStateOf(false) }
    // A14 Picker — Settings → Language sub-screen overlay flag. Mirrors the
    // showSecurityInfo pattern used for the security-info modal.
    var showLanguagePicker by remember { mutableStateOf(false) }
    var showHelp by remember { mutableStateOf(false) }

    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = context as? android.app.Activity
    val tooltipState = rememberTooltipState()

    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(state.errorMessage) {
        state.errorMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearError() }
    }
    LaunchedEffect(state.successMessage) {
        state.successMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearSuccess() }
    }

    // Refresh stats when screen appears
    LaunchedEffect(Unit) { viewModel.loadKeyStats() }

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
        topBar = { TopAppBar(title = { Text(stringResource(R.string.settings_title)) }) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
        ) {
            // ── PGPony Pro Section ─────────────────────────────────────
            SectionHeader(stringResource(R.string.settings_section_pgpony_pro))
            if (billingState.isPro) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Filled.Star, null, tint = Color(0xFF8B5CF6), modifier = Modifier.size(24.dp))
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.settings_pro_active_label), style = MaterialTheme.typography.bodyLarge)
                        Text(stringResource(R.string.settings_pro_active_subtitle), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Icon(Icons.Filled.CheckCircle, null, tint = Color(0xFF22C55E), modifier = Modifier.size(20.dp))
                }
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Filled.Star, null, tint = Color(0xFF8B5CF6), modifier = Modifier.size(24.dp))
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(stringResource(R.string.settings_pro_upgrade_label), style = MaterialTheme.typography.bodyLarge)
                            Spacer(modifier = Modifier.width(6.dp))
                            ProBadge()
                        }
                        Text(stringResource(R.string.settings_pro_unlock_price_format, billingState.proPrice),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { proGateFeature = ProFeature.UNLIMITED_KEYS },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8B5CF6))
                    ) {
                        Icon(Icons.Filled.Star, null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(stringResource(R.string.settings_pro_unlock_button))
                    }
                    OutlinedButton(onClick = { billingService.restorePurchases() }) {
                        Text(stringResource(R.string.settings_pro_restore_button))
                    }
                }
            }
            Spacer(modifier = Modifier.height(16.dp))

            // ── Security Section ───────────────────────────────────────
            SectionHeader(stringResource(R.string.settings_section_security))
            SettingsToggle(
                title = stringResource(R.string.settings_biometric_lock_title),
                subtitle = stringResource(R.string.settings_biometric_lock_subtitle),
                icon = Icons.Filled.Fingerprint,
                iconTint = Color(0xFF8B5CF6),
                checked = state.biometricLockEnabled,
                onCheckedChange = { viewModel.setBiometricLock(context, it) }
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
                onCheckedChange = { viewModel.setRequireBiometricForSign(it) }
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
            Spacer(modifier = Modifier.height(16.dp))

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
            state.defaultKeyName?.let { name ->
                SettingsRow(
                    title = stringResource(R.string.settings_key_default_label),
                    value = stringResource(R.string.settings_key_default_format, name, state.defaultKeyFingerprint ?: ""),
                    icon = Icons.Filled.Star,
                    iconTint = Color(0xFFF59E0B)
                )
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
            Spacer(modifier = Modifier.height(16.dp))

            // ── Data Section ───────────────────────────────────────────
            SectionHeader(stringResource(R.string.settings_section_data))
            TextButton(
                onClick = { viewModel.showClearConfirm() },
                colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
            ) {
                Icon(Icons.Filled.Delete, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.settings_data_clear_all_button))
            }
            Spacer(modifier = Modifier.height(16.dp))

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
                            android.net.Uri.parse("https://pgpony.norsehor.se/privacy")
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
            Spacer(modifier = Modifier.height(16.dp))

            // ── More from NorseHorse ───────────────────────────────────
            // AgePony: play flavor opens the Play listing, foss opens
            // agepony.com, routed through the MoreLinks helper. The full app
            // source and the open-source crypto engine (PGPonyCore-Kotlin)
            // both open on GitHub in a Custom Tab.
            SectionHeader(stringResource(R.string.settings_section_more))
            SettingsAction(
                title = stringResource(R.string.settings_more_agepony_title),
                subtitle = stringResource(R.string.settings_more_agepony_subtitle),
                icon = Icons.Filled.Lock,
                iconTint = Color(0xFF22C55E),
                trailingIcon = Icons.AutoMirrored.Filled.OpenInNew,
                onClick = {
                    // FD2: routed through the flavor-specific MoreLinks helper.
                    // play opens the Play listing; foss opens agepony.com, so
                    // the FOSS APK carries no market:// or play.google.com link.
                    MoreLinks.openAgePony(context) {
                        viewModel.showError(
                            context.getString(R.string.settings_support_browser_error)
                        )
                    }
                }
            )
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

            // Footer
            Text(
                stringResource(R.string.settings_about_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                modifier = Modifier.fillMaxWidth().padding(bottom = 24.dp)
            )
        }
    }

    // ── Clear Data Dialogs ─────────────────────────────────────────────
    if (state.showClearConfirm) {
        AlertDialog(
            onDismissRequest = { viewModel.dismissClear() },
            title = { Text(stringResource(R.string.settings_data_clear_step1_title)) },
            text = { Text(stringResource(R.string.settings_data_clear_step1_body)) },
            confirmButton = {
                TextButton(
                    onClick = { viewModel.showClearStep2() },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                ) { Text(stringResource(R.string.common_button_continue)) }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissClear() }) { Text(stringResource(R.string.common_button_cancel)) }
            }
        )
    }

    if (state.showClearStep2) {
        AlertDialog(
            onDismissRequest = { viewModel.dismissClear() },
            title = { Text(stringResource(R.string.settings_data_clear_step2_title)) },
            text = { Text(stringResource(R.string.settings_data_clear_step2_body)) },
            confirmButton = {
                TextButton(
                    onClick = { viewModel.clearAllData() },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                ) { Text(stringResource(R.string.settings_data_clear_step2_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissClear() }) { Text(stringResource(R.string.common_button_cancel)) }
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
