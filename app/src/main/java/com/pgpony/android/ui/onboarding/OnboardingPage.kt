// OnboardingPage.kt
// PGPony Android
//
// Renders a single onboarding slide. Icon + title + body, with optional
// inline action: a "Generate now" call-to-action button on slide 2, or
// a "Enable Biometric Lock" toggle on slide 5.
//
// Phase 3.1: The "Generate now" CTA now opens an inline ModalBottomSheet
// (OnboardingGenerateSheet) that actually generates the key. On success,
// the parent OnboardingScreen is told to advance the pager to the next
// slide via the onAdvance callback. If the user already has keys on file
// (e.g. they're replaying the tour from Settings), the CTA is replaced
// with a quiet confirmation row so they don't accidentally create
// another key.

package com.pgpony.android.ui.onboarding

import android.content.SharedPreferences
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.foundation.clickable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.i18n.LanguageManager
import com.pgpony.android.update.UpdateCheckService
import com.pgpony.android.i18n.LanguageState
import com.pgpony.android.i18n.SupportedLanguage
import com.pgpony.android.ui.keyring.KeyringViewModel

@Composable
fun OnboardingPage(
    slide: OnboardingSlide,
    prefs: SharedPreferences,
    keyringVm: KeyringViewModel,
    onAdvance: () -> Unit,
    onImportExisting: () -> Unit = {},
    onRestoreBackup: () -> Unit = {}
) {
    var showGenerateSheet by remember { mutableStateOf(false) }
    val keyringState by keyringVm.state.collectAsState()
    // 4.1.0 Phase 12b — keyPairCount, not myKeys.size. Behaviour here is
    // unchanged (a card-backed key still does not count as "you already
    // have a key"), but it is now explicit rather than a side effect of how
    // the keyring happens to be grouped. Whether importing a hardware key
    // should satisfy onboarding is a real question, deliberately left to
    // 4.2.0 rather than answered by accident here.
    val existingKeyCount = keyringState.keyPairCount

    // 4.1.1: the slide content had no scroll, so at a large display size or
    // font scale the generate CTA on slide 2 sat below the pager viewport
    // with no way to reach it. Issue #23, "impossible to create keys", and
    // the reporter was right. fillMaxSize stays so short slides still
    // center; the scroll only engages once content overflows the pager.
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 32.dp, vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // ── Icon ────────────────────────────────────────────────────────
        Box(
            modifier = Modifier
                .size(140.dp)
                .clip(CircleShape)
                .background(slide.iconTint.copy(alpha = 0.15f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                slide.icon,
                contentDescription = null,
                tint = slide.iconTint,
                modifier = Modifier.size(80.dp)
            )
        }

        Spacer(modifier = Modifier.height(40.dp))

        // ── Title ───────────────────────────────────────────────────────
        Text(
            stringResource(slide.titleResId),
            style = MaterialTheme.typography.headlineMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onBackground
        )

        Spacer(modifier = Modifier.height(20.dp))

        // ── Body ────────────────────────────────────────────────────────
        Text(
            stringResource(slide.bodyResId),
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        // ── Optional inline action ──────────────────────────────────────
        if (slide.showGenerateCta) {
            Spacer(modifier = Modifier.height(32.dp))
            if (existingKeyCount > 0) {
                // Replay scenario — they already have keys. Don't push more.
                ExistingKeysIndicator(count = existingKeyCount)
            } else {
                Button(
                    onClick = { showGenerateSheet = true },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8B5CF6)),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp)
                ) {
                    Icon(Icons.Filled.Add, null, modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        stringResource(R.string.onboarding_page_generate_cta),
                        style = MaterialTheme.typography.titleMedium
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    stringResource(R.string.onboarding_page_generate_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(16.dp))
                OpenKeychainOnboardingCard()
                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = onImportExisting, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.onboarding_page_import_existing))
                }
                TextButton(onClick = onRestoreBackup, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.onboarding_page_restore_backup))
                }
            }
        }

        if (slide.showBiometricToggle) {
            Spacer(modifier = Modifier.height(32.dp))
            BiometricToggleRow(prefs = prefs)
        }
        // RC1 offline switch: offered on the privacy slide, below biometric.
        if (slide.showOfflineToggle) {
            Spacer(modifier = Modifier.height(16.dp))
            OfflineToggleRow(prefs = prefs)
        }
        // §5.6.9 (Piotr): sideload update-check opt-in.
        if (slide.showUpdateToggle) {
            Spacer(modifier = Modifier.height(32.dp))
            UpdateToggleRow(prefs = prefs)
        }

        // A14 Picker — slide 0 hosts an inline language picker. Tapping
        // a row calls LanguageManager.setLanguage(), which:
        //   1. Updates LanguageState.current so the checkmark moves
        //      immediately (this Composable subscribes to the snapshot).
        //   2. Calls AppCompatDelegate.setApplicationLocales(), which on
        //      AppCompatActivity instances recreates the Activity within
        //      a few hundred ms. The carousel rebuilds in the new locale,
        //      so the body text + button labels on the remaining slides
        //      pick up the chosen language on the next slide swipe.
        if (slide.showLanguagePicker) {
            Spacer(modifier = Modifier.height(32.dp))
            OnboardingLanguagePicker()
        }
    }

    // ── Inline generate sheet (Phase 3.1) ────────────────────────────────
    if (showGenerateSheet) {
        OnboardingGenerateSheet(
            keyringVm = keyringVm,
            onSuccess = {
                showGenerateSheet = false
                onAdvance()
            },
            onDismiss = { showGenerateSheet = false }
        )
    }
}

// ── A14 Picker — inline language picker on slide 0 ──────────────────────
//
// Self-contained Composable so OnboardingPage doesn't need to grow its
// import list with the i18n types. Six rows, native names, tap-to-select.
//
// Layout differs from the Settings → Language picker:
//   • Settings picker is full-screen (room for footer footnote).
//   • Onboarding picker is inline below the slide body. The slide is
//     vertically space-constrained, so the rows are tighter (12dp pad
//     instead of 14dp) and there's no footer.
//
// Both call the same LanguageManager.setLanguage entry point, so the
// behaviour is identical — only the chrome differs.

@Composable
private fun OnboardingLanguagePicker() {
    val current by LanguageState.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
    ) {
        val langs = SupportedLanguage.entries
        langs.forEachIndexed { index, lang ->
            val selected = current == lang.tag
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { LanguageManager.setLanguage(lang) }
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = lang.nativeName,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
                if (selected) {
                    Icon(
                        imageVector = Icons.Filled.Check,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp),
                    )
                }
            }
            if (index < langs.size - 1) {
                HorizontalDivider(
                    modifier = Modifier.padding(start = 16.dp),
                    thickness = 0.5.dp,
                    color = MaterialTheme.colorScheme.outlineVariant,
                )
            }
        }
    }
}

@Composable
private fun ExistingKeysIndicator(count: Int) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = Color(0xFF22C55E).copy(alpha = 0.12f)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Filled.CheckCircle,
                contentDescription = null,
                tint = Color(0xFF22C55E),
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    if (count == 1) stringResource(R.string.onboarding_page_already_have_keys_one) else stringResource(R.string.onboarding_page_already_have_keys_other_format, count),
                    style = MaterialTheme.typography.bodyLarge
                )
                Text(
                    stringResource(R.string.onboarding_page_keyring_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun BiometricToggleRow(prefs: SharedPreferences) {
    var enabled by remember {
        mutableStateOf(prefs.getBoolean("biometric_lock", false))
    }
    // RC5 P3 (#23): same capability gate as Settings' setBiometricLock.
    // MainActivity's A11 lock gate assumes `biometric_lock == true`
    // implies the device could authenticate when it was enabled; this
    // toggle previously wrote the pref without checking. When the device
    // can't authenticate the switch renders disabled instead of arming a
    // lock the user could not open.
    val context = androidx.compose.ui.platform.LocalContext.current
    val canAuthenticate = remember {
        com.pgpony.android.ui.keyring.BiometricGate.canAuthenticate(context) ==
            com.pgpony.android.ui.keyring.BiometricAvailability.Available
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Filled.Fingerprint,
                contentDescription = null,
                tint = Color(0xFF8B5CF6),
                modifier = Modifier.size(28.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.onboarding_page_biometric_toggle_title),
                    style = MaterialTheme.typography.bodyLarge
                )
                Text(
                    stringResource(R.string.onboarding_page_biometric_toggle_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = enabled,
                enabled = canAuthenticate,
                onCheckedChange = { newValue ->
                    enabled = newValue
                    prefs.edit().putBoolean("biometric_lock", newValue).apply()
                }
            )
        }
    }
}

@Composable
private fun UpdateToggleRow(prefs: SharedPreferences) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var enabled by remember {
        mutableStateOf(UpdateCheckService.isEnabled(context))
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Filled.SystemUpdate,
                contentDescription = null,
                tint = Color(0xFF8B5CF6),
                modifier = Modifier.size(28.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.onboarding_page_updates_toggle_title),
                    style = MaterialTheme.typography.bodyLarge
                )
                Text(
                    stringResource(R.string.onboarding_page_updates_toggle_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = enabled,
                onCheckedChange = { newValue ->
                    enabled = newValue
                    UpdateCheckService.setEnabled(context, newValue)
                }
            )
        }
    }
}

@Composable
private fun OfflineToggleRow(prefs: SharedPreferences) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var enabled by remember {
        mutableStateOf(com.pgpony.android.network.OfflineMode.isEnabled())
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Filled.CloudOff,
                contentDescription = null,
                tint = Color(0xFF22C55E),
                modifier = Modifier.size(28.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.onboarding_page_offline_toggle_title),
                    style = MaterialTheme.typography.bodyLarge
                )
                Text(
                    stringResource(R.string.onboarding_page_offline_toggle_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = enabled,
                onCheckedChange = { newValue ->
                    enabled = newValue
                    com.pgpony.android.network.OfflineMode.set(newValue)
                    com.pgpony.android.sync.KeyRefreshScheduler.apply(context)
                }
            )
        }
    }
}

@Composable
private fun OpenKeychainOnboardingCard() {
    Surface(
        color = Color(0xFF8B5CF6).copy(alpha = 0.10f),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.Top) {
            Icon(
                Icons.Filled.SwapHoriz,
                contentDescription = null,
                tint = Color(0xFF8B5CF6),
                modifier = Modifier.size(22.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column {
                Text(
                    stringResource(R.string.okc_migration_title),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Start
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    stringResource(R.string.okc_migration_onboarding_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Start
                )
            }
        }
    }
}
