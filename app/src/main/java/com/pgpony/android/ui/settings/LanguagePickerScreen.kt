// LanguagePickerScreen.kt
// PGPony Android — A14 Picker
//
// Settings → Appearance → Language full-screen Composable. Android equivalent
// of iOS LanguagePickerView.swift. Lists the six supported languages by their
// native names with a checkmark next to the currently-selected one. Tapping
// a row calls LanguageManager.setLanguage(), which persists via AppCompat
// and triggers Activity recreation — the new translations apply across the
// whole UI within ~200ms.
//
// Rendered as an overlay (full-screen Composable conditionally shown from
// SettingsScreen) rather than a NavController route. That matches the pattern
// SecurityInfoScreen already uses elsewhere in Settings, and avoids polluting
// the bottom-nav graph with a sub-route that's only reachable from one place.
//
// Footer footnote ("Most screens update immediately. Restart PGPony if some
// text remains in the previous language.") mirrors iOS — caveats apply to
// a handful of surfaces that re-read their locale only at activity create,
// notably anything launched as a separate process (e.g. unlikely-to-exist
// future widget contexts).

package com.pgpony.android.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.i18n.LanguageManager
import com.pgpony.android.i18n.LanguageState
import com.pgpony.android.i18n.SupportedLanguage

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LanguagePickerScreen(onDismiss: () -> Unit) {
    // Subscribe to the observable so the checkmark moves instantly when
    // the user taps a different row. AppCompatDelegate will follow up
    // with an Activity recreation that re-renders the entire UI in the
    // new language, but the tap feedback shouldn't wait for that round trip.
    val current by LanguageState.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.language_picker_title)) },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.common_button_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize(),
            contentPadding = PaddingValues(vertical = 16.dp),
        ) {
            items(SupportedLanguage.entries.toList()) { lang ->
                LanguageRow(
                    lang = lang,
                    isSelected = current == lang.tag,
                    onClick = { LanguageManager.setLanguage(lang) },
                )
            }
            item {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.language_picker_footer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 20.dp),
                )
            }
        }
    }
}

@Composable
private fun LanguageRow(
    lang: SupportedLanguage,
    isSelected: Boolean,
    onClick: () -> Unit,
) {
    val container =
        if (isSelected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f)
        else androidx.compose.ui.graphics.Color.Transparent
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 2.dp)
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .background(container),
        color = androidx.compose.ui.graphics.Color.Transparent,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = lang.nativeName,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                modifier = Modifier.weight(1f),
            )
            if (isSelected) {
                Icon(
                    imageVector = Icons.Default.Check,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }
}
