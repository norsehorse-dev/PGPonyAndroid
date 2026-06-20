// TrustLevelSheet.kt
// PGPony Android — Phase A4b
//
// Modal bottom sheet for changing a key's trust level. Replaces the
// A4a "Coming in next update" stub on the Trust Level row of the
// Details section.
//
// Four levels (matches iOS PGPony TrustLevelPicker):
//   • Unknown    — no validation done
//   • Unverified — added to keyring but not vetted
//   • Verified   — verified via QR / fingerprint exchange
//   • Ultimate   — your own key, or a key you fully control
//
// Trust is a UI/UX hint stored on PGPKeyEntity; it doesn't affect
// what crypto operations are permitted. The "Verified" check icon
// rendered next to a key in lists is what surfaces this status to
// the user during recipient selection.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.data.TrustLevel
import com.pgpony.android.ui.components.TrustBadge

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrustLevelSheet(
    currentTrust: TrustLevel,
    onSelect: (TrustLevel) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState()
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                stringResource(R.string.trust_sheet_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                stringResource(R.string.trust_sheet_subtitle),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))

            // One row per level. The currently-selected level shows a
            // check icon on the right; tapping any row applies it and
            // dismisses the sheet (matches iOS picker UX — no separate
            // Save button needed).
            TrustLevel.entries.forEach { level ->
                TrustLevelRow(
                    level = level,
                    isSelected = level == currentTrust,
                    onClick = { onSelect(level) }
                )
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun TrustLevelRow(
    level: TrustLevel,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .background(
                if (isSelected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
                else androidx.compose.ui.graphics.Color.Transparent
            )
            .padding(horizontal = 12.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Reuse the same TrustBadge that KeyCard uses so the icon
        // matches across surfaces.
        TrustBadge(level)
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = level.localizedName(),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = level.descriptionText(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (isSelected) {
            Icon(
                imageVector = Icons.Filled.Check,
                contentDescription = stringResource(R.string.trust_sheet_selected_cd),
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

/** Per-level descriptive blurb shown under the name.
 *
 *  Phase A13 — was a `private fun` returning a hardcoded English
 *  string. Now `@Composable` so it can call stringResource(), and
 *  promoted to `internal` so KeyCard (which previously duplicated
 *  the same English strings inline) can share it.
 */
@androidx.compose.runtime.Composable
internal fun TrustLevel.descriptionText(): String = when (this) {
    TrustLevel.UNKNOWN     -> stringResource(R.string.trust_level_unknown_description)
    TrustLevel.UNVERIFIED  -> stringResource(R.string.trust_level_unverified_description)
    TrustLevel.VERIFIED    -> stringResource(R.string.trust_level_verified_description)
    TrustLevel.ULTIMATE    -> stringResource(R.string.trust_level_ultimate_description)
}

/** Phase A13 — localized name lookup for TrustLevel enum.
 *  The enum still exposes displayName as English for compat;
 *  UI call sites use this @Composable extension instead. */
@androidx.compose.runtime.Composable
internal fun TrustLevel.localizedName(): String = when (this) {
    TrustLevel.UNKNOWN    -> stringResource(R.string.trust_level_unknown_name)
    TrustLevel.UNVERIFIED -> stringResource(R.string.trust_level_unverified_name)
    TrustLevel.VERIFIED   -> stringResource(R.string.trust_level_verified_name)
    TrustLevel.ULTIMATE   -> stringResource(R.string.trust_level_ultimate_name)
}
