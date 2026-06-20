// SignAsSheet.kt
// PGPony Android — Phase A5
//
// Modal bottom sheet for picking which key pair to sign with. Replaces
// the implicit "auto-pick default key" behavior from A2 in two places:
//
//   1. EncryptModeBody: when the user toggles on "Also sign this
//      message" AND they own more than one key pair, the Sign-as row
//      becomes tappable and opens this sheet.
//   2. SignModeBody: signing IS the operation in this mode, so the
//      sign-as row is always tappable when there are 2+ key pairs.
//
// iOS-parity reference: EncryptView.swift's `signingKeyPicker`
// (a SwiftUI Picker with .pickerStyle(.menu)). Android picks
// ModalBottomSheet over DropdownMenu because the per-key row carries
// more visual info (name, email, fingerprint, default pill, check
// indicator) than a flat dropdown menu row can sensibly show.
//
// Scope deliberately limited to KEY PAIR selection, not subkey
// selection. For PGPony's Ed25519+Cv25519 keys the primary is the
// signing key and the only encryption subkey is Cv25519 — there's no
// meaningful subkey choice to make. If/when multi-signing-subkey
// support lands (post-v1.0), a second-level picker can sit inside this
// sheet or be its own follow-on.

package com.pgpony.android.ui.encrypt

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SignAsSheet(
    keyPairs: List<PGPKeyEntity>,
    currentSelection: PGPKeyEntity?,
    onSelect: (PGPKeyEntity) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 8.dp)
        ) {
            Text(
                text = stringResource(R.string.sign_as_sheet_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.sign_as_sheet_explainer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(12.dp))

            when {
                keyPairs.isEmpty() -> EmptyState()
                else -> SigningKeyList(
                    keyPairs = keyPairs,
                    currentSelection = currentSelection,
                    onSelect = onSelect
                )
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

// ── Body composables ──────────────────────────────────────────────────

@Composable
private fun SigningKeyList(
    keyPairs: List<PGPKeyEntity>,
    currentSelection: PGPKeyEntity?,
    onSelect: (PGPKeyEntity) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(max = 480.dp)
    ) {
        items(keyPairs, key = { it.fingerprint }) { key ->
            SigningKeyRow(
                key = key,
                isSelected = currentSelection?.fingerprint == key.fingerprint,
                onClick = { onSelect(key) }
            )
            HorizontalDivider(
                modifier = Modifier.padding(start = 60.dp),
                color = MaterialTheme.colorScheme.surfaceVariant
            )
        }
    }
}

@Composable
private fun SigningKeyRow(
    key: PGPKeyEntity,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Small avatar — matches the KeyCard 44dp convention but a bit
        // smaller (36dp) since rows are denser inside a sheet.
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(CircleShape)
                .background(Color(0xFF8B5CF6)),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = key.initials,
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )
        }
        Spacer(modifier = Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = key.userName.ifBlank { key.userEmail.ifBlank { "(no name)" } },
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                if (key.isDefault) {
                    DefaultPill()
                }
            }
            // Email shown as the second line ONLY when it differs from
            // the first line. Avoids "Alice / Alice" double-rendering
            // when the user ID has no display-name component.
            if (key.userName.isNotBlank() && key.userEmail.isNotBlank()) {
                Text(
                    text = key.userEmail,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(
                text = key.shortFingerprint,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = FontFamily.Monospace
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
            )
        }

        if (isSelected) {
            Icon(
                imageVector = Icons.Filled.Check,
                contentDescription = stringResource(R.string.sign_as_sheet_selected_cd),
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

/** Small purple pill rendered next to the default key's name. Visually
 *  matches the DEFAULT pill in KeyDetailScreen's header so users can
 *  pattern-match across the two surfaces. */
@Composable
private fun DefaultPill() {
    Surface(
        shape = RoundedCornerShape(50),
        color = Color(0xFF8B5CF6)
    ) {
        Text(
            text = stringResource(R.string.sign_as_sheet_default_badge),
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp),
            fontWeight = FontWeight.Bold,
            color = Color.White,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

@Composable
private fun EmptyState() {
    // Defensive — the picker shouldn't be openable when there are no
    // key pairs, but if some race somehow gets us here, fail soft with
    // an explanatory message rather than a blank sheet.
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = stringResource(R.string.sign_as_sheet_empty),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Generate or import a private key first in the Keyring tab.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
