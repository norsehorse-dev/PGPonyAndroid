// ShareEncryptScreen.kt
// PGPony Android — Phase A15
//
// Recipient picker rendered inside ShareTargetActivity during the
// PickRecipients phase. Lighter than the main app's encrypt screen
// recipient list — no search, no trust-level filtering, no Pro gating:
//
//   • Why no search: the recipient list inside Quick Action is
//     typically the user's "people I send PGP to" set, which is
//     small (5–20 in practice). A full search bar inflates the UI
//     for marginal benefit on a screen that's already squeezed for
//     vertical space inside the activity card.
//   • Why no trust filtering: the user is in a hurry — Quick Action
//     is for the "I want to send this NOW" flow. Trust is a deeper
//     consideration; the main app's encrypt screen surfaces it.
//   • Why no Pro gate: monetization disabled until Nov 2026 per
//     project memory. When Pro lands, multi-recipient encrypt will
//     be gated, but for now multi-recipient is free for everyone.
//
// Selection model: tap a row to toggle in/out of selectedRecipients
// (Set<String> of fingerprints, owned by ShareTargetViewModel). The
// Encrypt button is disabled until at least one recipient is picked.

package com.pgpony.android.ui.share

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity

@Composable
fun ShareEncryptPicker(
    state: ShareTargetUiState,
    onToggleRecipient: (String) -> Unit,
    onConfirm: () -> Unit,
    onBack: () -> Unit,
) {
    val recipients = state.availableRecipients
    if (recipients.isEmpty()) {
        Text(
            text = stringResource(R.string.share_target_encrypt_recipients_empty),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
        )
        Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.common_button_back))
        }
        return
    }

    recipients.forEach { key ->
        val selected = key.fingerprint in state.selectedRecipients
        ShareRecipientRow(
            key = key,
            selected = selected,
            onClick = { onToggleRecipient(key.fingerprint) },
        )
    }

    if (state.errorMessage != null) {
        Text(
            text = state.errorMessage,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) {
            Text(stringResource(R.string.common_button_back))
        }
        Button(
            onClick = onConfirm,
            modifier = Modifier.weight(1f),
            enabled = state.selectedRecipients.isNotEmpty(),
        ) {
            Text(stringResource(R.string.share_target_encrypt_button))
        }
    }
}

@Composable
fun ShareRecipientRow(
    key: PGPKeyEntity,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val containerColor =
        if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f)
        else MaterialTheme.colorScheme.surfaceContainerHigh
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        color = containerColor,
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = if (selected) Icons.Default.Check else Icons.Default.Person,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp),
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = key.userID.ifBlank { key.fingerprint.take(16) },
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = key.longKeyId.chunked(4).joinToString(" "),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}
