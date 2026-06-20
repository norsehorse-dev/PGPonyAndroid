// ContactLinkSheet.kt
// PGPony Android — Phase A4b
//
// Modal bottom sheet for linking a PGP key to a contact in the user's
// device address book. Replaces the A4a "Coming in next update" stubs
// for both "Link to Contact" and "Auto-match by email" actions.
//
// Permission handling lives in KeyDetailScreen (because Compose's
// rememberLauncherForActivityResult belongs at the screen level); by
// the time this sheet is shown, READ_CONTACTS has been granted and a
// snapshot of contacts-with-email has been fetched. The sheet is a
// pure presentation layer over that snapshot — no Android Contacts
// API calls happen here.
//
// Two presentation modes via the [filterEmail] arg:
//   • null  — full picker, every contact with at least one email
//   • set   — auto-match mode, only contacts whose email list contains
//             the supplied email (case-insensitive)
//
// The state machine for the auto-match case is handled at the screen
// level: if filterEmail yields exactly one hit, the screen can short-
// circuit and link directly without showing this sheet; if multiple
// hits or none, the sheet renders the filtered list (or the empty
// state) so the user picks the right one.

package com.pgpony.android.ui.keyring

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
import androidx.compose.material.icons.filled.ContactPage
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pgpony.android.R
import com.pgpony.android.contacts.DeviceContact

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactLinkSheet(
    contacts: List<DeviceContact>,
    filterEmail: String? = null,
    onSelect: (DeviceContact) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val visible = remember(contacts, filterEmail) {
        if (filterEmail.isNullOrBlank()) contacts
        else {
            val needle = filterEmail.trim().lowercase()
            contacts.filter { c -> c.emails.any { it.lowercase() == needle } }
        }
    }

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
                text = if (filterEmail.isNullOrBlank()) stringResource(R.string.contact_link_sheet_title_link) else stringResource(R.string.contact_link_sheet_title_auto_match),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            if (!filterEmail.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.contact_link_sheet_filter_format, filterEmail),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(modifier = Modifier.height(12.dp))

            when {
                visible.isEmpty() -> EmptyState(filterEmail = filterEmail, onDismiss = onDismiss)
                else -> ContactList(
                    contacts = visible,
                    onSelect = onSelect
                )
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun ContactList(
    contacts: List<DeviceContact>,
    onSelect: (DeviceContact) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(max = 480.dp)
    ) {
        items(contacts, key = { it.contactId }) { contact ->
            ContactRow(contact = contact, onClick = { onSelect(contact) })
            HorizontalDivider(
                modifier = Modifier.padding(start = 60.dp),
                color = MaterialTheme.colorScheme.surfaceVariant
            )
        }
    }
}

@Composable
private fun ContactRow(
    contact: DeviceContact,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        ContactInitialsAvatar(name = contact.displayName)
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = contact.displayName.ifBlank { contact.emails.firstOrNull() ?: "(no name)" },
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface
            )
            val emailSummary = if (contact.emails.size <= 1) {
                contact.emails.firstOrNull().orEmpty()
            } else {
                "${contact.emails.first()} (+${contact.emails.size - 1} more)"
            }
            if (emailSummary.isNotBlank()) {
                Text(
                    text = emailSummary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun ContactInitialsAvatar(name: String) {
    // Derive initials the same way PGPKeyEntity does — first letter of
    // up to two words. Keeps the look consistent with KeyCard / KeyAvatarHero.
    val initials = remember(name) {
        val parts = name.split(" ").filter { it.isNotBlank() }
        when {
            parts.size >= 2 -> "${parts[0].take(1)}${parts[1].take(1)}".uppercase()
            parts.isNotEmpty() -> parts[0].take(2).uppercase()
            else -> "?"
        }
    }
    Box(
        modifier = Modifier
            .size(36.dp)
            .clip(CircleShape)
            .background(Color(0xFF6366F1)),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = initials,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 14.sp
        )
    }
}

@Composable
private fun EmptyState(filterEmail: String?, onDismiss: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Icon(
            imageVector = Icons.Filled.ContactPage,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(40.dp)
        )
        Text(
            text = if (filterEmail.isNullOrBlank()) {
stringResource(R.string.contact_link_sheet_empty_generic)
            } else {
stringResource(R.string.contact_link_sheet_empty_filtered_format, filterEmail)
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedButton(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.common_button_close))
        }
    }
}
