// GroupParts.kt
// PGPony Android, 4.8.0 RC8 (item 4n): the pieces of the recipient group UI
// that more than one screen uses: the Encrypt picker sheet (group rows, the
// pick note, Save as group), the Groups screen and Key Details (the name
// dialog). Texts come from string resources; the rules behind them are in
// data/groups/RecipientGroups.

package com.pgpony.android.ui.groups

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.clickable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.data.groups.GroupNameProblem
import com.pgpony.android.data.groups.LeftOutMember
import com.pgpony.android.data.groups.LeftOutReason
import com.pgpony.android.data.groups.RecipientGroup
import com.pgpony.android.data.groups.RecipientGroups
import com.pgpony.android.ui.encrypt.GroupPickNote
import kotlinx.coroutines.launch

/** The message for a refused group name. */
@Composable
fun groupNameProblemText(problem: GroupNameProblem): String = when (problem) {
    GroupNameProblem.BLANK -> stringResource(R.string.groups_name_blank)
    GroupNameProblem.TOO_LONG -> stringResource(R.string.groups_name_too_long, RecipientGroups.NAME_MAX_LENGTH)
    GroupNameProblem.TAKEN -> stringResource(R.string.groups_name_taken)
}

/** A left-out member as "Name (why)". */
@Composable
fun leftOutText(member: LeftOutMember): String = when (member.reason) {
    LeftOutReason.REVOKED -> stringResource(R.string.groups_left_out_revoked, member.label)
    LeftOutReason.EXPIRED -> stringResource(R.string.groups_left_out_expired, member.label)
    LeftOutReason.NO_CERTIFICATE -> stringResource(R.string.groups_left_out_no_certificate, member.label)
    LeftOutReason.DELETED -> stringResource(R.string.groups_left_out_deleted, member.label)
    LeftOutReason.NOT_IN_KEYRING -> stringResource(R.string.groups_left_out_missing, member.label)
}

/** A member's state as a short status word, or null for a usable key. */
@Composable
fun memberStatusText(reason: LeftOutReason?): String? = when (reason) {
    null -> null
    LeftOutReason.REVOKED -> stringResource(R.string.groups_status_revoked)
    LeftOutReason.EXPIRED -> stringResource(R.string.groups_status_expired)
    LeftOutReason.NO_CERTIFICATE -> stringResource(R.string.groups_status_no_certificate)
    LeftOutReason.DELETED -> stringResource(R.string.groups_status_deleted)
    LeftOutReason.NOT_IN_KEYRING -> stringResource(R.string.groups_status_missing)
}

/** One group in the Encrypt picker sheet: tap to add its keys. */
@Composable
fun RecipientGroupPickRow(group: RecipientGroup, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.Groups,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 12.dp).size(24.dp)
        )
        Spacer(modifier = Modifier.width(4.dp))
        Column(modifier = Modifier.weight(1f)) {
            // bodyMedium, like the key rows under it.
            Text(group.name, style = MaterialTheme.typography.bodyMedium)
            Text(
                pluralStringResource(R.plurals.groups_member_count, group.members.size, group.members.size),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/** What the last group pick added and left out. */
@Composable
fun GroupPickNoteText(note: GroupPickNote, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth()) {
        Text(
            if (note.added > 0) {
                pluralStringResource(R.plurals.groups_pick_added, note.added, note.added, note.groupName)
            } else {
                stringResource(R.string.groups_pick_none, note.groupName)
            },
            style = MaterialTheme.typography.bodyMedium
        )
        if (note.leftOut.isNotEmpty()) {
            val names = note.leftOut.map { leftOutText(it) }.joinToString(", ")
            Text(
                stringResource(R.string.groups_pick_left_out, names),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * Asks for a group name. [onConfirm] saves it and returns null, or returns
 * why the name was refused, which shows under the field and keeps the dialog
 * open. If it throws (the database), the save error shows there instead and
 * the dialog stays open; cancellation passes through.
 */
@Composable
fun GroupNameDialog(
    title: String,
    initialName: String = "",
    onConfirm: suspend (String) -> GroupNameProblem?,
    onDismiss: () -> Unit
) {
    var name by remember { mutableStateOf(initialName) }
    var problem by remember { mutableStateOf<GroupNameProblem?>(null) }
    var saveFailed by remember { mutableStateOf(false) }
    var working by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = { Text(title) },
        text = {
            val shownProblem = problem
            val failed = saveFailed
            OutlinedTextField(
                value = name,
                onValueChange = { name = it; problem = null; saveFailed = false },
                label = { Text(stringResource(R.string.groups_name_label)) },
                singleLine = true,
                isError = problem != null || failed,
                supportingText = if (shownProblem != null) {
                    { Text(groupNameProblemText(shownProblem)) }
                } else if (failed) {
                    { Text(stringResource(R.string.groups_error_save)) }
                } else null,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                modifier = Modifier.fillMaxWidth()
            )
        },
        confirmButton = {
            TextButton(
                enabled = !working && name.isNotBlank(),
                onClick = {
                    working = true
                    saveFailed = false
                    scope.launch {
                        val p = try {
                            onConfirm(name)
                        } catch (e: kotlinx.coroutines.CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            working = false
                            saveFailed = true
                            return@launch
                        }
                        working = false
                        if (p == null) onDismiss() else problem = p
                    }
                }
            ) {
                Text(stringResource(R.string.common_button_save))
            }
        },
        dismissButton = {
            TextButton(enabled = !working, onClick = onDismiss) {
                Text(stringResource(R.string.common_button_cancel))
            }
        }
    )
}
