// GroupsScreen.kt
// PGPony Android, 4.8.0 RC8 (item 4n): Keyring > Groups.
//
// Lists the recipient groups and creates, renames, edits the keys of and
// deletes them. A pushed page under the Keyring (the "groups" route in
// MainActivity, reached from the Keyring's More menu), the same way Recently
// Deleted is. Picking a group happens in the Encrypt recipient sheet; this
// page only manages them. A member whose key is in Recently Deleted stays in
// the group and is shown as such, so restoring the key puts it back.

package com.pgpony.android.ui.groups

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Checklist
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.material3.rememberModalBottomSheetState
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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.pgpony.android.R
import com.pgpony.android.data.groups.GroupNameProblem
import com.pgpony.android.data.groups.LeftOutReason
import com.pgpony.android.data.groups.RecipientGroup
import com.pgpony.android.data.groups.RecipientGroups
import com.pgpony.android.ui.util.dismissKeyboardOnTap
import com.pgpony.android.ui.util.keepsKeyboard
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupsScreen(onBack: () -> Unit) {
    val vm: GroupsViewModel = viewModel()
    val state by vm.state.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    var creating by remember { mutableStateOf(false) }
    var editTarget by remember { mutableStateOf<RecipientGroup?>(null) }
    var renameTarget by remember { mutableStateOf<RecipientGroup?>(null) }
    var deleteTarget by remember { mutableStateOf<RecipientGroup?>(null) }

    // Read again on every entry, so a key deleted or restored meanwhile shows.
    LaunchedEffect(Unit) { vm.refresh() }
    LaunchedEffect(state.message) {
        state.message?.let {
            snackbarHostState.showSnackbar(it)
            vm.consumeMessage()
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.groups_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.common_button_back)
                        )
                    }
                },
                actions = {
                    if (state.loaded && !state.loadFailed && state.groups.isNotEmpty()) {
                        IconButton(onClick = { creating = true }) {
                            Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.groups_new))
                        }
                    }
                }
            )
        }
    ) { padding ->
        // Nothing until the first read, so the empty state never flashes.
        if (!state.loaded) return@Scaffold
        when {
            state.loadFailed -> CenteredNote(
                text = stringResource(R.string.groups_load_failed),
                modifier = Modifier.padding(padding)
            )
            state.groups.isEmpty() -> Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.padding(32.dp)
                ) {
                    Text(
                        text = stringResource(R.string.groups_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(onClick = { creating = true }, enabled = state.keys.isNotEmpty()) {
                        Text(stringResource(R.string.groups_new))
                    }
                }
            }
            else -> LazyColumn(modifier = Modifier.fillMaxSize().padding(padding)) {
                items(state.groups, key = { it.id }) { group ->
                    GroupRow(
                        group = group,
                        deletedCount = group.members.count { vm.reasonFor(it) == LeftOutReason.DELETED },
                        onOpen = { editTarget = group },
                        onRename = { renameTarget = group },
                        onDelete = { deleteTarget = group }
                    )
                    HorizontalDivider(modifier = Modifier.padding(horizontal = 16.dp))
                }
            }
        }
    }

    if (creating) {
        GroupEditorSheet(
            title = stringResource(R.string.groups_new),
            askName = true,
            initialMembers = emptySet(),
            vm = vm,
            onSave = { name, members -> vm.create(name, members) },
            onDismiss = { creating = false }
        )
    }
    editTarget?.let { target ->
        GroupEditorSheet(
            title = stringResource(R.string.groups_edit_keys_title, target.name),
            askName = false,
            initialMembers = target.members.toSet(),
            vm = vm,
            onSave = { _, members -> vm.setMembers(target.id, members); null },
            onDismiss = { editTarget = null }
        )
    }
    renameTarget?.let { target ->
        GroupNameDialog(
            title = stringResource(R.string.groups_rename_title),
            initialName = target.name,
            onConfirm = { vm.rename(target.id, it) },
            onDismiss = { renameTarget = null }
        )
    }
    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(stringResource(R.string.groups_delete_title)) },
            text = { Text(stringResource(R.string.groups_delete_body, target.name)) },
            confirmButton = {
                TextButton(onClick = {
                    vm.delete(target.id)
                    deleteTarget = null
                }) {
                    Text(stringResource(R.string.common_button_delete), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        )
    }
}

@Composable
private fun CenteredNote(text: String, modifier: Modifier = Modifier) {
    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(32.dp)
        )
    }
}

@Composable
private fun GroupRow(
    group: RecipientGroup,
    deletedCount: Int,
    onOpen: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit
) {
    var menuOpen by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen)
            .padding(start = 16.dp, end = 4.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(group.name, style = MaterialTheme.typography.bodyLarge)
            val count = pluralStringResource(R.plurals.groups_member_count, group.members.size, group.members.size)
            Text(
                if (deletedCount > 0) {
                    count + " · " + pluralStringResource(R.plurals.groups_member_deleted_count, deletedCount, deletedCount)
                } else count,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Box {
            IconButton(onClick = { menuOpen = true }) {
                Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.keyring_more_cd))
            }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.groups_edit_keys)) },
                    leadingIcon = { Icon(Icons.Filled.Checklist, contentDescription = null) },
                    onClick = { menuOpen = false; onOpen() }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.groups_rename)) },
                    leadingIcon = { Icon(Icons.Filled.Edit, contentDescription = null) },
                    onClick = { menuOpen = false; onRename() }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.common_button_delete)) },
                    leadingIcon = { Icon(Icons.Filled.Delete, contentDescription = null) },
                    onClick = { menuOpen = false; onDelete() }
                )
            }
        }
    }
}

/**
 * Names a new group and picks its keys, or edits the keys of one. Lists the
 * live keys in the picker's order, then the group's members whose key is in
 * Recently Deleted or gone, which can be taken out. [onSave] returns
 * null once saved, or why the name was refused.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GroupEditorSheet(
    title: String,
    askName: Boolean,
    initialMembers: Set<String>,
    vm: GroupsViewModel,
    onSave: suspend (name: String, members: Set<String>) -> GroupNameProblem?,
    onDismiss: () -> Unit
) {
    val state by vm.state.collectAsState()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<GroupNameProblem?>(null) }
    var query by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var members by remember { mutableStateOf(initialMembers.map(RecipientGroups::normalize).toSet()) }

    val liveFps = state.keys.map { RecipientGroups.normalize(it.fingerprint) }.toSet()
    // Members without a live key: binned or gone. Listed so they can be taken out.
    val others = initialMembers.map(RecipientGroups::normalize).filter { it !in liveFps }.distinct()
    val q = query.trim().lowercase()
    val shownKeys = state.keys.filter {
        q.isEmpty() || it.userName.lowercase().contains(q) || it.userEmail.lowercase().contains(q) ||
            it.fingerprint.lowercase().contains(q)
    }
    val shownOthers = others.filter { q.isEmpty() || vm.labelFor(it).lowercase().contains(q) || it.contains(q) }
    val toggle: (String) -> Unit = { fp -> members = if (fp in members) members - fp else members + fp }

    ModalBottomSheet(onDismissRequest = { if (!working) onDismiss() }, sheetState = sheetState) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp)
                .dismissKeyboardOnTap()
        ) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(12.dp))
            if (askName) {
                val shownProblem = problem
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it; problem = null },
                    label = { Text(stringResource(R.string.groups_name_label)) },
                    singleLine = true,
                    isError = problem != null,
                    supportingText = if (shownProblem != null) {
                        { Text(groupNameProblemText(shownProblem)) }
                    } else null,
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                    modifier = Modifier.keepsKeyboard().fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
            }
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text(stringResource(R.string.encrypt_recipients_search_label)) },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                modifier = Modifier.keepsKeyboard().fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (state.keys.isEmpty() && others.isEmpty()) {
                Text(
                    stringResource(R.string.groups_editor_no_keys),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 16.dp)
                )
            } else if (shownKeys.isEmpty() && shownOthers.isEmpty()) {
                Text(
                    stringResource(R.string.encrypt_recipients_no_match_format, query),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 16.dp)
                )
            } else {
                LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 360.dp)) {
                    items(shownKeys.distinctBy { it.fingerprint }, key = { it.fingerprint }) { key ->
                        val fp = RecipientGroups.normalize(key.fingerprint)
                        val secondary = if (key.userName.isNotBlank() && key.userEmail.isNotBlank())
                            "${key.userEmail} · ${key.shortFingerprint}" else key.shortFingerprint
                        MemberRow(
                            label = key.userName.ifBlank { key.userEmail.ifBlank { key.shortFingerprint } },
                            secondary = secondary,
                            reason = vm.reasonFor(fp),
                            checked = fp in members,
                            enabled = true,
                            onToggle = { toggle(fp) }
                        )
                    }
                    items(shownOthers, key = { "other:$it" }) { fp ->
                        MemberRow(
                            label = vm.labelFor(fp),
                            secondary = RecipientGroups.shortFingerprint(fp),
                            reason = vm.reasonFor(fp),
                            checked = fp in members,
                            // Only the group's own members are listed here, so
                            // putting one back after taking it out is allowed.
                            enabled = true,
                            onToggle = { toggle(fp) }
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                TextButton(onClick = onDismiss, enabled = !working, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.common_button_cancel))
                }
                Button(
                    enabled = !working && (!askName || (name.isNotBlank() && members.isNotEmpty())),
                    onClick = {
                        working = true
                        scope.launch {
                            val p = onSave(name, members)
                            working = false
                            if (p == null) onDismiss() else problem = p
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Text(stringResource(R.string.common_button_save))
                }
            }
        }
    }
}

@Composable
private fun MemberRow(
    label: String,
    secondary: String,
    reason: LeftOutReason?,
    checked: Boolean,
    enabled: Boolean,
    onToggle: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(value = checked, enabled = enabled, role = Role.Checkbox, onValueChange = { onToggle() })
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(
            checked = checked,
            onCheckedChange = null,
            enabled = enabled,
            modifier = Modifier.minimumInteractiveComponentSize()
        )
        Spacer(modifier = Modifier.width(4.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                secondary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            memberStatusText(reason)?.let { status ->
                Text(
                    status,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (reason == LeftOutReason.REVOKED || reason == LeftOutReason.EXPIRED)
                        MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
