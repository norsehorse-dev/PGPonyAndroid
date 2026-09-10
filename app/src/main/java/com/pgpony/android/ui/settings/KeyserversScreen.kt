// KeyserversScreen.kt
// PGPony Android — 4.0.0 Phase 5a
//
// Settings → Key servers: manage the ordered directory. Per server, a
// lookup toggle and a publish toggle; reorder with up/down (lookup
// priority = list order); reset to defaults. Custom-server entry is a
// stretch item (plan) — deferred; the two seeds cover v1.
//
// Full-height ModalBottomSheet, self-contained via PGPonyApp.instance,
// same pattern as the other Settings overlays.

package com.pgpony.android.ui.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.keyserver.KeyServer
import com.pgpony.android.keyserver.KeyServerDirectory
import com.pgpony.android.network.WkdLookup
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyserversScreen(onDismiss: () -> Unit) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val directory = remember { KeyServerDirectory.get(PGPonyApp.instance) }
    val scope = rememberCoroutineScope()

    var servers by remember { mutableStateOf<List<KeyServer>>(emptyList()) }
    var refresh by remember { mutableIntStateOf(0) }
    var showAdd by remember { mutableStateOf(false) }

    LaunchedEffect(refresh) { servers = directory.readOnce() }

    fun reload() { refresh++ }

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
                .padding(bottom = 32.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Filled.Dns,
                    contentDescription = null,
                    tint = Color(0xFF8B5CF6),
                    modifier = Modifier.size(36.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    stringResource(R.string.keyservers_title),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                stringResource(R.string.keyservers_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 16.dp)
            )

            // item 21 (#request): WKD is the first lookup source but is not a
            // configured server, so surface it here as a lookup-only row that
            // matches the Import dialog and the real behavior.
            var wkdEnabled by remember { mutableStateOf(WkdLookup.isEnabled()) }
            WkdCard(
                enabled = wkdEnabled,
                onEnabledChange = { WkdLookup.set(it); wkdEnabled = it }
            )
            if (servers.isNotEmpty()) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
            }

            servers.forEachIndexed { index, server ->
                ServerCard(
                    server = server,
                    isFirst = index == 0,
                    isLast = index == servers.lastIndex,
                    onLookupChange = { scope.launch { directory.setLookupEnabled(server.id, it); reload() } },
                    onPublishChange = { scope.launch { directory.setPublishEnabled(server.id, it); reload() } },
                    onUp = { scope.launch { directory.move(server.id, up = true); reload() } },
                    onDown = { scope.launch { directory.move(server.id, up = false); reload() } },
                    removable = !KeyServerDirectory.isSeed(server.id),
                    onRemove = { scope.launch { directory.remove(server.id); reload() } }
                )
                if (index != servers.lastIndex) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                }
            }

            Spacer(modifier = Modifier.padding(vertical = 8.dp))
            TextButton(onClick = { showAdd = true }) {
                Icon(Icons.Filled.Add, contentDescription = null)
                Spacer(modifier = Modifier.width(4.dp))
                Text(stringResource(R.string.keyservers_add))
            }
            TextButton(onClick = { scope.launch { directory.resetToDefaults(); reload() } }) {
                Text(stringResource(R.string.keyservers_reset))
            }
        }
    }

    if (showAdd) {
        AddServerDialog(
            onAdd = { label, url ->
                scope.launch { directory.addCustom(label, url); reload() }
                showAdd = false
            },
            onDismiss = { showAdd = false }
        )
    }
}

@Composable
private fun AddServerDialog(
    onAdd: (label: String, url: String) -> Unit,
    onDismiss: () -> Unit
) {
    var label by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.keyservers_add_title)) },
        text = {
            Column {
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it },
                    label = { Text(stringResource(R.string.keyservers_add_label_hint)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.padding(vertical = 4.dp))
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it; error = false },
                    label = { Text(stringResource(R.string.keyservers_add_url_hint)) },
                    isError = error,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                if (error) {
                    Text(
                        stringResource(R.string.keyservers_add_invalid_url),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (KeyServerDirectory.normalizeBaseUrl(url) == null) error = true
                else onAdd(label, url)
            }) { Text(stringResource(R.string.keyservers_add_confirm)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_button_cancel)) }
        }
    )
}

@Composable
private fun WkdCard(enabled: Boolean, onEnabledChange: (Boolean) -> Unit) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(
            stringResource(R.string.keyservers_wkd_label),
            style = MaterialTheme.typography.bodyLarge
        )
        Text(
            stringResource(R.string.keyservers_wkd_desc),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        ToggleRow(
            label = stringResource(R.string.keyservers_lookup),
            checked = enabled,
            onCheckedChange = onEnabledChange
        )
    }
}

@Composable
private fun ServerCard(
    server: KeyServer,
    isFirst: Boolean,
    isLast: Boolean,
    onLookupChange: (Boolean) -> Unit,
    onPublishChange: (Boolean) -> Unit,
    onUp: () -> Unit,
    onDown: () -> Unit,
    removable: Boolean = false,
    onRemove: () -> Unit = {}
) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(server.label, style = MaterialTheme.typography.bodyLarge)
                    if (server.isFirstParty) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            stringResource(R.string.keyservers_first_party_badge),
                            style = MaterialTheme.typography.labelSmall,
                            color = Color(0xFF8B5CF6),
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
                Text(
                    server.baseUrl.removePrefix("https://"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(onClick = onUp, enabled = !isFirst) {
                Icon(Icons.Filled.ArrowUpward, stringResource(R.string.keyservers_move_up))
            }
            IconButton(onClick = onDown, enabled = !isLast) {
                Icon(Icons.Filled.ArrowDownward, stringResource(R.string.keyservers_move_down))
            }
            if (removable) {
                IconButton(onClick = onRemove) {
                    Icon(
                        Icons.Filled.Delete,
                        contentDescription = stringResource(R.string.keyservers_remove),
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
        ToggleRow(
            label = stringResource(R.string.keyservers_lookup),
            checked = server.lookupEnabled,
            onCheckedChange = onLookupChange
        )
        ToggleRow(
            label = stringResource(R.string.keyservers_publish),
            checked = server.publishEnabled,
            onCheckedChange = onPublishChange
        )
    }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 8.dp, top = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
