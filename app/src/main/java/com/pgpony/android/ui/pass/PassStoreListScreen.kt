// Phase C0 — Password Store list. Lists imported pass stores and imports new
// ones via the Storage Access Framework folder picker (ACTION_OPEN_DOCUMENT_TREE
// + persistable read permission). Read-only; browsing + decryption land in C1.
// This screen is only reachable when "Password Store" is enabled in Settings.

package com.pgpony.android.ui.pass

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import android.content.Context
import com.pgpony.android.R
import com.pgpony.android.crypto.pass.PassStorePrefs
import com.pgpony.android.crypto.pass.PassStoreRef
import com.pgpony.android.crypto.pass.PassStoreService

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PassStoreListScreen(
    onBack: () -> Unit,
    onOpenStore: (String) -> Unit = {}
) {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("pgpony_prefs", Context.MODE_PRIVATE) }
    val service = remember { PassStoreService(context) }

    var stores by remember { mutableStateOf(PassStorePrefs.load(prefs)) }
    var pendingDelete by remember { mutableStateOf<PassStoreRef?>(null) }

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            try {
                service.persistPermission(uri)
                val ref = service.buildRef(uri)
                stores = PassStorePrefs.upsert(prefs, ref)
            } catch (_: Exception) {
                // A revoked/!persistable grant just leaves the list unchanged.
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.pass_store_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = stringResource(R.string.pass_back))
                    }
                },
                actions = {
                    IconButton(onClick = { picker.launch(null) }) {
                        Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.pass_store_import))
                    }
                }
            )
        }
    ) { padding ->
        if (stores.isEmpty()) {
            EmptyState(
                modifier = Modifier.padding(padding),
                onImport = { picker.launch(null) }
            )
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(stores, key = { it.id }) { store ->
                    StoreRow(
                        store = store,
                        onOpen = { onOpenStore(store.id) },
                        onDelete = { pendingDelete = store }
                    )
                }
            }
        }
    }

    val toDelete = pendingDelete
    if (toDelete != null) {
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(stringResource(R.string.pass_store_remove_title)) },
            text = { Text(stringResource(R.string.pass_store_remove_message, toDelete.displayName)) },
            confirmButton = {
                TextButton(onClick = {
                    stores = PassStorePrefs.remove(prefs, toDelete.id)
                    pendingDelete = null
                }) { Text(stringResource(R.string.pass_store_remove_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(stringResource(R.string.pass_cancel))
                }
            }
        )
    }
}

@Composable
private fun StoreRow(store: PassStoreRef, onOpen: () -> Unit, onDelete: () -> Unit) {
    Card(
        onClick = onOpen,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Filled.Folder, contentDescription = null, modifier = Modifier.size(28.dp))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(store.displayName, style = MaterialTheme.typography.titleMedium)
                val count = store.rootGpgIds.size
                Text(
                    if (count > 0)
                        pluralStringResource(R.plurals.pass_store_recipients, count, count)
                    else
                        stringResource(R.string.pass_store_no_gpg_id),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(onClick = onDelete) {
                Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.pass_store_remove_title))
            }
        }
    }
}

@Composable
private fun EmptyState(modifier: Modifier = Modifier, onImport: () -> Unit) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            Icons.Filled.Lock,
            contentDescription = null,
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.height(16.dp))
        Text(
            stringResource(R.string.pass_store_empty_title),
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.pass_store_empty_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(24.dp))
        Button(onClick = onImport) {
            Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.pass_store_import))
        }
    }
}
