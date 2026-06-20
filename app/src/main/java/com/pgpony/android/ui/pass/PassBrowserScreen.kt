// Phase C1 — browses a pass store's tree (folders + entries), built from
// filenames only (never decrypts to browse). The full tree is walked once off
// the main thread; folder navigation is an in-memory path stack so arbitrary
// depth works without a nav route per folder. Tapping an entry opens
// PassEntryScreen, which performs the (lazy) decryption.

package com.pgpony.android.ui.pass

import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.crypto.pass.PassNode
import com.pgpony.android.crypto.pass.PassStorePrefs
import com.pgpony.android.crypto.pass.PassStoreService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private sealed class LoadState {
    data object Loading : LoadState()
    data class Loaded(val root: PassNode.Folder) : LoadState()
    data object Failed : LoadState()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PassBrowserScreen(
    storeId: String,
    onBack: () -> Unit,
    onOpenEntry: (storeId: String, relativePath: String) -> Unit
) {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("pgpony_prefs", Context.MODE_PRIVATE) }
    val service = remember { PassStoreService(context) }
    val ref = remember(storeId) { PassStorePrefs.load(prefs).firstOrNull { it.id == storeId } }

    var loadState by remember { mutableStateOf<LoadState>(LoadState.Loading) }
    // Path stack of folders below the root; empty = at the root.
    val pathStack: SnapshotStateList<PassNode.Folder> = remember { mutableStateListOf() }

    LaunchedEffect(storeId) {
        if (ref == null) {
            loadState = LoadState.Failed
            return@LaunchedEffect
        }
        loadState = LoadState.Loading
        val root = withContext(Dispatchers.IO) { service.walkTree(ref) }
        loadState = if (root != null) LoadState.Loaded(root) else LoadState.Failed
    }

    val rootFolder = (loadState as? LoadState.Loaded)?.root
    val current = pathStack.lastOrNull() ?: rootFolder

    // System back pops the in-memory folder stack before leaving the screen.
    BackHandler(enabled = pathStack.isNotEmpty()) { pathStack.removeAt(pathStack.lastIndex) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(current?.name ?: ref?.displayName ?: stringResource(R.string.pass_store_title)) },
                navigationIcon = {
                    IconButton(onClick = {
                        if (pathStack.isNotEmpty()) pathStack.removeAt(pathStack.lastIndex) else onBack()
                    }) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = stringResource(R.string.pass_back))
                    }
                }
            )
        }
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (loadState) {
                is LoadState.Loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                is LoadState.Failed -> CenterNote(stringResource(R.string.pass_browser_unavailable))
                is LoadState.Loaded -> {
                    val children = current?.children ?: emptyList()
                    if (children.isEmpty()) {
                        CenterNote(stringResource(R.string.pass_browser_empty_folder))
                    } else {
                        LazyColumn(Modifier.fillMaxSize()) {
                            items(children, key = { it.id }) { node ->
                                when (node) {
                                    is PassNode.Folder -> NodeRow(
                                        icon = Icons.Filled.Folder,
                                        label = node.name,
                                        onClick = { pathStack.add(node) }
                                    )
                                    is PassNode.Entry -> NodeRow(
                                        icon = Icons.Filled.Description,
                                        label = node.name,
                                        onClick = { onOpenEntry(storeId, node.relativePath) }
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun NodeRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(24.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(16.dp))
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Icon(Icons.Filled.ChevronRight, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun BoxScope.CenterNote(text: String) {
    Text(
        text,
        modifier = Modifier.align(Alignment.Center).padding(32.dp),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center
    )
}
