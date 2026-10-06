// RecentlyDeletedScreen.kt
// PGPony Android — 4.3.0 RC4 §5.6.1 (#36 part 1) key recycle bin
//
// Lists soft-deleted keys. Each can be restored (its secret material was
// never removed) or destroyed now; the whole bin can be emptied. Keys left
// here are auto-purged after KeyRepository.RECYCLE_BIN_RETENTION_DAYS on the
// next launch (see PGPonyApp).

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.repository.KeyRepository

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RecentlyDeletedScreen(
    viewModel: KeyringViewModel,
    onBack: () -> Unit
) {
    val state by viewModel.state.collectAsState()
    LaunchedEffect(Unit) { viewModel.loadDeletedKeys() }
    var purgeTarget by remember { mutableStateOf<PGPKeyEntity?>(null) }
    var showEmptyConfirm by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.recycle_bin_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.common_button_back)
                        )
                    }
                },
                actions = {
                    if (state.deletedKeys.isNotEmpty()) {
                        TextButton(onClick = { showEmptyConfirm = true }) {
                            Text(stringResource(R.string.recycle_bin_empty_action))
                        }
                    }
                }
            )
        }
    ) { padding ->
        if (state.deletedKeys.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = stringResource(
                        R.string.recycle_bin_empty_state,
                        KeyRepository.RECYCLE_BIN_RETENTION_DAYS
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(32.dp)
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(state.deletedKeys, key = { it.id }) { key ->
                    DeletedKeyRow(
                        key = key,
                        onRestore = { viewModel.restoreDeletedKey(key) },
                        onPurge = { purgeTarget = key }
                    )
                }
            }
        }
    }

    purgeTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { purgeTarget = null },
            text = { Text(stringResource(R.string.recycle_bin_purge_confirm_body)) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.purgeDeletedKey(target)
                    purgeTarget = null
                }) {
                    Text(
                        stringResource(R.string.recycle_bin_delete_now),
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { purgeTarget = null }) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        )
    }

    if (showEmptyConfirm) {
        AlertDialog(
            onDismissRequest = { showEmptyConfirm = false },
            text = { Text(stringResource(R.string.recycle_bin_empty_confirm_body)) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.emptyRecycleBin()
                    showEmptyConfirm = false
                }) {
                    Text(
                        stringResource(R.string.recycle_bin_empty_action),
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showEmptyConfirm = false }) {
                    Text(stringResource(R.string.common_button_cancel))
                }
            }
        )
    }
}

@Composable
private fun DeletedKeyRow(
    key: PGPKeyEntity,
    onRestore: () -> Unit,
    onPurge: () -> Unit
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        shape = MaterialTheme.shapes.medium
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            Text(
                text = key.userName.ifBlank { key.userEmail.ifBlank { key.shortFingerprint } },
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = key.shortFingerprint,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
            )
            key.deletedAt?.let { ts ->
                val date = java.text.DateFormat.getDateInstance().format(java.util.Date(ts))
                Text(
                    text = stringResource(R.string.recycle_bin_deleted_on, date),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                // 4.6.4 (#58): how long until the key is destroyed. Read when the
                // screen composes, which is every time it opens.
                val daysLeft = RecycleBinCountdown.daysLeft(ts, System.currentTimeMillis())
                Text(
                    text = if (daysLeft >= 1) {
                        pluralStringResource(R.plurals.recycle_bin_days_left, daysLeft, daysLeft)
                    } else {
                        stringResource(R.string.recycle_bin_less_than_a_day_left)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Row(
                modifier = Modifier.padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                TextButton(onClick = onRestore) {
                    Text(stringResource(R.string.recycle_bin_restore))
                }
                TextButton(onClick = onPurge) {
                    Text(
                        stringResource(R.string.recycle_bin_delete_now),
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

/**
 * 4.6.4 (#58): whole days until a deleted key is destroyed. Keys are purged on
 * the first launch after [KeyRepository.RECYCLE_BIN_RETENTION_MS] has passed
 * since [deletedAt], so this counts down to that moment. Rounds to the
 * nearest day, so a key deleted a minute ago reads as the full retention the
 * delete sheet promised. Under one day left returns 0 (shown as "less than a
 * day"), as does a key past retention still waiting for the next launch.
 */
internal object RecycleBinCountdown {
    private const val DAY_MS = 24L * 60 * 60 * 1000

    fun daysLeft(deletedAt: Long, now: Long): Int {
        val remaining = deletedAt + KeyRepository.RECYCLE_BIN_RETENTION_MS - now
        if (remaining < DAY_MS) return 0
        return ((remaining + DAY_MS / 2) / DAY_MS).toInt()
    }
}
