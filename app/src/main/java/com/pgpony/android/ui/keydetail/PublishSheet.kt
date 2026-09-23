// PublishSheet.kt
// PGPony Android — 4.0.0 Phase 5a
//
// "Publish to key servers" from Key Detail. One checkbox per
// publish-enabled server in the directory, both pre-checked (plan §6
// Q6 funnel). On publish, each selected server is uploaded to and its
// result shown inline. Below each server, the per-(key,server)
// verification status is polled and displayed.
//
// R5 — per-server key-type compatibility: before publishing, a server
// that mayNotAccept() this key's algorithm shows a non-coercive inline
// heads-up ("May not accept <algorithm> keys — your other servers still
// will."). The toggle stays on; the user decides. On an actual
// rejection, the failure copy is key-type-specific rather than a raw
// HTTP error. keys.pgpony.app and user-added servers are never flagged.
//
// Self-contained (reads the repo + directory via PGPonyApp.instance),
// same pattern as ApiClientsScreen / LicensesScreen.
//
// 4.6.0 (item 9): also the "Update on Key Servers" sheet. A key published
// before pre-checks only the servers it went to (KeyPublicationStore) and
// shows when each last got a copy; each server row lists the key's addresses
// and whether that server has confirmed them, so a newly added identity's
// confirmation is visible. The payload comes from KeyRepository.publishPayload,
// which refuses a key whose primary identity is ambiguous.

package com.pgpony.android.ui.keydetail

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
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.keyserver.KeyServer
import com.pgpony.android.keyserver.MultiKeyServerService
import com.pgpony.android.keyserver.PublishOutcome
import com.pgpony.android.keyserver.ServerCopy
import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.data.KeyPublicationStore
import com.pgpony.android.data.repository.KeyRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private sealed class RowState {
    object Idle : RowState()
    object Publishing : RowState()
    data class Done(val outcome: PublishOutcome) : RowState()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PublishSheet(fingerprint: String, onDismiss: () -> Unit) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scope = rememberCoroutineScope()
    val repo = remember { PGPonyApp.instance.keyRepository }
    val directory = remember { com.pgpony.android.keyserver.KeyServerDirectory.get(PGPonyApp.instance) }
    val service = remember { MultiKeyServerService.shared }

    var entity by remember { mutableStateOf<PGPKeyEntity?>(null) }
    var servers by remember { mutableStateOf<List<KeyServer>>(emptyList()) }
    val checked = remember { mutableStateMapOf<String, Boolean>() }
    val rowStates = remember { mutableStateMapOf<String, RowState>() }
    val copies = remember { mutableStateMapOf<String, ServerCopy>() }
    val uploadedAt = remember { mutableStateMapOf<String, Long>() }
    var addresses by remember { mutableStateOf<List<String>>(emptyList()) }
    var payload by remember { mutableStateOf<KeyRepository.PublishPayload?>(null) }
    var isUpdate by remember { mutableStateOf(false) }

    LaunchedEffect(fingerprint) {
        val e = repo.getByFingerprint(fingerprint)
        entity = e
        servers = directory.readOnce().filter { it.publishEnabled }
        val records = KeyPublicationStore.servers(fingerprint)
        uploadedAt.putAll(records)
        isUpdate = records.isNotEmpty() || e?.keyServerUploaded == true
        servers.forEach { s ->
            // An update goes to the servers used before; a first upload (or a
            // key uploaded before per-server records existed) to all of them.
            checked.putIfAbsent(s.id, records.isEmpty() || s.id in records)
            rowStates.putIfAbsent(s.id, RowState.Idle)
        }
        withContext(Dispatchers.IO) {
            addresses = repo.exportPublicKeyBytes(fingerprint)
                ?.let { CertificateBindings.analyze(it)?.certifiedUserIds }
                ?.map { CertificateBindings.mailboxOf(it) }
                ?.filter { it.contains('@') }
                ?.distinct()
                .orEmpty()
            payload = e?.let { repo.publishPayload(fingerprint, it.userID) }
        }
        servers.forEach { s -> copies[s.id] = service.serverCopy(s, fingerprint) }
    }

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
                    Icons.Filled.CloudUpload,
                    contentDescription = null,
                    tint = Color(0xFF8B5CF6),
                    modifier = Modifier.size(36.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    stringResource(if (isUpdate) R.string.publish_title_update else R.string.publish_title),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                stringResource(R.string.publish_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 16.dp)
            )

            val algorithm = entity?.algorithm
            servers.forEachIndexed { index, server ->
                ServerRow(
                    server = server,
                    checked = checked[server.id] ?: true,
                    onCheckedChange = { checked[server.id] = it },
                    mayNotAccept = algorithm != null && server.mayNotAccept(algorithm),
                    algorithmLabel = algorithm?.displayName ?: "",
                    state = rowStates[server.id] ?: RowState.Idle,
                    copy = copies[server.id],
                    addresses = addresses,
                    lastUploadedAt = uploadedAt[server.id]
                )
                if (index != servers.lastIndex) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                }
            }

            Spacer(modifier = Modifier.padding(vertical = 8.dp))
            (payload as? KeyRepository.PublishPayload.NeedsRepair)?.let { repair ->
                Text(
                    stringResource(
                        R.string.publish_primary_repair_format,
                        repair.flagged.joinToString(", ").ifEmpty { "-" },
                        repair.shown
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
            }
            val anyChecked = servers.any { checked[it.id] == true }
            val anyPublishing = rowStates.values.any { it is RowState.Publishing }
            val ready = payload as? KeyRepository.PublishPayload.Ready
            Button(
                enabled = anyChecked && !anyPublishing && ready != null,
                onClick = {
                    val armored = ready?.armored ?: return@Button
                    servers.filter { checked[it.id] == true }.forEach { server ->
                        rowStates[server.id] = RowState.Publishing
                        scope.launch {
                            val outcome = service.publish(server, armored)
                            rowStates[server.id] = RowState.Done(outcome)
                            if (outcome is PublishOutcome.Ok) {
                                // 4.6.0 (item 9): Key Detail uploads now count as
                                // uploads (the flag, the date, the server).
                                repo.markKeyServerUploaded(fingerprint, server.id)
                                uploadedAt[server.id] = System.currentTimeMillis()
                                copies[server.id] = service.serverCopy(server, fingerprint)
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(if (isUpdate) R.string.publish_action_update else R.string.publish_action))
            }
            // item 8 (#request): an explicit, unambiguous skip so the online
            // post-keygen prompt does not have to be dismissed by tapping away.
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.publish_not_now))
            }
        }
    }
}

@Composable
private fun ServerRow(
    server: KeyServer,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    mayNotAccept: Boolean,
    algorithmLabel: String,
    state: RowState,
    copy: ServerCopy?,
    addresses: List<String>,
    lastUploadedAt: Long?
) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(checked = checked, onCheckedChange = onCheckedChange)
            Spacer(modifier = Modifier.width(4.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(server.label, style = MaterialTheme.typography.bodyLarge)
                lastUploadedAt?.let {
                    Text(
                        stringResource(
                            R.string.publish_last_uploaded_format,
                            java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(it))
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                CopyLines(copy, addresses)
            }
            when (state) {
                is RowState.Publishing ->
                    CircularProgressIndicator(modifier = Modifier.size(20.dp))
                else -> {}
            }
        }

        // R5 pre-publish key-type heads-up (non-coercive).
        if (mayNotAccept && state !is RowState.Done) {
            InlineNote(
                stringResource(R.string.publish_may_not_accept_format, algorithmLabel),
                MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        // Result copy.
        when (state) {
            is RowState.Done -> when (val o = state.outcome) {
                is PublishOutcome.Ok -> InlineNote(
                    if (o.pendingEmails.isEmpty())
                        stringResource(R.string.publish_ok)
                    else
                        stringResource(R.string.publish_ok_pending, o.pendingEmails.joinToString()),
                    Color(0xFF22C55E)
                )
                is PublishOutcome.RejectedKeyType -> InlineNote(
                    stringResource(R.string.publish_rejected_key_type_format, algorithmLabel),
                    MaterialTheme.colorScheme.error
                )
                is PublishOutcome.Failed -> InlineNote(
                    stringResource(R.string.publish_failed_format, o.message),
                    MaterialTheme.colorScheme.error
                )
            }
            else -> {}
        }
    }
}

/** 4.6.0 (item 9): what this server holds, per address of the key. */
@Composable
private fun CopyLines(copy: ServerCopy?, addresses: List<String>) {
    when (copy) {
        null, ServerCopy.Unknown -> {}
        ServerCopy.NotPublished -> Text(
            stringResource(R.string.publish_status_not_published),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        is ServerCopy.Published -> {
            if (addresses.isEmpty()) {
                Text(
                    stringResource(R.string.publish_status_published),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            addresses.forEach { address ->
                val confirmed = address in copy.addresses
                Text(
                    stringResource(
                        if (confirmed) R.string.publish_address_confirmed_format
                        else R.string.publish_address_pending_format,
                        address
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (confirmed) Color(0xFF22C55E) else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun InlineNote(text: String, color: Color) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 48.dp, top = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(Icons.Filled.Info, null, tint = color, modifier = Modifier.size(14.dp))
        Spacer(modifier = Modifier.width(6.dp))
        Text(text, style = MaterialTheme.typography.bodySmall, color = color)
    }
}
