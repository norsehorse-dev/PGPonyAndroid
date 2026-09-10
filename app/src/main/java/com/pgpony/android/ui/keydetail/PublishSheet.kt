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
import com.pgpony.android.keyserver.VerificationStatus
import kotlinx.coroutines.launch

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
    val verification = remember { mutableStateMapOf<String, VerificationStatus>() }

    LaunchedEffect(fingerprint) {
        entity = repo.getByFingerprint(fingerprint)
        servers = directory.readOnce().filter { it.publishEnabled }
        servers.forEach { s ->
            checked.putIfAbsent(s.id, true)
            rowStates.putIfAbsent(s.id, RowState.Idle)
        }
        // Kick off verification-status polling for each server.
        val email = entity?.userEmail
        servers.forEach { s ->
            verification[s.id] = service.verificationStatus(s, fingerprint, email)
        }
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
                    stringResource(R.string.publish_title),
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
                    verification = verification[server.id] ?: VerificationStatus.Unknown
                )
                if (index != servers.lastIndex) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                }
            }

            Spacer(modifier = Modifier.padding(vertical = 8.dp))
            val anyChecked = servers.any { checked[it.id] == true }
            val anyPublishing = rowStates.values.any { it is RowState.Publishing }
            Button(
                enabled = anyChecked && !anyPublishing,
                onClick = {
                    val armored = entity?.let { repo.exportArmoredPublicKey(it.fingerprint) }
                        ?: return@Button
                    servers.filter { checked[it.id] == true }.forEach { server ->
                        rowStates[server.id] = RowState.Publishing
                        scope.launch {
                            val outcome = service.publish(server, armored)
                            rowStates[server.id] = RowState.Done(outcome)
                            // Refresh verification status after a successful publish.
                            if (outcome is PublishOutcome.Ok) {
                                verification[server.id] =
                                    service.verificationStatus(server, fingerprint, entity?.userEmail)
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.publish_action))
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
    verification: VerificationStatus
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
                VerificationLine(verification)
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

@Composable
private fun VerificationLine(status: VerificationStatus) {
    val text = when (status) {
        VerificationStatus.VerifiedIdentity -> stringResource(R.string.publish_status_verified)
        VerificationStatus.AwaitingEmailVerification -> stringResource(R.string.publish_status_awaiting)
        VerificationStatus.Published -> stringResource(R.string.publish_status_published)
        VerificationStatus.NotPublished -> stringResource(R.string.publish_status_not_published)
        VerificationStatus.Unknown -> ""
    }
    if (text.isNotEmpty()) {
        Text(
            text,
            style = MaterialTheme.typography.bodySmall,
            color = if (status == VerificationStatus.VerifiedIdentity) Color(0xFF22C55E)
            else MaterialTheme.colorScheme.onSurfaceVariant
        )
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
