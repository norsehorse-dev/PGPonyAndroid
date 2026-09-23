// SshAgentScreen.kt
// PGPony Android, 4.6.0 (item 16b): Settings > SSH agent for Termux.
//
// Everything the SSHPony bridge needs from the user in one place: the on
// switch, pairing with Termux (a secret PGPony generates and the user moves
// over as "sshpony pair <code>"), the two Android permissions the bridge
// depends on (starting in the background, and posting the unlock / card
// prompts as notifications), and which keys the agent offers.

package com.pgpony.android.ui.settings

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatteryFull
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.ssh.SshAuth
import com.pgpony.android.provider.agent.AgentBridge
import com.pgpony.android.provider.agent.AgentBridgePrefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private class AgentKeyRow(val fingerprint: String, val label: String, val detail: String)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SshAgentScreen(onDismiss: () -> Unit) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current

    var enabled by remember { mutableStateOf(AgentBridgePrefs.isEnabled(context)) }
    var paired by remember { mutableStateOf(AgentBridgePrefs.isPaired(context)) }
    var shownCommand by remember { mutableStateOf<String?>(null) }
    var copied by remember { mutableStateOf(false) }
    var excluded by remember { mutableStateOf(AgentBridgePrefs.excluded(context)) }
    var keys by remember { mutableStateOf<List<AgentKeyRow>?>(null) }
    // Re-read the two permissions whenever the user comes back from Settings.
    var permTick by remember { mutableIntStateOf(0) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { permTick++ }
    val background = remember(permTick) { isIgnoringBatteryOptimizations(context) }
    val notifications = remember(permTick) { NotificationManagerCompat.from(context).areNotificationsEnabled() }

    LaunchedEffect(Unit) {
        keys = withContext(Dispatchers.Default) { authKeys() }
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
                Icon(Icons.Filled.Terminal, null, tint = Color(0xFF8B5CF6), modifier = Modifier.size(36.dp))
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    stringResource(R.string.agent_settings_title),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                stringResource(R.string.agent_settings_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 16.dp)
            )

            // ── On / off ───────────────────────────────────────────────
            Row(modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.agent_settings_enable), style = MaterialTheme.typography.bodyLarge)
                    Text(
                        stringResource(R.string.agent_settings_enable_caption),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(checked = enabled, onCheckedChange = {
                    enabled = it
                    AgentBridgePrefs.setEnabled(context, it)
                })
            }
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // ── Pairing ────────────────────────────────────────────────
            Text(stringResource(R.string.agent_settings_pairing), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(
                stringResource(if (paired) R.string.agent_settings_paired else R.string.agent_settings_not_paired),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
            )
            shownCommand?.let { cmd ->
                Text(
                    cmd,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp))
                        .padding(10.dp)
                )
                Row(modifier = Modifier.padding(top = 4.dp)) {
                    TextButton(onClick = {
                        clipboard.setText(AnnotatedString(cmd))
                        copied = true
                    }) {
                        Text(stringResource(if (copied) R.string.agent_settings_copied else R.string.agent_settings_copy_command))
                    }
                }
                Text(
                    stringResource(R.string.agent_settings_pair_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
            }
            Row {
                OutlinedButton(onClick = {
                    shownCommand = AgentBridge.pairCommand(AgentBridgePrefs.pair(context))
                    paired = true
                    copied = false
                }) {
                    Text(stringResource(if (paired) R.string.agent_settings_repair else R.string.agent_settings_pair))
                }
                if (paired) {
                    Spacer(modifier = Modifier.width(8.dp))
                    TextButton(onClick = {
                        AgentBridgePrefs.unpair(context)
                        paired = false
                        shownCommand = null
                    }) { Text(stringResource(R.string.agent_settings_unpair)) }
                }
            }
            HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))

            // ── Android permissions ────────────────────────────────────
            PermissionRow(
                ok = background,
                icon = Icons.Filled.BatteryFull,
                title = stringResource(R.string.agent_settings_background),
                caption = stringResource(
                    if (background) R.string.agent_settings_background_ok else R.string.agent_settings_background_needed
                ),
                onClick = { context.startActivity(appDetails(context)) }
            )
            PermissionRow(
                ok = notifications,
                icon = Icons.Filled.Notifications,
                title = stringResource(R.string.agent_settings_notifications),
                caption = stringResource(
                    if (notifications) R.string.agent_settings_notifications_ok else R.string.agent_settings_notifications_needed
                ),
                onClick = {
                    context.startActivity(
                        Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                    )
                }
            )
            HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))

            // ── Keys offered ───────────────────────────────────────────
            Text(stringResource(R.string.agent_settings_keys), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Spacer(modifier = Modifier.height(4.dp))
            val list = keys
            if (list != null && list.isEmpty()) {
                Text(
                    stringResource(R.string.agent_settings_keys_empty),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            list?.forEach { k ->
                val offered = k.fingerprint.uppercase() !in excluded
                Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(k.label, style = MaterialTheme.typography.bodyMedium)
                        Text(
                            k.detail,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(checked = offered, onCheckedChange = {
                        AgentBridgePrefs.setOffered(context, k.fingerprint, it)
                        excluded = AgentBridgePrefs.excluded(context)
                    })
                }
            }
            HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))

            // ── Termux side ────────────────────────────────────────────
            Text(stringResource(R.string.agent_settings_termux), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(
                stringResource(R.string.agent_settings_termux_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
    }
}

@Composable
private fun PermissionRow(
    ok: Boolean,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    caption: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, tint = Color(0xFF8B5CF6), modifier = Modifier.size(24.dp))
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(caption, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Icon(
            if (ok) Icons.Filled.CheckCircle else Icons.Filled.Warning,
            null,
            tint = if (ok) Color(0xFF22C55E) else Color(0xFFF59E0B),
            modifier = Modifier.size(20.dp)
        )
    }
}

private fun isIgnoringBatteryOptimizations(context: Context): Boolean =
    context.getSystemService(PowerManager::class.java)?.isIgnoringBatteryOptimizations(context.packageName) == true

private fun appDetails(context: Context): Intent =
    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).setData(Uri.parse("package:${context.packageName}"))

/** Keys with a usable SSH authentication subkey (key pairs and card keys). */
private suspend fun authKeys(): List<AgentKeyRow> {
    val repo = PGPonyApp.instance.keyRepository
    return repo.getAllKeys()
        .filter { (it.isKeyPair || it.isCardBacked) && !it.isRevoked }
        .mapNotNull { e ->
            val cert = repo.sshAuthCertificate(e.fingerprint) ?: return@mapNotNull null
            val sub = SshAuth.authSubkey(cert) ?: return@mapNotNull null
            val m = SshAuth.material(sub.publicBody) ?: return@mapNotNull null
            AgentKeyRow(e.fingerprint, e.userID.ifBlank { e.shortFingerprint }, "${m.sshType}  ${SshAuth.sshFingerprint(m)}")
        }
}
