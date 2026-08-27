// ApiClientsScreen.kt
// PGPony Android — 4.0.0 Succession Phase 1 (OpenPGP API provider)
//
// Settings → Connected apps: the management/revocation UI for OpenPGP
// API clients (plan §5: "a revocation UI is non-negotiable"). Lists
// every package the user has authorized, with its app label, package
// name, and grant date; a delete action revokes instantly — the very
// next provider call from that package lands back in the consent flow.
//
// Presented as a full-height ModalBottomSheet, same pattern as the
// SecurityInfoScreen / LanguagePickerScreen / LicensesScreen overlays
// in this package. Self-contained (reads the DAO via PGPonyApp.instance
// like CardPinCacheSection reads its cache) — no SettingsViewModel
// changes needed.

package com.pgpony.android.ui.settings

import android.content.pm.PackageManager
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Link
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.Switch
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.data.ApiClientEntity
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApiClientsScreen(onDismiss: () -> Unit) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val context = LocalContext.current
    val dao = remember { PGPonyApp.instance.database.apiClientDao() }
    val scope = rememberCoroutineScope()

    var clients by remember { mutableStateOf<List<ApiClientEntity>>(emptyList()) }
    var loaded by remember { mutableStateOf(false) }
    // Bumped after every revoke so the list re-reads.
    var refresh by remember { mutableIntStateOf(0) }

    LaunchedEffect(refresh) {
        clients = dao.getAll()
        loaded = true
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
                .padding(bottom = 32.dp)
        ) {
            // ── Header ──────────────────────────────────────────────────
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Filled.Link,
                    contentDescription = null,
                    tint = Color(0xFF8B5CF6),
                    modifier = Modifier.size(36.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    stringResource(R.string.provider_clients_title),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                stringResource(R.string.provider_clients_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 20.dp)
            )

            // #51: let the user be asked which key to sign with on each send,
            // instead of being locked to the key the mail app cached first.
            val prefs = remember {
                context.getSharedPreferences("pgpony_prefs", android.content.Context.MODE_MULTI_PROCESS)
            }
            var askSignEachSend by remember {
                mutableStateOf(prefs.getBoolean("provider_ask_sign_key_each_send", false))
            }
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.provider_ask_sign_key_title),
                        style = MaterialTheme.typography.bodyLarge
                    )
                    Text(
                        stringResource(R.string.provider_ask_sign_key_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Switch(
                    checked = askSignEachSend,
                    onCheckedChange = {
                        askSignEachSend = it
                        prefs.edit().putBoolean("provider_ask_sign_key_each_send", it).apply()
                    }
                )
            }
            HorizontalDivider(modifier = Modifier.padding(bottom = 16.dp))

            // #51: change the remembered per-address signing key from inside
            // PGPony, so it never depends on the mail client offering the choice.
            SigningKeyPerAddressSection(prefs)

            if (loaded && clients.isEmpty()) {
                // ── Empty state: how a client gets here ─────────────────
                Text(
                    stringResource(R.string.provider_clients_empty_title),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(bottom = 6.dp)
                )
                Text(
                    stringResource(R.string.provider_clients_empty_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            clients.forEachIndexed { index, client ->
                ApiClientRow(
                    client = client,
                    label = rememberAppLabel(client.packageName),
                    onRevoke = {
                        scope.launch {
                            dao.deleteByPackage(client.packageName)
                            refresh++
                        }
                    }
                )
                if (index != clients.lastIndex) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                }
            }
        }
    }
}

@Composable
private fun rememberAppLabel(packageName: String): String {
    val context = LocalContext.current
    return remember(packageName) {
        try {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            context.packageManager.getApplicationLabel(info).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            // App was uninstalled but the grant row remains — show the
            // package so the user can still clean it up.
            packageName
        }
    }
}

@Composable
private fun ApiClientRow(
    client: ApiClientEntity,
    label: String,
    onRevoke: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.Extension,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge)
            Text(
                client.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                stringResource(
                    R.string.provider_clients_granted_format,
                    DateFormat.getDateInstance(DateFormat.MEDIUM)
                        .format(Date(client.grantedAt))
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        IconButton(onClick = onRevoke) {
            Icon(
                Icons.Filled.Delete,
                contentDescription = stringResource(R.string.provider_clients_revoke),
                tint = MaterialTheme.colorScheme.error
            )
        }
    }
}


// ── #51: per-address signing-key selector ──────────────────────────────
// When an address carries more than one of the user's signing keys, this lets
// the user set which one PGPony signs with, writing the same
// "sign_key_choice::<email>" preference the provider reads on send. Self-owned,
// so clients that cannot offer the choice (e.g. FairEmail) are not a dead end.
@Composable
private fun SigningKeyPerAddressSection(prefs: android.content.SharedPreferences) {
    var groups by remember {
        mutableStateOf<List<Pair<String, List<PGPKeyEntity>>>>(emptyList())
    }
    LaunchedEffect(Unit) {
        val signing = PGPonyApp.instance.keyRepository.getAllKeys()
            .filter { (it.isKeyPair || it.isCardBacked) && !it.isRevoked }
        groups = signing.groupBy { it.userEmail.lowercase() }
            .filter { it.value.size > 1 }
            .map { (_, keys) -> keys.first().userEmail to keys.sortedBy { it.userName.lowercase() } }
            .sortedBy { it.first.lowercase() }
    }
    if (groups.isEmpty()) return

    Text(
        stringResource(R.string.provider_sign_per_address_title),
        style = MaterialTheme.typography.bodyLarge
    )
    Text(
        stringResource(R.string.provider_sign_per_address_subtitle),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(bottom = 8.dp)
    )
    groups.forEach { (email, keys) ->
        SigningKeyAddressRow(email = email, keys = keys, prefs = prefs)
    }
    HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp))
}

private fun signingKeyLabel(k: PGPKeyEntity): String =
    (k.userName.ifEmpty { k.userEmail }) + " \u00b7 " + k.shortFingerprint

private fun signingKeyIdOf(k: PGPKeyEntity): Long =
    runCatching { java.lang.Long.parseUnsignedLong(k.longKeyId, 16) }.getOrDefault(0L)

@Composable
private fun SigningKeyAddressRow(
    email: String,
    keys: List<PGPKeyEntity>,
    prefs: android.content.SharedPreferences
) {
    val prefKey = "sign_key_choice::" + email.lowercase()
    var selectedId by remember {
        mutableStateOf(
            prefs.getLong(prefKey, 0L).takeIf { it != 0L }
                ?: signingKeyIdOf(keys.firstOrNull { it.isDefault } ?: keys.first())
        )
    }
    var expanded by remember { mutableStateOf(false) }
    val selectedKey = keys.firstOrNull { signingKeyIdOf(it) == selectedId } ?: keys.first()

    Column(modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp)) {
        Text(
            email,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold
        )
        Box {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = true }
                    .padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    signingKeyLabel(selectedKey),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f)
                )
                Icon(Icons.Filled.ArrowDropDown, contentDescription = null)
            }
            DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                keys.forEach { k ->
                    DropdownMenuItem(
                        text = { Text(signingKeyLabel(k)) },
                        onClick = {
                            val id = signingKeyIdOf(k)
                            selectedId = id
                            prefs.edit().putLong(prefKey, id).apply()
                            expanded = false
                        }
                    )
                }
            }
        }
    }
}
