// Phase B1c — on-card key generation UI. Collects a UID + the admin and user
// PINs, requires an explicit no-backup acknowledgment, then runs
// CardKeygenService.generateOnCard inside a single card tap and persists the
// assembled public key as a card-backed keyring entry. The generated secret
// keys live only on the card and cannot be backed up — hence the hard gate.

package com.pgpony.android.ui.card

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.pgpony.android.MainActivity
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.card.CardKeygenService
import kotlinx.coroutines.launch

private const val PW1_MIN = 6
private const val PW3_MIN = 8

private sealed class KeygenState {
    data object Form : KeygenState()
    data object Waiting : KeygenState()       // armed; awaiting card tap
    data object Persisting : KeygenState()     // tap done; saving to keyring
    data class Done(val primaryFp: String, val subkeyFp: String) : KeygenState()
    data class Failed(val message: String) : KeygenState()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CardKeygenScreen(onBack: () -> Unit, onDone: () -> Unit = {}) {
    val context = LocalContext.current
    val activity = context as? MainActivity
    val repo = remember { PGPonyApp.instance.keyRepository }
    val scope = rememberCoroutineScope()

    val state = remember { mutableStateOf<KeygenState>(KeygenState.Form) }

    var name by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var adminPin by remember { mutableStateOf("") }
    var userPin by remember { mutableStateOf("") }
    var acknowledged by remember { mutableStateOf(false) }

    DisposableEffect(Unit) { onDispose { activity?.stopCardScan() } }

    val genFail = stringResource(R.string.card_keygen_failed_generate)
    val saveFail = stringResource(R.string.card_keygen_failed_save)

    fun generate() {
        state.value = KeygenState.Waiting
        val started = activity?.startCardOperation({ session ->
            CardKeygenService.generateOnCard(
                session = session,
                name = name.trim(),
                email = email.trim(),
                expirationSeconds = null,
                adminPin = adminPin,
                userPin = userPin
            )
        }) { result ->
            result
                .onSuccess { r ->
                    state.value = KeygenState.Persisting
                    scope.launch {
                        try {
                            repo.importGeneratedCardKey(r.publicKeyBinary, r.cardInfo)
                            state.value = KeygenState.Done(r.primaryFingerprintHex, r.subkeyFingerprintHex)
                        } catch (e: Exception) {
                            state.value = KeygenState.Failed(e.message ?: saveFail)
                        }
                    }
                }
                .onFailure { e -> state.value = KeygenState.Failed(e.message ?: genFail) }
        } ?: false
        if (started != true) state.value = KeygenState.Failed(genFail)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.card_keygen_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = stringResource(R.string.card_keygen_back))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 24.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(16.dp))
            when (val s = state.value) {
                is KeygenState.Waiting -> Prompt(
                    icon = Icons.Filled.Nfc,
                    text = stringResource(R.string.card_keygen_tap_prompt),
                    spinner = true,
                )
                is KeygenState.Persisting -> Prompt(
                    icon = Icons.Filled.VpnKey,
                    text = stringResource(R.string.card_keygen_saving),
                    spinner = true,
                )
                is KeygenState.Done -> DoneBody(s.primaryFp, s.subkeyFp, onDone)
                is KeygenState.Failed -> FailedBody(s.message, onRetry = { state.value = KeygenState.Form })
                is KeygenState.Form -> FormBody(
                    name = name, onName = { name = it },
                    email = email, onEmail = { email = it },
                    adminPin = adminPin, onAdminPin = { if (it.all(Char::isDigit)) adminPin = it },
                    userPin = userPin, onUserPin = { if (it.all(Char::isDigit)) userPin = it },
                    acknowledged = acknowledged, onAck = { acknowledged = it },
                    onGenerate = ::generate,
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FormBody(
    name: String, onName: (String) -> Unit,
    email: String, onEmail: (String) -> Unit,
    adminPin: String, onAdminPin: (String) -> Unit,
    userPin: String, onUserPin: (String) -> Unit,
    acknowledged: Boolean, onAck: (Boolean) -> Unit,
    onGenerate: () -> Unit,
) {
    val valid = name.isNotBlank() && email.isNotBlank() &&
        adminPin.length >= PW3_MIN && userPin.length >= PW1_MIN && acknowledged

    Text(
        stringResource(R.string.card_keygen_subtitle),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(16.dp))

    // No-backup warning.
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
            Icon(
                Icons.Filled.Warning,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(R.string.card_keygen_no_backup_warning),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
        }
    }
    Spacer(Modifier.height(16.dp))

    OutlinedTextField(
        value = name, onValueChange = onName,
        label = { Text(stringResource(R.string.card_keygen_field_name)) },
        singleLine = true, modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = email, onValueChange = onEmail,
        label = { Text(stringResource(R.string.card_keygen_field_email)) },
        singleLine = true, modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = adminPin, onValueChange = onAdminPin,
        label = { Text(stringResource(R.string.card_keygen_field_admin_pin)) },
        visualTransformation = PasswordVisualTransformation(),
        singleLine = true, modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = userPin, onValueChange = onUserPin,
        label = { Text(stringResource(R.string.card_keygen_field_user_pin)) },
        visualTransformation = PasswordVisualTransformation(),
        singleLine = true, modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(8.dp))

    Row(
        Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = acknowledged, onCheckedChange = onAck)
        Spacer(Modifier.width(4.dp))
        Text(
            stringResource(R.string.card_keygen_ack),
            style = MaterialTheme.typography.bodySmall,
        )
    }
    Spacer(Modifier.height(16.dp))

    Button(onClick = onGenerate, enabled = valid, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Filled.VpnKey, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(stringResource(R.string.card_keygen_generate))
    }
}

@Composable
private fun DoneBody(primaryFp: String, subkeyFp: String, onDone: () -> Unit) {
    Icon(
        Icons.Filled.CheckCircle,
        contentDescription = null,
        modifier = Modifier.size(64.dp),
        tint = MaterialTheme.colorScheme.primary,
    )
    Spacer(Modifier.height(16.dp))
    Text(
        stringResource(R.string.card_keygen_done),
        style = MaterialTheme.typography.bodyLarge,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(12.dp))
    Text(
        stringResource(R.string.card_keygen_done_primary_fp, primaryFp),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(4.dp))
    Text(
        stringResource(R.string.card_keygen_done_subkey_fp, subkeyFp),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(16.dp))
    Button(onClick = onDone) { Text(stringResource(R.string.card_keygen_done_button)) }
}

@Composable
private fun FailedBody(message: String, onRetry: () -> Unit) {
    Icon(
        Icons.Filled.ErrorOutline,
        contentDescription = null,
        modifier = Modifier.size(64.dp),
        tint = MaterialTheme.colorScheme.error,
    )
    Spacer(Modifier.height(16.dp))
    Text(message, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center)
    Spacer(Modifier.height(16.dp))
    Button(onClick = onRetry) { Text(stringResource(R.string.card_keygen_retry)) }
}

@Composable
private fun Prompt(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String, spinner: Boolean) {
    Icon(icon, contentDescription = null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.primary)
    Spacer(Modifier.height(16.dp))
    Text(text, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center)
    if (spinner) {
        Spacer(Modifier.height(16.dp))
        CircularProgressIndicator()
    }
}
