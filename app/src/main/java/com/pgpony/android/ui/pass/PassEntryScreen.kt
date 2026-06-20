// Phase C1/C2 — decrypted detail for a single pass entry. Gated by the optional
// pass-store biometric setting, then routed by recipient matching: a software
// keypair decrypts on device (C1); a card-backed recipient decrypts over NFC
// with a PIN + tap (C2), reusing CardDecryptService. Shows the password
// (reveal/copy), `key: value` metadata (per-field copy), and any detected
// otpauth URI read-only. Copies go through the auto-clearing ClipboardService.
// Plaintext lives only in composable state; FLAG_SECURE blocks screenshots /
// recents thumbnails while the entry is open.

package com.pgpony.android.ui.pass

import android.app.Activity
import android.content.Context
import android.view.WindowManager
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.pgpony.android.MainActivity
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.card.CardDecryptService
import com.pgpony.android.crypto.card.OpenPgpCardException
import com.pgpony.android.crypto.pass.PassDecryptCoordinator
import com.pgpony.android.crypto.pass.PassEntryContent
import com.pgpony.android.crypto.pass.PassEntryParser
import com.pgpony.android.crypto.pass.PassRoute
import com.pgpony.android.crypto.pass.PassStorePrefs
import com.pgpony.android.crypto.pass.PassStoreService
import com.pgpony.android.ui.keyring.BiometricAvailability
import com.pgpony.android.ui.keyring.BiometricGate
import com.pgpony.android.ui.util.ClipboardService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.openpgp.PGPSecretKeyRing

private sealed class EntryState {
    data object Locked : EntryState()
    data object Working : EntryState()
    data class PassphraseNeeded(val retry: Boolean) : EntryState()
    data object CardNeeded : EntryState()       // entry is encrypted to a card key — collect PIN + tap
    data object CardWaiting : EntryState()        // armed; awaiting the card tap
    data class Shown(val content: PassEntryContent) : EntryState()
    data class Failed(val message: String) : EntryState()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PassEntryScreen(
    storeId: String,
    relativePath: String,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val activity = context as? MainActivity
    val prefs = remember { context.getSharedPreferences("pgpony_prefs", Context.MODE_PRIVATE) }
    val service = remember { PassStoreService(context) }
    val repo = remember { PGPonyApp.instance.keyRepository }
    val ref = remember(storeId) { PassStorePrefs.load(prefs).firstOrNull { it.id == storeId } }
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val nfcReady = remember { activity != null && activity.isNfcAvailable() && activity.isNfcEnabled() }

    var state by remember { mutableStateOf<EntryState>(EntryState.Locked) }
    var passphrase by remember { mutableStateOf("") }
    var cardPin by remember { mutableStateOf("") }
    var leafBytes by remember { mutableStateOf<ByteArray?>(null) }
    var rings by remember { mutableStateOf<List<PGPSecretKeyRing>?>(null) }

    val entryName = remember(relativePath) { relativePath.substringAfterLast('/') }

    DisposableEffect(Unit) {
        val window = (context as? Activity)?.window
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
    DisposableEffect(Unit) { onDispose { activity?.stopCardScan() } }

    val notFound = stringResource(R.string.pass_entry_not_found)
    val unreadable = stringResource(R.string.pass_entry_unreadable)
    val noKey = stringResource(R.string.pass_entry_no_key)
    val nfcUnavailable = stringResource(R.string.pass_entry_card_nfc_off)
    val cardFailed = stringResource(R.string.pass_entry_card_failed)
    val copiedMsg = stringResource(R.string.pass_copied)

    suspend fun attemptSoftware(withPassphrase: String?) {
        try {
            val text = withContext(Dispatchers.Default) {
                PassDecryptCoordinator.decryptSoftware(leafBytes!!, rings!!, withPassphrase)
            }
            state = EntryState.Shown(PassEntryParser.parse(text))
        } catch (_: Exception) {
            state = EntryState.PassphraseNeeded(retry = withPassphrase != null)
        }
    }

    fun loadAndRoute() {
        state = EntryState.Working
        scope.launch {
            if (ref == null) { state = EntryState.Failed(notFound); return@launch }
            val b = leafBytes ?: withContext(Dispatchers.IO) { service.readEntryBytes(ref, relativePath) }
            if (b == null) { state = EntryState.Failed(unreadable); return@launch }
            leafBytes = b
            when (val route = PassDecryptCoordinator.route(repo, b)) {
                is PassRoute.Software -> { rings = route.rings; attemptSoftware(null) }
                is PassRoute.Card -> state = if (nfcReady) EntryState.CardNeeded else EntryState.Failed(nfcUnavailable)
                is PassRoute.NoMatch -> state = EntryState.Failed(noKey)
            }
        }
    }

    fun runCardDecrypt(pin: String) {
        val b = leafBytes ?: return
        state = EntryState.CardWaiting
        val started = activity?.startCardOperation({ session ->
            session.select()
            val ard = session.getApplicationRelatedData()
            val primaryFp = ard.sigFingerprint ?: ard.decFingerprint
                ?: throw OpenPgpCardException.Malformed("This card has no keys.")
            val pubRing = repo.loadPublicKeyRing(primaryFp)
                ?: throw OpenPgpCardException.Malformed("Pair this card's public key into your keyring first.")
            CardDecryptService.shared.decryptBytes(session, pubRing, pin.toByteArray(Charsets.UTF_8), b)
        }) { result ->
            result
                .onSuccess { state = EntryState.Shown(PassEntryParser.parse(it.data.toString(Charsets.UTF_8))) }
                .onFailure { e -> state = EntryState.Failed(e.message ?: cardFailed) }
        } ?: false
        if (started != true) state = EntryState.Failed(cardFailed)
    }

    fun gateThenDecrypt() {
        val requireBio = prefs.getBoolean("biometric_pass_store", true)
        if (requireBio && activity != null &&
            BiometricGate.canAuthenticate(activity) == BiometricAvailability.Available
        ) {
            BiometricGate.authenticate(
                activity = activity,
                title = context.getString(R.string.pass_entry_biometric_title),
                subtitle = context.getString(R.string.pass_entry_biometric_subtitle),
                onSuccess = { loadAndRoute() },
                onError = { _, _ -> /* cancelled / lockout — stay locked, button retappable */ }
            )
        } else {
            loadAndRoute()
        }
    }

    fun copy(value: String) {
        ClipboardService.copyText(context, value)
        scope.launch { snackbar.showSnackbar(copiedMsg) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(entryName) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = stringResource(R.string.pass_back))
                    }
                }
            )
        },
        snackbarHost = { SnackbarHost(snackbar) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            Spacer(Modifier.height(16.dp))
            when (val s = state) {
                is EntryState.Locked -> LockedBody(onDecrypt = ::gateThenDecrypt)
                is EntryState.Working -> CenterSpinner(null)
                is EntryState.CardWaiting -> CenterSpinner(stringResource(R.string.pass_entry_card_tap))
                is EntryState.PassphraseNeeded -> PassphraseBody(
                    passphrase = passphrase,
                    onPassphrase = { passphrase = it },
                    showError = s.retry,
                    onUnlock = { scope.launch { state = EntryState.Working; attemptSoftware(passphrase) } }
                )
                is EntryState.CardNeeded -> CardBody(
                    pin = cardPin,
                    onPin = { if (it.all(Char::isDigit)) cardPin = it },
                    onDecrypt = { runCardDecrypt(cardPin) }
                )
                is EntryState.Failed -> FailedBody(s.message, onRetry = { state = EntryState.Locked })
                is EntryState.Shown -> ShownBody(s.content, onCopy = ::copy)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun LockedBody(onDecrypt: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        Spacer(Modifier.height(24.dp))
        Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(56.dp), tint = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(16.dp))
        Text(stringResource(R.string.pass_entry_locked_hint), style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(20.dp))
        Button(onClick = onDecrypt) {
            Icon(Icons.Filled.LockOpen, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.pass_entry_decrypt))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PassphraseBody(
    passphrase: String,
    onPassphrase: (String) -> Unit,
    showError: Boolean,
    onUnlock: () -> Unit
) {
    Text(stringResource(R.string.pass_entry_passphrase_hint), style = MaterialTheme.typography.bodyMedium)
    if (showError) {
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.pass_entry_passphrase_wrong), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    }
    Spacer(Modifier.height(12.dp))
    OutlinedTextField(
        value = passphrase,
        onValueChange = onPassphrase,
        label = { Text(stringResource(R.string.pass_entry_passphrase_label)) },
        visualTransformation = PasswordVisualTransformation(),
        singleLine = true,
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(Modifier.height(16.dp))
    Button(onClick = onUnlock, enabled = passphrase.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.pass_entry_unlock))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CardBody(pin: String, onPin: (String) -> Unit, onDecrypt: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Filled.Nfc, contentDescription = null, modifier = Modifier.size(48.dp), tint = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(12.dp))
        Text(stringResource(R.string.pass_entry_card_hint), style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = pin,
            onValueChange = onPin,
            label = { Text(stringResource(R.string.pass_entry_card_pin_label)) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(16.dp))
        Button(onClick = onDecrypt, enabled = pin.length >= 6, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Filled.Nfc, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.pass_entry_card_decrypt))
        }
    }
}

@Composable
private fun ShownBody(content: PassEntryContent, onCopy: (String) -> Unit) {
    var revealed by remember { mutableStateOf(false) }

    Text(stringResource(R.string.pass_entry_password_label), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(4.dp))
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(
            if (revealed) content.password.ifEmpty { stringResource(R.string.pass_entry_empty_password) } else "••••••••••",
            style = MaterialTheme.typography.titleMedium,
            fontFamily = if (revealed) FontFamily.Monospace else FontFamily.Default,
            modifier = Modifier.weight(1f)
        )
        IconButton(onClick = { revealed = !revealed }) {
            Icon(
                if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                contentDescription = stringResource(R.string.pass_entry_reveal)
            )
        }
        IconButton(onClick = { onCopy(content.password) }) {
            Icon(Icons.Filled.ContentCopy, contentDescription = stringResource(R.string.pass_entry_copy))
        }
    }

    if (content.fields.isNotEmpty()) {
        Spacer(Modifier.height(16.dp))
        Divider()
        for (field in content.fields) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                Column(Modifier.weight(1f)) {
                    Text(field.key, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    SelectionContainer { Text(field.value, style = MaterialTheme.typography.bodyLarge) }
                }
                IconButton(onClick = { onCopy(field.value) }) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = stringResource(R.string.pass_entry_copy))
                }
            }
        }
    }

    val otp = content.otpauth
    if (otp != null) {
        Spacer(Modifier.height(16.dp))
        Divider()
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.pass_entry_otp_label), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(stringResource(R.string.pass_entry_otp_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            SelectionContainer { Text(otp, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f)) }
            IconButton(onClick = { onCopy(otp) }) {
                Icon(Icons.Filled.ContentCopy, contentDescription = stringResource(R.string.pass_entry_copy))
            }
        }
    }

    if (content.extraLines.isNotEmpty()) {
        Spacer(Modifier.height(16.dp))
        Divider()
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.pass_entry_notes_label), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(4.dp))
        SelectionContainer {
            Text(content.extraLines.joinToString("\n"), style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
        }
    }
}

@Composable
private fun FailedBody(message: String, onRetry: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        Spacer(Modifier.height(24.dp))
        Icon(Icons.Filled.ErrorOutline, contentDescription = null, modifier = Modifier.size(56.dp), tint = MaterialTheme.colorScheme.error)
        Spacer(Modifier.height(16.dp))
        Text(message, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
        Spacer(Modifier.height(20.dp))
        Button(onClick = onRetry) { Text(stringResource(R.string.pass_entry_try_again)) }
    }
}

@Composable
private fun CenterSpinner(label: String?) {
    Column(Modifier.fillMaxWidth().padding(top = 48.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        if (label != null) {
            Text(label, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center)
            Spacer(Modifier.height(16.dp))
        }
        CircularProgressIndicator()
    }
}
