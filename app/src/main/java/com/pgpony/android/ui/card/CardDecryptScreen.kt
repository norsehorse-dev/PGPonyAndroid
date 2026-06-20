// CardDecryptScreen.kt
// PGPony Android — HW Phase 3b
//
// Focused, self-contained flow to decrypt a PGP message with the card's
// cv25519 key — the verification harness for the card decryption bridge.
// Paste a message encrypted to the card key (e.g. `gpg --encrypt -r
// <cardkey> --armor`), enter PW1, tap the card, and the plaintext appears.
// Once this verifies, Phase 3 wiring can move card decryption into the main
// Decrypt tab.
//
// The whole decrypt runs inside one NFC operation (binder thread, card
// present): SELECT → load the PAIRED public key ring → VERIFY PW1 (0x82) →
// BC parses the message and calls the card for the ECDH step.

package com.pgpony.android.ui.card

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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.pgpony.android.MainActivity
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.card.CardDecryptService
import com.pgpony.android.crypto.card.OpenPgpCardException

private sealed class DecState {
    data object Form : DecState()
    data object Waiting : DecState()
    data class Result(val plaintext: String) : DecState()
    data class Failed(val message: String) : DecState()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CardDecryptScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val activity = context as? MainActivity
    val clipboard = LocalClipboardManager.current

    val nfcAvailable = remember { activity?.isNfcAvailable() == true }
    val nfcEnabled = remember { activity?.isNfcEnabled() == true }

    var ciphertext by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    val state = remember { mutableStateOf<DecState>(DecState.Form) }

    val formValid = ciphertext.isNotBlank() && pin.isNotEmpty()

    fun startDecrypt() {
        if (activity == null || !formValid) return
        state.value = DecState.Waiting
        val msg = ciphertext
        val pinBytes = pin.toByteArray(Charsets.UTF_8)
        activity.startCardOperation({ session ->
            session.select()
            val ard = session.getApplicationRelatedData()
            val primaryFp = ard.sigFingerprint ?: ard.decFingerprint
                ?: throw OpenPgpCardException.Malformed("This card has no keys.")
            val pubRing = PGPonyApp.instance.keyRepository.loadPublicKeyRing(primaryFp)
                ?: throw OpenPgpCardException.Malformed(
                    "Pair this card's public key into your keyring first, then try again."
                )
            CardDecryptService.shared.decrypt(session, pubRing, pinBytes, msg)
        }) { result ->
            result
                .onSuccess { state.value = DecState.Result(it.data.toString(Charsets.UTF_8)) }
                .onFailure { e -> state.value = DecState.Failed(e.message ?: "Decryption failed") }
        }
    }

    DisposableEffect(Unit) {
        onDispose { activity?.stopCardScan() }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.card_decrypt_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = stringResource(R.string.card_scan_back))
                    }
                }
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 24.dp),
            contentAlignment = Alignment.Center
        ) {
            when {
                activity == null || !nfcAvailable ->
                    DecCentered(Icons.Filled.Nfc, stringResource(R.string.card_scan_nfc_unavailable))

                !nfcEnabled ->
                    DecCentered(Icons.Filled.Nfc, stringResource(R.string.card_scan_nfc_disabled))

                else -> when (val s = state.value) {
                    is DecState.Waiting -> DecCentered(
                        Icons.Filled.Contactless,
                        stringResource(R.string.card_decrypt_hold_card),
                        showSpinner = true
                    )

                    is DecState.Result -> DecResultPanel(
                        plaintext = s.plaintext,
                        onCopy = { clipboard.setText(AnnotatedString(s.plaintext)) },
                        onAgain = { state.value = DecState.Form },
                        onBack = onBack
                    )

                    is DecState.Failed -> DecFailed(
                        message = s.message,
                        onRetry = { state.value = DecState.Form }
                    )

                    is DecState.Form -> Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(vertical = 24.dp)
                    ) {
                        Text(
                            stringResource(R.string.card_decrypt_intro),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(20.dp))

                        OutlinedTextField(
                            value = ciphertext,
                            onValueChange = { ciphertext = it },
                            label = { Text(stringResource(R.string.card_decrypt_message_label)) },
                            minLines = 4,
                            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(12.dp))

                        OutlinedTextField(
                            value = pin,
                            onValueChange = { pin = it },
                            label = { Text(stringResource(R.string.card_decrypt_pin_label)) },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(24.dp))

                        Button(
                            onClick = { startDecrypt() },
                            enabled = formValid,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Filled.LockOpen, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.card_decrypt_button))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DecCentered(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    text: String,
    showSpinner: Boolean = false
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(
            icon,
            contentDescription = null,
            modifier = Modifier.size(if (showSpinner) 96.dp else 64.dp),
            tint = if (showSpinner) MaterialTheme.colorScheme.primary
            else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
        )
        Spacer(Modifier.height(20.dp))
        Text(text, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyLarge)
        if (showSpinner) {
            Spacer(Modifier.height(24.dp))
            CircularProgressIndicator()
        }
    }
}

@Composable
private fun DecResultPanel(
    plaintext: String,
    onCopy: () -> Unit,
    onAgain: () -> Unit,
    onBack: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(vertical = 16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Filled.LockOpen,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(R.string.card_decrypt_result_title),
                style = MaterialTheme.typography.titleMedium
            )
        }
        Spacer(Modifier.height(12.dp))

        ElevatedCard(modifier = Modifier.fillMaxWidth().weight(1f, fill = false)) {
            SelectionContainer {
                Text(
                    plaintext,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(12.dp)
                )
            }
        }
        Spacer(Modifier.height(12.dp))

        Button(onClick = onCopy, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Filled.ContentCopy, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.card_decrypt_copy))
        }
        OutlinedButton(onClick = onAgain, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.card_decrypt_again))
        }
        TextButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.card_pin_change_done))
        }
    }
}

@Composable
private fun DecFailed(message: String, onRetry: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(
            Icons.Filled.ErrorOutline,
            contentDescription = null,
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.error
        )
        Spacer(Modifier.height(16.dp))
        Text(message, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyLarge)
        Spacer(Modifier.height(24.dp))
        Button(onClick = onRetry) {
            Icon(Icons.Filled.Refresh, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.card_pin_change_try_again))
        }
    }
}
