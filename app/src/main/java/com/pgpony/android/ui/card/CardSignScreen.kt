// CardSignScreen.kt
// PGPony Android — HW Phase 2b
//
// Focused, self-contained flow to clear-sign a message with the card's
// signature key — the verification harness for the card signing bridge.
// Enter a message + PW1, tap the card, and the armored output appears for
// copying so it can be checked with `gpg --verify`. Once a card signature
// verifies cleanly, Phase 2b-step2 wires card keys into the main Sign tab.
//
// The whole sign runs inside one NFC operation (binder thread, card
// present): SELECT → read the signature fingerprint → load the PAIRED
// public key from the keyring → VERIFY PW1 → PSO:CDS, assembled by BC.

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
import com.pgpony.android.crypto.card.CardSigningService
import com.pgpony.android.crypto.card.OpenPgpCardException

private sealed class SignState {
    data object Form : SignState()
    data object Waiting : SignState()
    data class Result(val armored: String) : SignState()
    data class Failed(val message: String) : SignState()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CardSignScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val activity = context as? MainActivity
    val clipboard = LocalClipboardManager.current

    val nfcAvailable = remember { activity?.isNfcAvailable() == true }
    val nfcEnabled = remember { activity?.isNfcEnabled() == true }

    var message by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    val state = remember { mutableStateOf<SignState>(SignState.Form) }

    val formValid = message.isNotBlank() && pin.isNotEmpty()

    fun startSign() {
        if (activity == null || !formValid) return
        state.value = SignState.Waiting
        val msg = message
        val pinBytes = pin.toByteArray(Charsets.UTF_8)
        // Reader mode stays engaged until the screen is disposed; the
        // reader's one-shot guard prevents a second tap from re-signing.
        activity.startCardOperation({ session ->
            session.select()
            val ard = session.getApplicationRelatedData()
            val fp = ard.sigFingerprint
                ?: throw OpenPgpCardException.Malformed("This card has no signature key.")
            val pubRing = PGPonyApp.instance.keyRepository.loadPublicKeyRing(fp)
                ?: throw OpenPgpCardException.Malformed(
                    "Pair this card's public key into your keyring first (import the matching public key), then try again."
                )
            CardSigningService.shared.signClear(session, pubRing.publicKey, pinBytes, msg)
        }) { result ->
            result
                .onSuccess { state.value = SignState.Result(it) }
                .onFailure { e -> state.value = SignState.Failed(e.message ?: "Signing failed") }
        }
    }

    DisposableEffect(Unit) {
        onDispose { activity?.stopCardScan() }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.card_sign_title)) },
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
                    SignCentered(Icons.Filled.Nfc, stringResource(R.string.card_scan_nfc_unavailable))

                !nfcEnabled ->
                    SignCentered(Icons.Filled.Nfc, stringResource(R.string.card_scan_nfc_disabled))

                else -> when (val s = state.value) {
                    is SignState.Waiting -> SignCentered(
                        Icons.Filled.Contactless,
                        stringResource(R.string.card_sign_hold_card),
                        showSpinner = true
                    )

                    is SignState.Result -> ResultPanel(
                        armored = s.armored,
                        onCopy = {
                            clipboard.setText(AnnotatedString(s.armored))
                        },
                        onSignAgain = { state.value = SignState.Form },
                        onBack = onBack
                    )

                    is SignState.Failed -> SignFailed(
                        message = s.message,
                        onRetry = { state.value = SignState.Form }
                    )

                    is SignState.Form -> Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(vertical = 24.dp)
                    ) {
                        Text(
                            stringResource(R.string.card_sign_intro),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(20.dp))

                        OutlinedTextField(
                            value = message,
                            onValueChange = { message = it },
                            label = { Text(stringResource(R.string.card_sign_message_label)) },
                            minLines = 3,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(12.dp))

                        OutlinedTextField(
                            value = pin,
                            onValueChange = { pin = it },
                            label = { Text(stringResource(R.string.card_sign_pin_label)) },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(24.dp))

                        Button(
                            onClick = { startSign() },
                            enabled = formValid,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Filled.Edit, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.card_sign_button))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SignCentered(
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
private fun ResultPanel(
    armored: String,
    onCopy: () -> Unit,
    onSignAgain: () -> Unit,
    onBack: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(vertical = 16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Filled.CheckCircle,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(R.string.card_sign_result_title),
                style = MaterialTheme.typography.titleMedium
            )
        }
        Spacer(Modifier.height(12.dp))

        ElevatedCard(modifier = Modifier.fillMaxWidth().weight(1f, fill = false)) {
            SelectionContainer {
                Text(
                    armored,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
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
            Text(stringResource(R.string.card_sign_copy))
        }
        OutlinedButton(onClick = onSignAgain, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.card_sign_again))
        }
        TextButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.card_pin_change_done))
        }
    }
}

@Composable
private fun SignFailed(message: String, onRetry: () -> Unit) {
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
