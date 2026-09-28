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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import android.content.Context
import android.hardware.usb.UsbManager
import androidx.compose.material.icons.filled.Usb
import com.pgpony.android.MainActivity
import com.pgpony.android.crypto.card.CardLinkAdvice
import com.pgpony.android.crypto.card.CardLinkKind
import com.pgpony.android.usb.UsbCardConnectionManager
import com.pgpony.android.usb.UsbCardOperations
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.card.CardDecryptService
import com.pgpony.android.crypto.card.OpenPgpCardException
import com.pgpony.android.i18n.ErrorText

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

    // 4.1.0 USB Phase 2 — recomputed, not remembered once: a key can be
    // plugged in while this screen is open.
    var usbTick by remember { mutableStateOf(0) }
    val usbCards = remember { UsbCardConnectionManager(context) { usbTick++ } }
    DisposableEffect(usbCards) {
        usbCards.register()
        onDispose { usbCards.unregister() }
    }
    val nfcAvailable = activity?.isNfcAvailable() == true
    val nfcEnabled = activity?.isNfcEnabled() == true
    val link = remember(usbTick, nfcAvailable, nfcEnabled) {
        usbCards.availability(nfcAvailable, nfcEnabled)
    }
    val noReaderMessage = stringResource(R.string.card_usb_no_reader)

    LaunchedEffect(link.advice) {
        if (link.advice == CardLinkAdvice.AttachedReaderNeedsPermission) {
            usbCards.firstReader()?.let { device ->
                usbCards.requestPermission(device) { usbTick++ }
            }
        }
    }

    var ciphertext by remember { mutableStateOf("") }
    // 3.1.0 Phase 7 (B1): prefill from the PIN cache when enabled.
    var pin by remember { mutableStateOf(com.pgpony.android.crypto.card.CardPinCache.retrieve() ?: "") }
    val state = remember { mutableStateOf<DecState>(DecState.Form) }

    val formValid = ciphertext.isNotBlank() && pin.isNotEmpty()

    fun startDecrypt() {
        if (!formValid) return
        state.value = DecState.Waiting
        val msg = ciphertext
        val pinBytes = pin.toByteArray(Charsets.UTF_8)

        // IDENTICAL on both transports. OpenPgpCardSession depends only on the
        // CardTransport interface, which is why adding a second physical link
        // did not touch the protocol layer at all.
        val operation = { session: com.pgpony.android.crypto.card.OpenPgpCardSession ->
            session.select()
            val ard = session.getApplicationRelatedData()
            val primaryFp = ard.sigFingerprint ?: ard.decFingerprint
                ?: throw OpenPgpCardException.Malformed(context.getString(R.string.card_decrypt_no_keys))
            // 3.1.0 Phase 7 Fix1: this fingerprint is card-derived and is a
            // SUBKEY on offline-primary layouts — tolerant loader.
            val pubRing = PGPonyApp.instance.keyRepository
                .loadPublicKeyRingByCardFingerprint(primaryFp)
                ?: throw OpenPgpCardException.Malformed(
                    context.getString(R.string.card_sign_pair_first)
                )
            CardDecryptService.shared.decrypt(session, pubRing, pinBytes, msg)
        }

        when (link.preferred) {
            CardLinkKind.USB -> {
                val manager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
                val device = usbCards.firstReader()
                if (manager == null || device == null) {
                    state.value = DecState.Failed(noReaderMessage)
                } else {
                    UsbCardOperations.run(manager, device, operation) { result ->
                        result
                            .onSuccess { state.value = DecState.Result(it.data.toString(Charsets.UTF_8)) }
                            .onFailure { e -> state.value = DecState.Failed(ErrorText.localize(context, e.message) ?: context.getString(R.string.card_decrypt_failed_generic)) }
                    }
                }
            }
            CardLinkKind.NFC -> activity?.startCardOperation(operation) { result ->
                result
                    .onSuccess { state.value = DecState.Result(it.data.toString(Charsets.UTF_8)) }
                    .onFailure { e -> state.value = DecState.Failed(ErrorText.localize(context, e.message) ?: context.getString(R.string.card_decrypt_failed_generic)) }
            }
            null -> state.value = DecState.Failed(noReaderMessage)
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
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.card_scan_back))
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
                // Permission first: something IS plugged in, so telling the
                // user there is no way to reach a card would be wrong as well
                // as unhelpful.
                link.advice == CardLinkAdvice.AttachedReaderNeedsPermission ->
                    DecCentered(Icons.Filled.Usb, stringResource(R.string.card_scan_usb_permission))

                link.advice == CardLinkAdvice.EnableNfc ->
                    DecCentered(Icons.Filled.Nfc, stringResource(R.string.card_scan_nfc_disabled))

                !link.anyUsable ->
                    DecCentered(Icons.Filled.Nfc, stringResource(R.string.card_scan_nfc_unavailable))

                else -> when (val s = state.value) {
                    is DecState.Waiting -> DecCentered(
                        if (link.preferred == CardLinkKind.USB) Icons.Filled.Usb
                        else Icons.Filled.Contactless,
                        // Over a cable there is nothing to hold against the
                        // phone, so "hold your card here" is simply wrong.
                        if (link.preferred == CardLinkKind.USB)
                            stringResource(R.string.card_usb_working)
                        else stringResource(R.string.card_decrypt_hold_card),
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
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
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
