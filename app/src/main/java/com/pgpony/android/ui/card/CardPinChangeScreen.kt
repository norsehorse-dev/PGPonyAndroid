// CardPinChangeScreen.kt
// PGPony Android — HW Phase 2a
//
// Change the card's user PIN (PW1) over NFC. The "nicety" from the v6.0
// plan: low-risk (no admin PIN, no key material), and it exercises the
// exact enter-PIN → tap-card → run-command machinery that on-card signing
// reuses in Phase 2b.
//
// Self-contained like CardScanScreen: talks to the Activity's generic
// startCardOperation helper and runs OpenPgpCardSession.changeUserPin on
// the binder thread. PIN strings live only in Compose state for the
// duration of the screen and are never logged or persisted.

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
import com.pgpony.android.R

private sealed class PinState {
    data object Form : PinState()
    data object Waiting : PinState()
    data object Done : PinState()
    data class Failed(val message: String) : PinState()
}

private const val PW1_MIN_LEN = 6
private const val PW1_MAX_LEN = 127

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CardPinChangeScreen(onBack: () -> Unit, onDone: () -> Unit = {}) {
    val context = LocalContext.current
    val activity = context as? MainActivity

    val nfcAvailable = remember { activity?.isNfcAvailable() == true }
    val nfcEnabled = remember { activity?.isNfcEnabled() == true }

    var current by remember { mutableStateOf("") }
    var newPin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    val state = remember { mutableStateOf<PinState>(PinState.Form) }

    val newTooShort = newPin.isNotEmpty() && newPin.length < PW1_MIN_LEN
    val mismatch = confirm.isNotEmpty() && confirm != newPin
    val formValid = current.isNotEmpty() &&
        newPin.length in PW1_MIN_LEN..PW1_MAX_LEN &&
        confirm == newPin

    fun startChange() {
        if (activity == null || !formValid) return
        state.value = PinState.Waiting
        val cur = current
        val nw = newPin
        // Reader mode stays engaged until the screen is disposed; the
        // reader's one-shot guard prevents a second tap from re-running
        // the change. Disabling it here (while the card is still on the
        // phone) is what made the OS show "no supported application".
        activity.startCardOperation({ session -> session.changeUserPin(cur, nw) }) { result ->
            result
                .onSuccess { state.value = PinState.Done }
                .onFailure { e -> state.value = PinState.Failed(e.message ?: "PIN change failed") }
        }
    }

    DisposableEffect(Unit) {
        onDispose { activity?.stopCardScan() }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.card_pin_change_title)) },
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
                    Centered(Icons.Filled.Nfc, stringResource(R.string.card_scan_nfc_unavailable))

                !nfcEnabled ->
                    Centered(Icons.Filled.Nfc, stringResource(R.string.card_scan_nfc_disabled))

                else -> when (val s = state.value) {
                    is PinState.Waiting -> Centered(
                        Icons.Filled.Contactless,
                        stringResource(R.string.card_pin_change_hold_card),
                        showSpinner = true
                    )
                    is PinState.Done -> DonePanel(onDone = onDone)
                    is PinState.Failed -> FailedPanel(
                        message = s.message,
                        onRetry = { state.value = PinState.Form }
                    )
                    is PinState.Form -> Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(vertical = 24.dp)
                    ) {
                        Text(
                            stringResource(R.string.card_pin_change_intro),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(20.dp))

                        OutlinedTextField(
                            value = current,
                            onValueChange = { current = it },
                            label = { Text(stringResource(R.string.card_pin_change_current_label)) },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(12.dp))

                        OutlinedTextField(
                            value = newPin,
                            onValueChange = { newPin = it },
                            label = { Text(stringResource(R.string.card_pin_change_new_label)) },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            isError = newTooShort,
                            supportingText = if (newTooShort) {
                                { Text(stringResource(R.string.card_pin_change_too_short)) }
                            } else null,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(12.dp))

                        OutlinedTextField(
                            value = confirm,
                            onValueChange = { confirm = it },
                            label = { Text(stringResource(R.string.card_pin_change_confirm_label)) },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            isError = mismatch,
                            supportingText = if (mismatch) {
                                { Text(stringResource(R.string.card_pin_change_mismatch)) }
                            } else null,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(24.dp))

                        Button(
                            onClick = { startChange() },
                            enabled = formValid,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Filled.Password, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.card_pin_change_button))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun Centered(
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
private fun DonePanel(onDone: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(
            Icons.Filled.CheckCircle,
            contentDescription = null,
            modifier = Modifier.size(72.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.height(16.dp))
        Text(
            stringResource(R.string.card_pin_change_success),
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(24.dp))
        Button(onClick = onDone) { Text(stringResource(R.string.card_pin_change_done)) }
    }
}

@Composable
private fun FailedPanel(message: String, onRetry: () -> Unit) {
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
