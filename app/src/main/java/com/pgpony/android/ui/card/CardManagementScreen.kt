// Phase B2 — admin-PIN lifecycle management. One self-contained screen with a
// menu and three operation modes: change admin PIN (PW3), unblock the user PIN
// (PW1) with the admin PIN, and factory-reset the card. Each operation arms the
// Activity's startCardOperation helper for a single tap, exactly like the
// user-PIN change screen. PINs live only in Compose state for the screen's
// lifetime and are never logged or persisted. Factory reset is gated behind an
// explicit two-step confirmation because it irreversibly wipes the card.

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

private const val PW1_MIN = 6
private const val PW3_MIN = 8

private enum class MgmtMode { MENU, CHANGE_ADMIN, UNBLOCK, FACTORY_RESET }

private sealed class OpState {
    /** Showing the menu or a form. */
    data object Idle : OpState()
    /** Operation armed; waiting for the card tap. */
    data object Waiting : OpState()
    data class Done(val message: String) : OpState()
    data class Failed(val message: String) : OpState()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CardManagementScreen(onBack: () -> Unit, onDone: () -> Unit = {}) {
    val context = LocalContext.current
    val activity = context as? MainActivity

    var mode by remember { mutableStateOf(MgmtMode.MENU) }
    val opState = remember { mutableStateOf<OpState>(OpState.Idle) }

    DisposableEffect(Unit) {
        onDispose { activity?.stopCardScan() }
    }

    val doneAdmin = stringResource(R.string.card_mgmt_done_admin)
    val doneUnblock = stringResource(R.string.card_mgmt_done_unblock)
    val doneReset = stringResource(R.string.card_mgmt_done_reset)
    val failGeneric = stringResource(R.string.card_mgmt_failed_generic)

    fun arm(operation: (com.pgpony.android.crypto.card.OpenPgpCardSession) -> Unit, doneMsg: String) {
        opState.value = OpState.Waiting
        val started = activity?.startCardOperation(operation) { result ->
            result
                .onSuccess { opState.value = OpState.Done(doneMsg) }
                .onFailure { e -> opState.value = OpState.Failed(e.message ?: failGeneric) }
        } ?: false
        if (started != true) {
            opState.value = OpState.Failed(failGeneric)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.card_mgmt_title)) },
                navigationIcon = {
                    IconButton(onClick = {
                        if (mode == MgmtMode.MENU || opState.value !is OpState.Idle) onBack()
                        else { mode = MgmtMode.MENU }
                    }) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = stringResource(R.string.card_mgmt_back))
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
            when (val s = opState.value) {
                is OpState.Waiting -> WaitingPrompt()
                is OpState.Done -> DonePrompt(s.message, onDone = {
                    opState.value = OpState.Idle
                    mode = MgmtMode.MENU
                    onDone()
                })
                is OpState.Failed -> FailedPrompt(s.message, onRetry = {
                    opState.value = OpState.Idle
                })
                is OpState.Idle -> when (mode) {
                    MgmtMode.MENU -> MenuBody(onSelect = { mode = it })
                    MgmtMode.CHANGE_ADMIN -> ChangeAdminForm { cur, new -> arm({ it.changeAdminPin(cur, new) }, doneAdmin) }
                    MgmtMode.UNBLOCK -> UnblockForm { admin, newUser -> arm({ it.unblockUserPin(admin, newUser) }, doneUnblock) }
                    MgmtMode.FACTORY_RESET -> FactoryResetForm { arm({ it.factoryReset() }, doneReset) }
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun MenuBody(onSelect: (MgmtMode) -> Unit) {
    Text(
        stringResource(R.string.card_mgmt_subtitle),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(16.dp))
    OutlinedButton(onClick = { onSelect(MgmtMode.CHANGE_ADMIN) }, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Filled.Shield, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(stringResource(R.string.card_mgmt_action_change_admin))
    }
    Spacer(Modifier.height(8.dp))
    OutlinedButton(onClick = { onSelect(MgmtMode.UNBLOCK) }, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Filled.LockOpen, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(stringResource(R.string.card_mgmt_action_unblock))
    }
    Spacer(Modifier.height(8.dp))
    OutlinedButton(
        onClick = { onSelect(MgmtMode.FACTORY_RESET) },
        modifier = Modifier.fillMaxWidth(),
        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
    ) {
        Icon(Icons.Filled.Delete, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(stringResource(R.string.card_mgmt_action_factory_reset))
    }
}

@Composable
private fun ChangeAdminForm(onSubmit: (String, String) -> Unit) {
    var current by remember { mutableStateOf("") }
    var newPin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    val tooShort = newPin.isNotEmpty() && newPin.length < PW3_MIN
    val mismatch = confirm.isNotEmpty() && confirm != newPin
    val valid = current.length >= PW3_MIN && newPin.length >= PW3_MIN && newPin == confirm

    SectionTitle(stringResource(R.string.card_mgmt_action_change_admin))
    Text(
        stringResource(R.string.card_mgmt_admin_hint),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(12.dp))
    PinField(current, { current = it }, stringResource(R.string.card_mgmt_field_current_admin))
    Spacer(Modifier.height(8.dp))
    PinField(newPin, { newPin = it }, stringResource(R.string.card_mgmt_field_new_admin), isError = tooShort)
    Spacer(Modifier.height(8.dp))
    PinField(confirm, { confirm = it }, stringResource(R.string.card_mgmt_field_confirm), isError = mismatch)
    if (mismatch) ErrorLine(stringResource(R.string.card_mgmt_error_mismatch))
    if (tooShort) ErrorLine(stringResource(R.string.card_mgmt_error_admin_short))
    Spacer(Modifier.height(16.dp))
    Button(onClick = { onSubmit(current, newPin) }, enabled = valid, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.card_mgmt_submit_then_tap))
    }
}

@Composable
private fun UnblockForm(onSubmit: (String, String) -> Unit) {
    var admin by remember { mutableStateOf("") }
    var newUser by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    val tooShort = newUser.isNotEmpty() && newUser.length < PW1_MIN
    val mismatch = confirm.isNotEmpty() && confirm != newUser
    val valid = admin.length >= PW3_MIN && newUser.length >= PW1_MIN && newUser == confirm

    SectionTitle(stringResource(R.string.card_mgmt_action_unblock))
    Text(
        stringResource(R.string.card_mgmt_unblock_hint),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(12.dp))
    PinField(admin, { admin = it }, stringResource(R.string.card_mgmt_field_admin))
    Spacer(Modifier.height(8.dp))
    PinField(newUser, { newUser = it }, stringResource(R.string.card_mgmt_field_new_user), isError = tooShort)
    Spacer(Modifier.height(8.dp))
    PinField(confirm, { confirm = it }, stringResource(R.string.card_mgmt_field_confirm), isError = mismatch)
    if (mismatch) ErrorLine(stringResource(R.string.card_mgmt_error_mismatch))
    if (tooShort) ErrorLine(stringResource(R.string.card_mgmt_error_user_short))
    Spacer(Modifier.height(16.dp))
    Button(onClick = { onSubmit(admin, newUser) }, enabled = valid, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.card_mgmt_submit_then_tap))
    }
}

@Composable
private fun FactoryResetForm(onConfirm: () -> Unit) {
    var step2 by remember { mutableStateOf(false) }

    SectionTitle(stringResource(R.string.card_mgmt_action_factory_reset))
    Icon(
        Icons.Filled.Warning,
        contentDescription = null,
        tint = MaterialTheme.colorScheme.error,
        modifier = Modifier.size(48.dp),
    )
    Spacer(Modifier.height(12.dp))
    Text(
        stringResource(R.string.card_mgmt_reset_warning),
        style = MaterialTheme.typography.bodyMedium,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(16.dp))
    if (!step2) {
        Button(
            onClick = { step2 = true },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
        ) {
            Text(stringResource(R.string.card_mgmt_reset_confirm1))
        }
    } else {
        Text(
            stringResource(R.string.card_mgmt_reset_confirm2_prompt),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = onConfirm,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
        ) {
            Icon(Icons.Filled.Delete, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.card_mgmt_reset_confirm2))
        }
    }
}

@Composable
private fun WaitingPrompt() {
    Icon(
        Icons.Filled.Nfc,
        contentDescription = null,
        modifier = Modifier.size(64.dp),
        tint = MaterialTheme.colorScheme.primary,
    )
    Spacer(Modifier.height(16.dp))
    Text(
        stringResource(R.string.card_mgmt_tap_prompt),
        style = MaterialTheme.typography.bodyLarge,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(16.dp))
    CircularProgressIndicator()
}

@Composable
private fun DonePrompt(message: String, onDone: () -> Unit) {
    Icon(
        Icons.Filled.CheckCircle,
        contentDescription = null,
        modifier = Modifier.size(64.dp),
        tint = MaterialTheme.colorScheme.primary,
    )
    Spacer(Modifier.height(16.dp))
    Text(message, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center)
    Spacer(Modifier.height(16.dp))
    Button(onClick = onDone) { Text(stringResource(R.string.card_mgmt_done_button)) }
}

@Composable
private fun FailedPrompt(message: String, onRetry: () -> Unit) {
    Icon(
        Icons.Filled.ErrorOutline,
        contentDescription = null,
        modifier = Modifier.size(64.dp),
        tint = MaterialTheme.colorScheme.error,
    )
    Spacer(Modifier.height(16.dp))
    Text(message, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center)
    Spacer(Modifier.height(16.dp))
    Button(onClick = onRetry) { Text(stringResource(R.string.card_mgmt_retry)) }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun ErrorLine(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.error,
        modifier = Modifier.fillMaxWidth(),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PinField(value: String, onChange: (String) -> Unit, label: String, isError: Boolean = false) {
    OutlinedTextField(
        value = value,
        onValueChange = { if (it.all { c -> c.isDigit() }) onChange(it) },
        label = { Text(label) },
        visualTransformation = PasswordVisualTransformation(),
        singleLine = true,
        isError = isError,
        modifier = Modifier.fillMaxWidth(),
    )
}
