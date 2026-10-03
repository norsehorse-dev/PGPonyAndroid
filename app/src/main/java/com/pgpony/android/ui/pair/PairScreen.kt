// PairScreen.kt
// PGPony Android 4.6.3 (4.7.0 item 21): "Pair with another device", the phone
// side of desktop 3.0's pairing (docs/PAIRING_PROTOCOL.md). One device waits
// and shows a QR invite and its address, the other scans or types it; the
// joining device shows a six-digit code and asks whether the waiting one shows
// the same, and the waiting device's user types the code the joining one shows
// (section 4). Then either side can send public keys, key pairs or a full
// backup; the receiver picks what to take and sees each item, as read from its
// bytes, before anything is written.
//
// Each item gets a row with its outcome (added on the other side, skipped,
// failed), and Done ends the session with a count of what moved and a way to
// open the keys that arrived.
//
// Nothing is remembered: leaving the screen ends the session and wipes its
// keys, and no socket is touched on the main thread. Offline mode blocks
// pairing (it opens a socket even though the traffic stays on the local
// network). A key pair or a backup leaves the phone only after device
// authentication when the phone has it set up, as for a private key export.

package com.pgpony.android.ui.pair

import android.os.Build
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.RemoveCircleOutline
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pgpony.android.BuildConfig
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.network.OfflineMode
import com.pgpony.android.pair.PairAnswer
import com.pgpony.android.pair.PairAttempt
import com.pgpony.android.pair.PairException
import com.pgpony.android.pair.PairFailure
import com.pgpony.android.pair.PairInfo
import com.pgpony.android.pair.PairItem
import com.pgpony.android.pair.PairMessage
import com.pgpony.android.pair.PairOffer
import com.pgpony.android.pair.PairResult
import com.pgpony.android.pair.PairRole
import com.pgpony.android.pair.PairSession
import com.pgpony.android.qr.QrBitmap
import com.pgpony.android.ui.keyring.BiometricAvailability
import com.pgpony.android.ui.keyring.BiometricGate
import com.pgpony.android.ui.scanner.QRScannerScreen
import com.pgpony.android.ui.util.ClipboardService
import com.pgpony.android.ui.util.rememberHaptics
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

private sealed class PairStage {
    object Choose : PairStage()
    /** [peer] is set once a device connected and the handshake runs. */
    class Hosting(val window: PairController.HostWindow, val peer: String? = null) : PairStage()
    object Joining : PairStage()
    class Compare(val attempt: PairAttempt, val peer: String, val waiting: Boolean = false) : PairStage()
    class Paired(val session: PairSession, val peer: String) : PairStage()
    class Failed(val message: String) : PairStage()
    /** The session ended after something moved: what it moved, and who ended it. */
    class Finished(val rows: List<PairRow>, val peerName: String?, val byPeer: Boolean) : PairStage()
}

/** Runs [block] on a daemon thread, so a socket write never runs on the main thread. */
private fun inBackground(block: () -> Unit) {
    Thread({ runCatching(block) }, "pgpony-pair-ui").apply { isDaemon = true }.start()
}

private fun str(id: Int, vararg args: Any): String =
    if (args.isEmpty()) PGPonyApp.instance.getString(id) else PGPonyApp.instance.getString(id, *args)

/** The message a failed attempt shows. */
private fun pairFailureMessage(e: Throwable): String {
    val failure = (e as? PairException)?.failure ?: return str(R.string.pair_fail_closed)
    return when (failure) {
        PairFailure.REFUSED -> str(R.string.pair_fail_refused)
        PairFailure.HANDSHAKE -> str(R.string.pair_fail_handshake)
        PairFailure.TIMEOUT ->
            if (e.message == PairController.HostWindow.WINDOW_EXPIRED) str(R.string.pair_err_window_expired)
            else str(R.string.pair_fail_timeout)
        PairFailure.VERSION -> str(R.string.pair_fail_version)
        PairFailure.PROTOCOL -> str(R.string.pair_fail_protocol)
        PairFailure.BUSY, PairFailure.CLOSED -> str(R.string.pair_fail_closed)
    }
}

/** The message a failed join shows: a refused or cut connection may mean the window was taken. */
private fun joinFailureMessage(e: Throwable): String = when {
    e is java.net.SocketTimeoutException -> str(R.string.pair_fail_timeout)
    PairController.windowMayBeTaken(e) -> str(R.string.pair_fail_window_taken)
    else -> pairFailureMessage(e)
}

/** A fingerprint in groups of four. */
private fun grouped(fp: String) = fp.uppercase().chunked(4).joinToString(" ")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairScreen(
    onBack: () -> Unit,
    onKeysChanged: () -> Unit,
    onOpenKey: (fingerprint: String) -> Unit = {},
    onOpenKeyring: () -> Unit = {}
) {
    val scope = rememberCoroutineScope()
    val controller = remember { PairController(PGPonyApp.instance.keyRepository) }
    var stage by remember { mutableStateOf<PairStage>(PairStage.Choose) }
    var scanning by remember { mutableStateOf(false) }
    // A scanned invite connects from here, not from JoiningPane: while it
    // runs, the pane's own Scan and Connect stay disabled.
    var joinBusy by remember { mutableStateOf(false) }

    // The screen stays on while this screen is up: a pairing is short and a
    // sleeping phone drops its Wi-Fi.
    val view = LocalView.current
    DisposableEffect(view) {
        view.keepScreenOn = true
        onDispose { view.keepScreenOn = false }
    }

    // Whatever is open when the screen goes away is closed: the listener, the
    // attempt, the session. Nothing here waits on the network.
    fun teardown() {
        when (val s = stage) {
            is PairStage.Hosting -> s.window.close()
            is PairStage.Compare -> inBackground { s.attempt.reject() }
            is PairStage.Paired -> s.session.endAsync()
            else -> {}
        }
    }
    DisposableEffect(Unit) { onDispose { teardown() } }

    fun fail(e: Throwable) {
        stage = PairStage.Failed(pairFailureMessage(e))
    }

    fun startCompare(attempt: PairAttempt, peer: String) {
        // One attempt at a time: a second one that got through is refused,
        // never left open with the other device waiting on its code.
        val current = stage
        if (current is PairStage.Compare && current.attempt !== attempt) {
            inBackground { attempt.reject() }
            return
        }
        stage = PairStage.Compare(attempt, peer)
        attempt.peerRefused.thenAccept { failure ->
            scope.launch {
                val s = stage
                if (s is PairStage.Compare && s.attempt === attempt) {
                    stage = PairStage.Failed(pairFailureMessage(PairException(failure, "")))
                }
            }
        }
    }

    fun host() {
        val window = try {
            PairController.HostWindow()
        } catch (e: Exception) {
            fail(e)
            return
        }
        stage = PairStage.Hosting(window)
        scope.launch {
            try {
                val peer = withContext(Dispatchers.IO) { window.awaitConnection() }
                if (stage !is PairStage.Hosting) return@launch
                stage = PairStage.Hosting(window, peer)
                val attempt = withContext(Dispatchers.IO) { window.handshake() }
                startCompare(attempt, peer)
            } catch (e: Exception) {
                if (stage is PairStage.Hosting) fail(e)
            }
        }
    }

    fun confirm(compare: PairStage.Compare) {
        stage = PairStage.Compare(compare.attempt, compare.peer, waiting = true)
        scope.launch {
            try {
                val session = withContext(Dispatchers.IO) { compare.attempt.confirm() }
                stage = PairStage.Paired(session, compare.peer)
            } catch (e: Exception) {
                fail(e)
            }
        }
    }

    fun refuse(compare: PairStage.Compare, message: String) {
        inBackground { compare.attempt.reject() }
        stage = PairStage.Failed(message)
    }

    // Done, BYE or a lost connection. Done with nothing moved simply closes the screen
    // (teardown ends the session); otherwise the session ends here and the summary shows.
    fun finish(paired: PairStage.Paired, rows: List<PairRow>, peerName: String?, byPeer: Boolean) {
        if (stage !== paired) return
        val closed = PairLedger.closed(rows)
        if (closed.isEmpty() && !byPeer) {
            onBack()
            return
        }
        paired.session.endAsync()
        stage = if (closed.isEmpty()) PairStage.Failed(str(R.string.pair_ended))
        else PairStage.Finished(closed, peerName, byPeer)
    }

    if (scanning) {
        QRScannerScreen(
            onScanned = { text ->
                scanning = false
                stage = PairStage.Joining
                joinBusy = true
                scope.launch {
                    try {
                        val target = withContext(Dispatchers.IO) { PairController.target(text) }
                        if (target == null) {
                            stage = PairStage.Failed(str(R.string.pair_bad_invite))
                            return@launch
                        }
                        val connection = withContext(Dispatchers.IO + NonCancellable) { controller.connect(target) }
                        if (!isActive) {
                            inBackground { connection.attempt.reject() }
                            return@launch
                        }
                        startCompare(connection.attempt, connection.peer)
                    } catch (e: Exception) {
                        if (isActive) stage = PairStage.Failed(joinFailureMessage(e))
                    } finally {
                        joinBusy = false
                    }
                }
            },
            onDismiss = { scanning = false }
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.pair_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.pair_back_cd))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            when (val s = stage) {
                PairStage.Choose -> {
                    Text(stringResource(R.string.pair_intro), style = MaterialTheme.typography.bodyMedium)
                    if (OfflineMode.isEnabled()) {
                        Text(
                            stringResource(R.string.pair_offline),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                    } else {
                        Button(onClick = { host() }, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.pair_host))
                        }
                        OutlinedButton(onClick = { stage = PairStage.Joining }, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.pair_join))
                        }
                    }
                }
                is PairStage.Hosting -> if (s.peer == null) {
                    HostingPane(s.window)
                } else {
                    Text(stringResource(R.string.pair_host_connected, s.peer), style = MaterialTheme.typography.bodyMedium)
                }
                PairStage.Joining -> JoiningPane(
                    controller,
                    busy = joinBusy,
                    onScan = { scanning = true },
                    onAttempt = { startCompare(it.attempt, it.peer) },
                    onError = { stage = PairStage.Failed(joinFailureMessage(it)) }
                )
                is PairStage.Compare -> if (s.attempt.role == PairRole.HOST) {
                    HostComparePane(
                        s,
                        onMatch = { confirm(s) },
                        onCancel = { refuse(s, str(R.string.pair_fail_you_cancelled)) },
                        onTooManyWrong = { refuse(s, str(R.string.pair_fail_typed_wrong)) }
                    )
                } else {
                    ComparePane(
                        s,
                        onMatch = { confirm(s) },
                        onDiffer = { refuse(s, str(R.string.pair_fail_you_refused)) }
                    )
                }
                is PairStage.Paired -> SessionPane(controller, s.session, s.peer, onKeysChanged) { rows, peerName, byPeer ->
                    finish(s, rows, peerName, byPeer)
                }
                is PairStage.Finished -> FinishedPane(
                    s,
                    onClose = onBack,
                    onAgain = { stage = PairStage.Choose },
                    onOpenKey = onOpenKey,
                    onOpenKeyring = onOpenKeyring
                )
                is PairStage.Failed -> {
                    Text(s.message, style = MaterialTheme.typography.bodyMedium)
                    OutlinedButton(onClick = { stage = PairStage.Choose }) { Text(stringResource(R.string.pair_again)) }
                }
            }
        }
    }
}

@Composable
private fun ColumnScope.HostingPane(window: PairController.HostWindow) {
    val context = LocalContext.current
    val addresses = remember(window) { window.addressTexts() }
    val closesAt = remember(window) {
        DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(window.openedAt + PairController.WINDOW_MS))
    }
    if (addresses.isEmpty()) {
        Text(stringResource(R.string.pair_no_address), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
        return
    }
    Text(stringResource(R.string.pair_host_waiting), style = MaterialTheme.typography.bodyMedium)
    // The invite: the other side scans it, which also checks it reached this phone.
    val invite = remember(window) { window.invite() }
    val qr = remember(invite) { invite?.let { runCatching { QrBitmap.encodeOne(it.toUri()) }.getOrNull() } }
    if (qr != null) {
        Image(
            bitmap = qr.asImageBitmap(),
            contentDescription = stringResource(R.string.pair_invite_cd),
            modifier = Modifier.size(240.dp).align(Alignment.CenterHorizontally)
        )
    }
    Text(addresses.first(), style = MaterialTheme.typography.headlineSmall, fontFamily = FontFamily.Monospace)
    addresses.drop(1).forEach { Text(it, style = MaterialTheme.typography.bodyLarge, fontFamily = FontFamily.Monospace) }
    if (invite != null) {
        TextButton(onClick = { ClipboardService.copyText(context, invite.toUri()) }) {
            Text(stringResource(R.string.pair_copy_invite))
        }
    }
    Text(
        stringResource(R.string.pair_host_closes, closesAt),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@Composable
private fun JoiningPane(
    controller: PairController,
    busy: Boolean,
    onScan: () -> Unit,
    onAttempt: (PairController.Connection) -> Unit,
    onError: (Throwable) -> Unit
) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var bad by remember { mutableStateOf(false) }
    var working by remember { mutableStateOf(false) }
    Text(stringResource(R.string.pair_join_intro), style = MaterialTheme.typography.bodyMedium)
    Button(onClick = onScan, enabled = !working && !busy, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.pair_scan))
    }
    OutlinedTextField(
        value = text,
        onValueChange = { text = it; bad = false },
        label = { Text(stringResource(R.string.pair_join_label)) },
        placeholder = { Text("192.168.1.20:49152") },
        singleLine = true,
        isError = bad,
        enabled = !working && !busy,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
        modifier = Modifier.fillMaxWidth()
    )
    if (bad) {
        Text(
            stringResource(if (PairController.looksLikeInvite(text)) R.string.pair_bad_invite else R.string.pair_bad_address),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error
        )
    }
    OutlinedButton(enabled = !working && !busy && text.isNotBlank(), onClick = {
        working = true
        scope.launch {
            try {
                val target = withContext(Dispatchers.IO) { PairController.target(text) }
                if (target == null) {
                    bad = true
                    return@launch
                }
                // Not cancelled half way: an attempt that connected after the
                // screen closed is refused rather than left open.
                val connection = withContext(Dispatchers.IO + NonCancellable) { controller.connect(target) }
                if (!isActive) {
                    inBackground { connection.attempt.reject() }
                    return@launch
                }
                onAttempt(connection)
            } catch (e: Exception) {
                if (isActive) onError(e)
            } finally {
                working = false
            }
        }
    }) { Text(stringResource(if (working) R.string.pair_working else R.string.pair_connect)) }
}

/** The joining side: the code, and whether the other device shows the same one. */
@Composable
private fun ComparePane(compare: PairStage.Compare, onMatch: () -> Unit, onDiffer: () -> Unit) {
    Text(
        stringResource(R.string.pair_peer_address, compare.peer),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Text(stringResource(R.string.pair_compare_body), style = MaterialTheme.typography.bodyMedium)
    Text(compare.attempt.code, fontSize = 40.sp, fontWeight = FontWeight.SemiBold, fontFamily = FontFamily.Monospace)
    if (compare.waiting) {
        Text(stringResource(R.string.pair_waiting_other), style = MaterialTheme.typography.bodyMedium)
    } else {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onMatch) { Text(stringResource(R.string.pair_codes_match)) }
            OutlinedButton(onClick = onDiffer) { Text(stringResource(R.string.pair_codes_differ)) }
        }
    }
}

/**
 * The waiting side: its user types the code the joining device shows instead
 * of pressing a "same code" button, so the pairing cannot be confirmed when
 * the other screen shows no code (docs/PAIRING_PROTOCOL.md, section 4).
 */
@Composable
private fun HostComparePane(
    compare: PairStage.Compare,
    onMatch: () -> Unit,
    onCancel: () -> Unit,
    onTooManyWrong: () -> Unit
) {
    var typed by remember(compare.attempt) { mutableStateOf("") }
    var wrong by remember(compare.attempt) { mutableStateOf(false) }
    var tries by remember(compare.attempt) { mutableIntStateOf(0) }
    Text(
        stringResource(R.string.pair_peer_address, compare.peer),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    if (compare.waiting) {
        Text(stringResource(R.string.pair_waiting_other), style = MaterialTheme.typography.bodyMedium)
        return
    }
    Text(stringResource(R.string.pair_compare_host_body), style = MaterialTheme.typography.bodyMedium)
    OutlinedTextField(
        value = typed,
        onValueChange = { v -> typed = v.filter { it in '0'..'9' || it == ' ' }.take(7); wrong = false },
        label = { Text(stringResource(R.string.pair_typed_code_label)) },
        singleLine = true,
        isError = wrong,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        textStyle = MaterialTheme.typography.headlineSmall.copy(fontFamily = FontFamily.Monospace),
        modifier = Modifier.fillMaxWidth()
    )
    if (wrong) {
        Text(stringResource(R.string.pair_typed_code_wrong), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(enabled = typed.count { it in '0'..'9' } == 6, onClick = {
            if (compare.attempt.matchesTypedCode(typed)) {
                onMatch()
            } else {
                tries += 1
                if (tries >= PairController.TYPED_CODE_TRIES) onTooManyWrong() else {
                    wrong = true
                    typed = ""
                }
            }
        }) { Text(stringResource(R.string.pair_typed_code_confirm)) }
        OutlinedButton(onClick = onCancel) { Text(stringResource(R.string.pair_cancel)) }
    }
    Text(
        stringResource(R.string.pair_compare_host_own),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Text(compare.attempt.code, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace)
}

/** An offer from the other side, waiting for this user's picks. */
private class Incoming(val offer: PairOffer)

@Composable
private fun SessionPane(
    controller: PairController,
    session: PairSession,
    peer: String,
    onKeysChanged: () -> Unit,
    onFinished: (rows: List<PairRow>, peerName: String?, byPeer: Boolean) -> Unit
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val haptics = rememberHaptics()
    var peerName by remember { mutableStateOf<String?>(null) }
    // What the other side can import (its INFO); nothing is offered that it cannot take.
    var peerInfo by remember { mutableStateOf<PairInfo?>(null) }
    // Messages that belong to no one item: a send or an offer that did not go out.
    val log = remember { mutableStateListOf<String>() }
    // Every item this session sent or received, in order, with its outcome.
    var rows by remember { mutableStateOf(listOf<PairRow>()) }
    var incoming by remember { mutableStateOf<Incoming?>(null) }
    var outgoing by remember { mutableStateOf<PairController.Prepared?>(null) }
    var pendingResults by remember { mutableIntStateOf(0) }
    var progress by remember { mutableStateOf<String?>(null) }
    // Accepted ids and sizes; the reader checks arriving items against it, so it is live.
    val expected = remember { ConcurrentHashMap<Int, Long>() }
    val acceptedItems = remember { ConcurrentHashMap<Int, PairItem>() }
    var backupCode by remember { mutableStateOf("") }
    var backupError by remember { mutableStateOf<String?>(null) }
    // Received items that passed the checks, each waiting for this user's Add or Skip.
    val received = remember { mutableStateListOf<PairController.Received>() }

    fun sendResult(result: PairResult) {
        scope.launch { runCatching { withContext(Dispatchers.IO) { session.sendResult(result) } } }
    }

    /** A received item's row, named and fingerprinted as read from its bytes when it got that far. */
    fun receivedRow(item: PairItem, preview: com.pgpony.android.data.repository.ImportPreview?, outcome: PairOutcome, detail: String? = null) =
        PairRow(
            id = item.id,
            direction = PairDirection.RECEIVED,
            kind = item.kind,
            name = preview?.userId?.takeIf { it.isNotBlank() } ?: item.name,
            fingerprint = (preview?.fingerprint ?: item.fingerprint)?.takeIf { item.kind != PairItem.BACKUP },
            outcome = outcome,
            detail = detail
        )

    // Nothing is written before the user accepted the preview; the RESULT goes out after.
    fun decide(r: PairController.Received, add: Boolean) {
        if (!received.remove(r)) return // a second tap on the same item
        val item = r.item
        if (!add) {
            rows = rows + receivedRow(item, r.preview, PairOutcome.SKIPPED)
            sendResult(PairResult(item.id, false, str(R.string.pair_skipped_reason)))
            return
        }
        scope.launch {
            val result = try {
                val summary = controller.apply(item, r.bytes, backupCode)
                rows = rows + receivedRow(item, r.preview, PairOutcome.ADDED, summary)
                haptics.success()
                PairResult(item.id, true)
            } catch (e: com.pgpony.android.backup.BackupError.WrongCode) {
                // A mistyped recovery code keeps the backup here for another
                // try instead of losing it: nothing is reported yet.
                backupError = str(R.string.err_that_recovery_code_didn_t_unlock)
                received.add(0, r)
                return@launch
            } catch (e: Exception) {
                val why = com.pgpony.android.i18n.ErrorText.localize(e.message) ?: e.javaClass.simpleName
                rows = rows + receivedRow(item, r.preview, PairOutcome.FAILED, why)
                PairResult(item.id, false, why)
            }
            backupError = null
            onKeysChanged()
            runCatching { withContext(Dispatchers.IO) { session.sendResult(result) } }
        }
    }

    fun onMessage(m: PairMessage) {
        when (m) {
            is PairMessage.Info -> {
                peerName = m.info.name.takeIf { it.isNotBlank() }
                peerInfo = m.info
            }
            is PairMessage.Offer -> incoming = Incoming(m.offer)
            is PairMessage.Answer -> {
                val prepared = outgoing ?: return
                val accepted = prepared.items.filter { it.id in m.answer.accept }
                rows = PairLedger.offered(rows, prepared.items, m.answer.accept)
                if (accepted.isEmpty()) {
                    outgoing = null
                    return
                }
                pendingResults = accepted.size
                scope.launch {
                    try {
                        for (item in accepted) {
                            progress = str(R.string.pair_sending, item.name)
                            withContext(Dispatchers.IO) { session.sendItem(item.id, prepared.payloads.getValue(item.id)) }
                        }
                    } catch (e: Exception) {
                        log += pairFailureMessage(e)
                    } finally {
                        progress = null
                    }
                }
            }
            is PairMessage.Item -> {
                val item = acceptedItems[m.id] ?: return
                expected.remove(m.id)
                // Checked against the offer first; only an item that passes is shown for Add or Skip.
                scope.launch {
                    try {
                        received += controller.check(item, m.bytes)
                    } catch (e: Exception) {
                        val why = e.message ?: e.javaClass.simpleName
                        rows = rows + receivedRow(item, null, PairOutcome.FAILED, why)
                        sendResult(PairResult(item.id, false, why))
                    }
                }
            }
            is PairMessage.Result -> {
                val (next, settled) = PairLedger.answered(rows, m.result.id, m.result.ok, m.result.error)
                rows = next
                if (settled?.outcome == PairOutcome.ADDED) haptics.success()
                pendingResults -= 1
                if (pendingResults <= 0) outgoing = null
            }
            PairMessage.Bye -> onFinished(rows, peerName, true)
        }
    }

    // The reader: one loop for the session, handing each message to the UI.
    LaunchedEffect(session) {
        try {
            withContext(Dispatchers.IO) {
                session.sendInfo(PairInfo(Build.MODEL.orEmpty(), "PGPony Android ${BuildConfig.VERSION_NAME}", PairItem.KINDS))
            }
            while (true) {
                val m = withContext(Dispatchers.IO) {
                    session.receive(expected) { id, n ->
                        val item = acceptedItems[id]
                        if (item != null && item.size > 0) {
                            progress = str(R.string.pair_receiving, item.name, (n * 100 / item.size).toInt())
                        }
                    }
                }
                progress = null
                onMessage(m)
                if (m == PairMessage.Bye) break
            }
        } catch (e: CancellationException) {
            // This pane went away (Done, or the screen closed); that path already ended the session.
            throw e
        } catch (e: Exception) {
            onFinished(rows, peerName, true)
        }
    }

    Text(
        peerName?.let { stringResource(R.string.pair_paired_with, it) } ?: stringResource(R.string.pair_paired_unnamed),
        style = MaterialTheme.typography.titleMedium
    )
    // The name comes from the other side; the address is what this phone actually talks to.
    Text(
        stringResource(R.string.pair_peer_address, peer),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    val inc = incoming
    val first = received.firstOrNull()
    if (first != null) {
        ReceivedPane(first, backupCode, { backupCode = it; backupError = null }, backupError) { add -> decide(first, add) }
    } else if (inc != null) {
        IncomingPane(inc.offer, peerName, backupCode, { backupCode = it }) { accept ->
            val picked = inc.offer.items.filter { it.id in accept }
            picked.forEach { expected[it.id] = it.size; acceptedItems[it.id] = it }
            incoming = null
            scope.launch { runCatching { withContext(Dispatchers.IO) { session.sendAnswer(PairAnswer(picked.map { it.id })) } } }
        }
    } else if (outgoing != null) {
        Text(progress ?: stringResource(R.string.pair_waiting_answer), style = MaterialTheme.typography.bodyMedium)
        outgoing?.recoveryCode?.let { code ->
            Text(stringResource(R.string.pair_backup_code_tell), style = MaterialTheme.typography.bodyMedium)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(code, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace)
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = { ClipboardService.copyText(context, code) }) {
                    Text(stringResource(R.string.pair_copy))
                }
            }
        }
    } else {
        progress?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        SendPane(controller, peerInfo) { prepared ->
            outgoing = prepared
            scope.launch {
                runCatching { withContext(Dispatchers.IO) { session.sendOffer(PairOffer(prepared.items)) } }
                    .onFailure { log += pairFailureMessage(it) }
            }
        }
    }

    if (log.isNotEmpty()) {
        Spacer(Modifier.height(8.dp))
        log.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    }

    PairRows(rows, peerName)

    Spacer(Modifier.height(8.dp))
    OutlinedButton(onClick = { onFinished(rows, peerName, false) }, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.pair_done))
    }
}

/** The sent and received rows, each group under its heading. [action] adds a button under a row. */
@Composable
private fun PairRows(
    rows: List<PairRow>,
    peerName: String?,
    action: (@Composable (PairRow) -> Unit)? = null
) {
    for (direction in PairDirection.entries) {
        val group = rows.filter { it.direction == direction }
        if (group.isEmpty()) continue
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(if (direction == PairDirection.SENT) R.string.pair_rows_sent else R.string.pair_rows_received),
            style = MaterialTheme.typography.titleSmall
        )
        group.forEach { row -> PairRowView(row, peerName) { action?.invoke(row) } }
    }
}

@Composable
private fun PairRowView(row: PairRow, peerName: String?, action: @Composable () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Box(Modifier.size(24.dp), contentAlignment = Alignment.Center) {
            when (row.outcome) {
                PairOutcome.WAITING -> CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                PairOutcome.ADDED -> Icon(Icons.Filled.CheckCircle, null, tint = MaterialTheme.colorScheme.primary)
                PairOutcome.FAILED -> Icon(Icons.Outlined.ErrorOutline, null, tint = MaterialTheme.colorScheme.error)
                else -> Icon(Icons.Outlined.RemoveCircleOutline, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Column(Modifier.weight(1f)) {
            Text(
                when (row.kind) {
                    PairItem.KEY_PAIR -> stringResource(R.string.pair_kind_keypair, row.name)
                    PairItem.PUBLIC_KEY -> stringResource(R.string.pair_kind_public, row.name)
                    else -> stringResource(R.string.pair_item_backup)
                },
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                rowStatus(row, peerName),
                style = MaterialTheme.typography.bodySmall,
                color = if (row.outcome == PairOutcome.FAILED) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.onSurfaceVariant
            )
            // The same grouping both apps use on the received preview, so the two screens can be compared.
            row.fingerprint?.let {
                Text(
                    grouped(it),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            action()
        }
    }
}

@Composable
private fun rowStatus(row: PairRow, peerName: String?): String {
    val failed = row.detail?.let { stringResource(R.string.pair_row_failed, it) } ?: stringResource(R.string.pair_row_failed_plain)
    return if (row.direction == PairDirection.SENT) when (row.outcome) {
        PairOutcome.WAITING -> stringResource(R.string.pair_row_waiting)
        PairOutcome.ADDED -> peerName?.let { stringResource(R.string.pair_row_added_on, it) }
            ?: stringResource(R.string.pair_row_added_on_unnamed)
        PairOutcome.SKIPPED -> peerName?.let { stringResource(R.string.pair_row_skipped_on, it) }
            ?: stringResource(R.string.pair_row_skipped_on_unnamed)
        PairOutcome.DECLINED -> stringResource(R.string.pair_row_declined)
        PairOutcome.FAILED -> failed
        PairOutcome.NO_ANSWER -> stringResource(R.string.pair_row_no_answer)
    } else when (row.outcome) {
        PairOutcome.ADDED -> (row.detail ?: stringResource(R.string.pair_import_added))
            .replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.getDefault()) else it.toString() }
        PairOutcome.FAILED -> failed
        else -> stringResource(R.string.pair_row_skipped_here)
    }
}

/** After Done or the other side ending: the counts, every row, and a way to open what arrived. */
@Composable
private fun FinishedPane(
    finished: PairStage.Finished,
    onClose: () -> Unit,
    onAgain: () -> Unit,
    onOpenKey: (String) -> Unit,
    onOpenKeyring: () -> Unit
) {
    val tally = remember(finished) { PairLedger.tally(finished.rows) }
    Text(stringResource(R.string.pair_finished_title), style = MaterialTheme.typography.titleMedium)
    if (finished.byPeer) {
        Text(stringResource(R.string.pair_finished_by_peer), style = MaterialTheme.typography.bodyMedium)
    }
    Text(
        stringResource(R.string.pair_ended),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(Modifier.height(4.dp))
    TallyLine(stringResource(R.string.pair_tally_sent), tally.sent)
    TallyLine(stringResource(R.string.pair_tally_received), tally.received)
    TallyLine(stringResource(R.string.pair_tally_skipped), tally.skipped)
    if (tally.failed > 0) TallyLine(stringResource(R.string.pair_tally_failed), tally.failed)
    if (tally.unanswered > 0) TallyLine(stringResource(R.string.pair_tally_unanswered), tally.unanswered)

    PairRows(finished.rows, finished.peerName) { row ->
        if (row.direction == PairDirection.RECEIVED && row.outcome == PairOutcome.ADDED) {
            val fp = row.fingerprint
            if (fp != null) {
                TextButton(onClick = { onOpenKey(fp) }) { Text(stringResource(R.string.pair_view_key)) }
            } else if (row.isBackup) {
                TextButton(onClick = onOpenKeyring) { Text(stringResource(R.string.pair_view_keyring)) }
            }
        }
    }

    Spacer(Modifier.height(8.dp))
    Button(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pair_close)) }
    OutlinedButton(onClick = onAgain, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pair_again)) }
}

@Composable
private fun TallyLine(label: String, count: Int) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(count.toString(), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun SendPane(controller: PairController, peer: PairInfo?, onPrepared: (PairController.Prepared) -> Unit) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var candidates by remember { mutableStateOf<List<PairController.Outgoing>>(emptyList()) }
    val picked = remember { mutableStateListOf<PairController.Outgoing>() }
    var pass by remember { mutableStateOf("") }
    var pass2 by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) { candidates = controller.candidates() }

    val needsPass = picked.any { it is PairController.Outgoing.KeyPair && !it.protected }
    val passOk = !needsPass || (pass.isNotEmpty() && pass == pass2)
    val secretsLeave = picked.any { it is PairController.Outgoing.KeyPair || it is PairController.Outgoing.Backup }

    fun prepareAndSend() {
        working = true
        error = null
        scope.launch {
            try {
                onPrepared(controller.prepare(picked.toList(), pass.takeIf { needsPass }))
            } catch (e: Exception) {
                error = e.message ?: e.javaClass.simpleName
            } finally {
                working = false
            }
        }
    }

    Text(stringResource(R.string.pair_send_heading), style = MaterialTheme.typography.titleSmall)
    // A side that has not said what it takes (no INFO yet, or one without accepts) takes all three.
    fun takes(kind: String) = peer?.takes(kind) ?: true
    if (takes(PairItem.KEY_PAIR)) {
        OutgoingGroup(stringResource(R.string.pair_group_keypairs), candidates.filterIsInstance<PairController.Outgoing.KeyPair>(), picked, !working)
    }
    if (takes(PairItem.PUBLIC_KEY)) {
        OutgoingGroup(stringResource(R.string.pair_group_public), candidates.filterIsInstance<PairController.Outgoing.PublicKey>(), picked, !working)
    }
    if (takes(PairItem.BACKUP)) {
        OutgoingGroup(stringResource(R.string.pair_group_backup), candidates.filterIsInstance<PairController.Outgoing.Backup>(), picked, !working)
    }
    if (needsPass) {
        Text(
            stringResource(R.string.pair_transfer_pass_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedTextField(
            value = pass, onValueChange = { pass = it }, label = { Text(stringResource(R.string.pair_transfer_pass)) },
            singleLine = true, visualTransformation = PasswordVisualTransformation(), enabled = !working,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = pass2, onValueChange = { pass2 = it }, label = { Text(stringResource(R.string.pair_transfer_pass_repeat)) },
            singleLine = true, visualTransformation = PasswordVisualTransformation(), enabled = !working,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            isError = pass2.isNotEmpty() && pass != pass2, modifier = Modifier.fillMaxWidth()
        )
    }
    error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    Button(enabled = picked.isNotEmpty() && passOk && !working, onClick = {
        // A private key or a backup leaves the phone only after device
        // authentication, as for a private key export, when it is set up.
        val activity = context as? androidx.fragment.app.FragmentActivity
        if (secretsLeave && activity != null &&
            BiometricGate.canAuthenticate(context) == BiometricAvailability.Available
        ) {
            BiometricGate.authenticate(
                activity = activity,
                title = context.getString(R.string.pair_biometric_title),
                subtitle = context.getString(R.string.pair_biometric_subtitle),
                onSuccess = { prepareAndSend() },
                onError = { _, message -> error = message }
            )
        } else {
            prepareAndSend()
        }
    }, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(if (working) R.string.pair_working else R.string.pair_send))
    }
}

@Composable
private fun OutgoingGroup(
    title: String,
    list: List<PairController.Outgoing>,
    picked: MutableList<PairController.Outgoing>,
    enabled: Boolean
) {
    if (list.isEmpty()) return
    Text(title, style = MaterialTheme.typography.labelLarge)
    list.forEach { o ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = o in picked, enabled = enabled, onCheckedChange = { if (it) picked += o else picked -= o })
            Text(o.name, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun IncomingPane(
    offer: PairOffer,
    from: String?,
    backupCode: String,
    onBackupCode: (String) -> Unit,
    onAnswer: (List<Int>) -> Unit
) {
    // An item of a kind this version does not know is not shown, so it can never be accepted.
    val items = remember(offer) { offer.items.filter { it.kind in PairItem.KINDS } }
    // Nothing is picked until the user picks it.
    val chosen = remember(offer) { mutableStateListOf<Int>() }
    Text(
        from?.let { stringResource(R.string.pair_incoming_heading, it) } ?: stringResource(R.string.pair_incoming_heading_unnamed),
        style = MaterialTheme.typography.titleSmall
    )
    items.forEach { item ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = item.id in chosen, onCheckedChange = { if (it) chosen += item.id else chosen -= item.id })
            Column {
                Text(
                    when (item.kind) {
                        PairItem.KEY_PAIR -> stringResource(R.string.pair_kind_keypair, item.name)
                        PairItem.PUBLIC_KEY -> stringResource(R.string.pair_kind_public, item.name)
                        else -> stringResource(R.string.pair_item_backup)
                    },
                    style = MaterialTheme.typography.bodyMedium
                )
                item.fingerprint?.takeIf { item.kind != PairItem.BACKUP }?.let { fp ->
                    Text(
                        stringResource(R.string.pair_incoming_fingerprint, grouped(fp)),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
    val wantsBackup = items.any { it.kind == PairItem.BACKUP && it.id in chosen }
    if (wantsBackup) {
        OutlinedTextField(
            value = backupCode,
            onValueChange = onBackupCode,
            label = { Text(stringResource(R.string.pair_backup_code_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(enabled = chosen.isNotEmpty() && (!wantsBackup || backupCode.isNotBlank()), onClick = { onAnswer(chosen.toList()) }) {
            Text(stringResource(R.string.pair_accept))
        }
        OutlinedButton(onClick = { onAnswer(emptyList()) }) { Text(stringResource(R.string.pair_decline)) }
    }
}

/**
 * A received item that passed the checks, as read from its own bytes (not as
 * the offer named it): the key's fingerprint and user ID, or what restoring
 * the backup does. Nothing is written until the user chooses Add or Restore.
 */
@Composable
private fun ReceivedPane(
    received: PairController.Received,
    backupCode: String,
    onBackupCode: (String) -> Unit,
    backupError: String?,
    onDecide: (Boolean) -> Unit
) {
    val key = received.preview
    val isBackup = received.item.kind == PairItem.BACKUP || key == null
    if (isBackup) {
        Text(stringResource(R.string.pair_received_backup), style = MaterialTheme.typography.bodyMedium)
        // The code can be corrected here after a wrong one.
        OutlinedTextField(
            value = backupCode,
            onValueChange = onBackupCode,
            label = { Text(stringResource(R.string.pair_backup_code_label)) },
            singleLine = true,
            isError = backupError != null,
            modifier = Modifier.fillMaxWidth()
        )
        backupError?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
    } else {
        Text(
            stringResource(if (key!!.hasPrivateKey) R.string.pair_received_keypair else R.string.pair_received_public),
            style = MaterialTheme.typography.titleSmall
        )
        Text(key.userId, style = MaterialTheme.typography.bodyMedium)
        Text(grouped(key.fingerprint), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
        if (key.isDuplicate) {
            Text(
                stringResource(R.string.pair_received_in_keyring),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(enabled = !isBackup || backupCode.isNotBlank(), onClick = { onDecide(true) }) {
            Text(stringResource(if (isBackup) R.string.pair_received_restore else R.string.pair_received_add))
        }
        OutlinedButton(onClick = { onDecide(false) }) { Text(stringResource(R.string.pair_received_skip)) }
    }
}
