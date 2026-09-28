// CardScanScreen.kt
// PGPony Android — HW Phase 1
//
// The "tap your security key" screen. Self-contained: it talks to the
// Activity's reader-mode helpers (startCardScan / stopCardScan) and to
// KeyRepository directly, so it doesn't need an entry in the shared
// PGPonyViewModelFactory. Flow:
//
//   Scanning ──tap──▶ Found(CardInfo) ──Import──▶ imported
//        ▲                  │
//        └────── error ◀────┘ (reader stays live; re-tap to retry)
//
// Phase 1 is read-only discovery — Import creates a card-backed keyring
// record (isKeyPair = false). No on-card crypto is wired yet.

package com.pgpony.android.ui.card

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
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
import com.pgpony.android.crypto.card.CardInfo
import com.pgpony.android.crypto.card.CardSlot
import com.pgpony.android.crypto.card.CardSlotInfo
import com.pgpony.android.i18n.ErrorText
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.launch

private sealed class ScanState {
    data object Scanning : ScanState()
    data class Found(val info: CardInfo) : ScanState()
    data class Failed(val message: String) : ScanState()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CardScanScreen(
    onBack: () -> Unit,
    onChangePin: () -> Unit = {},
    onSignTest: () -> Unit = {},
    onDecryptTest: () -> Unit = {},
    onManageCard: () -> Unit = {},
    onGenerateKey: () -> Unit = {}
) {
    val context = LocalContext.current
    val activity = context as? MainActivity
    val repo = remember { PGPonyApp.instance.keyRepository }
    val scope = rememberCoroutineScope()

    // 4.1.0 USB Phase 2 — this screen used to read two booleans once and
    // assume NFC was the only way in. USB availability CHANGES while the
    // screen is open, because someone can plug a key in, so it is recomputed
    // rather than remembered forever.
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

    val scanState = remember { mutableStateOf<ScanState>(ScanState.Scanning) }
    var importing by remember { mutableStateOf(false) }
    var imported by remember { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }
    val importedMsg = stringResource(R.string.card_scan_imported)

    // Arm the reader for one tap. Reader mode stays engaged until the
    // screen is disposed; the reader's one-shot guard means each arm
    // handles exactly one tap, so we don't disable on success (doing so
    // while the card is still present made the OS show "no supported
    // application"). Re-arm for retry / scan-again by calling this again.
    fun armScan() {
        activity?.startCardScan { result ->
            result
                .onSuccess { info -> scanState.value = ScanState.Found(info) }
                .onFailure { e -> scanState.value = ScanState.Failed(ErrorText.localize(context, e.message) ?: context.getString(R.string.card_scan_read_failed)) }
            // Re-arm for the next physical tap so the user can read again
            // in place (lift and tap) without leaving the screen. Reader
            // mode stays engaged; this only resets the one-shot flag.
            activity?.rearmCardScan()
        }
    }

    // 4.1.0 USB Phase 2 — read the card over the wire. No awaitRemoval twin:
    // that exists on NFC because a tag left in the field falls through to the
    // platform dispatcher and launches Yubico Authenticator (issue #7), and
    // unplugging a USB key cannot do that.
    fun scanOverUsb() {
        val manager = context.getSystemService(Context.USB_SERVICE) as? UsbManager ?: return
        val device = usbCards.firstReader() ?: return
        scanState.value = ScanState.Scanning
        UsbCardOperations.run(manager, device, { it.readCardInfo() }) { result ->
            result
                .onSuccess { info -> scanState.value = ScanState.Found(info) }
                .onFailure { e ->
                    scanState.value = ScanState.Failed(ErrorText.localize(context, e.message) ?: context.getString(R.string.card_scan_read_failed))
                }
        }
    }

    // A reader is plugged in but not yet permitted. Asking immediately is the
    // right call here: the user physically attached a key and then opened the
    // card screen, so the dialog is the step they are already expecting.
    LaunchedEffect(link.advice) {
        if (link.advice == CardLinkAdvice.AttachedReaderNeedsPermission) {
            usbCards.firstReader()?.let { device ->
                usbCards.requestPermission(device) { usbTick++ }
            }
        }
    }

    // Engage whichever transport is preferred, and re-engage if that changes
    // while the screen is open (a key plugged in mid-scan switches to USB).
    DisposableEffect(activity, link.preferred) {
        when (link.preferred) {
            CardLinkKind.USB -> scanOverUsb()
            CardLinkKind.NFC -> if (activity != null) armScan()
            null -> Unit
        }
        onDispose { activity?.stopCardScan() }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.card_scan_title)) },
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
                // Permission outranks the unavailable message: something IS
                // plugged in, so telling the user there is no way to read a
                // card would be wrong as well as unhelpful.
                link.advice == CardLinkAdvice.AttachedReaderNeedsPermission ->
                    CenteredMessage(Icons.Filled.Usb, stringResource(R.string.card_scan_usb_permission))

                // One branch, because "NFC off" only matters when there is
                // nothing else usable. Kept separate before, it fired even
                // with a working wired reader attached.
                !link.anyUsable ->
                    CenteredMessage(
                        Icons.Filled.Nfc,
                        stringResource(
                            if (link.advice == CardLinkAdvice.EnableNfc)
                                R.string.card_scan_nfc_disabled
                            else R.string.card_scan_nfc_unavailable
                        )
                    )

                else -> when (val s = scanState.value) {
                    is ScanState.Scanning -> ScanningPrompt()
                    is ScanState.Failed -> ScanError(
                        message = s.message,
                        onRetry = { scanState.value = ScanState.Scanning; activity?.rearmCardScan() }
                    )
                    is ScanState.Found -> {
                        if (imported) {
                            ImportedConfirmation(onScanAgain = {
                                imported = false
                                scanState.value = ScanState.Scanning
                                activity?.rearmCardScan()
                            })
                        } else {
                            CardDetail(
                                info = s.info,
                                importing = importing,
                                onImport = {
                                    importing = true
                                    scope.launch {
                                        try {
                                            repo.importCardKey(s.info)
                                            imported = true
                                            snackbarHostState.showSnackbar(importedMsg)
                                        } catch (e: Exception) {
                                            scanState.value =
                                                ScanState.Failed(ErrorText.localize(context, e.message) ?: context.getString(R.string.card_scan_import_failed))
                                        } finally {
                                            importing = false
                                        }
                                    }
                                },
                                onChangePin = onChangePin,
                                onSignTest = onSignTest,
                                onDecryptTest = onDecryptTest,
                                onManageCard = onManageCard,
                                onGenerateKey = onGenerateKey
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CenteredMessage(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(
            icon,
            contentDescription = null,
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
        )
        Spacer(Modifier.height(16.dp))
        Text(text, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun ScanningPrompt() {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(
            Icons.Filled.Contactless,
            contentDescription = null,
            modifier = Modifier.size(96.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.height(24.dp))
        Text(
            stringResource(R.string.card_scan_prompt_title),
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.card_scan_prompt_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(24.dp))
        CircularProgressIndicator()
    }
}

@Composable
private fun ScanError(message: String, onRetry: () -> Unit) {
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
            Text(stringResource(R.string.card_scan_scan_again))
        }
    }
}

@Composable
private fun ImportedConfirmation(onScanAgain: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(
            Icons.Filled.CheckCircle,
            contentDescription = null,
            modifier = Modifier.size(72.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.height(16.dp))
        Text(
            stringResource(R.string.card_scan_imported),
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(24.dp))
        OutlinedButton(onClick = onScanAgain) {
            Icon(Icons.Filled.Nfc, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.card_scan_scan_again))
        }
    }
}

@Composable
private fun CardDetail(
    info: CardInfo,
    importing: Boolean,
    onImport: () -> Unit,
    onChangePin: () -> Unit,
    onSignTest: () -> Unit,
    onDecryptTest: () -> Unit,
    onManageCard: () -> Unit,
    onGenerateKey: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            Icons.Filled.Memory,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.card_scan_found_title),
            style = MaterialTheme.typography.titleMedium
        )
        Spacer(Modifier.height(16.dp))

        // ── Card identity ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                SectionHeader(stringResource(R.string.card_scan_section_card))
                LabeledRow(stringResource(R.string.card_scan_label_manufacturer), info.manufacturerName)
                LabeledRow(stringResource(R.string.card_scan_label_serial), info.serialHex)
                LabeledRow(stringResource(R.string.card_scan_label_aid), info.aidHex)
                if (info.pw1TriesRemaining >= 0) {
                    LabeledRow(
                        stringResource(R.string.card_scan_label_pin_tries),
                        info.pw1TriesRemaining.toString()
                    )
                }
                if (info.pw3TriesRemaining >= 0) {
                    LabeledRow(
                        stringResource(R.string.card_scan_label_admin_tries),
                        info.pw3TriesRemaining.toString()
                    )
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // ── Keys on card ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                SectionHeader(stringResource(R.string.card_scan_section_keys))
                info.slots.forEach { slot ->
                    SlotRow(slot)
                    Spacer(Modifier.height(8.dp))
                }
            }
        }

        Spacer(Modifier.height(24.dp))

        Button(
            onClick = onImport,
            enabled = !importing && info.hasAnyKey,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (importing) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.card_scan_importing))
            } else {
                Icon(Icons.Filled.Download, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.card_scan_import_button))
            }
        }
        TextButton(
            onClick = onChangePin,
            enabled = !importing,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Filled.Password, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.card_pin_change_open))
        }
        TextButton(
            onClick = onManageCard,
            enabled = !importing,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Filled.Shield, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.card_mgmt_open))
        }
        TextButton(
            onClick = onGenerateKey,
            enabled = !importing,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Filled.VpnKey, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.card_keygen_open))
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(bottom = 8.dp)
    )
}

@Composable
private fun LabeledRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun SlotRow(slot: CardSlotInfo) {
    val slotLabel = when (slot.slot) {
        CardSlot.SIGNATURE -> stringResource(R.string.card_scan_slot_signature)
        CardSlot.DECRYPTION -> stringResource(R.string.card_scan_slot_decryption)
        CardSlot.AUTHENTICATION -> stringResource(R.string.card_scan_slot_authentication)
    }
    Column(Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(slotLabel, style = MaterialTheme.typography.bodyMedium)
            Text(
                if (slot.hasKey) slot.displayAlgorithm else stringResource(R.string.card_scan_slot_empty),
                style = MaterialTheme.typography.bodyMedium,
                color = if (slot.hasKey) MaterialTheme.colorScheme.onSurface
                else MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        slot.fingerprint?.let { fp ->
            Text(
                formatFingerprint(fp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        // Per-slot key generation date. Imported keys leave the card's
        // generation-time DO (0xCD) at zero, so this is often "Not recorded";
        // on-card-generated keys (B1) will carry a real date here. Only shown
        // for populated slots — an empty slot has no key to date.
        if (slot.hasKey) {
            Text(
                stringResource(
                    R.string.card_scan_slot_generated,
                    slot.generationTime?.let { formatCardDate(it) }
                        ?: stringResource(R.string.card_scan_slot_generated_unknown)
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun formatCardDate(epochMillis: Long): String =
    java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM, Locale.getDefault()).format(Date(epochMillis))

private fun formatFingerprint(fp: String): String =
    fp.uppercase().chunked(4).joinToString(" ")
