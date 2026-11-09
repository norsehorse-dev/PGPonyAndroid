package com.pgpony.android.ui.scanner

import android.Manifest
import androidx.compose.foundation.border
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.pgpony.android.R
import com.pgpony.android.MainActivity
import androidx.activity.compose.BackHandler
import com.pgpony.android.qr.QrScanSession
import com.pgpony.android.qr.QrScanMetrics
import com.pgpony.android.qr.CollectionEvent
import com.pgpony.android.qr.ScanMilestone
import com.pgpony.android.qr.PublicKeyQrCollector
import com.pgpony.android.qr.PublicKeyQrResult
import com.pgpony.android.qr.QrPreviewTiming
import com.pgpony.android.qr.QrCollectionProcessor
import com.pgpony.android.qr.QrMissingParts
import androidx.compose.foundation.Canvas
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import com.pgpony.android.ui.util.rememberHaptics

internal val LocalQrScanMetrics = staticCompositionLocalOf { QrScanMetrics.None }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QRScannerScreen(
    onScanned: (String) -> Unit,
    onDismiss: () -> Unit,
    acceptOtherText: Boolean = false,
    onScannedWithTiming: ((String, QrPreviewTiming) -> Unit)? = null,
) {
    val context = LocalContext.current
    val haptics = rememberHaptics()
    var hasCameraPermission by remember { mutableStateOf(false) }
    val session = remember { QrScanSession() }
    val latestOnScanned by rememberUpdatedState(onScanned)
    val latestTimedCallback by rememberUpdatedState(onScannedWithTiming)
    val latestOnDismiss by rememberUpdatedState(onDismiss)
    val metrics = LocalQrScanMetrics.current
    var firstPartReceived by remember { mutableStateOf(false) }
    var cameraError by remember { mutableStateOf(false) }
    var cameraRetry by remember { mutableIntStateOf(0) }
    val dismiss = { session.close(); latestOnDismiss() }
    BackHandler(onBack = dismiss)
    DisposableEffect(session) { onDispose { session.close() } }

    // Partial public-key frames survive duplicate decodes and camera lifecycle pauses.
    val frameCollector = remember(acceptOtherText) { PublicKeyQrCollector(acceptOtherText) }
    var scanProgress by remember { mutableStateOf<String?>(null) }
    // 4.8.0 RC8 (#100): the parts of a PGPONY1 code still to come, and its part
    // count, for the missing-parts line and strip. Zero parts hides both.
    var partsTotal by remember { mutableIntStateOf(0) }
    var partsMissing by remember { mutableStateOf<List<Int>>(emptyList()) }
    val collectionScope = rememberCoroutineScope()
    val collectionProcessor = remember(session, frameCollector, collectionScope) {
        QrCollectionProcessor(session, collectionScope, collect = frameCollector::offer)
    }

    // Phase A10a — permission flow routes through MainActivity helper
    // because Compose's rememberLauncherForActivityResult crashes on
    // FragmentActivity (request codes >16 bits). The helper calls
    // ActivityCompat.requestPermissions with a known small code.
    val activity = context as? MainActivity

    LaunchedEffect(Unit) {
        val permission = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA)
        if (permission == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            hasCameraPermission = true
        } else {
            activity?.requestRuntimePermission(Manifest.permission.CAMERA) { granted ->
                hasCameraPermission = granted
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.qr_scanner_title)) },
                navigationIcon = {
                    IconButton(onClick = dismiss) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            // 4.1.0 Phase 12b — was a hardcoded "Back", missed
                            // by A13's string extraction.
                            stringResource(R.string.common_button_back)
                        )
                    }
                }
            )
        }
    ) { padding ->
        if (!hasCameraPermission) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Filled.CameraAlt, null, modifier = Modifier.size(48.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f))
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(stringResource(R.string.qr_scanner_permission_title))
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(onClick = {
                        // A10a — same MainActivity helper as the
                        // initial LaunchedEffect request; the
                        // "Grant Permission" button is the user's
                        // way to retry after a previous denial.
                        activity?.requestRuntimePermission(
                            Manifest.permission.CAMERA
                        ) { granted ->
                            hasCameraPermission = granted
                        }
                    }) { Text(stringResource(R.string.qr_scanner_grant_button)) }
                }
            }
        } else {
            Box(modifier = Modifier.fillMaxSize().padding(padding)) {
                // Camera preview
                CameraQrPreview(
                    session = session,
                    metrics = metrics,
                    retryToken = cameraRetry,
                    onCameraError = { cameraError = true },
                    onQRDetected = { text, token, markProgress ->
                        collectionProcessor.submit(text, token) { outcome ->
                        val fresh = when (outcome) {
                            is PublicKeyQrResult.Complete -> {
                                if (session.tryComplete(token)) {
                                    scanProgress = null
                                    partsTotal = 0
                                    partsMissing = emptyList()
                                    if (!firstPartReceived) {
                                        firstPartReceived = true
                                        metrics.milestone(session.id, ScanMilestone.FIRST_PART, System.nanoTime())
                                    }
                                    metrics.collection(session.id, CollectionEvent.COMPLETE)
                                    metrics.milestone(session.id, ScanMilestone.COMPLETE, System.nanoTime())
                                    haptics.success()
                                    val timed = latestTimedCallback
                                    if (timed != null) timed(outcome.text, QrPreviewTiming(session.id, metrics))
                                    else latestOnScanned(outcome.text)
                                }
                                true
                            }
                            is PublicKeyQrResult.Progress -> {
                                if (!firstPartReceived) {
                                    firstPartReceived = true
                                    metrics.milestone(session.id, ScanMilestone.FIRST_PART, System.nanoTime())
                                }
                                metrics.collection(session.id,
                                    if (outcome.restarted) CollectionEvent.RESTARTED else CollectionEvent.NEW_PART)
                                haptics.tap()
                                // 4.8.0 RC6 (#95): a different key mid-scan says so, and the
                                // next part's progress replaces it.
                                scanProgress = if (outcome.restarted) {
                                    context.getString(R.string.qr_scan_restarted)
                                } else context.getString(
                                    if (outcome.enhanced) R.string.qr_enhanced_progress_format else R.string.qr_scan_progress_format,
                                    outcome.have, outcome.required)
                                // 4.8.0 RC8 (#100): a PGPONY1 code names its missing parts;
                                // PGPONY2 completes from any of its parts, so it has none.
                                if (outcome.enhanced) {
                                    partsTotal = 0
                                    partsMissing = emptyList()
                                } else {
                                    partsTotal = outcome.required
                                    partsMissing = outcome.missing
                                }
                                true
                            }
                            PublicKeyQrResult.Duplicate -> {
                                metrics.collection(session.id, CollectionEvent.DUPLICATE)
                                false
                            }
                            PublicKeyQrResult.Unsupported -> {
                                scanProgress = context.getString(R.string.qr_unsupported_version)
                                false
                            }
                            PublicKeyQrResult.Malformed -> {
                                metrics.collection(session.id, CollectionEvent.MALFORMED)
                                scanProgress = context.getString(R.string.qr_integrity_error)
                                false
                            }
                            // 4.8.0 RC6 (#95): a link or plain text is not a key, not a broken part.
                            PublicKeyQrResult.NotAKey -> {
                                scanProgress = context.getString(R.string.keyring_error_no_key_data)
                                false
                            }
                        }
                        if (fresh) markProgress()
                        }
                    }
                )

                // Scan overlay
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    // Viewfinder frame
                    Box(
                        modifier = Modifier
                            .size(250.dp)
                            .border(2.dp, Color(0xFF8B5CF6), RoundedCornerShape(12.dp))
                    )
                }

                // Bottom hint
                Box(
                    modifier = Modifier.fillMaxSize().padding(bottom = 48.dp),
                    contentAlignment = Alignment.BottomCenter
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            scanProgress ?: stringResource(R.string.qr_scanner_hint),
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color.White
                        )
                        // 4.8.0 RC8 (#100): which parts are still missing.
                        if (partsTotal > 1 && partsMissing.isNotEmpty()) {
                            QrMissingParts.toList(partsMissing)?.let { listed ->
                                Text(
                                    pluralStringResource(
                                        R.plurals.qr_scan_missing_parts, listed.size,
                                        listed.joinToString(", ")
                                    ),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = Color.White
                                )
                            }
                            Spacer(Modifier.height(8.dp))
                            MissingPartsStrip(total = partsTotal, missing = partsMissing)
                            Spacer(Modifier.height(8.dp))
                        }
                        Text(stringResource(R.string.qr_focus_hint),
                            style = MaterialTheme.typography.bodySmall, color = Color.White)
                    }
                }
                if (cameraError) {
                    Box(Modifier.fillMaxSize().background(Color.Black), contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally,
                            modifier = Modifier.padding(24.dp)) {
                            Text(stringResource(R.string.qr_camera_error),color = Color.White)
                            Spacer(Modifier.height(16.dp))
                            Button(onClick = { cameraError = false; cameraRetry++ }) {
                                Text(stringResource(R.string.qr_retry))
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * 4.8.0 RC8 (#100): one cell per part, solid once received and faint while
 * missing. It wraps into rows (32 per row for a normal code, 64 for a long
 * one) so 512 parts make a short block. The line above it lists the missing
 * numbers once few are left, so the strip is hidden from TalkBack.
 */
@Composable
private fun MissingPartsStrip(total: Int, missing: List<Int>) {
    val columns = QrMissingParts.columns(total)
    val rows = QrMissingParts.rows(total)
    val missingSet = remember(missing) { missing.toHashSet() }
    val long = columns > 32
    val cellGap = if (long) 1.dp else 2.dp
    val rowHeight = if (long) 4.dp else 12.dp
    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp)
            .height(rowHeight * rows + cellGap * (rows - 1))
            .clearAndSetSemantics {}
    ) {
        val gap = cellGap.toPx()
        val cellWidth = (size.width - gap * (columns - 1)) / columns
        val cellHeight = rowHeight.toPx()
        val cell = Size(cellWidth, cellHeight)
        for (part in 1..total) {
            val index = part - 1
            val topLeft = Offset((index % columns) * (cellWidth + gap), (index / columns) * (cellHeight + gap))
            drawRect(if (part in missingSet) Color.White.copy(alpha = 0.3f) else Color.White, topLeft, cell)
        }
    }
}
