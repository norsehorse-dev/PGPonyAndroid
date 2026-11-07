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
                                scanProgress = context.getString(
                                    if (outcome.enhanced) R.string.qr_enhanced_progress_format else R.string.qr_scan_progress_format,
                                    outcome.have, outcome.required)
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
