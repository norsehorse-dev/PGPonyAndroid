package com.pgpony.android.ui.components

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FastForward
import androidx.compose.material.icons.filled.FastRewind
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.pgpony.android.R
import com.pgpony.android.qr.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private data class RenderedQr(val index: Int, val pixels: Int, val bitmap: Bitmap)

/** Shared by normal and enlarged presentations so manual positioning survives resizing. */
private class QrPlaybackState(store: QrFrameStore) {
    val controller = QrPlaybackController(store.frameCount)
    var revision by mutableIntStateOf(0)
}

/**
 * Shared sender surface for Exchange and Key Details. The store is immutable per sequence;
 * changing it resets playback even when the new sequence has the same number of parts.
 * Rendering is asynchronous and the dwell timer starts only after that part is visible.
 */
@Composable
fun PublicKeyQrDisplay(
    store: QrFrameStore?,
    mode: QrTransferMode,
    policy: QrEncodingPolicy,
    onModeChange: (QrTransferMode) -> Unit,
    onPolicyChange: (QrEncodingPolicy) -> Unit,
    errorMessage: String? = null,
    fingerprint: String? = null,
) {
    val playback = remember(store) { store?.let(::QrPlaybackState) }
    val dialogHeight = LocalConfiguration.current.screenHeightDp.dp * 0.9f
    var enlarged by remember { mutableStateOf(false) }
    var slow by remember { mutableStateOf(false) }
    Column(horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = mode == QrTransferMode.COMPATIBLE,
                onClick = { onModeChange(QrTransferMode.COMPATIBLE) },
                label = { Text(stringResource(R.string.qr_mode_compatible)) })
            FilterChip(selected = mode == QrTransferMode.ENHANCED,
                onClick = { onModeChange(QrTransferMode.ENHANCED) },
                label = { Text(stringResource(R.string.qr_mode_enhanced)) })
        }
        if (mode == QrTransferMode.ENHANCED) {
            Text(stringResource(R.string.qr_enhanced_hint), style = MaterialTheme.typography.bodySmall)
        }
        if (mode == QrTransferMode.COMPATIBLE) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = policy == QrEncodingPolicy.BASELINE,
                    onClick = { onPolicyChange(QrEncodingPolicy.BASELINE) },
                    label = { Text(stringResource(R.string.qr_density_normal)) })
                FilterChip(selected = policy != QrEncodingPolicy.BASELINE,
                    onClick = { onPolicyChange(QrEncodingPolicy.ROBUST) },
                    label = { Text(stringResource(R.string.qr_density_roomy)) })
            }
        }
        if (store == null || playback == null) {
            Box(Modifier.fillMaxWidth().heightIn(max = dialogHeight * 0.6f).background(Color.White),
                contentAlignment = Alignment.Center) {
                if (errorMessage != null) {
                    Text(errorMessage, color = Color.Black, modifier = Modifier.padding(16.dp))
                } else {
                    CircularProgressIndicator(Modifier.padding(24.dp))
                }
            }
        } else {
            if (!enlarged) QrPlaybackSurface(store, slow, playback)
            if (store.frameCount > 1) {
                FilterChip(selected = slow, onClick = { slow = !slow },
                    label = { Text(stringResource(R.string.qr_playback_slow)) })
                Text(stringResource(R.string.qr_multipart_hint), style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = { enlarged = true }) {
                Text(stringResource(R.string.qr_enlarge))
            }
        }
    }
    if (enlarged && store != null && playback != null) {
        androidx.compose.ui.window.Dialog(onDismissRequest = { enlarged = false },
            properties = androidx.compose.ui.window.DialogProperties(usePlatformDefaultWidth = false)) {
            Surface(Modifier.fillMaxWidth().padding(8.dp)) {
                Column(Modifier.heightIn(max = dialogHeight).verticalScroll(rememberScrollState()).padding(8.dp),
                    horizontalAlignment = Alignment.CenterHorizontally) {
                    QrPlaybackSurface(store, slow, playback)
                    fingerprint?.let {
                        Text(it, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(8.dp))
                    }
                    TextButton(onClick = { enlarged = false }) {
                        Text(stringResource(R.string.common_button_close))
                    }
                }
            }
        }
    }
}

@Composable
private fun QrPlaybackSurface(store: QrFrameStore, slow: Boolean, playback: QrPlaybackState) {
    val density = LocalDensity.current
    val controller = playback.controller
    val (index, playing) = remember(store, playback.revision) { controller.index to controller.playing }
    var targetPixels by remember { mutableIntStateOf(0) }
    var rendered by remember(store) { mutableStateOf<RenderedQr?>(null) }
    var failed by remember(store) { mutableStateOf(false) }
    val lifecycleOwner = LocalLifecycleOwner.current
    var foreground by remember(lifecycleOwner) {
        mutableStateOf(lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))
    }
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, _ ->
            foreground = lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    LaunchedEffect(store, index, targetPixels) {
        if (targetPixels > 0) {
            failed = false
            try {
                val bitmap = withContext(Dispatchers.Default) { store.bitmap(index, targetPixels) }
                rendered = RenderedQr(index, targetPixels, bitmap)
                // Prefetch uses the same bounded cache and never blocks the UI thread.
                if (store.frameCount > 1) withContext(Dispatchers.Default) {
                    store.bitmap((index + 1) % store.frameCount, targetPixels)
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: IllegalArgumentException) {
                failed = true
            }
        }
    }
    val frameReady = rendered?.let { it.index == index && it.pixels == targetPixels } == true
    LaunchedEffect(store, index, playing, foreground, frameReady, slow) {
        if (store.frameCount > 1 && playing && foreground && frameReady) {
            delay(if (slow) QrAnimation.SLOW_FRAME_INTERVAL_MS else QrAnimation.FRAME_INTERVAL_MS)
            controller.tick(foreground, frameReady)
            playback.revision++
        }
    }
    // A whole symbol must fit vertically even in landscape or a short multi-window pane.
    val maxSymbolHeight = LocalConfiguration.current.screenHeightDp.dp * 0.55f
    BoxWithConstraints(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        val side = minOf(maxWidth, maxSymbolHeight)
        Box(Modifier.size(side).background(Color.White)
            .onSizeChanged { targetPixels = minOf(it.width, it.height) }, contentAlignment = Alignment.Center) {
            rendered?.takeIf { it.pixels == targetPixels }?.let {
                Image(bitmap = it.bitmap.asImageBitmap(),
                    contentDescription = stringResource(R.string.exchange_qr_cd),
                    filterQuality = FilterQuality.None,
                    modifier = Modifier.testTag("public-key-qr-image")
                        .size(with(density) { it.bitmap.width.toDp() }))
            } ?: if (failed) {
                Text(stringResource(R.string.qr_render_small), color = Color.Black, modifier = Modifier.padding(16.dp))
            } else {
                CircularProgressIndicator()
            }
        }
    }
    if (store.frameCount > 1) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { controller.previous(); playback.revision++ }) {
                Icon(Icons.Default.FastRewind, stringResource(R.string.qr_part_previous))
            }
            IconButton(onClick = { controller.toggle(); playback.revision++ }) {
                Icon(if (playing) Icons.Default.Pause else Icons.Default.PlayArrow,
                    stringResource(if (playing) R.string.qr_autorotate_pause_cd else R.string.qr_autorotate_play_cd))
            }
            Text(stringResource(R.string.qr_part_of_format, (rendered?.index ?: index) + 1, store.frameCount))
            IconButton(onClick = { controller.next(); playback.revision++ }) {
                Icon(Icons.Default.FastForward, stringResource(R.string.qr_part_next))
            }
        }
    }
}
