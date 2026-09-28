// KeyDetailQRSheet.kt
// PGPony Android — Phase A4a
//
// Modal bottom sheet showing the key's public-key QR code at large
// size, with copy-armored and share buttons. Opens from the QRSection
// action row.
//
// QR encoding itself lives in KeyDetailViewModel.encodeQR(); this
// composable just renders the cached bitmap. Caller is responsible for
// passing in the cached bitmap (null = encoding hasn't completed yet,
// which shows a spinner).
//
// Share action is stubbed in A4a — it routes through the same
// onComingSoon channel as the action sections, since "Share Public
// Key" is one of the A4b deliverables. Copy-to-clipboard is fully
// functional in A4a since it doesn't need any system-level integration
// beyond LocalClipboardManager.

package com.pgpony.android.ui.keyring

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.IosShare
import androidx.compose.material.icons.filled.FastForward
import androidx.compose.material.icons.filled.FastRewind
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.qr.QrAnimation

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyDetailQRSheet(
    key: PGPKeyEntity,
    qrFrames: List<Bitmap>,
    qrIndex: Int,
    onPrevFrame: () -> Unit,
    onNextFrame: () -> Unit,
    onCopyArmored: () -> Unit,
    onShare: () -> Unit,
    onDismiss: () -> Unit
) {
    val qrBitmap: Bitmap? = qrFrames.getOrNull(qrIndex)
    // §5.6.5 (#37): auto-rotate multi-part frames so the receiver can hold
    // the camera up and let it cycle. Manual next/prev stay for now; tapping
    // one pauses rotation so a specific part can be held.
    var autoRotate by remember { mutableStateOf(true) }
    LaunchedEffect(qrFrames.size, autoRotate) {
        if (qrFrames.size > 1 && autoRotate) {
            while (true) {
                kotlinx.coroutines.delay(QrAnimation.FRAME_INTERVAL_MS)
                onNextFrame()
            }
        }
    }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        // 4.1.0 Phase 12b — the full triad. No lazy list in here, so
        // the Column can scroll, which is what keeps the sheet usable
        // at a large font scale rather than clipping its last row.
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            val publicKeyFallback = stringResource(R.string.key_detail_type_public_key)
            Text(
                text = key.userName.ifBlank { key.userEmail.ifBlank { publicKeyFallback } },
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )

            // QR — white-on-black bitmap from ZXing. We frame it on a
            // white surface so any margin around the matrix doesn't
            // bleed into the surfaceVariant of the sheet.
            if (qrBitmap == null) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(1f)
                        .clip(RoundedCornerShape(12.dp))
                        .background(Color.White),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    CircularProgressIndicator()
                }
            } else {
                Image(
                    bitmap = qrBitmap.asImageBitmap(),
                    contentDescription = stringResource(R.string.key_detail_qr_image_cd, key.userEmail),
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(1f)
                        .clip(RoundedCornerShape(12.dp))
                        .background(Color.White)
                        .padding(12.dp)
                )
            }

            // 4.1.0 Phase 9 (issue #3) — a post-quantum key does not fit in
            // one symbol, so it is split. Nothing about this row appears for
            // a key that fits, which is every classic key.
            if (qrFrames.size > 1) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedButton(onClick = { autoRotate = false; onPrevFrame() }) {
                        Icon(
                            imageVector = Icons.Filled.FastRewind,
                            contentDescription = stringResource(R.string.qr_part_previous)
                        )
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onClick = { autoRotate = !autoRotate }) {
                            Icon(
                                imageVector = if (autoRotate) Icons.Filled.Pause else Icons.Filled.PlayArrow,
                                contentDescription = stringResource(
                                    if (autoRotate) R.string.qr_autorotate_pause_cd
                                    else R.string.qr_autorotate_play_cd
                                )
                            )
                        }
                        Text(
                            text = stringResource(
                                R.string.qr_part_of_format,
                                qrIndex + 1,
                                qrFrames.size
                            ),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    OutlinedButton(onClick = { autoRotate = false; onNextFrame() }) {
                        Icon(
                            imageVector = Icons.Filled.FastForward,
                            contentDescription = stringResource(R.string.qr_part_next)
                        )
                    }
                }
                Text(
                    text = stringResource(R.string.qr_multipart_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    modifier = Modifier.fillMaxWidth()
                )
            }

            // Fingerprint label — formatted as grouped hex, monospace.
            // Renders below the QR for verification: the other person
            // scans the QR AND compares the visible fingerprint to
            // what their imported key reports.
            Text(
                text = key.formattedFingerprint,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = FontFamily.Monospace
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = onCopyArmored,
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(
                        imageVector = Icons.Filled.ContentCopy,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.common_button_copy))
                }
                Button(
                    onClick = onShare,
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(
                        imageVector = Icons.Filled.IosShare,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.common_button_share))
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}
