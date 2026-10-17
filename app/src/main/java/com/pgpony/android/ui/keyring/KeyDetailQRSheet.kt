package com.pgpony.android.ui.keyring

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.IosShare
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.qr.QrEncodingPolicy
import com.pgpony.android.qr.QrFrameStore
import com.pgpony.android.qr.QrTransferMode
import com.pgpony.android.ui.components.PublicKeyQrDisplay

/**
 * Public-key sharing sheet using the same rendering and playback surface as Exchange.
 * The owner supplies an immutable sequence; Copy and Share export the complete armored key.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyDetailQRSheet(
    key: PGPKeyEntity,
    qrStore: QrFrameStore?,
    mode: QrTransferMode,
    policy: QrEncodingPolicy,
    onModeChange: (QrTransferMode) -> Unit,
    onPolicyChange: (QrEncodingPolicy) -> Unit,
    onCopyArmored: () -> Unit,
    onShare: () -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).imePadding()
            .navigationBarsPadding().padding(horizontal = 24.dp).padding(bottom = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            val fallback = stringResource(R.string.key_detail_type_public_key)
            Text(key.userName.ifBlank { key.userEmail.ifBlank { fallback } },
                style = MaterialTheme.typography.titleMedium)
            PublicKeyQrDisplay(qrStore, mode, policy, onModeChange, onPolicyChange, fingerprint = key.formattedFingerprint)
            // A transport checksum cannot authenticate an owner. Keep the fingerprint visible.
            Text(key.formattedFingerprint,
                style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(onClick = onCopyArmored, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Default.ContentCopy, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.common_button_copy))
                }
                Button(onClick = onShare, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Default.IosShare, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.common_button_share))
                }
            }
        }
    }
}
