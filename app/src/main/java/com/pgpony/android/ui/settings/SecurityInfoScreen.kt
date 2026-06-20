// SecurityInfoScreen.kt
// PGPony Android
//
// "Security & Encryption" reference screen accessible from Settings > Support.
// Explains the crypto stack — OpenPGP standards, Bouncy Castle, on-device
// storage, biometric lock, clipboard auto-clear — in plain language.
// Implemented as a full-height ModalBottomSheet to match SecretUnlockScreen.
//
// Added in Phase 1 (Tester Feedback Implementation Plan).

package com.pgpony.android.ui.settings

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityInfoScreen(onDismiss: () -> Unit) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
                .padding(bottom = 32.dp)
        ) {
            // ── Header ──────────────────────────────────────────────────
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Filled.Shield,
                    contentDescription = null,
                    tint = Color(0xFF8B5CF6),
                    modifier = Modifier.size(36.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    stringResource(R.string.security_info_title),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                stringResource(R.string.security_info_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 24.dp)
            )

            // ── Encryption standards ────────────────────────────────────
            InfoBlock(
                icon = Icons.Filled.Lock,
                iconTint = Color(0xFF8B5CF6),
                title = stringResource(R.string.security_info_block_openpgp_title),
                body = stringResource(R.string.security_info_block_openpgp_body)
            )

            // ── Algorithms ──────────────────────────────────────────────
            InfoBlock(
                icon = Icons.Filled.Calculate,
                iconTint = Color(0xFF6366F1),
                title = stringResource(R.string.security_info_block_algorithms_title),
                body = stringResource(R.string.security_info_block_algorithms_body)
            )

            // ── Crypto library ──────────────────────────────────────────
            InfoBlock(
                icon = Icons.Filled.Build,
                iconTint = Color(0xFFA78BFA),
                title = stringResource(R.string.security_info_block_library_title),
                body = stringResource(R.string.security_info_block_library_body)
            )

            // ── On-device storage ───────────────────────────────────────
            InfoBlock(
                icon = Icons.Filled.PhoneAndroid,
                iconTint = Color(0xFF22C55E),
                title = stringResource(R.string.security_info_block_on_device_title),
                body = stringResource(R.string.security_info_block_on_device_body)
            )

            // ── Key storage ─────────────────────────────────────────────
            InfoBlock(
                icon = Icons.Filled.VpnKey,
                iconTint = Color(0xFFF59E0B),
                title = stringResource(R.string.security_info_block_at_rest_title),
                body = stringResource(R.string.security_info_block_at_rest_body)
            )

            // ── Biometric lock ──────────────────────────────────────────
            InfoBlock(
                icon = Icons.Filled.Fingerprint,
                iconTint = Color(0xFF8B5CF6),
                title = stringResource(R.string.security_info_block_biometric_title),
                body = stringResource(R.string.security_info_block_biometric_body)
            )

            // ── Clipboard hygiene ───────────────────────────────────────
            InfoBlock(
                icon = Icons.Filled.Timer,
                iconTint = Color(0xFFEAB308),
                title = stringResource(R.string.security_info_block_clipboard_title),
                body = stringResource(R.string.security_info_block_clipboard_body)
            )

            // ── What we DON'T do ────────────────────────────────────────
            Spacer(modifier = Modifier.height(8.dp))
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Filled.Block,
                            contentDescription = null,
                            tint = Color(0xFFEF4444),
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            stringResource(R.string.security_info_not_doing_title),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    BulletLine(stringResource(R.string.security_info_not_doing_bullet_1))
                    BulletLine(stringResource(R.string.security_info_not_doing_bullet_2))
                    BulletLine(stringResource(R.string.security_info_not_doing_bullet_3))
                    BulletLine(stringResource(R.string.security_info_not_doing_bullet_4))
                    BulletLine(stringResource(R.string.security_info_not_doing_bullet_5))
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ── Footer ──────────────────────────────────────────────────
            Text(
                stringResource(R.string.security_info_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8B5CF6))
            ) { Text(stringResource(R.string.common_button_close)) }
        }
    }
}

// ── Reusable info components ──────────────────────────────────────────────

@Composable
private fun InfoBlock(
    icon: ImageVector,
    iconTint: Color,
    title: String,
    body: String
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(bottom = 20.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = iconTint,
            modifier = Modifier.size(24.dp).padding(top = 2.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                body,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun BulletLine(text: String) {
    Row(
        modifier = Modifier.padding(vertical = 2.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            "•",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(end = 8.dp)
        )
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
