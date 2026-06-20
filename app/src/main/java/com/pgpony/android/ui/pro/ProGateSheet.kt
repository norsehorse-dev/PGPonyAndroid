// ProGateSheet.kt
// PGPony Android
//
// Paywall bottom sheet — shown when free users tap a Pro feature.
// Matches iOS ProGateView: hero icon, feature description, all Pro features
// list, purchase button, restore button.

package com.pgpony.android.ui.pro

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pgpony.android.R
import com.pgpony.android.billing.BillingService

// ── Pro Features ───────────────────────────────────────────────────────

enum class ProFeature(
    val displayName: String,
    val description: String,
    val icon: ImageVector
) {
    UNLIMITED_KEYS(
        "Unlimited Key Pairs",
        "Create unlimited key pairs for different identities — work, personal, projects. Free includes 1 key pair.",
        Icons.Filled.Key
    ),
    ED25519(
        "Ed25519 + Cv25519 Keys",
        "Generate modern Ed25519 signing keys with Cv25519 encryption subkeys. Compact, fast, and recommended by security experts.",
        Icons.Filled.Shield
    ),
    KEY_SERVER(
        "Key Server Upload",
        "Publish your public key to keys.openpgp.org so anyone can find and encrypt messages to you.",
        Icons.Filled.Public
    ),
    MULTI_RECIPIENT(
        "Multiple Recipients",
        "Encrypt messages for multiple recipients at once. Free allows one recipient per message.",
        Icons.Filled.Group
    ),
    FILE_ENCRYPTION(
        "File Encryption",
        "Encrypt and decrypt any file type — documents, photos, archives. Share encrypted files securely.",
        Icons.Filled.InsertDriveFile
    )
}

// Free tier limits
object ProLimits {
    const val FREE_MAX_KEY_PAIRS = 1
    const val FREE_MAX_RECIPIENTS = 1

    fun canGenerateKey(currentKeyPairCount: Int, isPro: Boolean): Boolean {
        return isPro || currentKeyPairCount < FREE_MAX_KEY_PAIRS
    }

    fun canUseEd25519(isPro: Boolean): Boolean = isPro

    fun canUploadToKeyServer(isPro: Boolean): Boolean = isPro

    fun canUseMultipleRecipients(isPro: Boolean): Boolean = isPro
}

// ── Pro Gate Bottom Sheet ──────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProGateSheet(
    feature: ProFeature,
    billingService: BillingService,
    onDismiss: () -> Unit
) {
    val billingState by billingService.state.collectAsState()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var showSuccess by remember { mutableStateOf(false) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Hero icon
            Box(
                modifier = Modifier
                    .size(80.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.linearGradient(
                            colors = listOf(Color(0xFF6366F1), Color(0xFF8B5CF6))
                        )
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    feature.icon,
                    contentDescription = null,
                    modifier = Modifier.size(36.dp),
                    tint = Color.White
                )
            }
            Spacer(modifier = Modifier.height(16.dp))

            Text(
                stringResource(R.string.pro_gate_sheet_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))

            Text(
                feature.localizedDescription(),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 16.dp)
            )
            Spacer(modifier = Modifier.height(20.dp))

            // All Pro features list
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        stringResource(R.string.pro_gate_everything_in_pro),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    ProFeature.entries.forEach { feat ->
                        val isHighlighted = feat == feature
                        Row(
                            modifier = Modifier.padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                feat.icon,
                                contentDescription = null,
                                modifier = Modifier.size(22.dp),
                                tint = if (isHighlighted) Color(0xFF8B5CF6) else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    feat.localizedName(),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = if (isHighlighted) FontWeight.Bold else FontWeight.Medium,
                                    color = if (isHighlighted) Color(0xFF8B5CF6) else MaterialTheme.colorScheme.onSurface
                                )
                                if (isHighlighted) {
                                    Text(
                                        stringResource(R.string.pro_gate_you_tapped_this),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = Color(0xFF8B5CF6)
                                    )
                                }
                            }
                            Icon(
                                Icons.Filled.CheckCircle,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp),
                                tint = Color(0xFF8B5CF6).copy(alpha = 0.6f)
                            )
                        }
                    }
                }
            }
            Spacer(modifier = Modifier.height(20.dp))

            // Purchase button
            Button(
                onClick = { billingService.purchasePro() },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                enabled = !billingState.isLoading,
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF8B5CF6)
                ),
                shape = RoundedCornerShape(14.dp)
            ) {
                if (billingState.isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                        color = Color.White
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.pro_gate_purchasing))
                } else {
                    Icon(Icons.Filled.Star, null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Unlock Pro — ${billingState.proPrice}", fontWeight = FontWeight.Bold)
                }
            }
            Spacer(modifier = Modifier.height(8.dp))

            // Restore button
            TextButton(
                onClick = { billingService.restorePurchases() },
                enabled = !billingState.isLoading
            ) {
                Text("Restore Purchase", color = Color(0xFF8B5CF6))
            }

            Text(
                stringResource(R.string.pro_gate_one_time_purchase),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
            )

            // Error
            billingState.errorMessage?.let { error ->
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    error,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center
                )
            }

            Spacer(modifier = Modifier.height(32.dp))
        }
    }

    // Success check
    LaunchedEffect(billingState.isPro) {
        if (billingState.isPro && !showSuccess) {
            showSuccess = true
        }
    }

    if (showSuccess) {
        AlertDialog(
            onDismissRequest = { showSuccess = false; onDismiss() },
            title = { Text(stringResource(R.string.pro_gate_welcome_dialog_title)) },
            text = { Text(stringResource(R.string.pro_gate_welcome_dialog_body)) },
            confirmButton = {
                TextButton(onClick = { showSuccess = false; onDismiss() }) {
                    Text(stringResource(R.string.pro_gate_welcome_dialog_confirm))
                }
            }
        )
    }
}

// ── Pro Badge (inline use) ─────────────────────────────────────────────

@Composable
fun ProBadge(modifier: Modifier = Modifier) {
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = Color(0xFF8B5CF6),
        modifier = modifier
    ) {
        Text(
            "PRO",
            style = MaterialTheme.typography.labelSmall.copy(
                fontSize = 9.sp,
                fontWeight = FontWeight.Black
            ),
            color = Color.White,
            modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp)
        )
    }
}


/**
 * Phase A13 — localized name + description for ProFeature enum.
 * Enum still holds displayName/description as English fields for
 * compatibility; UI call sites use these @Composable extensions
 * instead. Same pattern as TrustLevel / RevocationReason.
 */
@androidx.compose.runtime.Composable
internal fun ProFeature.localizedName(): String = when (this) {
    ProFeature.UNLIMITED_KEYS   -> stringResource(R.string.pro_feature_unlimited_keys_title)
    ProFeature.ED25519          -> stringResource(R.string.pro_feature_modern_algos_title)
    ProFeature.KEY_SERVER       -> stringResource(R.string.pro_feature_keyserver_title)
    ProFeature.MULTI_RECIPIENT  -> stringResource(R.string.pro_feature_multi_recipients_title)
    ProFeature.FILE_ENCRYPTION  -> stringResource(R.string.pro_feature_file_encryption_title)
}

@androidx.compose.runtime.Composable
internal fun ProFeature.localizedDescription(): String = when (this) {
    ProFeature.UNLIMITED_KEYS   -> stringResource(R.string.pro_feature_unlimited_keys_body)
    ProFeature.ED25519          -> stringResource(R.string.pro_feature_modern_algos_body)
    ProFeature.KEY_SERVER       -> stringResource(R.string.pro_feature_keyserver_body)
    ProFeature.MULTI_RECIPIENT  -> stringResource(R.string.pro_feature_multi_recipients_body)
    ProFeature.FILE_ENCRYPTION  -> stringResource(R.string.pro_feature_file_encryption_body)
}
