// KeyDetailSections.kt
// PGPony Android — Phase A4a
//
// Section composables that make up the body of KeyDetailScreen. Each
// section maps 1:1 to an iOS KeyDetailView Section { } block:
//
//   HeaderSection           ←  iOS "Header Section"
//   FingerprintSection      ←  iOS "Fingerprint"
//   DetailsSection          ←  iOS "Details"
//   ContactSection          ←  iOS "Contact"
//   NotesSection            ←  iOS "Notes"
//   QRSection               ←  iOS "QR Code" button row
//   ActionsSection          ←  iOS "Actions"
//   DangerZoneSection       ←  iOS "Danger Zone"
//
// A4a renders all sections with data, but action-side controls
// (TrustLevel picker, Contact picker, Notes editor, Share / Export /
// Set Default / Upload / Revoke / Delete) route through an
// onComingSoon(label) callback which the host screen surfaces as a
// snackbar. A4b replaces each onComingSoon site with the real handler.
//
// SectionGroup is a thin Surface+Column wrapper that gives every
// section the iOS-style grouped-list visual (rounded corners on the
// surface variant, group title above). It's the Compose equivalent of
// SwiftUI's Section() inside a List with .insetGrouped style.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.IosShare
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Report
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.TrustLevel
import com.pgpony.android.ui.components.TrustBadge
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Phase A13 — stable English routing keys for action dispatch.
 *
 * Action-row composables pass one of these constants to their
 * onComingSoon callback; KeyDetailScreen's dispatchAction matches
 * against the same constants to choose what to do. The constants
 * are intentionally English — they're internal IDs, never shown to
 * the user. Localized labels come from string resources at the
 * call sites (label = stringResource(R.string.key_detail_action_*)).
 *
 * This decouples display labels from dispatch keys so localization
 * doesn't break routing.
 */
internal object KeyDetailActionIds {
    const val CHANGE_TRUST = "Change Trust Level"
    const val ADD_NOTES = "Add notes"
    const val EDIT_NOTES = "Edit notes"
    const val LINK_CONTACT = "Link to Contact"
    const val AUTO_MATCH_EMAIL = "Auto-match by email"
    const val UNLINK_CONTACT = "Unlink Contact"
    const val SHARE_PUBLIC_KEY = "Share Public Key"
    const val CHANGE_CARD_PIN = "Change Card PIN"
    const val SET_AS_DEFAULT = "Set as Default Key"
    const val UPLOAD_TO_KEY_SERVER = "Upload to Key Server"
    const val CHECK_KEY_SERVER = "Check Key Server"
    const val DELETE_KEY = "Delete Key"
    const val REVOKE_KEY = "Revoke Key"
    const val EXPORT_REVOCATION_CERT = "Export Revocation Certificate"
    const val EXPORT_PRIVATE_KEY = "Export Private Key"
}

// ── SectionGroup — visual wrapper for grouped-list sections ────────────

/**
 * Material 3 equivalent of SwiftUI's grouped-list Section. The optional
 * [title] renders above the surface in the iOS section-header style
 * (small, uppercase-ish, secondary color). Section content sits on a
 * rounded surfaceVariant background so adjacent sections separate
 * visually.
 */
@Composable
private fun SectionGroup(
    title: String? = null,
    content: @Composable () -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        if (title != null) {
            Text(
                text = title.uppercase(),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 24.dp, end = 16.dp, bottom = 6.dp, top = 4.dp)
            )
        }
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
        ) {
            Column(modifier = Modifier.padding(vertical = 4.dp)) {
                content()
            }
        }
    }
}

// ── Detail row helper (iOS DetailRow equivalent) ───────────────────────

/**
 * Label-on-left / value-on-right row used inside DetailsSection. The
 * optional [valueColor] override is for "Expires" rows that switch to
 * red when expired / orange when imminent. The optional [icon] sits to
 * the left of the value (matches iOS pattern for "iCloud Sync" rows).
 */
@Composable
private fun DetailRow(
    label: String,
    value: String,
    valueColor: Color? = null,
    icon: ImageVector? = null
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
        if (icon != null) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(14.dp)
            )
            Spacer(modifier = Modifier.width(4.dp))
        }
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = valueColor ?: MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

// ── Action row helper — tappable label + icon ─────────────────────────

/**
 * Material 3 row mimicking iOS Section { Button(action:) { Label(...) } }.
 * Used by ContactSection, NotesSection, QRSection, ActionsSection,
 * DangerZoneSection. Tint is configurable so destructive (red) and
 * sensitive (orange) actions can stand out while neutral actions stay
 * on the primary indigo.
 */
@Composable
private fun ActionRow(
    icon: ImageVector,
    label: String,
    tint: Color = Color(0xFF8B5CF6),
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    val effectiveTint = if (enabled) tint else MaterialTheme.colorScheme.onSurfaceVariant
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = effectiveTint,
            modifier = Modifier.size(20.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = effectiveTint
        )
    }
}

// ── Header section ────────────────────────────────────────────────────

/**
 * Hero avatar + display name + email + key-pair / default badges.
 * Mirrors iOS KeyDetailView "Header Section" (lines 46-92). No
 * SectionGroup wrapping — the header sits at the top of the screen
 * without a grouped-list surface to match the iOS .listRowBackground(.clear) feel.
 */
@Composable
fun KeyHeaderSection(key: PGPKeyEntity) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        KeyAvatarHero(key = key)

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = key.userName.ifBlank { key.userEmail },
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            if (key.userName.isNotBlank() && key.userEmail.isNotBlank()) {
                Text(
                    text = key.userEmail,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(top = 4.dp)
            ) {
                KeyTypeChip(isKeyPair = key.isKeyPair)
                if (key.isDefault) {
                    DefaultChip()
                }
            }
        }
    }
}

@Composable
private fun KeyTypeChip(isKeyPair: Boolean) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Icon(
            imageVector = if (isKeyPair) Icons.Filled.VpnKey else Icons.Filled.Key,
            contentDescription = null,
            modifier = Modifier.size(14.dp),
            tint = if (isKeyPair) Color(0xFF8B5CF6) else MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = if (isKeyPair) stringResource(R.string.key_detail_type_key_pair) else stringResource(R.string.key_detail_type_public_key),
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            color = if (isKeyPair) Color(0xFF8B5CF6) else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun DefaultChip() {
    Surface(
        shape = RoundedCornerShape(50),
        color = Color(0xFF8B5CF6)
    ) {
        Text(
            text = stringResource(R.string.key_detail_badge_default),
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp),
            fontWeight = FontWeight.Bold,
            color = Color.White,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
        )
    }
}

// ── Fingerprint section ────────────────────────────────────────────────

/**
 * The big monospaced fingerprint block with tap-to-copy. iOS-equivalent
 * behavior: tap anywhere in the row → clipboard write + "Copied!"
 * inline feedback that auto-resets after 2 seconds. The
 * [copiedRecently] flag is owned by the VM; the actual clipboard call
 * is the caller's job (LocalClipboardManager is a Composable concern).
 */
@Composable
fun FingerprintSection(
    key: PGPKeyEntity,
    copiedRecently: Boolean,
    onCopy: () -> Unit
) {
    SectionGroup(title = stringResource(R.string.key_detail_section_fingerprint)) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onCopy)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = key.formattedFingerprint,
                style = MaterialTheme.typography.bodyMedium.copy(
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Medium
                ),
                color = MaterialTheme.colorScheme.onSurface
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = if (copiedRecently) Icons.Filled.CheckCircle else Icons.Filled.ContentCopy,
                    contentDescription = null,
                    tint = if (copiedRecently) Color(0xFF22C55E) else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(14.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = if (copiedRecently) stringResource(R.string.key_detail_fingerprint_copied) else stringResource(R.string.key_detail_fingerprint_tap_to_copy),
                    style = MaterialTheme.typography.labelMedium,
                    color = if (copiedRecently) Color(0xFF22C55E) else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// ── Details section ────────────────────────────────────────────────────

/**
 * Algorithm / Created / Expires / Trust / Drive Sync / Key Server rows.
 * The Trust row is tappable in A4a (renders the chevron and trust
 * badge) but the click routes through onComingSoon — A4b replaces with
 * the real TrustLevelPicker sheet.
 */
@Composable
fun DetailsSection(
    key: PGPKeyEntity,
    onTrustTap: () -> Unit,
    onEditExpiry: (() -> Unit)? = null
) {
    SectionGroup(title = stringResource(R.string.key_detail_section_details)) {
        DetailRow(label = stringResource(R.string.key_detail_detail_algorithm), value = key.algorithm.displayName)
        DetailRow(
            label = stringResource(R.string.key_detail_detail_format),
            value = if (key.isV6Key) stringResource(R.string.key_detail_detail_format_v6)
                    else stringResource(R.string.key_detail_detail_format_v4)
        )
        DetailRow(label = stringResource(R.string.key_detail_detail_created), value = formatDate(key.createdAt))
        ExpiresRow(key = key, onEditExpiry = onEditExpiry)
        TrustLevelRow(trust = key.trustLevel, onClick = onTrustTap)
        if (key.isSynced) {
            DetailRow(label = stringResource(R.string.key_detail_detail_drive_backup), value = stringResource(R.string.key_detail_detail_drive_backup_enabled), icon = Icons.Filled.CloudDone)
        }
        if (key.keyServerUploaded) {
            DetailRow(label = stringResource(R.string.key_detail_detail_key_server), value = stringResource(R.string.key_detail_detail_key_server_published), icon = Icons.Filled.CloudUpload)
        }
        // 3.0.0-KS1 (Lukas request) — keyserver activity timestamps. Always
        // shown so the user can see status at a glance; "Never" until set.
        DetailRow(
            label = stringResource(R.string.key_detail_last_uploaded_label),
            value = key.lastUploadedAt?.let { formatDate(it) }
                ?: stringResource(R.string.key_detail_timestamp_never),
        )
        DetailRow(
            label = stringResource(R.string.key_detail_last_checked_label),
            value = key.lastCheckedAt?.let { formatDate(it) }
                ?: stringResource(R.string.key_detail_timestamp_never),
        )
    }
}

@Composable
private fun ExpiresRow(key: PGPKeyEntity, onEditExpiry: (() -> Unit)? = null) {
    val expiresAt = key.expiresAt
    val now = System.currentTimeMillis()
    val color = when {
        expiresAt == null            -> null
        key.isExpired                -> MaterialTheme.colorScheme.error
        (expiresAt - now) / (1000L * 60 * 60 * 24) in 0..30 -> Color(0xFFFBBF24)  // amber
        else                         -> null
    }
    val valueText = if (expiresAt == null) {
        stringResource(R.string.key_detail_detail_expires_never)
    } else {
        formatDate(expiresAt)
    }

    // Editable keys (software pairs + card-backed) get a tappable row with
    // an edit affordance; public-only keys keep the plain read-only row.
    if (onEditExpiry == null) {
        DetailRow(
            label = stringResource(R.string.key_detail_detail_expires),
            value = valueText,
            valueColor = color
        )
        return
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onEditExpiry)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = stringResource(R.string.key_detail_detail_expires),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text(
                text = valueText,
                style = MaterialTheme.typography.bodyMedium,
                color = color ?: MaterialTheme.colorScheme.onSurfaceVariant
            )
            Icon(
                imageVector = Icons.Filled.Edit,
                contentDescription = stringResource(R.string.key_detail_expiry_edit),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(16.dp)
            )
        }
    }
}

@Composable
private fun TrustLevelRow(trust: TrustLevel, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = stringResource(R.string.key_detail_trust_level_label),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            TrustBadge(trust)
            Text(
                text = trust.displayName,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = "›",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// ── Contact section ────────────────────────────────────────────────────

/**
 * Read-only display in A4a:
 *   • If contact is linked → show linked-contact name + checkmark
 *     + an "Unlink" stub that routes through onComingSoon
 *   • If no contact linked → "Link to Contact" CTA stub
 *     + "Auto-match by email" stub when email is present
 */
@Composable
fun ContactSection(
    key: PGPKeyEntity,
    onComingSoon: (String) -> Unit
) {
    SectionGroup(title = stringResource(R.string.key_detail_section_contact)) {
        if (!key.contactName.isNullOrBlank() && key.contactId != null) {
            // Linked
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(Color(0xFF6366F1)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = key.initials,
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = key.contactName,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = stringResource(R.string.key_detail_contact_linked),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Icon(
                    imageVector = Icons.Filled.CheckCircle,
                    contentDescription = stringResource(R.string.key_detail_contact_linked_cd),
                    tint = Color(0xFF22C55E),
                    modifier = Modifier.size(20.dp)
                )
            }
            ActionRow(
                icon = Icons.Filled.Cancel,
                label = stringResource(R.string.key_detail_action_unlink_contact),
                tint = MaterialTheme.colorScheme.error,
                onClick = { onComingSoon(KeyDetailActionIds.UNLINK_CONTACT) }
            )
        } else {
            ActionRow(
                icon = Icons.Filled.PersonAdd,
                label = stringResource(R.string.key_detail_action_link_contact),
                onClick = { onComingSoon(KeyDetailActionIds.LINK_CONTACT) }
            )
            if (key.userEmail.isNotBlank()) {
                ActionRow(
                    icon = Icons.Filled.Star,
                    label = stringResource(R.string.key_detail_action_auto_match_email),
                    onClick = { onComingSoon(KeyDetailActionIds.AUTO_MATCH_EMAIL) }
                )
            }
        }
    }
}

// ── Notes section ──────────────────────────────────────────────────────

/**
 * Read-only display in A4a. If notes exist, render them; otherwise show
 * a "Add notes..." stub that routes through onComingSoon. A4b adds the
 * actual editor (likely a TextField in a ModalBottomSheet).
 */
@Composable
fun NotesSection(
    key: PGPKeyEntity,
    onComingSoon: (String) -> Unit
) {
    SectionGroup(title = stringResource(R.string.key_detail_section_notes)) {
        val notes = key.notes
        if (!notes.isNullOrBlank()) {
            Text(
                text = notes,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)
            )
            // Phase A4b: pencil icon now that Edit is wired
            ActionRow(
                icon = Icons.Filled.Edit,
                label = stringResource(R.string.key_detail_action_edit_notes),
                onClick = { onComingSoon(KeyDetailActionIds.EDIT_NOTES) }
            )
        } else {
            // Phase A4b: pencil icon now that Add is wired
            ActionRow(
                icon = Icons.Filled.Edit,
                label = stringResource(R.string.key_detail_action_add_notes),
                onClick = { onComingSoon(KeyDetailActionIds.ADD_NOTES) }
            )
        }
    }
}

// ── QR section ────────────────────────────────────────────────────────

@Composable
fun QRSection(onShowQR: () -> Unit) {
    SectionGroup {
        ActionRow(
            icon = Icons.Filled.QrCode,
            label = stringResource(R.string.key_detail_action_show_qr_code),
            onClick = onShowQR
        )
    }
}

// ── Actions section ────────────────────────────────────────────────────

/**
 * Share Public Key (always), Export Private Key (key pairs only),
 * Set as Default (key pairs not yet default), Upload to Key Server
 * (key pairs not yet uploaded). All stubbed in A4a — A4b wires each
 * to its real implementation.
 */
@Composable
fun ActionsSection(
    key: PGPKeyEntity,
    onComingSoon: (String) -> Unit
) {
    SectionGroup {
        ActionRow(
            icon = Icons.Filled.IosShare,
            label = stringResource(R.string.key_detail_action_share_public_key),
            onClick = { onComingSoon(KeyDetailActionIds.SHARE_PUBLIC_KEY) }
        )
        if (key.isCardBacked) {
            ActionRow(
                icon = Icons.Filled.Password,
                label = stringResource(R.string.key_detail_action_change_card_pin),
                onClick = { onComingSoon(KeyDetailActionIds.CHANGE_CARD_PIN) }
            )
        }
        if (key.isKeyPair) {
            ActionRow(
                icon = Icons.Filled.VpnKey,
                label = stringResource(R.string.key_detail_action_export_private_key),
                tint = Color(0xFFFB923C),  // orange — sensitive action telegraph
                onClick = { onComingSoon(KeyDetailActionIds.EXPORT_PRIVATE_KEY) }
            )
        }
        if (key.isKeyPair && !key.isDefault) {
            ActionRow(
                icon = Icons.Filled.Star,
                label = stringResource(R.string.key_detail_action_set_as_default),
                onClick = { onComingSoon(KeyDetailActionIds.SET_AS_DEFAULT) }
            )
        }
        if (key.isKeyPair && !key.keyServerUploaded) {
            ActionRow(
                icon = Icons.Filled.CloudUpload,
                label = stringResource(R.string.key_detail_action_upload_to_key_server),
                onClick = { onComingSoon(KeyDetailActionIds.UPLOAD_TO_KEY_SERVER) }
            )
        }
        // 3.0.0-KS1 (Lukas request) — look this key up on a keyserver and
        // stamp "Last checked". Available for any key (read-only lookup).
        ActionRow(
            icon = Icons.Filled.CloudDownload,
            label = stringResource(R.string.key_detail_action_check_key_server),
            onClick = { onComingSoon(KeyDetailActionIds.CHECK_KEY_SERVER) }
        )
    }
}

// ── Danger Zone ────────────────────────────────────────────────────────

/**
 * Revoke Key (key pairs only — needs private key for revocation cert)
 * and Delete Key.
 *
 * Phase A6: when [key].isRevoked is true, "Revoke Key…" disappears
 * (already revoked) and is replaced by "Export Revocation Certificate"
 * so the user can share the cert with anyone holding their old public
 * key. Delete Key is always available regardless of revocation state.
 */
@Composable
fun DangerZoneSection(
    key: PGPKeyEntity,
    onComingSoon: (String) -> Unit
) {
    SectionGroup {
        if (key.isKeyPair) {
            if (key.isRevoked) {
                // Phase A6 — post-revocation: surface re-export of the
                // stored cert so the user can share it with contacts
                // still holding their pre-revocation public key. Uses
                // a non-error tint since this is a benign read-only
                // action, not a destructive one.
                ActionRow(
                    icon = Icons.Filled.IosShare,
                    label = stringResource(R.string.key_detail_action_export_revocation_cert),
                    onClick = { onComingSoon(KeyDetailActionIds.EXPORT_REVOCATION_CERT) }
                )
            } else {
                ActionRow(
                    icon = Icons.Filled.Report,
                    label = stringResource(R.string.key_detail_action_revoke_key),
                    tint = MaterialTheme.colorScheme.error,
                    onClick = { onComingSoon(KeyDetailActionIds.REVOKE_KEY) }
                )
            }
        }
        ActionRow(
            icon = Icons.Filled.Delete,
            label = stringResource(R.string.key_detail_action_delete_key),
            tint = MaterialTheme.colorScheme.error,
            onClick = { onComingSoon(KeyDetailActionIds.DELETE_KEY) }
        )
    }
}

// ── Phase A6: Revoked banner ──────────────────────────────────────────

/**
 * Red banner shown directly below the header on a revoked key. Rendered
 * by LoadedBody (or whichever screen-level Composable owns section
 * order) when [key].isRevoked is true. Three pieces of info:
 *   • "REVOKED" label (eyebrow text in red)
 *   • Revoked-on date (epoch ms → formatted via the same SimpleDateFormat
 *     used elsewhere in this file)
 *   • Reason — pulled from the enum's displayName, falls back to
 *     "No reason specified" if the field is null (pre-cached cert case
 *     where the user hasn't revoked through the UI but somehow the flag
 *     got set; defensive).
 *
 * Banner is non-interactive — it's a status surface, not a CTA. The
 * "Export Revocation Certificate" action that lets users re-share lives
 * in Danger Zone (above), keeping the banner visually clean.
 */
@Composable
fun RevokedBanner(key: PGPKeyEntity) {
    if (!key.isRevoked) return
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.errorContainer,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Filled.Report,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.key_detail_revoked_badge),
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.error
                )
                val revokedDate = key.revokedAt?.let { formatDate(it) }
                Text(
                    text = if (revokedDate != null) stringResource(R.string.key_detail_revoked_on_format, revokedDate) else stringResource(R.string.key_detail_revoked_label),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
                Text(
                    text = key.revocationReason?.localizedName() ?: stringResource(R.string.key_detail_revoked_no_reason),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    // Advisory — explains the practical implication of
                    // being revoked. Helps users understand why the key
                    // disappeared from recipient pickers.
                    text = stringResource(R.string.key_detail_revoked_explainer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.85f)
                )
            }
        }
    }
}

// ── Date formatter ────────────────────────────────────────────────────

/** "Jan 5, 2026" — matches iOS formatted(date: .abbreviated, time: .omitted). */
private fun formatDate(epochMillis: Long): String {
    val fmt = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
    return fmt.format(Date(epochMillis))
}
