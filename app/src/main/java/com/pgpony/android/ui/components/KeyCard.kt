// KeyCard.kt
// PGPony Android
//
// Reusable composable for displaying a PGP key in a list.
// Matches iOS KeyCardView.swift layout.
//
// Phase A6: When key.isRevoked is true, the card surfaces a red
// "Revoked" badge in the fingerprint row (next to the algorithm
// badge). Listed alongside the existing "Expired" badge — both occupy
// the same visual slot and reinforce "don't use this key".

package com.pgpony.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.automirrored.filled.Label
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.TrustLevel

@Composable
fun KeyCard(
    key: PGPKeyEntity,
    onClick: () -> Unit = {},
    modifier: Modifier = Modifier,
    trailing: (@Composable () -> Unit)? = null,
    /** 4.6.0 (item 20): how many stored keys share this key's identity. */
    sameIdentityCount: Int = 1,
    onSameIdentityClick: (() -> Unit)? = null
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Avatar circle with initials
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(
                        if (key.isKeyPair) Color(0xFF8B5CF6) else Color(0xFF6366F1)
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = key.initials,
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            // Name, email, fingerprint
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = key.userName.ifBlank { key.userEmail },
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    if (key.isKeyPair) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Icon(
                            imageVector = Icons.Filled.VpnKey,
                            contentDescription = stringResource(R.string.key_card_key_pair_cd),
                            modifier = Modifier.size(14.dp),
                            tint = Color(0xFF8B5CF6)
                        )
                    }
                    // #45: mark the default key so it can be picked out at a glance.
                    if (key.isDefault) {
                        Spacer(modifier = Modifier.width(6.dp))
                        DefaultPill()
                    }
                }

                if (key.userName.isNotBlank() && key.userEmail.isNotBlank()) {
                    Text(
                        text = key.userEmail,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                // 4.6.0 (item 1): the user's own label for the key (the first
                // line of its note), set apart from the key's own User ID.
                key.noteLabel?.let { label ->
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 2.dp)) {
                        Icon(
                            Icons.AutoMirrored.Filled.Label, null,
                            modifier = Modifier.size(12.dp),
                            tint = MaterialTheme.colorScheme.tertiary
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = label,
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.tertiary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                Spacer(modifier = Modifier.height(4.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Algorithm badge
                    AlgorithmBadge(key.algorithm.shortName)
                    Spacer(modifier = Modifier.width(6.dp))
                    // Short fingerprint
                    Text(
                        text = key.shortFingerprint,
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp
                        ),
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                    )
                    // Expiration warning
                    if (key.isExpired) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = stringResource(R.string.key_card_expired_badge),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                    // Phase A6 — revocation indicator. Rendered as a
                    // filled red pill (vs Expired's plain red text) so
                    // it carries more visual weight; a revoked key is a
                    // stronger statement than an expired one.
                    if (key.isRevoked) {
                        Spacer(modifier = Modifier.width(6.dp))
                        RevokedPill()
                    }
                    // 4.6.0 (item 20): other stored keys carry the same identity.
                    if (sameIdentityCount > 1) {
                        Spacer(modifier = Modifier.width(6.dp))
                        SameIdentityPill(sameIdentityCount, onSameIdentityClick)
                    }
                }
            }

            // Trust indicator
            TrustBadge(key.trustLevel)

            // Optional trailing slot (e.g. drag handle in manual sort mode)
            if (trailing != null) {
                Spacer(modifier = Modifier.width(8.dp))
                trailing()
            }
        }
    }
}

/**
 * Phase A6 — small filled red pill that reads "REVOKED". Same shape +
 * size as AlgorithmBadge so it sits visually balanced next to the
 * algorithm name in the fingerprint row.
 */
@Composable
fun RevokedPill() {
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = MaterialTheme.colorScheme.error,
        modifier = Modifier.height(18.dp)
    ) {
        Text(
            text = stringResource(R.string.key_card_revoked_badge),
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onError,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
        )
    }
}

/** 4.6.0 (item 20): "N keys" for an identity held by more than one stored key. */
@Composable
fun SameIdentityPill(count: Int, onClick: (() -> Unit)?) {
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = MaterialTheme.colorScheme.tertiaryContainer,
        modifier = Modifier.height(18.dp).let { if (onClick != null) it.clickable(onClick = onClick) else it }
    ) {
        Text(
            text = androidx.compose.ui.res.pluralStringResource(R.plurals.key_card_same_identity_count, count, count),
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onTertiaryContainer,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
        )
    }
}

@Composable
fun DefaultPill() {
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = Color(0xFF8B5CF6),
        modifier = Modifier.height(18.dp)
    ) {
        Text(
            text = stringResource(R.string.key_card_default_badge),
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
            fontWeight = FontWeight.Bold,
            color = Color.White,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
        )
    }
}

@Composable
fun AlgorithmBadge(name: String) {
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f),
        modifier = Modifier.height(18.dp)
    ) {
        Text(
            text = name,
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
            color = MaterialTheme.colorScheme.onPrimaryContainer,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
        )
    }
}

@Composable
fun TrustBadge(trust: TrustLevel) {
    // #24 — renders through the shared TrustMark so KeyCard, KeyDetail, and
    // Contacts share one ladder and can't drift.
    TrustMark(trust = trust, size = 20.dp)
}
