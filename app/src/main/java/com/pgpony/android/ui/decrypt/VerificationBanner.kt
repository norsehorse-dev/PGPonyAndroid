// VerificationBanner.kt
// PGPony Android — Phase A3
//
// Renders the verification status above the decrypted/verified content.
// Four states map 1:1 to VerificationResult subclasses:
//
//   Verified      → green     "Verified — Alice <alice@example.com>"
//   Invalid       → red       "Signature did not match the content"
//   UnknownSigner → yellow    "Unknown signer · Tap to look up"        ← clickable
//   Unsigned      → gray      "Decrypted — no signature attached"
//
// The clickable yellow state is the entry point to SignerLookupSheet.
// All other states are non-interactive informational badges.
//
// Compose-only file — no ViewModel coupling. Caller passes the
// VerificationResult and the click handler that opens the lookup sheet.

package com.pgpony.android.ui.decrypt

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.HelpOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.crypto.VerificationResult

/**
 * Render a 4-state verification banner. `onTapUnknownSigner` is called
 * only when the result is UnknownSigner and the user taps the row.
 */
@Composable
fun VerificationBanner(
    result: VerificationResult,
    onTapUnknownSigner: () -> Unit,
    modifier: Modifier = Modifier
) {
    when (result) {
        is VerificationResult.Verified -> {
            val subtitle = formatVerifiedSubtitle(result)
            BannerRow(
                modifier = modifier,
                icon = Icons.Filled.VerifiedUser,
                iconTint = GreenTint,
                bg = GreenBg,
                title = stringResource(R.string.verify_banner_verified_title),
                subtitle = subtitle
            )
        }
        is VerificationResult.Invalid -> {
            BannerRow(
                modifier = modifier,
                icon = Icons.Filled.Cancel,
                iconTint = RedTint,
                bg = RedBg,
                title = stringResource(R.string.verify_banner_invalid_title),
                subtitle = result.reason
            )
        }
        is VerificationResult.UnknownSigner -> {
            BannerRow(
                modifier = modifier
                    .clip(RoundedCornerShape(12.dp))
                    .clickable(onClick = onTapUnknownSigner),
                icon = Icons.Filled.HelpOutline,
                iconTint = YellowTint,
                bg = YellowBg,
                title = stringResource(R.string.verify_banner_unknown_signer_title),
                subtitle = buildUnknownSignerSubtitle(result),
                trailing = {
                    Icon(
                        Icons.Filled.ChevronRight,
                        contentDescription = stringResource(R.string.verify_banner_unknown_signer_lookup_cd),
                        tint = YellowTint
                    )
                }
            )
        }
        is VerificationResult.Unsigned -> {
            BannerRow(
                modifier = modifier,
                icon = Icons.Filled.Info,
                iconTint = GrayTint,
                bg = GrayBg,
                title = stringResource(R.string.verify_banner_no_signature_title),
                subtitle = stringResource(R.string.verify_banner_no_signature_subtitle)
            )
        }
    }
}

// ── Internal row Composable ────────────────────────────────────────────

@Composable
private fun BannerRow(
    modifier: Modifier,
    icon: ImageVector,
    iconTint: Color,
    bg: Color,
    title: String,
    subtitle: String?,
    trailing: (@Composable () -> Unit)? = null
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(bg)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = iconTint,
            modifier = Modifier.size(20.dp)
        )
        Spacer(modifier = Modifier.width(10.dp))
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            Text(
                title,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = iconTint
            )
            if (!subtitle.isNullOrBlank()) {
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
        if (trailing != null) {
            Spacer(modifier = Modifier.width(8.dp))
            trailing()
        }
    }
}

// ── Subtitle formatters ────────────────────────────────────────────────
//
// Phase A13 — promoted to @Composable so they can resolve stringResource
// for the "Signed by …" format strings. Callers are already inside a
// @Composable scope (VerificationBanner), so the change is invisible at
// the call site.

@androidx.compose.runtime.Composable
private fun formatVerifiedSubtitle(v: VerificationResult.Verified): String {
    // "Alice <alice@example.com>" if both, else just whichever we have,
    // falling back to the short key ID.
    val name = v.signerName
    val email = v.signerEmail
    return when {
        !name.isNullOrBlank() && !email.isNullOrBlank() -> stringResource(R.string.verify_banner_signed_by_full_format, name, email)
        !name.isNullOrBlank()                            -> stringResource(R.string.verify_banner_signed_by_name_format, name)
        !email.isNullOrBlank()                           -> stringResource(R.string.verify_banner_signed_by_email_format, email)
        else                                              -> stringResource(R.string.verify_banner_signed_by_keyid_format, v.signerKeyID)
    }
}

@androidx.compose.runtime.Composable
private fun buildUnknownSignerSubtitle(u: VerificationResult.UnknownSigner): String {
    val short = u.claimedFingerprint?.takeLast(16)?.let { "0x$it" }
        ?: "0x${u.signerKeyID}"
    return stringResource(R.string.verify_banner_unknown_signer_subtitle_format, short)
}

// ── Color palette ──────────────────────────────────────────────────────
//
// Hardcoded for now; Phase A12 introduces a theme picker (Light/Dark/
// System) and these will need to be wired through Material colors then.
// Using semi-transparent backgrounds so the banner looks correct against
// the current dark theme; opacity = 0x1A is roughly 10%.

private val GreenTint  = Color(0xFF34C759)
private val GreenBg    = Color(0x1A34C759)
private val RedTint    = Color(0xFFFF3B30)
private val RedBg      = Color(0x1AFF3B30)
private val YellowTint = Color(0xFFFFCC00)
private val YellowBg   = Color(0x1AFFCC00)
private val GrayTint   = Color(0xFF8E8E93)
private val GrayBg     = Color(0x1A8E8E93)
