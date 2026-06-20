// ContactAvatar.kt
// PGPony Android — Phase A9
//
// Circular contact avatar matching iOS ContactsView's contactAvatar.
// Renders one of two states:
//
//   1. If the contact has a thumbnail bitmap (set eagerly by
//      ContactsService.buildContactsList → getContactPhoto), display
//      the photo cropped to a circle.
//
//   2. Otherwise, draw a gradient-filled circle with the contact's
//      initials in white centered text. Gradient color choice
//      signals whether the contact has linked PGP keys:
//        • Linked     → indigo-to-purple (app brand colors)
//        • Unlinked   → gray-on-gray (neutral)
//
// Initials extraction matches iOS:
//   • "Jane Smith"         → "JS"
//   • "Jane"               → "JA"
//   • "Mary-Jane Watson"   → "MW"   (split on whitespace only)
//   • ""                   → "?"    (placeholder for nameless rows)
//
// Size is a Dp param so call sites can use larger avatars in linked
// rows (44dp) and smaller in unlinked (40dp), matching iOS hierarchy.

package com.pgpony.android.ui.contacts

import android.graphics.Bitmap
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.Image

@Composable
fun ContactAvatar(
    displayName: String,
    thumbnail: Bitmap?,
    isLinked: Boolean,
    size: Dp = 44.dp
) {
    if (thumbnail != null) {
        // Real device-contact photo path. Bitmap is decoded once by
        // ContactsService.getContactPhoto and cached on the service;
        // re-using here is allocation-free.
        Image(
            bitmap = thumbnail.asImageBitmap(),
            contentDescription = null,
            modifier = Modifier
                .size(size)
                .clip(CircleShape),
            contentScale = ContentScale.Crop
        )
    } else {
        // Fallback path — gradient circle with initials. Two color
        // schemes:
        //   • Linked contacts use the app's indigo→purple gradient,
        //     matching iOS's [.indigo, .purple] start/end stops.
        //   • Unlinked contacts get a neutral gray gradient so the
        //     linked-vs-unlinked status reads at a glance, even
        //     without the surrounding section header.
        val gradient = if (isLinked) {
            Brush.linearGradient(
                colors = listOf(
                    Color(0xFF6366F1), // indigo-500
                    Color(0xFF8B5CF6)  // purple-500 (app primary)
                )
            )
        } else {
            Brush.linearGradient(
                colors = listOf(
                    Color(0xFF9CA3AF), // gray-400
                    Color(0xFFD1D5DB)  // gray-300
                )
            )
        }
        Box(
            modifier = Modifier
                .size(size)
                .clip(CircleShape)
                .background(gradient),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = initialsFor(displayName),
                color = Color.White,
                fontWeight = FontWeight.SemiBold,
                // Initials sized to ~35% of avatar diameter — matches
                // iOS scaling factor 0.35 in contactAvatar.
                fontSize = (size.value * 0.35f).sp
            )
        }
    }
}

/**
 * Initials extraction. Matches iOS initials(for:) semantics:
 *
 *   • Multi-word names → first letter of first two words (uppercased)
 *   • Single-word names → first two letters of the word (uppercased)
 *   • Blank names → "?" placeholder
 *
 * Whitespace is the only token delimiter — hyphens and other
 * punctuation stay attached to their word ("Mary-Jane" is treated
 * as a single word "Mary-Jane"). This matches iOS's
 * `name.split(separator: " ")` semantics.
 *
 * Trimming is applied so leading/trailing whitespace from sloppy
 * contact entries ("  Bob  ") doesn't produce a leading-space-only
 * initial.
 */
private fun initialsFor(name: String): String {
    val trimmed = name.trim()
    if (trimmed.isEmpty()) return "?"
    val parts = trimmed.split(Regex("\\s+"))
    return if (parts.size >= 2) {
        // First letter of the first two parts.
        "${parts[0].first()}${parts[1].first()}".uppercase()
    } else {
        // First two characters of the only part — guard against
        // 1-character names by falling back to the single character.
        trimmed.take(2).uppercase()
    }
}
