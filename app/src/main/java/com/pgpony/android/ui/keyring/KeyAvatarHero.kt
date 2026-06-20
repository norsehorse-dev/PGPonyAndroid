// KeyAvatarHero.kt
// PGPony Android — Phase A4a
//
// Larger circular avatar used in the KeyDetailScreen header. Mirrors
// iOS ContactAvatarView at size: 80 — the small 44dp version baked
// into KeyCard.kt handles list cells, this one is the hero portrait.
//
// Renders the key owner's initials inside a colored circle. The fill
// color mirrors KeyCard's convention (indigo for key pairs, secondary
// indigo for public-only) so the visual identity carries across both
// the list and detail surfaces. Phase A4b will swap in the user's
// Contact-app photo when contactPhotoUri is set, similar to iOS
// ContactAvatarView's photo branch.

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pgpony.android.data.PGPKeyEntity

@Composable
fun KeyAvatarHero(
    key: PGPKeyEntity,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .size(80.dp)
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
            fontSize = 28.sp
        )
    }
}
