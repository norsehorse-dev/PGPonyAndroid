// Tooltip.kt
// PGPony Android
//
// Coach-mark overlay shown on first visit to each main tab. Rendered as a
// Dialog with a darkened scrim and a centered callout card containing an
// icon, the tip text, and a "Got it" button. Tap anywhere outside the card
// or on Got it to dismiss; flag is persisted so the tooltip never reappears
// (until Reset Tips is invoked from Settings).
//
// `ScreenTooltip` is the convenience entry point — one call per screen.
//
// Added in Phase 4 (Tester Feedback Implementation Plan).

package com.pgpony.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lightbulb
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

/**
 * Drop-in tooltip for any screen. Renders once ever, persists dismissal in
 * SharedPreferences. The `enabled` flag lets callers gate on screen-specific
 * state (e.g. show the Keyring tip only when the user has no keys yet).
 */
@Composable
fun ScreenTooltip(
    tooltipKey: String,
    message: String,
    enabled: Boolean = true
) {
    val tooltipState = rememberTooltipState()
    var dismissed by remember { mutableStateOf(false) }
    val shouldShow = !dismissed && enabled && tooltipState.shouldShow(tooltipKey)
    if (shouldShow) {
        Tooltip(
            message = message,
            onDismiss = {
                tooltipState.markShown(tooltipKey)
                dismissed = true
            }
        )
    }
}

@Composable
fun Tooltip(
    message: String,
    onDismiss: () -> Unit
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnBackPress = true,
            dismissOnClickOutside = true
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black.copy(alpha = 0.6f))
                .clickable(
                    indication = null,
                    interactionSource = remember { MutableInteractionSource() }
                ) { onDismiss() },
            contentAlignment = Alignment.Center
        ) {
            Card(
                modifier = Modifier
                    .padding(32.dp)
                    .clickable(
                        indication = null,
                        interactionSource = remember { MutableInteractionSource() }
                    ) {
                        // Swallow taps on the card itself so they don't bubble
                        // up to the scrim and dismiss prematurely.
                    },
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Filled.Lightbulb,
                            contentDescription = null,
                            tint = Color(0xFFFBBF24),
                            modifier = Modifier.size(28.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            "Tip",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        message,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(20.dp))
                    Button(
                        onClick = onDismiss,
                        modifier = Modifier.align(Alignment.End),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF8B5CF6)
                        )
                    ) {
                        Text("Got it")
                    }
                }
            }
        }
    }
}
