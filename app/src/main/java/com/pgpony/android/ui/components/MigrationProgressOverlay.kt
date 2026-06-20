// MigrationProgressOverlay.kt
// PGPony Android
//
// Full-screen blocking overlay shown on first launch after upgrade to
// v1.5.0 while SubkeyMigrationService populates the new pgp_subkeys
// table. Hidden once the migration state flips to Complete.
//
// Most users will see this for a fraction of a second (10 keys parses
// in well under 100ms on a modern device). The progress count exists
// because power users with 50+ keys on low-end hardware can hit a
// visible delay, and showing "Updating key 23 of 50…" is much less
// scary than a frozen launch screen.
//
// Added in Phase A1 (Subkey Model Refactor).

package com.pgpony.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.data.SubkeyMigrationService

/**
 * Render the migration progress UI for the given state. Caller wraps
 * this in their navigation switch — e.g.:
 *
 * ```
 * when (val ms = migrationState) {
 *     is SubkeyMigrationService.State.NotStarted,
 *     is SubkeyMigrationService.State.InProgress -> MigrationProgressOverlay(ms)
 *     else -> PGPonyMainScreen(...)
 * }
 * ```
 */
@Composable
fun MigrationProgressOverlay(
    state: SubkeyMigrationService.State,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = Icons.Outlined.VpnKey,
                contentDescription = null,
                modifier = Modifier.size(72.dp),
                tint = Color(0xFF8B5CF6)
            )

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = stringResource(R.string.migration_overlay_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = stringResource(R.string.migration_overlay_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(32.dp))

            when (state) {
                is SubkeyMigrationService.State.NotStarted -> {
                    CircularProgressIndicator(
                        color = Color(0xFF8B5CF6),
                        modifier = Modifier.size(40.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = stringResource(R.string.migration_overlay_starting),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                is SubkeyMigrationService.State.InProgress -> {
                    LinearProgressIndicator(
                        progress = { state.current.toFloat() / state.total.toFloat().coerceAtLeast(1f) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp),
                        color = Color(0xFF8B5CF6),
                        trackColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = stringResource(R.string.migration_overlay_progress_format, state.current, state.total),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                is SubkeyMigrationService.State.Complete -> {
                    // The parent should have routed past this overlay
                    // already. If we somehow render with Complete state,
                    // show a quiet "done" indicator rather than a stuck
                    // progress bar.
                    Text(
                        text = stringResource(R.string.migration_overlay_done),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                is SubkeyMigrationService.State.Failed -> {
                    Text(
                        text = stringResource(R.string.migration_overlay_error),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 8.dp)
                    )
                }
            }
        }
    }
}
