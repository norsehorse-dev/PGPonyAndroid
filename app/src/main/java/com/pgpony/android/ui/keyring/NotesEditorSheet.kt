// NotesEditorSheet.kt
// PGPony Android — Phase A4b
//
// Modal bottom sheet for editing the freeform notes attached to a
// PGPKeyEntity. Replaces the A4a "Coming in next update" stub for the
// Add / Edit notes action.
//
// Notes are stored on PGPKeyEntity.notes and surfaced read-only in the
// detail screen's NotesSection. They're user-private memo text — never
// included in exported / shared key material.
//
// UX: large TextField with a 500-char counter, Cancel + Save buttons.
// Save writes via the supplied callback and dismisses; Cancel just
// dismisses without writing. Empty save deletes the existing notes
// (passing null to the callback).

package com.pgpony.android.ui.keyring

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.R

private const val NOTES_LIMIT = 500

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotesEditorSheet(
    initialNotes: String?,
    onSave: (String?) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    // Local state — the parent doesn't see in-progress edits, only the
    // final result when Save is tapped. This keeps the sheet self-
    // contained and means Cancel discards correctly.
    var text by remember { mutableStateOf(initialNotes.orEmpty()) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = if (initialNotes.isNullOrBlank()) stringResource(R.string.notes_editor_title_add) else stringResource(R.string.notes_editor_title_edit),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Text(
stringResource(R.string.notes_editor_explainer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            OutlinedTextField(
                value = text,
                onValueChange = {
                    // Enforce hard cap rather than just rendering a warning —
                    // simpler for both implementation and user mental model.
                    if (it.length <= NOTES_LIMIT) text = it
                },
                placeholder = { Text(stringResource(R.string.notes_editor_placeholder)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 120.dp),
                maxLines = 8
            )
            Text(
                text = "${text.length} / $NOTES_LIMIT",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.fillMaxWidth(),
                textAlign = androidx.compose.ui.text.style.TextAlign.End
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f)
                ) {
                    Text(stringResource(R.string.common_button_cancel))
                }
                Button(
                    onClick = {
                        // Empty text becomes null so the DB column is cleared
                        // rather than storing an empty string — matches iOS
                        // PGPKeyModel.notes optional semantics.
                        onSave(text.trim().ifBlank { null })
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Save")
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}
