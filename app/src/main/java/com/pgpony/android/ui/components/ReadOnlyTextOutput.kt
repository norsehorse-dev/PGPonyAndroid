// ReadOnlyTextOutput.kt
// PGPony Android — 4.1.0, issue #10 (AraafRoyall)
//
// Renders a block of produced text — a decrypted message, an armored
// ciphertext — cheaply, and keeps a long one from being composed until the
// user asks for it.
//
// WHAT THIS REPLACES, AND WHY IT WAS SLOW
//
// Both output blocks used to be a read-only OutlinedTextField holding the
// whole string. OutlinedTextField wraps BasicTextField, which builds full
// EDITING state for its value: an annotated string, a text layout, and the
// selection and cursor machinery. `maxLines` clips what is drawn; it does not
// stop the value being laid out or held. So a long message paid the full cost
// on first composition, and paid again on every recomposition of the scrolling
// tab it lived in. That is the second half of issue #10 — the first half was a
// keyring walk on the main thread, fixed separately in the Decrypt tab's
// recipient detection.
//
// A plain Text has no editing machinery at all, so the same content costs a
// fraction of it. Wrapping it in SelectionContainer keeps the text
// selectable, which is the only thing an editable field was really buying —
// but only when the whole string is on screen. See the truncated branch below:
// selecting inside a preview would silently yield a partial copy.
//
// WHY THERE IS STILL A LIMIT
//
// Text is cheaper, not free: it still lays out everything it is given. So
// anything past [INLINE_PREVIEW_CHARS] is held back behind an explicit
// "open" action. That is the reporter's own design — a compact result, with
// the full body composed only when asked for — and it is the only version
// that stays fast as messages grow. PGPony already does this shape for
// messages with attachments (StructuredDecryptionResultScreen); this brings
// plain text in line with it.

package com.pgpony.android.ui.components

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.OpenInFull
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.pgpony.android.R

/**
 * How much text is composed inline before the rest is held back.
 *
 * Chosen so that essentially every ordinary message shows in full — a long
 * email body is a few thousand characters — while the pathological case that
 * prompted the report never reaches first paint. The exact number matters
 * less than having one: the cost of laying out text climbs smoothly, and the
 * point is to stop it climbing without the user having asked.
 */
private const val INLINE_PREVIEW_CHARS = 4_000

/**
 * A bordered, scrollable, selectable block of read-only text.
 *
 * [text] is shown in full when short. When it exceeds the inline budget, the
 * beginning is shown with a note and a button that opens the whole thing in a
 * dialog. [onCopy] always receives the COMPLETE text, never the preview —
 * copying a truncated message would be a data-loss bug wearing a performance
 * fix's clothing.
 */
@Composable
fun ReadOnlyTextOutput(
    text: String,
    dialogTitle: String,
    onCopy: (String) -> Unit,
    modifier: Modifier = Modifier,
    textStyle: TextStyle = MaterialTheme.typography.bodyMedium,
    minHeight: Dp = 100.dp,
    maxHeight: Dp = 260.dp
) {
    var showFull by remember(text) { mutableStateOf(false) }
    val truncated = text.length > INLINE_PREVIEW_CHARS
    // remember(text) so a new message re-slices once rather than on every
    // recomposition of the surrounding tab.
    val preview = remember(text) {
        if (truncated) text.take(INLINE_PREVIEW_CHARS) else text
    }

    Column(modifier = modifier) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = minHeight, max = maxHeight)
                .border(
                    width = 1.dp,
                    color = MaterialTheme.colorScheme.outline,
                    shape = RoundedCornerShape(4.dp)
                )
                // Bounded height, so this nested vertical scroll sits inside
                // the tab's own scrolling column without an infinite-constraint
                // conflict — the same shape the text field had.
                .verticalScroll(rememberScrollState())
                .padding(12.dp)
        ) {
            // Selection is deliberately withheld from a TRUNCATED preview.
            //
            // A SelectionContainer here would let "Select all -> Copy" hand the
            // user the first INLINE_PREVIEW_CHARS characters and nothing else,
            // with no indication anything was missing. For armored ciphertext
            // that is silent corruption: a partial PGP MESSAGE block pastes and
            // looks plausible, then fails to decrypt somewhere else entirely.
            // Any bundle with an attachment is comfortably over the cap, so
            // this was not a corner case.
            //
            // The full text stays reachable and selectable in FullTextDialog,
            // and both Copy affordances take the complete string.
            if (truncated) {
                Text(text = preview, style = textStyle)
            } else {
                SelectionContainer {
                    Text(text = preview, style = textStyle)
                }
            }
        }

        if (truncated) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                stringResource(R.string.output_truncated_notice, INLINE_PREVIEW_CHARS, text.length),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = { showFull = true },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    Icons.Filled.OpenInFull,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.output_open_full))
            }
        }
    }

    if (showFull) {
        FullTextDialog(
            title = dialogTitle,
            text = text,
            onCopy = { onCopy(text) },
            onDismiss = { showFull = false }
        )
    }
}

/**
 * The whole text, composed only once the user has asked for it.
 *
 * 4.7.1 (Play ANR, two devices on 4.6.4): this used to be one Text holding the
 * entire string inside a scrolling Box. Opening a long message laid out every
 * line of it on the main thread in one measure pass, which a slow phone could
 * not finish in time. The text is now split into blocks at line breaks
 * ([TextBlocks]) and shown in a lazy list, so only the blocks on screen are
 * laid out. Each block is selectable on its own; a selection cannot span two
 * blocks, so Copy (always the complete text) stays the way to take all of it.
 *
 * A plain Dialog rather than AlertDialog, so the list's height is set here and
 * nothing asks the lazy list for intrinsic measurements.
 */
@Composable
private fun FullTextDialog(
    title: String,
    text: String,
    onCopy: () -> Unit,
    onDismiss: () -> Unit
) {
    val blocks = remember(text) { TextBlocks.split(text) }
    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = MaterialTheme.shapes.extraLarge,
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
            tonalElevation = 6.dp
        ) {
            Column(modifier = Modifier.padding(24.dp)) {
                Text(title, style = MaterialTheme.typography.headlineSmall)
                Spacer(modifier = Modifier.height(16.dp))
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f, fill = false)
                        .heightIn(max = 420.dp)
                ) {
                    items(blocks.size) { i ->
                        SelectionContainer {
                            Text(text = blocks[i], style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onDismiss) {
                        Text(stringResource(R.string.common_button_close))
                    }
                    TextButton(onClick = onCopy) {
                        Text(stringResource(R.string.common_button_copy))
                    }
                }
            }
        }
    }
}

/**
 * Splits a long text into blocks for [FullTextDialog]. Pure, so it is tested
 * on the JVM. Blocks end at a line break where one falls within [maxChars];
 * a single line longer than that (a decrypted file with no line breaks) is cut
 * every [maxChars] characters. Joining the blocks gives back the text exactly.
 */
internal object TextBlocks {
    const val MAX_CHARS = 2_000

    fun split(text: String, maxChars: Int = MAX_CHARS): List<String> {
        require(maxChars > 0)
        if (text.length <= maxChars) return listOf(text)
        val out = ArrayList<String>(text.length / maxChars + 1)
        var start = 0
        while (start < text.length) {
            val limit = minOf(start + maxChars, text.length)
            var end = limit
            if (limit < text.length) {
                val nl = text.lastIndexOf('\n', limit - 1)
                if (nl >= start) end = nl + 1
            }
            out.add(text.substring(start, end))
            start = end
        }
        return out
    }
}
