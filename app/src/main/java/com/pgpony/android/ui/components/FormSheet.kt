// FormSheet.kt
// PGPony Android, 4.8.0 RC10 (#109): bottom sheets that hold a form a swipe
// should not throw away.
//
// A tester lost the Generate Key form "half a dozen times" by sliding the
// sheet away while scrolling to the curves under Advanced. A sheet made with
// rememberFormSheetState() refuses to go to Hidden by a drag: a pull down on
// the handle or a fling on the content springs back, and scrolling the
// content works as before. Back still closes it (Material 3 1.3 hides the
// sheet for back without asking confirmValueChange), and so do the sheet's
// own Close and Cancel buttons. A tap on the scrim does not: Material 3 1.3
// asks confirmValueChange for that too, and cannot tell it from a drag.
// sheetGesturesEnabled, which would allow it, arrived in Material 3 1.4; the
// app's BOM (2024.12.01) has 1.3.

package com.pgpony.android.ui.components

import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.SheetState
import androidx.compose.material3.SheetValue
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember

/** A fully expanded sheet state that a drag cannot hide. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun rememberFormSheetState(): SheetState {
    // Remembered, so rememberModalBottomSheetState (keyed on it) keeps one state.
    val confirm = remember { { value: SheetValue -> value != SheetValue.Hidden } }
    return rememberModalBottomSheetState(skipPartiallyExpanded = true, confirmValueChange = confirm)
}
