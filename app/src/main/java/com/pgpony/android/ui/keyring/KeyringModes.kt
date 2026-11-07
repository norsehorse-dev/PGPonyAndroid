// KeyringModes.kt
// PGPony Android 4.8.0 (4m, #101 follow-up): the Keyring's select mode and
// reorder mode as one small pure state, so the rules (the two never mix,
// Cancel puts the order back, Done saves it) are testable on the JVM.

package com.pgpony.android.ui.keyring

/**
 * 4.8.0 (4m): the manual Keyring order, a list of primary fingerprints.
 *
 * Pulled out of KeyringViewModel.moveManual so the drag-saves-at-once path
 * (Settings > Drag to reorder keys on) and reorder mode's draft move keys
 * the same way.
 */
internal object ManualOrder {

    /** The order a move starts from: the saved one, or, when nothing has been
     *  saved yet, the order on screen, so the first drag keeps what the user
     *  sees. */
    fun seed(saved: List<String>, displayed: List<String>): List<String> =
        saved.ifEmpty { displayed }

    /**
     * [order] with [fromFp] moved into [toFp]'s slot, or null when there is
     * nothing to move (the same key). A fingerprint missing from [order] is
     * appended first, as moveManual always did.
     */
    fun move(order: List<String>, fromFp: String, toFp: String): List<String>? {
        if (fromFp == toFp) return null
        val next = order.toMutableList()
        if (!next.contains(fromFp)) next.add(fromFp)
        if (!next.contains(toFp)) next.add(toFp)
        // Both indices are taken before mutating. add(toIndex, removeAt(fromIndex))
        // evaluates removeAt first, so the pre-removal target index lands the
        // item correctly whether dragging up or down. (Recomputing the target
        // after removal was the bug that once broke downward drags.)
        val fromIndex = next.indexOf(fromFp)
        val toIndex = next.indexOf(toFp)
        next.add(toIndex, next.removeAt(fromIndex))
        return next
    }
}

/**
 * 4.8.0 (4m): which mode the Keyring list is in.
 *
 * [selection] is non-null in select mode (4.7.0 item 63, #93): the ticked
 * fingerprints. [reorderDraft] is non-null in reorder mode: the working order,
 * which nothing saves until [finishReorder]. At most one of the two is set;
 * entering either mode leaves the other, so a drag can never land while keys
 * are ticked and a tick can never land in a draft order.
 */
internal data class KeyringModes(
    val selection: List<String>? = null,
    val reorderDraft: List<String>? = null,
    /** True once a key has moved in the draft, so Done with no move saves
     *  nothing (and does not switch the sort to Custom order). */
    val reorderChanged: Boolean = false
) {
    val selecting: Boolean get() = selection != null
    val reordering: Boolean get() = reorderDraft != null

    /** Select mode, with [first] ticked (a long press) or nothing (the menu). */
    fun startSelect(first: String? = null): KeyringModes =
        KeyringModes(selection = listOfNotNull(first))

    /** Ticks or unticks [fp]; outside select mode nothing changes. */
    fun toggle(fp: String): KeyringModes {
        val cur = selection ?: return this
        return copy(selection = if (fp in cur) cur - fp else cur + fp)
    }

    fun selectAll(fingerprints: List<String>): KeyringModes =
        if (selecting) copy(selection = fingerprints) else this

    fun endSelect(): KeyringModes = copy(selection = null)

    /** Reorder mode, starting from [order] (every key, in Custom order). */
    fun startReorder(order: List<String>): KeyringModes =
        KeyringModes(reorderDraft = order)

    /** Moves a key in the draft; outside reorder mode nothing changes. */
    fun move(fromFp: String, toFp: String): KeyringModes {
        val draft = reorderDraft ?: return this
        val moved = ManualOrder.move(draft, fromFp, toFp) ?: return this
        return copy(reorderDraft = moved, reorderChanged = true)
    }

    /** Cancel or Back: the draft is dropped, so the saved order stands. */
    fun cancelReorder(): KeyringModes = copy(reorderDraft = null, reorderChanged = false)

    /** Done: leaves reorder mode and returns the order to save, or null when
     *  no key moved. */
    fun finishReorder(): Pair<KeyringModes, List<String>?> =
        cancelReorder() to reorderDraft?.takeIf { reorderChanged }
}
