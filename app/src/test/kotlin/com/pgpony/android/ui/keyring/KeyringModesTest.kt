// KeyringModesTest.kt
// PGPony Android 4.8.0 (4m, #101 follow-up): reorder mode on the Keyring.
// Enter, move, Cancel puts the order back, Done hands over the order to
// save, and select mode and reorder mode never mix.

package com.pgpony.android.ui.keyring

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyringModesTest {

    private val order = listOf("A", "B", "C", "D")

    // ── ManualOrder ────────────────────────────────────────────────────

    @Test
    fun `move works downward and upward`() {
        assertEquals(listOf("B", "C", "A", "D"), ManualOrder.move(order, "A", "C"))
        assertEquals(listOf("D", "A", "B", "C"), ManualOrder.move(order, "D", "A"))
        assertEquals(listOf("A", "C", "B", "D"), ManualOrder.move(order, "B", "C"))
    }

    @Test
    fun `move onto itself is nothing to save`() {
        assertNull(ManualOrder.move(order, "B", "B"))
    }

    @Test
    fun `move appends a fingerprint the order does not have yet`() {
        // A key added after the order was saved sits at the end until moved.
        assertEquals(listOf("A", "E", "B", "C", "D"), ManualOrder.move(order, "E", "B"))
    }

    @Test
    fun `seed takes the saved order and falls back to the one on screen`() {
        assertEquals(order, ManualOrder.seed(order, listOf("D", "C")))
        assertEquals(listOf("D", "C"), ManualOrder.seed(emptyList(), listOf("D", "C")))
    }

    // ── Reorder mode ───────────────────────────────────────────────────

    @Test
    fun `entering reorder mode starts a draft from the order on screen`() {
        val m = KeyringModes().startReorder(order)
        assertTrue(m.reordering)
        assertFalse(m.selecting)
        assertEquals(order, m.reorderDraft)
        assertFalse(m.reorderChanged)
    }

    @Test
    fun `a move changes the draft only`() {
        val m = KeyringModes().startReorder(order).move("A", "C")
        assertEquals(listOf("B", "C", "A", "D"), m.reorderDraft)
        assertTrue(m.reorderChanged)
        // The list the draft started from is untouched.
        assertEquals(listOf("A", "B", "C", "D"), order)
    }

    @Test
    fun `cancel drops the draft so the saved order stands`() {
        val m = KeyringModes().startReorder(order).move("A", "D").move("B", "A").cancelReorder()
        assertFalse(m.reordering)
        assertNull(m.reorderDraft)
        assertFalse(m.reorderChanged)
        // Done after Cancel has nothing to save.
        assertNull(m.finishReorder().second)
    }

    @Test
    fun `done hands over the moved order and leaves the mode`() {
        val (after, toSave) = KeyringModes().startReorder(order).move("D", "A").move("C", "A").finishReorder()
        // D to A's slot gives D A B C; then C to A's slot gives D C A B.
        assertEquals(listOf("D", "C", "A", "B"), toSave)
        assertFalse(after.reordering)
        assertFalse(after.selecting)
    }

    @Test
    fun `done with no move saves nothing`() {
        val (after, toSave) = KeyringModes().startReorder(order).move("B", "B").finishReorder()
        assertNull(toSave)
        assertFalse(after.reordering)
    }

    @Test
    fun `a move outside reorder mode changes nothing`() {
        val idle = KeyringModes()
        assertEquals(idle, idle.move("A", "C"))
        val selecting = KeyringModes().startSelect("A")
        assertEquals(selecting, selecting.move("A", "C"))
    }

    // ── Select mode and reorder mode do not mix ───────────────────────

    @Test
    fun `entering reorder mode leaves select mode`() {
        val m = KeyringModes().startSelect("A").toggle("B").startReorder(order)
        assertTrue(m.reordering)
        assertNull(m.selection)
    }

    @Test
    fun `entering select mode leaves reorder mode and drops its draft`() {
        val m = KeyringModes().startReorder(order).move("A", "C").startSelect("B")
        assertTrue(m.selecting)
        assertEquals(listOf("B"), m.selection)
        assertFalse(m.reordering)
        assertNull(m.finishReorder().second)
    }

    @Test
    fun `select mode ticks, unticks, selects all and ends`() {
        var m = KeyringModes().startSelect()
        assertEquals(emptyList<String>(), m.selection)
        m = m.toggle("A").toggle("B").toggle("A")
        assertEquals(listOf("B"), m.selection)
        m = m.selectAll(order)
        assertEquals(order, m.selection)
        m = m.endSelect()
        assertFalse(m.selecting)
        // Ticking outside select mode does not start it.
        assertEquals(m, m.toggle("A"))
        assertEquals(m, m.selectAll(order))
    }
}
