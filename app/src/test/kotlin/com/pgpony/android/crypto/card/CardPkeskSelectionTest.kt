// CardPkeskSelectionTest.kt
// PGPony Android, 4.7.2 RC6
//
// Key IDs are the public ones from issue #108: a message with three PKESKs,
// in the order gpg wrote them, decrypted on a card whose decryption slot
// holds the third.

package com.pgpony.android.crypto.card

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CardPkeskSelectionTest {

    private fun id(hex: String) = hex.toULong(16).toLong()

    private val auth = id("2AE019246C5C0CB6")
    private val otherCardAuth = id("B9E473DF106CBD8A")
    private val enc = id("03C78DF0C62F7C14")
    private val ring = setOf(auth, otherCardAuth, enc)
    private val inRing: (Long) -> Boolean = { it in ring }

    @Test
    fun keyIdIsLastEightBytesOfFingerprint() {
        assertEquals(id("A204F7146819140A"), CardPkeskSelection.v4KeyId("6C525E39CC819B93F4E94B95A204F7146819140A"))
        assertEquals(id("A204F7146819140A"), CardPkeskSelection.v4KeyId("6C52 5E39 CC81 9B93 F4E9  4B95 A204 F714 6819 140A"))
    }

    @Test
    fun keyIdRejectsEmptyAndOddLengths() {
        assertNull(CardPkeskSelection.v4KeyId(null))
        assertNull(CardPkeskSelection.v4KeyId(""))
        assertNull(CardPkeskSelection.v4KeyId("A204F7146819140A"))
        assertNull(CardPkeskSelection.v4KeyId("6C525E39CC819B93F4E94B95A204F7146819140A00"))
        assertNull(CardPkeskSelection.v4KeyId("6C525E39CC819B93F4E94B95A204F7146819140G"))
    }

    @Test
    fun keyIdHandlesHighBit() {
        assertEquals(id("B9E473DF106CBD8A"), CardPkeskSelection.v4KeyId("000000000000000000000000B9E473DF106CBD8A"))
    }

    @Test
    fun slotKeyWinsOverEarlierRingMatches() {
        val ids = listOf(auth, otherCardAuth, enc)
        assertEquals(2, CardPkeskSelection.pickAddressed(ids, enc, inRing))
    }

    @Test
    fun noSlotKeyFallsBackToFirstRingMatch() {
        val ids = listOf(auth, otherCardAuth, enc)
        assertEquals(0, CardPkeskSelection.pickAddressed(ids, null, inRing))
    }

    @Test
    fun slotKeyNotAddressedFallsBackToFirstRingMatch() {
        val ids = listOf(auth, otherCardAuth, enc)
        assertEquals(0, CardPkeskSelection.pickAddressed(ids, id("BDC5DA4245EFAC3D"), inRing))
    }

    @Test
    fun slotKeyAddressedButNotInRingIsNotChosen() {
        val ids = listOf(id("1111111111111111"), enc)
        assertEquals(1, CardPkeskSelection.pickAddressed(ids, id("1111111111111111"), inRing))
    }

    @Test
    fun wildcardIsNeverChosen() {
        assertEquals(-1, CardPkeskSelection.pickAddressed(listOf(0L), 0L) { true })
        assertEquals(1, CardPkeskSelection.pickAddressed(listOf(0L, enc), null, inRing))
    }

    @Test
    fun nothingInRing() {
        assertEquals(-1, CardPkeskSelection.pickAddressed(listOf(id("1111111111111111")), enc, inRing))
    }
}
