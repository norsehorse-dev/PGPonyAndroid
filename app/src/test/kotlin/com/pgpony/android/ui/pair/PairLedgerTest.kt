// PairLedgerTest.kt
// PGPony Android 4.6.3: the per-item outcomes the pairing screen shows and
// the counts at the end, including telling a Skip from a failure by the
// reason either app sends.

package com.pgpony.android.ui.pair

import com.pgpony.android.pair.PairItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairLedgerTest {

    private val keyPair = PairItem(1, PairItem.KEY_PAIR, "Alice", "AABBCCDD", 100)
    private val publicKey = PairItem(2, PairItem.PUBLIC_KEY, "Bob", "11223344", 50)
    private val backup = PairItem(3, PairItem.BACKUP, "Backup", null, 900)

    @Test
    fun anAnsweredOffer_waitsForAcceptedAndDeclinesTheRest() {
        val rows = PairLedger.offered(emptyList(), listOf(keyPair, publicKey, backup), listOf(1, 3))
        assertEquals(listOf(PairOutcome.WAITING, PairOutcome.DECLINED, PairOutcome.WAITING), rows.map { it.outcome })
        assertTrue(rows.all { it.direction == PairDirection.SENT })
        assertNull(rows[2].fingerprint)
    }

    @Test
    fun results_settleTheWaitingRow() {
        var rows = PairLedger.offered(emptyList(), listOf(keyPair, publicKey, backup), listOf(1, 2, 3))
        val (afterOk, ok) = PairLedger.answered(rows, 1, true, null)
        assertEquals(PairOutcome.ADDED, ok!!.outcome)
        rows = afterOk
        val (afterSkip, skip) = PairLedger.answered(rows, 2, false, "skipped by the other user")
        assertEquals(PairOutcome.SKIPPED, skip!!.outcome)
        rows = afterSkip
        val (afterFail, fail) = PairLedger.answered(rows, 3, false, "Could not import Backup.")
        assertEquals(PairOutcome.FAILED, fail!!.outcome)
        assertEquals("Could not import Backup.", fail.detail)
        rows = afterFail
        // A second RESULT for a settled id changes nothing.
        val (same, none) = PairLedger.answered(rows, 1, false, "late")
        assertNull(none)
        assertEquals(rows, same)
    }

    @Test
    fun closing_marksWhatIsStillWaiting() {
        val rows = PairLedger.offered(emptyList(), listOf(keyPair, publicKey), listOf(1, 2))
        val (answered, _) = PairLedger.answered(rows, 1, true, null)
        val closed = PairLedger.closed(answered)
        assertEquals(listOf(PairOutcome.ADDED, PairOutcome.NO_ANSWER), closed.map { it.outcome })
    }

    @Test
    fun theTally_countsAddedEachWayAndFoldsDeclinedIntoSkipped() {
        val sent = PairLedger.offered(emptyList(), listOf(keyPair, publicKey, backup), listOf(1, 3))
        val (r1, _) = PairLedger.answered(sent, 1, true, null)
        val (r2, _) = PairLedger.answered(r1, 3, false, "broken")
        val got = r2 + PairRow(7, PairDirection.RECEIVED, PairItem.PUBLIC_KEY, "Carol", "FF", PairOutcome.ADDED) +
            PairRow(8, PairDirection.RECEIVED, PairItem.PUBLIC_KEY, "Dave", "EE", PairOutcome.SKIPPED)
        assertEquals(PairTally(sent = 1, received = 1, skipped = 2, failed = 1, unanswered = 0), PairLedger.tally(got))
    }

    @Test
    fun skipReasons_fromEitherAppInEveryLanguage() {
        listOf(
            "skipped by the other user",
            " Skipped by the other user ",
            "ignoré par l’autre personne",
            "ignoré par l'autre personne",
            "pulado pela outra pessoa",
            "ignorado pela outra pessoa",
            "相手の利用者がスキップしました",
            "相手のユーザーがスキップしました",
            "对方已跳过",
            "已被对方跳过",
            "diğer kullanıcı tarafından atlandı"
        ).forEach { assertTrue(it, PairSkip.isSkip(it)) }
        assertFalse(PairSkip.isSkip(null))
        assertFalse(PairSkip.isSkip(""))
        assertFalse(PairSkip.isSkip("Could not import Alice."))
    }
}
