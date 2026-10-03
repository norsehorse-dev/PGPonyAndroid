// PairLedger.kt
// PGPony Android 4.6.3: what a pairing session moved, item by item. The
// session screen shows a row per item (sent or received) with its outcome,
// and the summary at the end counts them. Plain state with no Android in it,
// so it is unit tested.

package com.pgpony.android.ui.pair

import com.pgpony.android.pair.PairItem
import java.util.Locale

internal enum class PairDirection { SENT, RECEIVED }

internal enum class PairOutcome {
    /** Sent, and waiting for the other side's Add or Skip. */
    WAITING,
    ADDED,
    SKIPPED,
    /** Left out when the other side answered the offer. */
    DECLINED,
    FAILED,
    /** The session ended before the other side answered. */
    NO_ANSWER
}

internal data class PairRow(
    val id: Int,
    val direction: PairDirection,
    val kind: String,
    val name: String,
    /** The offered fingerprint for a sent key, the one read from the bytes for a received key. */
    val fingerprint: String?,
    val outcome: PairOutcome,
    /** The import summary for a received item, or why an item failed. */
    val detail: String? = null
) {
    val isBackup: Boolean get() = kind == PairItem.BACKUP
}

internal data class PairTally(
    val sent: Int,
    val received: Int,
    val skipped: Int,
    val failed: Int,
    val unanswered: Int
)

internal object PairLedger {

    /** The other side answered an offer: accepted items wait for a result, the rest were declined. */
    fun offered(rows: List<PairRow>, items: List<PairItem>, accepted: Collection<Int>): List<PairRow> =
        rows + items.map { item ->
            PairRow(
                id = item.id,
                direction = PairDirection.SENT,
                kind = item.kind,
                name = item.name,
                fingerprint = item.fingerprint?.takeIf { item.kind != PairItem.BACKUP },
                outcome = if (item.id in accepted) PairOutcome.WAITING else PairOutcome.DECLINED
            )
        }

    /**
     * A RESULT for a sent item. Returns the new rows and the row it settled, or null when no
     * sent item with that id is still waiting.
     */
    fun answered(rows: List<PairRow>, id: Int, ok: Boolean, error: String?): Pair<List<PairRow>, PairRow?> {
        val i = rows.indexOfLast { it.direction == PairDirection.SENT && it.id == id && it.outcome == PairOutcome.WAITING }
        if (i < 0) return rows to null
        val settled = rows[i].copy(
            outcome = when {
                ok -> PairOutcome.ADDED
                PairSkip.isSkip(error) -> PairOutcome.SKIPPED
                else -> PairOutcome.FAILED
            },
            detail = if (ok) null else error?.takeIf { it.isNotBlank() }
        )
        return rows.toMutableList().also { it[i] = settled } to settled
    }

    /** The session ended: anything still waiting got no answer. */
    fun closed(rows: List<PairRow>): List<PairRow> =
        rows.map { if (it.outcome == PairOutcome.WAITING) it.copy(outcome = PairOutcome.NO_ANSWER) else it }

    fun tally(rows: List<PairRow>) = PairTally(
        sent = rows.count { it.direction == PairDirection.SENT && it.outcome == PairOutcome.ADDED },
        received = rows.count { it.direction == PairDirection.RECEIVED && it.outcome == PairOutcome.ADDED },
        skipped = rows.count { it.outcome == PairOutcome.SKIPPED || it.outcome == PairOutcome.DECLINED },
        failed = rows.count { it.outcome == PairOutcome.FAILED },
        unanswered = rows.count { it.outcome == PairOutcome.NO_ANSWER || it.outcome == PairOutcome.WAITING }
    )
}

/**
 * Whether a RESULT error means the other user chose Skip. Protocol v1 has no flag for it, so this
 * matches the reason each PGPony sends, in every language it ships (Android pair_skipped_reason,
 * desktop d_pair_skipped_reason). Anything else is a failure.
 */
internal object PairSkip {
    private val KNOWN = setOf(
        "skipped by the other user",
        "von der anderen person übersprungen",
        "omitido por la otra persona",
        "ignoré par l'autre personne",
        "pulado pela outra pessoa",
        "ignorado pela outra pessoa",
        "пропущено другим пользователем",
        "пропущено іншим користувачем",
        "diğer kullanıcı tarafından atlandı",
        "相手の利用者がスキップしました",
        "相手のユーザーがスキップしました",
        "对方已跳过",
        "已被对方跳过",
        "상대방이 건너뜀"
    )

    private fun normalize(s: String) = s.trim().replace('’', '\'').lowercase(Locale.ROOT)

    fun isSkip(error: String?): Boolean = error != null && normalize(error) in KNOWN
}
