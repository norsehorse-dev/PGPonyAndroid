// PairSkip.kt
// PGPony Android: whether a pairing RESULT means the other user chose Skip.
// Moved here from ui/pair/PairLedger.kt in 4.8.0 RC10 (move only, now public)
// so PGPony Desktop vendors the same list instead of keeping its own copy.

package com.pgpony.android.pair

import java.util.Locale

/**
 * Whether a RESULT error means the other user chose Skip. From 4.8.0 a RESULT can say so in its
 * "skipped" member ([PairResult.skipped]); apps before that send only the reason text, so this
 * matches the reason each PGPony sends, in every language it ships (Android pair_skipped_reason,
 * desktop d_pair_skipped_reason). Anything else is a failure. A new language adds its text here.
 */
object PairSkip {
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
        "상대방이 건너뜀",
        // 4.8.0 RC9: the Korean text Android actually ships, and Polish (item 4f).
        "상대 사용자가 건너뜀",
        "pominięte przez drugiego użytkownika"
    )

    private fun normalize(s: String) = s.trim().replace('’', '\'').lowercase(Locale.ROOT)

    fun isSkip(error: String?): Boolean = error != null && normalize(error) in KNOWN
}
