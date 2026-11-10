// PairSkipTest.kt
// PGPony Android: the pairing skip reasons and the RESULT "skipped" member. The reason cases moved
// here from ui/pair/PairLedgerTest in 4.8.0 RC10, with PairSkip, so PGPony Desktop runs them too.

package com.pgpony.android.pair

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PairSkipTest {

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

    @Test
    fun skippedMember_isWrittenOnlyWhenTrue() {
        assertEquals("""{"id":1,"ok":true,"error":null}""", PairResult(1, true).toJson().toString())
        val skip = PairResult(2, false, "skipped by the other user", skipped = true)
        assertEquals("""{"id":2,"ok":false,"error":"skipped by the other user","skipped":true}""", skip.toJson().toString())
        assertEquals(skip, PairResult.fromJson(skip.toJson()))
    }

    @Test
    fun skippedMember_missingOrOddReadsAsFalse() {
        fun read(s: String) = PairResult.fromJson(Json.parseToJsonElement(s).jsonObject)
        assertFalse(read("""{"id":3,"ok":false,"error":"x"}""").skipped)
        assertFalse(read("""{"id":3,"ok":false,"error":"x","skipped":"yes"}""").skipped)
        assertFalse(read("""{"id":3,"ok":false,"error":"x","skipped":{}}""").skipped)
        assertTrue(read("""{"id":3,"ok":false,"error":"x","skipped":true}""").skipped)
    }
}
