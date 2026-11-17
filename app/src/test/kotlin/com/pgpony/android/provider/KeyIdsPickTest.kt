// KeyIdsPickTest.kt
// PGPony Android 4.8.1: GET_KEY_IDS with no user ids opens the public key
// picker, as OpenKeychain does, so a client's "pick from a key app" gets a key.
// It answered success with no ids before. Opportunistic requests stay silent,
// and a request that names addresses takes the 4.7.0 path unchanged.

package com.pgpony.android.provider

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.TrustLevel
import com.pgpony.android.provider.RecipientReview.KeyIdsStep
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyIdsPickTest {

    private fun step(userIds: Int, opportunistic: Boolean = false, selection: Boolean = false, unresolved: Int = 0) =
        RecipientReview.keyIdsStep(userIds, opportunistic, selection, unresolved)

    @Test
    fun `no user ids opens the picker`() {
        assertEquals(KeyIdsStep.PICK, step(0))
    }

    @Test
    fun `no user ids with a selection answers with it`() {
        assertEquals(KeyIdsStep.ANSWER_SELECTION, step(0, selection = true))
    }

    @Test
    fun `an opportunistic request with no user ids stays silent`() {
        assertEquals(KeyIdsStep.ANSWER, step(0, opportunistic = true))
        assertEquals(KeyIdsStep.ANSWER, step(0, opportunistic = true, selection = true))
    }

    @Test
    fun `a request that names addresses behaves as in 4_7_0`() {
        for (userIds in 1..3) for (unresolved in 0..userIds) for (opp in listOf(false, true)) for (sel in listOf(false, true)) {
            val expected = when {
                opp -> KeyIdsStep.ANSWER
                sel -> KeyIdsStep.ANSWER_SELECTION
                RecipientReview.needsReview(unresolved, opp, sel) -> KeyIdsStep.REVIEW
                else -> KeyIdsStep.ANSWER
            }
            assertEquals("ids=$userIds unresolved=$unresolved opp=$opp sel=$sel", expected, step(userIds, opp, sel, unresolved))
        }
    }

    @Test
    fun `a request with no user ids never recalls earlier picks`() {
        assertFalse(RecipientReview.mayRecall(0, opportunistic = false))
        assertFalse(RecipientReview.mayRecall(2, opportunistic = true))
        assertTrue(RecipientReview.mayRecall(2, opportunistic = false))
        // And the memory itself keeps nothing for, and returns nothing to, an empty address list.
        val clock = 0L
        val memory = RecipientReviewMemory(ttlMs = 60_000L, now = { clock })
        memory.remember("app.carrierpony", emptyList(), longArrayOf(1L))
        assertNull(memory.recall("app.carrierpony", emptyList()))
        assertNull(memory.lastPicks("app.carrierpony"))
    }

    private fun key(fp: String, alg: KeyAlgorithm, trust: TrustLevel = TrustLevel.UNKNOWN, revoked: Boolean = false) =
        PGPKeyEntity(
            id = "id-$fp",
            fingerprint = fp,
            userID = "K $fp <k@example.org>",
            userName = "K",
            userEmail = "k@example.org",
            algorithm = alg,
            isKeyPair = false,
            trustLevel = trust,
            createdAt = 0L,
            expiresAt = null,
            isDefault = false,
            isRevoked = revoked
        )

    @Test
    fun `v6 and ML-KEM keys are pickable by their API key id`() {
        val v6 = key("1122334455667788" + "AA".repeat(24), KeyAlgorithm.V6_ED25519)
        val mldsa = key("99AABBCCDDEEFF00" + "BB".repeat(24), KeyAlgorithm.MLDSA65_ED25519_V6)
        val v4kem = key("CC".repeat(12) + "0102030405060708", KeyAlgorithm.MLKEM768_X25519_V4)
        val offered = RecipientReview.offeredKeys(listOf(v6, mldsa, v4kem), allowExpired = false, senderEmail = null)
        assertEquals(3, offered.size)
        val ids = RecipientReview.selectedKeyIds(offered, offered.map { it.fingerprint }.toSet())
        assertArrayEquals(
            longArrayOf(0x1122334455667788L, java.lang.Long.parseUnsignedLong("99AABBCCDDEEFF00", 16), 0x0102030405060708L).sortedArray(),
            ids.sortedArray()
        )
        // The re-run accepts every id the picker offered.
        val sel = RecipientReview.resolveSelected(ids, listOf(v6, mldsa, v4kem), allowExpired = false)
        assertTrue(sel.refused.isEmpty())
        assertEquals(3, sel.accepted.size)
    }

    @Test
    fun `the picker never offers what the re-run refuses`() {
        val ok = key("AA".repeat(12) + "1111111111111111", KeyAlgorithm.ED25519_CV25519)
        val dontUse = key("AA".repeat(12) + "2222222222222222", KeyAlgorithm.ED25519_CV25519, trust = TrustLevel.DONT_USE)
        val revoked = key("AA".repeat(12) + "3333333333333333", KeyAlgorithm.ED25519_CV25519, revoked = true)
        val all = listOf(ok, dontUse, revoked)
        val offered = RecipientReview.offeredKeys(all, allowExpired = false, senderEmail = null)
        assertEquals(listOf(ok), offered)
        val sel = RecipientReview.resolveSelected(longArrayOf(0x2222222222222222L, 0x3333333333333333L), all, allowExpired = false)
        assertEquals(2, sel.refused.size)
    }
}
