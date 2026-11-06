// KeyServerCheckTest.kt
// PGPony Android 4.8.0 (#90): Check on Key Details asks the lookup servers in
// the user's order, stops at the first that has the key, skips a server that
// cannot be reached, and fails only when every server failed.

package com.pgpony.android.keyserver

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class KeyServerCheckTest {

    private val armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----"

    /** A fake fetcher: a name maps to the key, to nothing (null), or to a failure. */
    private class Fake(private val answers: Map<String, Any?>) {
        val asked = mutableListOf<String>()
        suspend fun fetch(server: String): String? {
            asked += server
            return when (val a = answers[server]) {
                is Exception -> throw a
                else -> a as String?
            }
        }
    }

    private fun check(servers: List<String>, fake: Fake) =
        runBlocking { KeyServerCheck.askInOrder(servers, { it }) { fake.fetch(it) } }

    @Test
    fun `the first server that has the key wins and the rest are not asked`() {
        val fake = Fake(mapOf("a" to null, "b" to armored, "c" to armored))
        val outcome = check(listOf("a", "b", "c"), fake)
        assertEquals(KeyServerCheck.Outcome.Found("b"), outcome)
        assertEquals(listOf("a", "b"), fake.asked)
    }

    @Test
    fun `a server that cannot be reached is skipped`() {
        val fake = Fake(mapOf("a" to IOException("unreachable"), "b" to armored))
        assertEquals(KeyServerCheck.Outcome.Found("b"), check(listOf("a", "b"), fake))
        assertEquals(listOf("a", "b"), fake.asked)
    }

    @Test
    fun `none has the key names the servers that answered`() {
        val fake = Fake(mapOf("a" to null, "b" to IOException("down"), "c" to ""))
        val outcome = check(listOf("a", "b", "c"), fake)
        assertEquals(KeyServerCheck.Outcome.NotFound(listOf("a", "c")), outcome)
        assertEquals(listOf("a", "b", "c"), fake.asked)
    }

    @Test
    fun `every server failing is an error, not a miss`() {
        val last = IOException("timeout")
        val fake = Fake(mapOf("a" to IOException("dns"), "b" to last))
        val outcome = check(listOf("a", "b"), fake)
        assertTrue(outcome is KeyServerCheck.Outcome.Failed)
        assertSame(last, (outcome as KeyServerCheck.Outcome.Failed).error)
    }

    private fun server(id: String, lookup: Boolean) = KeyServer(
        id = id, label = id, baseUrl = "https://$id", isFirstParty = false,
        lookupEnabled = lookup, publishEnabled = true, acceptsAllKeyTypes = true
    )

    @Test
    fun `the servers asked are the lookup ones in the user's order`() {
        val directory = listOf(
            server("keys.pgpony.app", true),
            server("off.example", false),
            server("keys.openpgp.org", true),
            server("mine.example", true)
        )
        assertEquals(
            listOf("keys.pgpony.app", "keys.openpgp.org", "mine.example"),
            KeyServerCheck.serversToAsk(directory).map { it.id }
        )
    }

    @Test
    fun `with no lookup server keys openpgp org is asked as before`() {
        val asked = KeyServerCheck.serversToAsk(listOf(server("off.example", false)))
        assertEquals(listOf(KeyServerDirectory.ID_OPENPGP), asked.map { it.id })
    }
}
