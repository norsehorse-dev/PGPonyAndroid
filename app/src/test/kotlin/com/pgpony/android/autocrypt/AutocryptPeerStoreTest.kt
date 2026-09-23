// AutocryptPeerStoreTest.kt
// PGPony Android — 4.0.0 Phase 4 (Autocrypt)
//
// Pure-JVM tests for the Autocrypt peer-state machine: the timestamp
// update rules and the encryption recommendation. Key import is faked
// (the real one needs a live keyring); the DAO is an in-memory fake.

package com.pgpony.android.autocrypt

import com.pgpony.android.data.AutocryptPeerDao
import com.pgpony.android.data.AutocryptPeerEntity
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

private class FakeDao : AutocryptPeerDao {
    val map = LinkedHashMap<String, AutocryptPeerEntity>()
    override suspend fun get(id: String) = map[id]
    override suspend fun upsert(peer: AutocryptPeerEntity) { map[peer.identifier] = peer }
    override suspend fun getAll() = map.values.sortedByDescending { it.lastSeen }
    override suspend fun delete(id: String) { map.remove(id) }
    override suspend fun clear() { map.clear() }
}

class AutocryptPeerStoreTest {

    private val DAY = 24L * 60 * 60 * 1000
    private val importer = AutocryptKeyImporter { _, _ -> "IMPORTEDFP" }

    private fun store(dao: FakeDao) = AutocryptPeerStore(dao, importer)

    // ── recommendation ───────────────────────────────────────────────

    @Test fun no_peer_is_discourage() = runBlocking {
        assertEquals(AutocryptRecommendation.DISCOURAGE, store(FakeDao()).recommendation("a@b.com"))
    }

    @Test fun fresh_key_not_mutual_is_available() = runBlocking {
        val dao = FakeDao()
        val t = 1_000_000L
        dao.upsert(AutocryptPeerEntity("a@b.com", lastSeen = t, autocryptTimestamp = t,
            autocryptKeyFingerprint = "FP", isMutual = false))
        assertEquals(AutocryptRecommendation.AVAILABLE, store(dao).recommendation("a@b.com"))
    }

    @Test fun fresh_key_mutual_is_mutual() = runBlocking {
        val dao = FakeDao()
        val t = 1_000_000L
        dao.upsert(AutocryptPeerEntity("a@b.com", lastSeen = t, autocryptTimestamp = t,
            autocryptKeyFingerprint = "FP", isMutual = true))
        assertEquals(AutocryptRecommendation.MUTUAL, store(dao).recommendation("a@b.com"))
    }

    @Test fun stale_key_is_discourage() = runBlocking {
        val dao = FakeDao()
        val keyT = 1_000_000L
        // last message 40 days after the key was last affirmed → stale
        dao.upsert(AutocryptPeerEntity("a@b.com", lastSeen = keyT + 40 * DAY,
            autocryptTimestamp = keyT, autocryptKeyFingerprint = "FP", isMutual = true))
        assertEquals(AutocryptRecommendation.DISCOURAGE, store(dao).recommendation("a@b.com"))
    }

    @Test fun gossip_only_is_discourage() = runBlocking {
        val dao = FakeDao()
        dao.upsert(AutocryptPeerEntity("a@b.com", gossipTimestamp = 1000,
            gossipKeyFingerprint = "GFP"))
        assertEquals(AutocryptRecommendation.DISCOURAGE, store(dao).recommendation("a@b.com"))
    }

    @Test fun recommendation_normalizes_name_and_case() = runBlocking {
        val dao = FakeDao()
        val t = 1_000_000L
        dao.upsert(AutocryptPeerEntity("a@b.com", lastSeen = t, autocryptTimestamp = t,
            autocryptKeyFingerprint = "FP"))
        assertEquals(AutocryptRecommendation.AVAILABLE,
            store(dao).recommendation("Alice <A@B.COM>"))
    }

    // ── updates ──────────────────────────────────────────────────────

    @Test fun last_seen_advances_only_forward() = runBlocking {
        val dao = FakeDao()
        val s = store(dao)
        s.updateLastSeen("a@b.com", 5000)
        s.updateLastSeen("a@b.com", 3000) // older — ignored
        assertEquals(5000L, dao.get("a@b.com")!!.lastSeen)
        s.updateLastSeen("a@b.com", 9000)
        assertEquals(9000L, dao.get("a@b.com")!!.lastSeen)
    }

    @Test fun update_key_newer_sets_key_and_mutual() = runBlocking {
        val dao = FakeDao()
        store(dao).updateKey("a@b.com", 5000, byteArrayOf(1, 2, 3), isMutual = true)
        val p = dao.get("a@b.com")!!
        assertEquals(5000L, p.autocryptTimestamp)
        assertEquals("IMPORTEDFP", p.autocryptKeyFingerprint)
        assertEquals(true, p.isMutual)
        assertEquals(5000L, p.lastSeen)
    }

    @Test fun update_key_older_is_rejected_but_advances_last_seen() = runBlocking {
        val dao = FakeDao()
        dao.upsert(AutocryptPeerEntity("a@b.com", lastSeen = 5000, autocryptTimestamp = 5000,
            autocryptKeyFingerprint = "OLD", isMutual = true))
        // an OLDER header arrives with lastSeen bump but must not replace the key
        store(dao).updateKey("a@b.com", 3000, byteArrayOf(9), isMutual = false)
        val p = dao.get("a@b.com")!!
        assertEquals(5000L, p.autocryptTimestamp)      // unchanged
        assertEquals("OLD", p.autocryptKeyFingerprint) // unchanged
        assertEquals(true, p.isMutual)                 // unchanged
    }

    @Test fun gossip_newer_only() = runBlocking {
        val dao = FakeDao()
        val s = store(dao)
        s.updateGossipKey("a@b.com", 5000, byteArrayOf(1))
        assertEquals(5000L, dao.get("a@b.com")!!.gossipTimestamp)
        assertEquals("IMPORTEDFP", dao.get("a@b.com")!!.gossipKeyFingerprint)
        s.updateGossipKey("a@b.com", 3000, byteArrayOf(2)) // older — ignored
        assertEquals(5000L, dao.get("a@b.com")!!.gossipTimestamp)
        // gossip must never set the autocrypt key
        assertNull(dao.get("a@b.com")!!.autocryptKeyFingerprint)
    }
}
