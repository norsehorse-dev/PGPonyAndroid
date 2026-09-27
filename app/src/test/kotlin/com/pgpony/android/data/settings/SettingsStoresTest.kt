// SettingsStoresTest.kt
// PGPony Android, 4.7.0: the settings seam keeps the stores' old behavior.
// With no implementation installed, reads return defaults and writes do
// nothing (what the stores did when PGPonyApp.instance was unavailable). With
// one installed, values round-trip. KeyPublicationStore is left to device
// testing because it uses org.json, which plain JVM unit tests stub out.

package com.pgpony.android.data.settings

import com.pgpony.android.crypto.FallbackPrefs
import com.pgpony.android.data.RemovedUserIdStore
import com.pgpony.android.network.WkdLookup
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SettingsStoresTest {

    private val fp = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"

    @After
    fun tearDown() = SettingsStores.uninstall()

    @Test
    fun noImplementationMeansDefaultsAndNoOps() {
        SettingsStores.uninstall()
        assertNull(SettingsStores.open())
        assertTrue(WkdLookup.isEnabled())
        WkdLookup.set(false)
        assertTrue(WkdLookup.isEnabled())
        assertFalse(FallbackPrefs.isStrict(fp))
        RemovedUserIdStore.addRemoved(fp, "a@example.org")
        assertEquals(emptySet<String>(), RemovedUserIdStore.removed(fp))
    }

    @Test
    fun installedImplementationRoundTrips() {
        val store = InMemoryKeyValueSettings()
        SettingsStores.install { _, _ -> store }

        WkdLookup.set(false)
        assertFalse(WkdLookup.isEnabled())

        FallbackPrefs.setStrict(fp, true)
        assertTrue(FallbackPrefs.isStrict(fp))

        RemovedUserIdStore.addRemoved(fp, "a@example.org")
        RemovedUserIdStore.addRemoved(fp, "b@example.org")
        assertEquals(setOf("a@example.org", "b@example.org"), RemovedUserIdStore.removed(fp))
        RemovedUserIdStore.forget(fp, "a@example.org")
        assertEquals(setOf("b@example.org"), RemovedUserIdStore.removed(fp))
        RemovedUserIdStore.clear(fp)
        assertEquals(emptySet<String>(), RemovedUserIdStore.removed(fp))
    }

    @Test
    fun keysMatchTheOldSharedPreferencesKeys() {
        val store = InMemoryKeyValueSettings()
        SettingsStores.install { name, _ ->
            assertEquals("pgpony_prefs", name)
            store
        }
        WkdLookup.set(false)
        FallbackPrefs.setStrict(fp, true)
        RemovedUserIdStore.addRemoved(fp, "a@example.org")
        assertFalse(store.getBoolean("wkd_lookup_enabled", true))
        assertTrue(store.getBoolean("fallback_strict_$fp", false))
        assertEquals(setOf("a@example.org"), store.getStringSet("removed_uids_${fp.lowercase()}", emptySet()))
    }
}
