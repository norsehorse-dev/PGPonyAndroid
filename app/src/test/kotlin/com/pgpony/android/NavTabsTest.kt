// NavTabsTest.kt
// PGPony Android: 4.8.0 RC6 (tabs): five bottom-bar tabs, Contacts pushed
// from the Keyring, and the rule that sends a tab tap from a sub-screen back
// to that tab's root.

package com.pgpony.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NavTabsTest {

    @Test
    fun `bottom bar has five tabs in order and no Contacts`() {
        assertEquals(
            listOf("keyring", "encrypt", "decrypt", "exchange", "settings"),
            bottomNavRoutes
        )
        assertFalse(NavRoutes.CONTACTS in bottomNavRoutes)
    }

    @Test
    fun `contacts keeps its old route name so a restored back stack resolves`() {
        assertEquals("contacts", NavRoutes.CONTACTS)
    }

    @Test
    fun `contacts belongs to the Keyring tab`() {
        assertTrue(NavRoutes.CONTACTS in keyringOwnedRoutes)
        assertTrue(isSubScreenOfTab(NavRoutes.CONTACTS, NavRoutes.KEYRING))
    }

    @Test
    fun `contacts is not a sub-screen of the other tabs`() {
        for (tab in bottomNavRoutes - NavRoutes.KEYRING) {
            assertFalse(tab, isSubScreenOfTab(NavRoutes.CONTACTS, tab))
        }
    }

    @Test
    fun `key detail and the other keyring routes still pop back to the list`() {
        assertTrue(isSubScreenOfTab("keyring/ABCDEF0123456789", NavRoutes.KEYRING))
        for (route in listOf(
            "card_scan", "card_pin_change", "card_keygen",
            "card_management", "card_sign", "card_decrypt", "recently_deleted"
        )) {
            assertTrue(route, isSubScreenOfTab(route, NavRoutes.KEYRING))
        }
    }

    @Test
    fun `a tab root or no destination is not a sub-screen`() {
        for (tab in bottomNavRoutes) {
            assertFalse(tab, isSubScreenOfTab(tab, tab))
            assertFalse(tab, isSubScreenOfTab(null, tab))
        }
        assertFalse(isSubScreenOfTab(NavRoutes.ENCRYPT, NavRoutes.KEYRING))
    }

    @Test
    fun `a prefix without the slash does not count`() {
        // "keyringx" is not under "keyring"; only "keyring/..." is.
        assertFalse(isSubScreenOfTab("keyringx", NavRoutes.KEYRING))
    }
}
