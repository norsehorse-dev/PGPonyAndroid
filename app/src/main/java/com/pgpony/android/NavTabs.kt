// NavTabs.kt
// PGPony Android
//
// 4.8.0 RC6 (tabs): the bottom bar went from six tabs to five. Contacts left
// the bar and is now a page pushed from the Keyring's top bar. The route
// names and the rule for which pushed routes belong to which tab live here,
// free of Compose and Android, so the JVM tests can check them.

package com.pgpony.android

/** Stable internal navigation keys. Not user-facing. */
object NavRoutes {
    const val KEYRING = "keyring"
    const val ENCRYPT = "encrypt"
    const val DECRYPT = "decrypt"
    const val EXCHANGE = "exchange"
    const val SETTINGS = "settings"

    // 4.8.0 RC6 (tabs): no longer a tab. The route keeps its old name so a
    // back stack saved by an earlier build (the system restores it after a
    // recreate) still resolves; it sits under the Keyring either way.
    const val CONTACTS = "contacts"

    // 4.8.0 RC8 (item 4n): Keyring > Groups, a pushed page like Recently Deleted.
    const val GROUPS = "groups"
}

/**
 * Bottom-bar tab routes, in bar order. 4.8.0 RC6 (tabs): five, without Contacts.
 */
val bottomNavRoutes: List<String> = listOf(
    NavRoutes.KEYRING, NavRoutes.ENCRYPT, NavRoutes.DECRYPT, NavRoutes.EXCHANGE, NavRoutes.SETTINGS
)

/**
 * Top-level routes that belong to the Keyring tab: the NFC/card flow, the
 * recycle bin, (4.8.0 RC6) Contacts and (4.8.0 RC8) Groups, reached from the Keyring but
 * registered as their own destinations. Tapping the Keyring tab from any of
 * them returns to the list.
 */
val keyringOwnedRoutes: Set<String> = setOf(
    "card_scan", "card_pin_change", "card_keygen",
    "card_management", "card_sign", "card_decrypt", "recently_deleted",
    NavRoutes.CONTACTS, NavRoutes.GROUPS
)

/**
 * True when [current] is a pushed screen under the tab [tabRoute], so a tap
 * on that tab should pop back to the tab's own root instead of the
 * save/restore navigate (which would save the sub-screen and restore it
 * straight back, leaving the view stuck where it was). Covers Key Detail
 * ("keyring/{fingerprint}") and the Keyring's [keyringOwnedRoutes].
 */
fun isSubScreenOfTab(current: String?, tabRoute: String): Boolean =
    current != null && (
        current.startsWith("$tabRoute/") ||
            (tabRoute == NavRoutes.KEYRING && current in keyringOwnedRoutes)
        )
