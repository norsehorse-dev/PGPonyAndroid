// KeyDeduplicationExpiryGuardTest.kt
// PGPony Android — 4.5.0 (item 24 / #55, lukascomer): a keyserver refresh must
// not silently strip or shorten a primary key's expiry.
//
// lukascomer imported a key whose primary expires 2050, then a background
// keyserver refresh fetched his re-published no-expiry copy and the merge
// overwrote the stored expiry with null, so Key Details read "Never". This
// locks the guard that blocks that downgrade while still allowing a refresh to
// add or extend an expiry.

package com.pgpony.android.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyDeduplicationExpiryGuardTest {

    private val y2050 = 2546656205000L
    private val y2060 = 2861929805000L
    private val y2040 = 2230000000000L

    @Test
    fun `removing an existing expiry is a downgrade`() {
        assertTrue(KeyDeduplicationService.isExpiryDowngrade(y2050, null))
    }

    @Test
    fun `shortening an existing expiry is a downgrade`() {
        assertTrue(KeyDeduplicationService.isExpiryDowngrade(y2050, y2040))
    }

    @Test
    fun `extending, matching, or adding an expiry is not a downgrade`() {
        assertFalse("extend", KeyDeduplicationService.isExpiryDowngrade(y2050, y2060))
        assertFalse("match", KeyDeduplicationService.isExpiryDowngrade(y2050, y2050))
        assertFalse("add where none existed", KeyDeduplicationService.isExpiryDowngrade(null, y2050))
    }

    @Test
    fun `no expiry either side is not a downgrade`() {
        assertFalse(KeyDeduplicationService.isExpiryDowngrade(null, null))
    }
}
