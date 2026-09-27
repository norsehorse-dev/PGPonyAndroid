// AddSubkeyLifetimeTest.kt
// PGPony Android 4.7.0 (item 18): the Add Subkey sheet hands over an expiry DATE, and the
// subkey generators write a key-expiration subpacket, which is seconds after creation. The
// date used to go straight through, so "1 year" produced a subkey good for about 58 years.

package com.pgpony.android.ui.keyring

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AddSubkeyLifetimeTest {

    private val now = 1_790_000_000_000L
    private val year = 365L * 24 * 60 * 60

    @Test
    fun `never stays never`() {
        assertNull(addSubkeyLifetimeSeconds(null, now))
    }

    @Test
    fun `a date a year out becomes a one-year lifetime`() {
        assertEquals(year, addSubkeyLifetimeSeconds(now / 1000 + year, now))
    }

    @Test
    fun `a date already past becomes one second, not never`() {
        assertEquals(1L, addSubkeyLifetimeSeconds(now / 1000 - 60, now))
    }
}
