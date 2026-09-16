// CompositeRemoveUserIdTest.kt
// PGPony Android — 4.5.1: local delete of a User ID on a composite ML-DSA
// primary (byte-splice, no revocation), mirroring the classical path.

package com.pgpony.android.crypto.pqc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CompositeRemoveUserIdTest {

    @Test
    fun `remove strips a User ID from a composite primary and keeps the rest`() {
        val ring = CompositePrimaryKeyGen.assemble("First <first@pgpony.app>")
        val two = CompositePrimaryKeyGen.addUserId(ring, "Second <second@pgpony.app>")
        assertEquals(
            listOf("First <first@pgpony.app>", "Second <second@pgpony.app>"),
            CompositeKeyFacade.parse(two).userIds
        )

        val removed = CompositePrimaryKeyGen.removeUserId(two, "Second <second@pgpony.app>")
        assertEquals(
            listOf("First <first@pgpony.app>"),
            CompositeKeyFacade.parse(removed).userIds
        )
    }

    @Test
    fun `remove refuses the only User ID on a composite primary`() {
        val ring = CompositePrimaryKeyGen.assemble("Solo <solo@pgpony.app>")
        assertThrows(IllegalStateException::class.java) {
            CompositePrimaryKeyGen.removeUserId(ring, "Solo <solo@pgpony.app>")
        }
    }
}
