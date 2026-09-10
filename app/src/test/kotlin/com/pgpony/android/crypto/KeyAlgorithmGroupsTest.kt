// KeyAlgorithmGroupsTest.kt
// PGPony Android — 4.5.0 (item 14 / #56): keygen picker group membership.
//
// Locks the interop tier: the three ML-KEM-768+X25519 wire shapes (v6 / v4 / v5)
// live together in generatableInterop, are absent from the other groups, and the
// flat union stays duplicate-free.

package com.pgpony.android.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyAlgorithmGroupsTest {

    private val shapes = listOf(
        KeyAlgorithm.MLKEM768_X25519_V6,
        KeyAlgorithm.MLKEM768_X25519_V4,
        KeyAlgorithm.MLKEM768_X25519_LIBREPGP
    )

    @Test
    fun `interop tier holds exactly the three ML-KEM-768 X25519 shapes`() {
        assertEquals(shapes, KeyAlgorithm.generatableInterop)
    }

    @Test
    fun `the three shapes are not in the other keygen groups`() {
        for (shape in shapes) {
            assertFalse("$shape leaked into PQC group", shape in KeyAlgorithm.generatablePostQuantum)
            assertFalse("$shape leaked into Advanced group", shape in KeyAlgorithm.generatableAdvanced)
            assertFalse("$shape leaked into Classical group", shape in KeyAlgorithm.generatableClassical)
        }
    }

    @Test
    fun `every interop shape is a composite key`() {
        for (shape in shapes) assertTrue("$shape must be composite", shape.isComposite)
    }

    @Test
    fun `the flat generatable union is duplicate-free and contains the interop tier`() {
        val all = KeyAlgorithm.generatable
        assertEquals("no duplicates across picker groups", all.size, all.toSet().size)
        assertTrue("interop tier is part of the union", all.containsAll(KeyAlgorithm.generatableInterop))
    }
}
