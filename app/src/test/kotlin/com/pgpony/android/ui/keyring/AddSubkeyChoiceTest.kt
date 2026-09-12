// AddSubkeyChoiceTest.kt
// PGPony Android — 4.5.0 (item 7 / #55): Add Subkey choice availability rules.
//
// The sheet offers different subkey kinds by key version. v6 keys take Ed25519/
// X25519 classical plus the full PQ set (ML-KEM 768/1024, ML-DSA 65/87). v4 keys
// take RSA/Ed25519/X25519 classical plus ML-KEM-768 only (which converts the key
// to the v4 interop shape); ML-KEM-1024 and every ML-DSA shape are v6-only.

package com.pgpony.android.ui.keyring

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AddSubkeyChoiceTest {

    @Test
    fun `v6 offers Ed25519 X25519 classical and the full PQ set`() {
        val classical = AddSubkeyChoice.classicalFor(isV6 = true)
        assertEquals(3, classical.size)
        assertTrue(classical.none {
            it.type.name.startsWith("RSA")
        })

        val pq = AddSubkeyChoice.postQuantumFor(isV6 = true)
        assertEquals(
            listOf(
                AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768),
                AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_1024),
                AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA65_ED25519),
                AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA87_ED448)
            ),
            pq
        )
    }

    @Test
    fun `v4 offers RSA classical and ML-KEM-768 only for PQ`() {
        val classical = AddSubkeyChoice.classicalFor(isV6 = false)
        assertEquals(ClassicalSubkeyGen.ClassicalSubkeyType.entries.size, classical.size)
        assertTrue("v4 keeps RSA options", classical.any { it.type.name.startsWith("RSA") })

        val pq = AddSubkeyChoice.postQuantumFor(isV6 = false)
        assertEquals(listOf(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768)), pq)
        assertFalse("no ML-KEM-1024 on v4", pq.contains(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_1024)))
        assertFalse("no ML-DSA signing on v4",
            pq.any { it is AddSubkeyChoice.PqSigning })
    }
}
