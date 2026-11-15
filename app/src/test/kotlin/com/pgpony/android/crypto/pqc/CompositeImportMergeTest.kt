// CompositeImportMergeTest.kt
// PGPony Android, 4.8.1: importing a copy of an ML-DSA key that is already
// held wrote that copy over the stored one, so a subkey the copy lacked
// disappeared from the key (reported on an ML-DSA-87 key with an ML-KEM-1024
// subkey; importing the full key again brought it back). The import now merges
// the copy into the stored one with CertificateMerge, as the Bouncy Castle
// import path does. These pin that merge on composite keys: a partial copy
// never removes a subkey, and the owner's full copy adds one back.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateMerge
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CompositeImportMergeTest {

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun subkeyFps(ring: ByteArray) = CompositeKeyFacade.listSubkeys(ring).map { it.fingerprintHex }.toSet()

    /** A generated key's public copy, and the same copy without its first subkey. */
    private fun fullAndPartial(suite: CompositeSignSuite): Pair<ByteArray, ByteArray> {
        val secret = CompositePrimaryKeyGen.assemble("Merge <merge@pgpony.app>", suite)
        val full = CompositeKeyFacade.publicRingOf(secret)
        val sub = CompositeKeyFacade.listSubkeys(full).first().fingerprintHex
        val partial = CompositeKeyFacade.publicRingOf(CompositePrimaryKeyGen.removeSubkey(secret, hex(sub)))
        assertEquals(subkeyFps(full) - sub, subkeyFps(partial))
        return full to partial
    }

    @Test
    fun `a partial copy imported over a key pair keeps the stored subkey`() {
        for (suite in listOf(CompositeSignSuite.MLDSA65_ED25519, CompositeSignSuite.MLDSA87_ED448)) {
            val (full, partial) = fullAndPartial(suite)
            val merged = CertificateMerge.merge(stored = full, fetched = partial, isKeyPair = true)
            assertEquals("$suite", subkeyFps(full), subkeyFps(merged))
        }
    }

    @Test
    fun `a partial copy imported over a public key keeps the stored subkey`() {
        val (full, partial) = fullAndPartial(CompositeSignSuite.MLDSA87_ED448)
        val merged = CertificateMerge.merge(stored = full, fetched = partial, isKeyPair = false)
        assertEquals(subkeyFps(full), subkeyFps(merged))
    }

    @Test
    fun `the owner's full copy adds back a subkey the stored copy lost`() {
        val (full, partial) = fullAndPartial(CompositeSignSuite.MLDSA87_ED448)
        // ownerCopy in KeyRepository.mergeImportedPublic merges as a public-only key.
        val merged = CertificateMerge.merge(stored = partial, fetched = full, isKeyPair = false)
        assertEquals(subkeyFps(full), subkeyFps(merged))
        assertTrue(CompositeKeyFacade.isCompositePrimary(merged))
    }

    @Test
    fun `the same copy imported again changes nothing`() {
        val (full, _) = fullAndPartial(CompositeSignSuite.MLDSA65_ED25519)
        val merged = CertificateMerge.merge(stored = full, fetched = full, isKeyPair = true)
        assertEquals(subkeyFps(full), subkeyFps(merged))
    }
}
