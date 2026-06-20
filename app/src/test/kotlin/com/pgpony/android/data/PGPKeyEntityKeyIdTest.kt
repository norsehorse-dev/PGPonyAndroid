// PGPKeyEntityKeyIdTest.kt
// PGPony Android
//
// Locks the version-aware key-ID derivation on PGPKeyEntity that the
// signer/recipient resolution in the Share + Encrypt/Decrypt view models
// now depends on (V6-2). The rule: a v6 key's long key ID is the LEADING
// 16 hex of its fingerprint; a v4 key's is the TRAILING 16. These props
// don't touch any Android framework, so they run as plain JVM tests.

package com.pgpony.android.data

import com.pgpony.android.crypto.KeyAlgorithm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PGPKeyEntityKeyIdTest {

    private fun entity(fp: String, algo: KeyAlgorithm) = PGPKeyEntity(
        id = "test-id",
        fingerprint = fp,
        userID = "Test <test@pgpony.app>",
        userName = "Test",
        userEmail = "test@pgpony.app",
        algorithm = algo,
        isKeyPair = false,
        createdAt = 0L
    )

    // Real v6 fingerprint from the sq interop key used in V6-1.
    private val v6Fp = "65BD1D14F8A5D7C9460F48D7C472A4BD6F570663F82B0CFA6E04603965EE7792"

    // A representative 40-hex v4 fingerprint.
    private val v4Fp = "ABCDEF0123456789ABCDEF0123456789DEADBEEF"

    @Test
    fun `v6 key reports isV6Key`() {
        assertTrue(entity(v6Fp, KeyAlgorithm.V6_ED25519).isV6Key)
    }

    @Test
    fun `v4 key does not report isV6Key`() {
        assertFalse(entity(v4Fp, KeyAlgorithm.ED25519_CV25519).isV6Key)
    }

    @Test
    fun `v6 long key id is the leading 16 hex`() {
        assertEquals("65BD1D14F8A5D7C9", entity(v6Fp, KeyAlgorithm.V6_ED25519).longKeyId)
    }

    @Test
    fun `v4 long key id is the trailing 16 hex`() {
        assertEquals("0123456789DEADBEEF".takeLast(16), entity(v4Fp, KeyAlgorithm.ED25519_CV25519).longKeyId)
    }

    @Test
    fun `v6 short fingerprint is the leading 8 hex`() {
        assertEquals("65BD1D14", entity(v6Fp, KeyAlgorithm.V6_ED25519).shortFingerprint)
    }

    @Test
    fun `v4 short fingerprint is the trailing 8 hex unchanged`() {
        assertEquals("DEADBEEF", entity(v4Fp, KeyAlgorithm.ED25519_CV25519).shortFingerprint)
    }

    @Test
    fun `the two versions select opposite ends of the fingerprint`() {
        val v6 = entity(v6Fp, KeyAlgorithm.V6_ED25519).longKeyId
        val v6TrailingStyle = v6Fp.takeLast(16).uppercase()
        assertFalse(v6 == v6TrailingStyle)
    }
}
