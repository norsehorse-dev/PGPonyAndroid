// SubkeyCapabilityTest.kt
// PGPony Android
//
// Phase A1 unit tests for the pure functions on SubkeyCapability —
// the bit-set helpers, the BC wire-flags mapper, and the heuristic
// fallback table. The full self-signature reader is exercised at
// runtime against real keyring data (and via Phase A2 integration
// tests) — too much BC scaffolding to mock at the unit level.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.sig.KeyFlags as BcKeyFlags
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SubkeyCapabilityTest {

    // ── Bit-set helpers ───────────────────────────────────────────────

    @Test
    fun fromBitsSplitsPackedFlags() {
        val packed = SubkeyCapability.Certify.flag or
                SubkeyCapability.Sign.flag or
                SubkeyCapability.Encrypt.flag
        val expanded = SubkeyCapability.fromBits(packed)
        assertEquals(
            listOf(SubkeyCapability.Certify, SubkeyCapability.Sign, SubkeyCapability.Encrypt),
            expanded
        )
    }

    @Test
    fun toBitsRoundTrips() {
        val caps = listOf(SubkeyCapability.Sign, SubkeyCapability.Authenticate)
        val packed = SubkeyCapability.toBits(caps)
        val expanded = SubkeyCapability.fromBits(packed)
        assertEquals(caps, expanded)
    }

    @Test
    fun hasCapabilityReadsIndividualBits() {
        val packed = SubkeyCapability.Sign.flag or SubkeyCapability.Encrypt.flag
        assertFalse(SubkeyCapability.hasCapability(packed, SubkeyCapability.Certify))
        assertTrue(SubkeyCapability.hasCapability(packed, SubkeyCapability.Sign))
        assertTrue(SubkeyCapability.hasCapability(packed, SubkeyCapability.Encrypt))
        assertFalse(SubkeyCapability.hasCapability(packed, SubkeyCapability.Authenticate))
    }

    @Test
    fun displayStringJoinsHumanLabels() {
        val packed = SubkeyCapability.Certify.flag or SubkeyCapability.Sign.flag
        assertEquals("Certify, Sign", SubkeyCapability.displayString(packed))
    }

    @Test
    fun displayStringHandlesZeroBits() {
        assertEquals("None", SubkeyCapability.displayString(0))
    }

    // ── BC wire-flag mapping ──────────────────────────────────────────

    @Test
    fun fromBcKeyFlagsMapsCertifyAndSign() {
        val bc = BcKeyFlags.CERTIFY_OTHER or BcKeyFlags.SIGN_DATA
        val ours = SubkeyCapability.fromBcKeyFlags(bc)
        assertEquals(SubkeyCapability.Certify.flag or SubkeyCapability.Sign.flag, ours)
    }

    @Test
    fun fromBcKeyFlagsFoldsBothEncryptBitsIntoOne() {
        // Wire-protocol distinguishes between encrypt-comms (0x04) and
        // encrypt-storage (0x08); we fold both into the single Encrypt
        // bit (0x04 in our scheme) so subkey rows match iOS exactly.
        val bcComms = BcKeyFlags.ENCRYPT_COMMS
        val bcStorage = BcKeyFlags.ENCRYPT_STORAGE
        val bcBoth = bcComms or bcStorage

        assertEquals(SubkeyCapability.Encrypt.flag, SubkeyCapability.fromBcKeyFlags(bcComms))
        assertEquals(SubkeyCapability.Encrypt.flag, SubkeyCapability.fromBcKeyFlags(bcStorage))
        assertEquals(SubkeyCapability.Encrypt.flag, SubkeyCapability.fromBcKeyFlags(bcBoth))
    }

    @Test
    fun fromBcKeyFlagsMapsAuthenticationFrom0x20to0x08() {
        // Wire-protocol AUTHENTICATION = 0x20. Our Authenticate = 0x08.
        // Easy bit to get wrong if someone copies the wire value.
        val ours = SubkeyCapability.fromBcKeyFlags(BcKeyFlags.AUTHENTICATION)
        assertEquals(SubkeyCapability.Authenticate.flag, ours)
        assertEquals(0x08, ours)
    }

    @Test
    fun fromBcKeyFlagsDropsSplitAndSharedBits() {
        // BC SPLIT = 0x10 and SHARED = 0x80 are key-management hints,
        // not capabilities. Our scheme has no slot for them.
        val bc = BcKeyFlags.SPLIT or BcKeyFlags.SHARED
        assertEquals(0, SubkeyCapability.fromBcKeyFlags(bc))
    }

    @Test
    fun fromBcKeyFlagsMapsFullMixedSet() {
        val bc = BcKeyFlags.CERTIFY_OTHER or
                BcKeyFlags.SIGN_DATA or
                BcKeyFlags.ENCRYPT_STORAGE or
                BcKeyFlags.AUTHENTICATION or
                BcKeyFlags.SPLIT
        val ours = SubkeyCapability.fromBcKeyFlags(bc)
        val expected = SubkeyCapability.Certify.flag or
                SubkeyCapability.Sign.flag or
                SubkeyCapability.Encrypt.flag or
                SubkeyCapability.Authenticate.flag
        assertEquals(expected, ours)
    }

    // ── Heuristic fallback ────────────────────────────────────────────

    @Test
    fun heuristicPrimaryRsaIsCertifySignEncrypt() {
        val expected = SubkeyCapability.Certify.flag or
                SubkeyCapability.Sign.flag or
                SubkeyCapability.Encrypt.flag
        assertEquals(expected, SubkeyCapability.heuristic(KeyAlgorithm.RSA_4096, isPrimary = true))
        assertEquals(expected, SubkeyCapability.heuristic(KeyAlgorithm.RSA_2048, isPrimary = true))
    }

    @Test
    fun heuristicSubkeyRsaIsSignEncrypt() {
        val expected = SubkeyCapability.Sign.flag or SubkeyCapability.Encrypt.flag
        assertEquals(expected, SubkeyCapability.heuristic(KeyAlgorithm.RSA_4096, isPrimary = false))
    }

    @Test
    fun heuristicPrimaryEd25519IsCertifyOnly() {
        // Ed25519 + Cv25519 keys split duties: primary certifies, the
        // Cv25519 subkey encrypts. The heuristic should reflect that.
        assertEquals(
            SubkeyCapability.Certify.flag,
            SubkeyCapability.heuristic(KeyAlgorithm.ED25519_CV25519, isPrimary = true)
        )
    }

    @Test
    fun heuristicSubkeyEd25519CvIsEncrypt() {
        // The "subkey" position of an Ed25519+Cv25519 key IS the Cv25519
        // encryption subkey, so heuristic returns Encrypt.
        assertEquals(
            SubkeyCapability.Encrypt.flag,
            SubkeyCapability.heuristic(KeyAlgorithm.ED25519_CV25519, isPrimary = false)
        )
    }

    @Test
    fun heuristicV6X25519SubkeyIsEncrypt() {
        assertEquals(
            SubkeyCapability.Encrypt.flag,
            SubkeyCapability.heuristic(KeyAlgorithm.V6_X25519, isPrimary = false)
        )
        assertEquals(
            SubkeyCapability.Encrypt.flag,
            SubkeyCapability.heuristic(KeyAlgorithm.V6_X448, isPrimary = false)
        )
    }

    @Test
    fun heuristicV6Ed25519SubkeyIsSign() {
        assertEquals(
            SubkeyCapability.Sign.flag,
            SubkeyCapability.heuristic(KeyAlgorithm.V6_ED25519, isPrimary = false)
        )
        assertEquals(
            SubkeyCapability.Sign.flag,
            SubkeyCapability.heuristic(KeyAlgorithm.V6_ED448, isPrimary = false)
        )
    }
}
