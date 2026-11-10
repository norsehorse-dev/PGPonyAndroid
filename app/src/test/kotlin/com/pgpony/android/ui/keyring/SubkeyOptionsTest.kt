// SubkeyOptionsTest.kt
// PGPony Android, 4.8.0 RC10 (#109): the one subkey list that Add subkey in Key
// Details and the composer in Generate Key both show, grouped by use.

package com.pgpony.android.ui.keyring

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.AddSubkeyChoice.Base
import com.pgpony.android.crypto.AddSubkeyChoice.Usage
import com.pgpony.android.crypto.ClassicalSubkeyGen.Capability
import com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SubkeyOptionsTest {

    private fun c(t: ClassicalSubkeyType) = AddSubkeyChoice.Classical(t)

    @Test fun `a v4 key gets every classical kind and ECDSA on the picked curve, grouped by use`() {
        assertEquals(
            listOf(
                c(ClassicalSubkeyType.ED25519_SIGN), c(ClassicalSubkeyType.ECDSA_BP384_SIGN),
                c(ClassicalSubkeyType.RSA_2048_SIGN), c(ClassicalSubkeyType.RSA_4096_SIGN),
                c(ClassicalSubkeyType.ED25519_AUTH), c(ClassicalSubkeyType.ECDSA_BP384_AUTH),
                c(ClassicalSubkeyType.RSA_2048_AUTH), c(ClassicalSubkeyType.RSA_4096_AUTH),
                c(ClassicalSubkeyType.X25519_ENCRYPT), c(ClassicalSubkeyType.ECDH_BP384_ENCRYPT),
                c(ClassicalSubkeyType.RSA_2048_ENCRYPT), c(ClassicalSubkeyType.RSA_4096_ENCRYPT),
                AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768)
            ),
            AddSubkeyChoice.optionsFor(Base.V4, KeyAlgorithm.ECDSA_BRAINPOOL_P384)
        )
    }

    @Test fun `a v6 key gets Ed25519, X25519 and every post-quantum kind, no RSA or ECDSA`() {
        assertEquals(
            listOf(
                c(ClassicalSubkeyType.ED25519_SIGN),
                AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA65_ED25519),
                AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA87_ED448),
                c(ClassicalSubkeyType.ED25519_AUTH),
                c(ClassicalSubkeyType.X25519_ENCRYPT),
                AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768),
                AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_1024)
            ),
            AddSubkeyChoice.optionsFor(Base.V6)
        )
        val composite = AddSubkeyChoice.optionsFor(Base.V6_COMPOSITE_SIGN)
        assertTrue("a composite ML-DSA primary also takes RSA", composite.contains(c(ClassicalSubkeyType.RSA_4096_ENCRYPT)))
        assertFalse(composite.any { it is AddSubkeyChoice.Classical && it.type.curve != null })
    }

    @Test fun `the groups come in usage order and a security key gets no post-quantum kinds`() {
        for (base in Base.entries) {
            val usages = AddSubkeyChoice.optionsFor(base).map { AddSubkeyChoice.usageOf(it) }
            assertEquals("$base grouped", usages.sortedBy { it.ordinal }, usages)
            assertTrue(AddSubkeyChoice.optionsFor(base, postQuantum = false).all { it is AddSubkeyChoice.Classical })
        }
        assertEquals(Usage.AUTHENTICATE, AddSubkeyChoice.usageOf(c(ClassicalSubkeyType.ECDSA_SECP256K1_AUTH)))
    }

    @Test fun `every generated curve has a sign, an authenticate and an encrypt subkey`() {
        for (curve in KeyAlgorithm.generatableEcdsa) {
            for (cap in Capability.entries) assertNotNull("$curve $cap", ClassicalSubkeyType.ecdsa(curve, cap))
        }
        assertEquals(21, ClassicalSubkeyType.entries.count { it.curve != null })
    }

    @Test fun `an ECDSA key starts on its own curve`() {
        assertEquals(KeyAlgorithm.ECDSA_BRAINPOOL_P512, AddSubkeyChoice.defaultCurve(KeyAlgorithm.ECDSA_BRAINPOOL_P512))
        assertEquals(KeyAlgorithm.ECDSA_NIST_P256, AddSubkeyChoice.defaultCurve(KeyAlgorithm.ED25519_CV25519))
        assertEquals(KeyAlgorithm.ECDSA_NIST_P256, AddSubkeyChoice.defaultCurve(null))
    }
}
