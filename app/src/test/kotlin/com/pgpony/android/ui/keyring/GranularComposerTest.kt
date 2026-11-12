// GranularComposerTest.kt
// PGPony Android, 4.8.0 (items 4i and 4j): the subkey composer's rules.
// 4.8.0 RC11 (#109): the composer builds on the primary picked in Generate Key.

package com.pgpony.android.ui.keyring

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GranularComposerTest {

    private val mlkem768 = AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768)
    private val mlkem1024 = AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_1024)
    private val mldsa87 = AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA87_ED448)
    private val rsaEnc = AddSubkeyChoice.Classical(ClassicalSubkeyType.RSA_4096_ENCRYPT)
    private val edSign = AddSubkeyChoice.Classical(ClassicalSubkeyType.ED25519_SIGN)
    private val bpAuth = AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_BP384_AUTH)
    private val p256Sign = AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_P256_SIGN)

    @Test
    fun `the options are the Add subkey list for a key of the picked primary's type`() {
        // A v6 key always gets an Ed25519 signing subkey (a fixed chip), so the picker leaves it out.
        assertEquals(
            SubkeyPick.options(AddSubkeyChoice.Base.V6, primary = KeyAlgorithm.V6_ED25519) - edSign,
            GranularComposer.options(KeyAlgorithm.V6_ED25519, emptyList())
        )
        assertEquals(
            SubkeyPick.options(AddSubkeyChoice.Base.V4, primary = KeyAlgorithm.ED25519_CV25519),
            GranularComposer.options(KeyAlgorithm.ED25519_CV25519, emptyList())
        )
        for (curve in KeyAlgorithm.generatableEcdsa) {
            val opts = GranularComposer.options(curve, emptyList())
            assertEquals("ECDSA primary, $curve", SubkeyPick.options(AddSubkeyChoice.Base.V4_OTHER, primary = curve), opts)
            // Every curve is offered, whatever the primary's.
            for (c in KeyAlgorithm.generatableEcdsa) {
                assertTrue("$curve offers ECDSA auth on $c",
                    opts.any { it is AddSubkeyChoice.Classical && it.type.curve == c &&
                        AddSubkeyChoice.usageOf(it) == AddSubkeyChoice.Usage.AUTHENTICATE })
            }
        }
        val rsa = GranularComposer.options(KeyAlgorithm.RSA_4096, emptyList())
        assertTrue(rsa.contains(rsaEnc))
        assertTrue("an RSA key takes ECDSA subkeys", rsa.contains(p256Sign))
        assertFalse("no ML-KEM on an RSA key", rsa.any { it is AddSubkeyChoice.PqEncryption })
        assertTrue("v6 keeps the post-quantum kinds", GranularComposer.options(KeyAlgorithm.V6_ED25519, emptyList()).contains(mldsa87))
        assertFalse("a v4 Ed25519 key takes one ML-KEM-768 subkey",
            GranularComposer.options(KeyAlgorithm.ED25519_CV25519, listOf(mlkem768)).any { it is AddSubkeyChoice.PqEncryption })
        assertTrue("no options on a post-quantum primary", GranularComposer.options(KeyAlgorithm.MLDSA65_ED25519_V6, emptyList()).isEmpty())
    }

    @Test
    fun `the picker starts on the first use the composed key lacks`() {
        val bp = KeyAlgorithm.ECDSA_BRAINPOOL_P384
        // Signing from the primary, encryption from the default subkey: authentication next, on the primary's curve.
        val opts = GranularComposer.options(bp, emptyList())
        assertEquals(bpAuth, SubkeyPick.start(opts, GranularComposer.have(bp, true, emptyList()), bp))
        // Without the default encryption subkey, encryption comes before it.
        assertEquals(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDH_BP384_ENCRYPT),
            SubkeyPick.start(opts, GranularComposer.have(bp, false, emptyList()), bp))
        // With an auth subkey composed and the default encryption on, every use is covered: back to signing.
        assertEquals(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_BP384_SIGN),
            SubkeyPick.start(opts, GranularComposer.have(bp, true, listOf(bpAuth)), bp))
    }

    @Test
    fun `the composer supports every classical primary and no post-quantum one`() {
        val classical = listOf(KeyAlgorithm.V6_ED25519, KeyAlgorithm.ED25519_CV25519, KeyAlgorithm.RSA_2048, KeyAlgorithm.RSA_4096) +
            KeyAlgorithm.generatableEcdsa
        for (a in classical) assertTrue("$a", GranularComposer.supports(a))
        for (a in KeyAlgorithm.generatable - classical.toSet()) assertFalse("$a", GranularComposer.supports(a))
    }

    @Test
    fun `a new primary keeps only the subkeys it can hold`() {
        assertEquals(listOf(edSign, mlkem768),
            GranularComposer.keptFor(KeyAlgorithm.ED25519_CV25519, listOf(mldsa87, edSign, mlkem1024, mlkem768, mlkem768)))
        assertEquals(listOf(bpAuth, p256Sign, rsaEnc), GranularComposer.keptFor(KeyAlgorithm.ECDSA_BRAINPOOL_P384, listOf(bpAuth, p256Sign, rsaEnc, mlkem768)))
        assertEquals(listOf(edSign, mldsa87), GranularComposer.keptFor(KeyAlgorithm.V6_ED25519, listOf(bpAuth, edSign, rsaEnc, p256Sign, mldsa87)))
        assertEquals("a post-quantum primary keeps the list for later", listOf(bpAuth, mldsa87),
            GranularComposer.keptFor(KeyAlgorithm.MLDSA65_ED25519_V6, listOf(bpAuth, mldsa87)))
    }

    @Test
    fun `the default encryption subkey matches what plain Generate makes`() {
        assertEquals(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDH_BP384_ENCRYPT), AddSubkeyChoice.defaultEncryptionFor(KeyAlgorithm.ECDSA_BRAINPOOL_P384))
        assertEquals(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDH_P256_ENCRYPT), AddSubkeyChoice.defaultEncryptionFor(KeyAlgorithm.ECDSA_NIST_P256))
        assertEquals(AddSubkeyChoice.Classical(ClassicalSubkeyType.RSA_2048_ENCRYPT), AddSubkeyChoice.defaultEncryptionFor(KeyAlgorithm.RSA_2048))
        assertEquals(AddSubkeyChoice.Classical(ClassicalSubkeyType.X25519_ENCRYPT), AddSubkeyChoice.defaultEncryptionFor(KeyAlgorithm.V6_ED25519))
        assertNull(AddSubkeyChoice.defaultEncryptionFor(KeyAlgorithm.MLDSA65_ED25519_V6))
    }

    @Test
    fun `the default encryption subkey is off for a post-quantum only list`() {
        assertTrue("an empty list keeps it", GranularComposer.defaultEncryptionSubkey(emptyList()))
        assertFalse(GranularComposer.defaultEncryptionSubkey(listOf(mlkem768)))
        assertFalse(GranularComposer.defaultEncryptionSubkey(listOf(mlkem1024, mldsa87)))
        assertTrue("a classical subkey in the list keeps it", GranularComposer.defaultEncryptionSubkey(listOf(mlkem768, edSign)))
        assertTrue("no post-quantum encryption subkey keeps it", GranularComposer.defaultEncryptionSubkey(listOf(mldsa87)))
    }

    @Test
    fun `the subkeys a key always gets are shown as fixed`() {
        assertEquals(listOf<AddSubkeyChoice>(edSign), GranularComposer.fixedSubkeys(KeyAlgorithm.V6_ED25519, false, emptyList()))
        assertTrue(GranularComposer.fixedSubkeys(KeyAlgorithm.ECDSA_BRAINPOOL_P384, false, emptyList()).isEmpty())
        assertEquals(
            listOf<AddSubkeyChoice>(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_BP384_SIGN)),
            GranularComposer.fixedSubkeys(KeyAlgorithm.ECDSA_BRAINPOOL_P384, true, listOf(bpAuth))
        )
        assertTrue("a composed signing subkey is enough",
            GranularComposer.fixedSubkeys(KeyAlgorithm.ECDSA_BRAINPOOL_P384, true, listOf(p256Sign)).isEmpty())
        assertEquals(
            listOf<AddSubkeyChoice>(AddSubkeyChoice.Classical(ClassicalSubkeyType.RSA_4096_SIGN)),
            GranularComposer.fixedSubkeys(KeyAlgorithm.RSA_4096, true, emptyList())
        )
        assertEquals(listOf<AddSubkeyChoice>(edSign), GranularComposer.fixedSubkeys(KeyAlgorithm.ED25519_CV25519, true, emptyList()))
    }
}
