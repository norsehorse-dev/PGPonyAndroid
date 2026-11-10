// GranularComposerTest.kt
// PGPony Android, 4.8.0 (items 4i and 4j): the subkey composer's rules.

package com.pgpony.android.ui.keyring

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GranularComposerTest {

    private val mlkem768 = AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768)
    private val mlkem1024 = AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_1024)
    private val mldsa87 = AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA87_ED448)
    private val rsaEnc = AddSubkeyChoice.Classical(ClassicalSubkeyType.RSA_4096_ENCRYPT)
    private val edSign = AddSubkeyChoice.Classical(ClassicalSubkeyType.ED25519_SIGN)

    @Test
    fun `the v6 menu is unchanged and the v4 menu holds only what v4 can`() {
        // 4.8.0 RC10 (#109): the same list Add subkey shows for a v6 key.
        assertEquals(
            AddSubkeyChoice.optionsFor(AddSubkeyChoice.Base.V6),
            GranularComposer.menu(baseV6 = true, chosen = emptyList())
        )
        val v4 = GranularComposer.menu(baseV6 = false, chosen = emptyList())
        assertTrue("v4 offers RSA", v4.contains(rsaEnc))
        assertTrue("v4 offers ML-KEM-768", v4.contains(mlkem768))
        assertFalse("v4 has no ML-DSA", v4.any { it is AddSubkeyChoice.PqSigning })
        assertFalse("v4 has no ML-KEM-1024", v4.contains(mlkem1024))
        assertFalse(
            "a v4 key takes one ML-KEM-768 subkey",
            GranularComposer.menu(baseV6 = false, chosen = listOf(mlkem768)).any { it is AddSubkeyChoice.PqEncryption }
        )
    }

    @Test
    fun `switching to v4 keeps only what v4 can hold`() {
        assertEquals(
            listOf(edSign, mlkem768),
            GranularComposer.keptForV4(listOf(mldsa87, edSign, mlkem1024, mlkem768, mlkem768))
        )
        assertEquals(listOf(rsaEnc), GranularComposer.keptForV4(listOf(rsaEnc)))
    }

    @Test
    fun `the default encryption subkey is off for a post-quantum only list`() {
        assertTrue("an empty list keeps it", GranularComposer.defaultEncryptionSubkey(emptyList()))
        assertFalse(GranularComposer.defaultEncryptionSubkey(listOf(mlkem768)))
        assertFalse(GranularComposer.defaultEncryptionSubkey(listOf(mlkem1024, mldsa87)))
        assertTrue("a classical subkey in the list keeps it", GranularComposer.defaultEncryptionSubkey(listOf(mlkem768, edSign)))
        assertTrue("no post-quantum encryption subkey keeps it", GranularComposer.defaultEncryptionSubkey(listOf(mldsa87)))
    }

    // ── 4.8.0 RC10 (#109) ────────────────────────────────────────────

    private val bpAuth = AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_BP384_AUTH)
    private val p256Sign = AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_P256_SIGN)

    @Test
    fun `the v4 menu is the Add subkey list for a v4 key, with the chosen curve`() {
        for (curve in com.pgpony.android.crypto.KeyAlgorithm.generatableEcdsa) {
            assertEquals(
                AddSubkeyChoice.optionsFor(AddSubkeyChoice.Base.V4, curve),
                GranularComposer.menu(baseV6 = false, chosen = emptyList(), curve = curve)
            )
        }
        val bp = GranularComposer.menu(false, emptyList(), com.pgpony.android.crypto.KeyAlgorithm.ECDSA_BRAINPOOL_P384)
        assertTrue(bp.contains(bpAuth))
        assertTrue(bp.contains(AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDH_BP384_ENCRYPT)))
        assertFalse("v6 has no ECDSA", GranularComposer.menu(true, emptyList()).any {
            it is AddSubkeyChoice.Classical && it.type.curve != null
        })
    }

    @Test
    fun `ECDSA subkeys stay on v4 and leave on v6`() {
        assertEquals(listOf(bpAuth, p256Sign, rsaEnc), GranularComposer.keptForV4(listOf(bpAuth, p256Sign, rsaEnc)))
        assertEquals(listOf(edSign, mldsa87), GranularComposer.keptForV6(listOf(bpAuth, edSign, rsaEnc, p256Sign, mldsa87)))
    }
}
