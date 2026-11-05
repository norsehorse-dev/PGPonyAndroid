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
        assertEquals(
            AddSubkeyChoice.classicalFor(isV6 = true) + AddSubkeyChoice.postQuantumFor(isV6 = true),
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
}
