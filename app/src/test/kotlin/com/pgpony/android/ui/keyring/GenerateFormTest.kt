// GenerateFormTest.kt
// PGPony Android, 4.8.0 RC11 (#109): the Generate Key form keeps the primary
// the user picked. KeyringViewModel's updateGenerateAlgorithm,
// toggleGenerateGranular and useSimpleGenerate are GenerateForm.withAlgorithm,
// withCompose and simple.

package com.pgpony.android.ui.keyring

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GenerateFormTest {

    private val bpAuth = AddSubkeyChoice.Classical(ClassicalSubkeyType.ECDSA_BP384_AUTH)
    private val mldsa = AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA65_ED25519)

    @Test fun `turning compose on or off never changes the picked primary`() {
        for (algorithm in KeyAlgorithm.generatable) {
            var s = GenerateForm.withAlgorithm(KeyringUiState(), algorithm)
            s = GenerateForm.withCompose(s, true)
            assertEquals("$algorithm on", algorithm, s.generateAlgorithm)
            s = GenerateForm.withCompose(s, false)
            assertEquals("$algorithm off", algorithm, s.generateAlgorithm)
        }
    }

    @Test fun `a primary that can't be composed turns compose off and clears it`() {
        val p256 = GenerateForm.withCompose(GenerateForm.withAlgorithm(KeyringUiState(), KeyAlgorithm.ECDSA_NIST_P256), true)
            .copy(granularSubkeys = listOf(bpAuth), granularCertifyOnly = true)
        assertTrue(GenerateForm.composes(p256))
        val pq = GenerateForm.withAlgorithm(p256, KeyAlgorithm.MLDSA65_ED25519_V6)
        assertFalse(pq.generateGranular)
        assertFalse(GenerateForm.composes(pq))
        assertTrue(pq.granularSubkeys.isEmpty())
        assertFalse(pq.granularCertifyOnly)
        assertFalse("nothing comes back on its own", GenerateForm.composes(GenerateForm.withAlgorithm(pq, KeyAlgorithm.ECDSA_NIST_P256)))
    }

    @Test fun `a new primary drops what it can't hold and names it`() {
        val start = GenerateForm.withAlgorithm(KeyringUiState(), KeyAlgorithm.ECDSA_BRAINPOOL_P384)
            .copy(generateGranular = true, granularSubkeys = listOf(bpAuth))
        val v6 = GenerateForm.withAlgorithm(start, KeyAlgorithm.V6_ED25519)
        assertEquals(emptyList<AddSubkeyChoice>(), v6.granularSubkeys)
        assertEquals(listOf<AddSubkeyChoice>(bpAuth), v6.granularDroppedSubkeys)
        val back = GenerateForm.withAlgorithm(v6.copy(granularSubkeys = listOf(mldsa)), KeyAlgorithm.ECDSA_BRAINPOOL_P384)
        assertEquals(KeyAlgorithm.ECDSA_BRAINPOOL_P384, back.generateAlgorithm)
        assertEquals(listOf<AddSubkeyChoice>(mldsa), back.granularDroppedSubkeys)
        val kept = GenerateForm.withAlgorithm(start, KeyAlgorithm.ECDSA_NIST_P384)
        assertEquals(listOf<AddSubkeyChoice>(bpAuth), kept.granularSubkeys)
        assertTrue(kept.granularDroppedSubkeys.isEmpty())
    }

    @Test fun `onboarding's plain key resets compose, the auth subkey and the expiry`() {
        val s = GenerateForm.simple(
            KeyringUiState(generateGranular = true, generateAuthSubkey = true, generateAuthForSsh = true,
                generateExpiration = ExpirationOption.NEVER)
        )
        assertFalse(s.generateGranular)
        assertFalse(s.generateAuthSubkey)
        assertFalse(s.generateAuthForSsh)
        assertEquals(ExpirationOption.TWO_YEARS, s.generateExpiration)
    }
}
