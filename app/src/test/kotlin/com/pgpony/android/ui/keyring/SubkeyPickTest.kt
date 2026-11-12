// SubkeyPickTest.kt
// PGPony Android, 4.8.0 RC11 (#109): the subkey picker Add subkey and the
// composer share. A tester provisioning brainpool keys onto a security key
// needs an Authenticate subkey on the key's own curve; the picker should get
// there without a hunt through a long menu.

package com.pgpony.android.ui.keyring

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.AddSubkeyChoice.Usage
import com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SubkeyPickTest {

    private fun c(t: ClassicalSubkeyType) = AddSubkeyChoice.Classical(t)
    private val v4 = SubkeyPick.options(AddSubkeyChoice.Base.V4, primary = KeyAlgorithm.ED25519_CV25519)
    private val bp = KeyAlgorithm.ECDSA_BRAINPOOL_P384
    private val bpOpts = SubkeyPick.options(AddSubkeyChoice.Base.V4_OTHER, primary = bp)

    @Test fun `options hold every curve once, grouped by use`() {
        assertEquals(bpOpts, bpOpts.distinct())
        assertEquals(bpOpts.map { AddSubkeyChoice.usageOf(it).ordinal }.sorted(), bpOpts.map { AddSubkeyChoice.usageOf(it).ordinal })
        for (curve in KeyAlgorithm.generatableEcdsa) for (u in Usage.entries) {
            assertEquals("$curve $u", 1, bpOpts.count {
                it is AddSubkeyChoice.Classical && it.type.curve == curve && AddSubkeyChoice.usageOf(it) == u
            })
        }
        // Every option a single-curve list had is still here.
        for (curve in KeyAlgorithm.generatableEcdsa) {
            assertTrue(bpOpts.containsAll(AddSubkeyChoice.optionsFor(AddSubkeyChoice.Base.V4_OTHER, curve, primary = bp)))
        }
    }

    @Test fun `a brainpool key with signing and encryption starts on an Authenticate subkey on its curve`() {
        val start = SubkeyPick.start(bpOpts, SubkeyPick.haveFrom(listOf(0x04)), bp)
        assertEquals(c(ClassicalSubkeyType.ECDSA_BP384_AUTH), start)
    }

    @Test fun `the primary's family is the first type in each use`() {
        for (u in Usage.entries) assertEquals(SubkeyPick.Kind.EC, SubkeyPick.kinds(bpOpts, u).first())
        assertEquals(SubkeyPick.Kind.CURVE25519, SubkeyPick.kinds(v4, Usage.AUTHENTICATE).first())
        val rsa = SubkeyPick.options(AddSubkeyChoice.Base.V4_OTHER, primary = KeyAlgorithm.RSA_2048)
        assertEquals(SubkeyPick.Kind.RSA, SubkeyPick.kinds(rsa, Usage.SIGN).first())
        assertEquals("RSA 2048 primary starts on 2048", c(ClassicalSubkeyType.RSA_2048_AUTH),
            SubkeyPick.start(rsa, SubkeyPick.haveFrom(listOf(0x04)), KeyAlgorithm.RSA_2048))
    }

    @Test fun `changing the use keeps the type and the curve`() {
        val auth = c(ClassicalSubkeyType.ECDSA_BP384_AUTH)
        assertEquals(c(ClassicalSubkeyType.ECDH_BP384_ENCRYPT), SubkeyPick.withUsage(bpOpts, auth, Usage.ENCRYPT, bp))
        assertEquals(c(ClassicalSubkeyType.ECDSA_BP384_SIGN), SubkeyPick.withUsage(bpOpts, auth, Usage.SIGN, bp))
        // A curve picked away from the primary's stays picked.
        val p521 = c(ClassicalSubkeyType.ECDSA_P521_AUTH)
        assertEquals(c(ClassicalSubkeyType.ECDH_P521_ENCRYPT), SubkeyPick.withUsage(bpOpts, p521, Usage.ENCRYPT, bp))
        assertEquals(c(ClassicalSubkeyType.RSA_2048_ENCRYPT),
            SubkeyPick.withUsage(bpOpts, c(ClassicalSubkeyType.RSA_2048_SIGN), Usage.ENCRYPT, bp))
        assertEquals(c(ClassicalSubkeyType.X25519_ENCRYPT),
            SubkeyPick.withUsage(v4, c(ClassicalSubkeyType.ED25519_AUTH), Usage.ENCRYPT, KeyAlgorithm.ED25519_CV25519))
    }

    @Test fun `a type a use lacks falls back to the use's first type`() {
        val v6 = SubkeyPick.options(AddSubkeyChoice.Base.V6, primary = KeyAlgorithm.V6_ED25519)
        val mldsa = AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA87_ED448)
        // No post-quantum Authenticate subkey: Ed25519.
        assertEquals(c(ClassicalSubkeyType.ED25519_AUTH), SubkeyPick.withUsage(v6, mldsa, Usage.AUTHENTICATE, KeyAlgorithm.V6_ED25519))
        // ML-DSA-87 to encryption keeps the level: ML-KEM-1024.
        assertEquals(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_1024), SubkeyPick.withUsage(v6, mldsa, Usage.ENCRYPT, KeyAlgorithm.V6_ED25519))
    }

    @Test fun `changing the type keeps the variant where it can`() {
        val ecdsa = SubkeyPick.withKind(bpOpts, c(ClassicalSubkeyType.RSA_2048_AUTH), SubkeyPick.Kind.EC, bp)
        assertEquals("EC starts on the primary's curve", c(ClassicalSubkeyType.ECDSA_BP384_AUTH), ecdsa)
        assertEquals("RSA starts on 4096 off an RSA key", c(ClassicalSubkeyType.RSA_4096_AUTH),
            SubkeyPick.withKind(bpOpts, ecdsa!!, SubkeyPick.Kind.RSA, bp))
    }

    @Test fun `rows only show when there is a choice`() {
        val v6 = SubkeyPick.options(AddSubkeyChoice.Base.V6, primary = KeyAlgorithm.V6_ED25519)
        assertEquals(listOf(SubkeyPick.Kind.CURVE25519), SubkeyPick.kinds(v6, Usage.AUTHENTICATE))
        assertEquals(1, SubkeyPick.variants(v4, Usage.ENCRYPT, SubkeyPick.Kind.PQ).size)
        assertEquals(KeyAlgorithm.generatableEcdsa.size, SubkeyPick.variants(bpOpts, Usage.AUTHENTICATE, SubkeyPick.Kind.EC).size)
        assertEquals(2, SubkeyPick.variants(bpOpts, Usage.SIGN, SubkeyPick.Kind.RSA).size)
    }

    @Test fun `no post-quantum options on a card-linked key`() {
        val card = SubkeyPick.options(AddSubkeyChoice.Base.V4, postQuantum = false, primary = KeyAlgorithm.ED25519_CV25519)
        assertFalse(card.any { SubkeyPick.kindOf(it) == SubkeyPick.Kind.PQ })
    }

    @Test fun `have counts signing always and the uses of usable subkeys`() {
        assertEquals(setOf(Usage.SIGN), SubkeyPick.haveFrom(emptyList()))
        assertEquals(setOf(Usage.SIGN, Usage.ENCRYPT, Usage.AUTHENTICATE), SubkeyPick.haveFrom(listOf(0x04, 0x08)))
        val all = SubkeyPick.start(bpOpts, SubkeyPick.haveFrom(listOf(0x04, 0x08)), bp)
        assertEquals("every use covered: signing", c(ClassicalSubkeyType.ECDSA_BP384_SIGN), all)
    }
}
