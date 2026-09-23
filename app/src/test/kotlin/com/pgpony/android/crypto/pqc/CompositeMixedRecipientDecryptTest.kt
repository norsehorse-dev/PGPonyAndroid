// CompositeMixedRecipientDecryptTest.kt
// PGPony Android — 4.5.0 RC7 (a tester, PGPony Android 4.4.1 feedback)
//
// A MIXED multi-recipient message: one classical recipient and one composite
// (post-quantum) recipient. A holder of only the CLASSICAL key must still be
// able to decrypt it. Before RC7 the composite path found no held composite
// key, threw "no held composite secret key", and BouncyCastle could not parse
// past the composite PKESK to reach the classical one, so the classical holder
// failed. RC7 strips the composite PKESKs and lets BC open the classical slot.
//
// A tester reported that any multi-recipient message with a post-quantum key in
// it failed to decrypt, while an all-classical message worked. This covers the
// half of that where the held key is the classical one; the all-composite half
// is CompositeMultiRecipientDecryptTest / CompositeLibrePGPMultiRecipientDecryptTest.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.io.ByteArrayInputStream

class CompositeMixedRecipientDecryptTest {

    private val svc = PGPCryptoService.shared

    private fun secretRing(bytes: ByteArray): PGPSecretKeyRing =
        PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(bytes)),
            JcaKeyFingerprintCalculator()
        )

    private fun keypair(name: String, algorithm: KeyAlgorithm): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val gen = svc.generateKeyPair(name, "$name@pgpony.app", algorithm, null)
        val sec = secretRing(gen.privateKeyData)
        val pub = PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
        return sec to pub
    }

    /** Encrypt to [classical] + [composite]; both a classical-only holder and a
     *  composite-only holder must decrypt. */
    private fun mixedDecrypts(compositeAlgorithm: KeyAlgorithm) {
        val (secClassical, pubClassical) = keypair("classical", KeyAlgorithm.ED25519_CV25519)
        val (secComposite, pubComposite) = keypair("composite", compositeAlgorithm)
        val plaintext = "mixed classical + composite recipients (tester report)".toByteArray()

        val message = svc.encrypt(plaintext, listOf(pubClassical, pubComposite))

        val asClassical = svc.decrypt(message, listOf(secClassical), passphrase = null)
        assertArrayEquals(
            "classical-key holder must open a mixed message with a composite co-recipient",
            plaintext, asClassical.data
        )

        val asComposite = svc.decrypt(message, listOf(secComposite), passphrase = null)
        assertArrayEquals(
            "composite-key holder must open the same message",
            plaintext, asComposite.data
        )
    }

    @Test
    fun `classical holder decrypts a mix with a LibrePGP composite co-recipient`() {
        mixedDecrypts(KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
    }

    @Test
    fun `classical holder decrypts a mix with an IETF composite co-recipient`() {
        mixedDecrypts(KeyAlgorithm.MLKEM768_X25519_V6)
    }
}
