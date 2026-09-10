// CompositeMultiRecipientDecryptTest.kt
// PGPony Android — 4.5.0 RC1 (item 18 / issue #57)
//
// Regression for the multi-recipient composite decrypt bug: a message
// encrypted to two composite (ML-KEM + X25519/X448) recipients must decrypt
// for EACH recipient, not only whichever one's composite PKESK is emitted
// first. Asserting BOTH recipients decrypt forces the "held key is not the
// first PKESK" case regardless of emit order.
//
// WundreLust (#57) reported this on ML-KEM-1024 v6; the 768 case is included
// too since the bug was in PKESK iteration, not the KEM suite.

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

class CompositeMultiRecipientDecryptTest {

    private val svc = PGPCryptoService.shared

    private fun secretRing(bytes: ByteArray): PGPSecretKeyRing =
        PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(bytes)),
            JcaKeyFingerprintCalculator()
        )

    private fun composite(name: String, algorithm: KeyAlgorithm): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val gen = svc.generateKeyPair(name, "$name@pgpony.app", algorithm, null)
        val sec = secretRing(gen.privateKeyData)
        val pub = PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
        return sec to pub
    }

    private fun bothRecipientsDecrypt(algorithm: KeyAlgorithm) {
        val (secA, pubA) = composite("alice", algorithm)
        val (secB, pubB) = composite("bob", algorithm)
        val plaintext = "multi-recipient composite round-trip #57".toByteArray()

        val message = svc.encrypt(plaintext, listOf(pubA, pubB))

        val asA = svc.decrypt(message, listOf(secA), passphrase = null)
        assertArrayEquals("first recipient must decrypt", plaintext, asA.data)

        val asB = svc.decrypt(message, listOf(secB), passphrase = null)
        assertArrayEquals("second recipient must also decrypt", plaintext, asB.data)
    }

    @Test
    fun `ML-KEM-768 v6 both recipients decrypt a multi-recipient message`() {
        bothRecipientsDecrypt(KeyAlgorithm.MLKEM768_X25519_V6)
    }

    @Test
    fun `ML-KEM-1024 v6 both recipients decrypt a multi-recipient message`() {
        bothRecipientsDecrypt(KeyAlgorithm.MLKEM1024_X448_V6)
    }
}
