// CompositeLibrePGPMultiRecipientDecryptTest.kt
// PGPony Android — 4.5.0 (a tester, PGPony Android 4.4.1 feedback)
//
// Regression for the multi-recipient LibrePGP composite (algorithm 8, v5)
// decrypt bug: a message encrypted to two LibrePGP composite recipients must
// decrypt for EACH recipient, not only whichever one's algo-8 PKESK is emitted
// first. Asserting BOTH recipients decrypt forces the "held key is not the
// first PKESK" case regardless of emit order.
//
// This is the same defect #57 fixed on the IETF algo-35/36 path, but in the
// separate CompositeLibrePGPDecryptor, which was still taking only the first
// PKESK (split() kept one, recover() tried one). A tester reported it on
// LibrePGP PQC keys generated in PGPony.

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

class CompositeLibrePGPMultiRecipientDecryptTest {

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
        val plaintext = "multi-recipient LibrePGP composite round-trip (tester report)".toByteArray()

        val message = svc.encrypt(plaintext, listOf(pubA, pubB))

        val asA = svc.decrypt(message, listOf(secA), passphrase = null)
        assertArrayEquals("first recipient must decrypt", plaintext, asA.data)

        val asB = svc.decrypt(message, listOf(secB), passphrase = null)
        assertArrayEquals("second recipient must also decrypt", plaintext, asB.data)
    }

    @Test
    fun `LibrePGP ML-KEM-768 both recipients decrypt a multi-recipient message`() {
        bothRecipientsDecrypt(KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
    }

    @Test
    fun `LibrePGP ML-KEM-1024 both recipients decrypt a multi-recipient message`() {
        bothRecipientsDecrypt(KeyAlgorithm.MLKEM1024_X448_LIBREPGP)
    }
}
