// LookupFilterTest.kt
// PGPony Android, 4.6.0 (item 17.8)
//
// A WKD answer is trusted only as far as it matches the address asked for,
// WKD hashing lowercases ASCII only, and the background refresh batch covers
// the keyring about weekly without ever sending all of it at once.

package com.pgpony.android.network

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.sync.KeyRefreshWorker
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LookupFilterTest {

    private val svc = PGPCryptoService.shared

    private fun withSecondUid(k: com.pgpony.android.crypto.GeneratedKeyResult, uid: String): ByteArray {
        val sec = PGPSecretKeyRing(k.privateKeyData, BcKeyFingerprintCalculator())
        val sk = sec.secretKey
        val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey)
        g.init(PGPSignature.POSITIVE_CERTIFICATION, sk.extractPrivateKey(null))
        val cert = g.generateCertification(uid, sk.publicKey)
        val pub = PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
        return PGPPublicKeyRing.insertPublicKey(pub, PGPPublicKey.addCertification(pub.publicKey, uid, cert)).encoded
    }

    private fun uids(armored: String): List<String> =
        PGPPublicKeyRing(ArmoredInputStream(armored.byteInputStream()).readBytes(), BcKeyFingerprintCalculator())
            .publicKey.userIDs.asSequence().toList()

    @Test
    fun `a WKD answer keeps only the queried address`() {
        val k = svc.generateKeyPair("Alice", "alice@example.org", KeyAlgorithm.ED25519_CV25519, null)
        val both = withSecondUid(k, "Alice Other <ceo@bank.example>")
        val out = WkdService().filterToAddress(both, "Alice@example.org")!!
        assertEquals(listOf("Alice <alice@example.org>"), uids(out))
    }

    @Test
    fun `a WKD answer for someone else is refused`() {
        val k = svc.generateKeyPair("Mallory", "mallory@evil.example", KeyAlgorithm.ED25519_CV25519, null)
        assertNull(WkdService().filterToAddress(k.publicKeyData, "alice@example.org"))
    }

    @Test
    fun `address matching lowercases ASCII only`() {
        assertEquals("Äbc@x.org", CertificateBindings.asciiLower("ÄBC@X.ORG"))
        assertEquals("a@b.c", CertificateBindings.mailboxOf("Name <A@B.C>"))
    }

    @Test
    fun `refresh batches cover the keyring about weekly and never all at once`() {
        assertEquals(1, KeyRefreshWorker.batchSize(1, 3))
        assertEquals(5, KeyRefreshWorker.batchSize(10, 3))
        assertEquals(12, KeyRefreshWorker.batchSize(200, 3))
        assertEquals(0, KeyRefreshWorker.batchSize(0, 3))
        assertTrue(KeyRefreshWorker.batchSize(3, 7) <= 3)
    }
}
