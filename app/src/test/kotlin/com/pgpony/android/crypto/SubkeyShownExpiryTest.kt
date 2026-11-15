// SubkeyShownExpiryTest.kt
// PGPony Android, 4.8.1 (#120): Key Details labelled subkeys Expired under an
// expiry date still to come. The date on a Bouncy Castle row came from
// PGPPublicKey.validSeconds, which takes the latest expiry in any binding,
// while the Expired label comes from the newest verified binding
// (CertificateBindings). A subkey whose newest binding expires sooner than an
// older one showed both at once. The row now shows the expiry the label reads.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class SubkeyShownExpiryTest {

    private val day = 86_400L
    private val nowS = System.currentTimeMillis() / 1000L
    private val created = nowS - 800 * day

    private fun ed(at: Long) = BcPGPKeyPair(
        PublicKeyAlgorithmTags.EDDSA_LEGACY,
        Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(),
        Date(at * 1000L)
    )

    private fun x(at: Long) = BcPGPKeyPair(
        PublicKeyAlgorithmTags.ECDH,
        X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(),
        Date(at * 1000L)
    )

    /**
     * An encryption subkey bound twice: first (at creation) to expire in
     * [firstExpiry] seconds, then [laterAt] with [laterExpiry] (null: none).
     */
    private fun twiceBound(firstExpiry: Long, laterAt: Long, laterExpiry: Long?): Pair<ByteArray, PGPPublicKey> {
        val primary = ed(created)
        val hashed = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
            setSignatureCreationTime(false, Date(created * 1000L))
        }.generate()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, primary, "Twice <twice@pgpony.test>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), hashed, null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256), null
        )
        val flags = KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE
        gen.addSubKey(x(created), PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, flags)
            setSignatureCreationTime(false, Date(created * 1000L))
            setKeyExpirationTime(false, firstExpiry)
        }.generate(), null)
        val ring = gen.generatePublicKeyRing()
        val sub = ring.publicKeys.asSequence().first { !it.isMasterKey }
        val sig = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256), primary.publicKey
        ).apply {
            init(PGPSignature.SUBKEY_BINDING, primary.privateKey)
            setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, flags)
                setSignatureCreationTime(false, Date(laterAt * 1000L))
                if (laterExpiry != null) setKeyExpirationTime(false, laterExpiry)
            }.generate())
        }.generateCertification(primary.publicKey, sub)
        val rebound = PGPPublicKey.addCertification(sub, sig)
        val out = PGPPublicKeyRing.insertPublicKey(ring, rebound)
        return out.encoded to rebound
    }

    private fun fp(k: PGPPublicKey) = k.fingerprint.joinToString("") { "%02X".format(it) }

    private fun bcExpiry(k: PGPPublicKey): Long? = k.validSeconds.takeIf { it > 0 }?.let { k.creationTime.time + it * 1000L }

    @Test
    fun `a newer binding that shortened the expiry is the one shown`() {
        val (raw, sub) = twiceBound(firstExpiry = 2000 * day, laterAt = created + 100 * day, laterExpiry = 400 * day)
        val report = CertificateBindings.analyze(raw)!!
        val longer = (created + 2000 * day) * 1000L
        val shorter = (created + 400 * day) * 1000L
        // What the row showed in 4.8.0, next to the label below.
        assertEquals(longer, bcExpiry(sub))
        assertEquals(SubkeyAdmission.Issue.EXPIRED, SubkeyAdmission.issueIn(raw, report, fp(sub), System.currentTimeMillis()))
        assertEquals(shorter, SubkeyAdmission.shownExpiry(report, fp(sub), bcExpiry(sub)))
    }

    @Test
    fun `a newer binding with no expiry shows never`() {
        val (raw, sub) = twiceBound(firstExpiry = 400 * day, laterAt = created + 100 * day, laterExpiry = null)
        val report = CertificateBindings.analyze(raw)!!
        assertEquals(null, SubkeyAdmission.issueIn(raw, report, fp(sub), System.currentTimeMillis()))
        assertNull(SubkeyAdmission.shownExpiry(report, fp(sub), bcExpiry(sub)))
    }

    @Test
    fun `a renewed subkey shows the renewal`() {
        val (raw, sub) = twiceBound(firstExpiry = 400 * day, laterAt = created + 390 * day, laterExpiry = 2000 * day)
        val report = CertificateBindings.analyze(raw)!!
        assertEquals((created + 2000 * day) * 1000L, SubkeyAdmission.shownExpiry(report, fp(sub), bcExpiry(sub)))
        assertEquals(null, SubkeyAdmission.issueIn(raw, report, fp(sub), System.currentTimeMillis()))
    }

    @Test
    fun `without a report the row keeps its own date`() {
        assertEquals(1234L, SubkeyAdmission.shownExpiry(null, "AB", 1234L))
    }
}
