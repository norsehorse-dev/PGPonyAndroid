// CardPrimaryEditTest.kt
// 4.8.0 (#71): the edits a primary key signs, when the primary is in an OpenPGP
// card's Signature slot and the phone keeps only a divert-to-card stub for it.
//
// The card is stood in for by a PGPContentSignerBuilder that signs with a
// software copy of the primary and records that it was called. It is handed to
// the edits exactly the way CardPrimarySigner hands them the card's
// CardPGPContentSignerBuilder: through PrimarySigner.external, so Bouncy Castle
// is initialised with the placeholder private key that carries no secret, as
// on a card. Each new signature is checked with the primary's public key, and
// the stored stubs are checked to still be stubs.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.card.CardPrimarySigner
import com.pgpony.android.crypto.card.KeyToCard
import com.pgpony.android.data.RevocationReason
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.PGPContentSigner
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream

class CardPrimaryEditTest {

    /** Stands in for the card: signs with [primaryPrivate], records each call. */
    private class FakeCardBuilder(
        private val primaryPrivate: PGPPrivateKey,
        private val algorithm: Int
    ) : PGPContentSignerBuilder {
        var calls = 0
        var gotSecretMaterial = false

        override fun build(signatureType: Int, privateKey: PGPPrivateKey?): PGPContentSigner {
            calls++
            // The card path passes a placeholder with no secret, as CardSigningService does.
            if (privateKey?.privateKeyDataPacket != null) gotSecretMaterial = true
            return BcPGPContentSignerBuilder(algorithm, HashAlgorithmTags.SHA256).build(signatureType, primaryPrivate)
        }
    }

    private class Fixture(
        val publicRing: PGPPublicKeyRing,
        /** Every secret key a divert-to-card stub, as after Move to security key with Remove. */
        val stubRing: PGPSecretKeyRing,
        val card: FakeCardBuilder,
        val signer: PrimarySigner
    ) {
        val primary: PGPPublicKey get() = publicRing.publicKey
    }

    private companion object {
        const val NEW_PASSPHRASE = "new subkey passphrase"
    }

    private val aid = KeyToCard.hexToBytes("D2760001240103040006123456780000")

    private fun fixture(): Fixture {
        val gen = PGPCryptoService.shared.generateKeyPair(
            "Card Primary", "card@pgpony.app", KeyAlgorithm.ED25519_CV25519, passphrase = null
        )
        val secret = PGPSecretKeyRing(ByteArrayInputStream(gen.privateKeyData), JcaKeyFingerprintCalculator())
        val public = PGPPublicKeyRing(ByteArrayInputStream(gen.publicKeyData), JcaKeyFingerprintCalculator())
        val primaryPrivate = SecretKeyUnlock.extract(secret.secretKey, null)!!
        var stubs = secret
        for (sk in secret.secretKeys.asSequence().toList()) {
            stubs = PGPSecretKeyRing.insertSecretKey(stubs, KeyToCard.divertToCardStub(sk, aid))
        }
        assertTrue(OfflineStub.allStubs(stubs))
        val card = FakeCardBuilder(primaryPrivate, public.publicKey.algorithm)
        return Fixture(public, stubs, card, PrimarySigner.external(public.publicKey, card))
    }

    private fun reparse(ring: PGPPublicKeyRing): PGPPublicKeyRing =
        PGPPublicKeyRing(ByteArrayInputStream(ring.encoded), JcaKeyFingerprintCalculator())

    private fun reparse(ring: PGPSecretKeyRing): PGPSecretKeyRing =
        PGPSecretKeyRing(ByteArrayInputStream(ring.encoded), JcaKeyFingerprintCalculator())

    private fun newestBinding(sub: PGPPublicKey): PGPSignature =
        sub.signatures.asSequence().filter { it.signatureType == PGPSignature.SUBKEY_BINDING }
            .maxByOrNull { it.creationTime }!!

    private fun assertStubsKept(f: Fixture, secretRing: PGPSecretKeyRing?) {
        assertNotNull("the stored stub ring is carried through the edit", secretRing)
        val ring = reparse(secretRing!!)
        assertTrue("the primary is still a divert-to-card stub", OfflineStub.isCardStub(ring.secretKey))
        for (old in f.stubRing.secretKeys) {
            val now = ring.getSecretKey(old.keyID)
            assertNotNull(now)
            assertTrue("stub ${java.lang.Long.toHexString(old.keyID)} is still a stub", OfflineStub.isCardStub(now))
        }
    }

    private fun assertCardSigned(f: Fixture, atLeast: Int = 1) {
        assertTrue("expected at least $atLeast card signatures, got ${f.card.calls}", f.card.calls >= atLeast)
        assertFalse("the card path must not hand Bouncy Castle a secret", f.card.gotSecretMaterial)
        assertTrue(f.signer.external)
    }

    @Test
    fun `add an encryption subkey with a stub primary binds it on the card path`() {
        val f = fixture()
        val edit = ClassicalSubkeyGen.addSubkeyWith(
            f.signer, f.stubRing, f.publicRing,
            ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT, passphrase = NEW_PASSPHRASE
        )
        assertCardSigned(f)

        val pub = reparse(edit.publicRing)
        val oldIds = f.publicRing.publicKeys.asSequence().map { it.keyID }.toSet()
        val added = pub.publicKeys.asSequence().filter { it.keyID !in oldIds }.toList()
        assertEquals(1, added.size)
        val sub = added.single()
        assertFalse(sub.isMasterKey)

        val binding = newestBinding(sub)
        binding.init(BcPGPContentVerifierBuilderProvider(), pub.publicKey)
        assertTrue("the 0x18 binding verifies with the primary public key", binding.verifyCertification(pub.publicKey, sub))
        assertEquals(f.primary.keyID, binding.keyID)

        assertStubsKept(f, edit.secretRing)
        val secret = reparse(edit.secretRing!!)
        val newSecret = secret.getSecretKey(sub.keyID)
        assertNotNull("the new subkey's secret is on the phone", newSecret)
        assertFalse(OfflineStub.isStub(newSecret))
        assertTrue("the new subkey's secret is protected", newSecret.s2KUsage.toInt() != 0)
        assertNotNull(SecretKeyUnlock.extract(newSecret, NEW_PASSPHRASE.toCharArray()))
        assertFalse("the ring is no longer all stubs", OfflineStub.allStubs(secret))
    }

    @Test
    fun `add subkey on an all-on-card key protects the new secret with the chosen passphrase`() {
        val f = fixture()
        val edit = ClassicalSubkeyGen.addSubkeyWith(
            f.signer, f.stubRing, f.publicRing,
            ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH, passphrase = NEW_PASSPHRASE
        )
        val secret = reparse(edit.secretRing!!)
        val oldIds = f.stubRing.secretKeys.asSequence().map { it.keyID }.toSet()
        val added = secret.secretKeys.asSequence().single { it.keyID !in oldIds }
        assertFalse(OfflineStub.isStub(added))
        assertTrue("never stored unprotected", added.s2KUsage.toInt() != 0)
        assertNotNull("unlocks with the chosen passphrase", SecretKeyUnlock.extract(added, NEW_PASSPHRASE.toCharArray()))
        val wrong = try {
            SecretKeyUnlock.extract(added, "not it".toCharArray())
        } catch (e: org.bouncycastle.openpgp.PGPException) {
            null
        }
        assertNull("a wrong passphrase does not unlock it", wrong)
        assertTrue(PGPCryptoService.shared.isPassphraseProtected(secret))
        assertStubsKept(f, edit.secretRing)
    }

    @Test
    fun `add subkey on an all-on-card key refuses to store the secret without a passphrase`() {
        val f = fixture()
        for (missing in listOf(null, "")) {
            try {
                ClassicalSubkeyGen.addSubkeyWith(
                    f.signer, f.stubRing, f.publicRing,
                    ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT, passphrase = missing
                )
                fail("a new subkey with no passphrase must be refused")
            } catch (e: ClassicalSubkeyGen.SubkeyAddError) {
                assertEquals(ClassicalSubkeyGen.PASSPHRASE_REQUIRED_MESSAGE, e.message)
            }
        }
        assertEquals("nothing is signed on the card before the check", 0, f.card.calls)
    }

    @Test
    fun `a signing subkey gets its back-signature from the new subkey`() {
        val f = fixture()
        val edit = ClassicalSubkeyGen.addSubkeyWith(
            f.signer, f.stubRing, f.publicRing,
            ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN, passphrase = NEW_PASSPHRASE
        )
        // Only the binding is the primary's; the back-signature is the subkey's own.
        assertEquals(1, f.card.calls)
        val pub = reparse(edit.publicRing)
        val oldIds = f.publicRing.publicKeys.asSequence().map { it.keyID }.toSet()
        val sub = pub.publicKeys.asSequence().single { it.keyID !in oldIds }
        val binding = newestBinding(sub)
        binding.init(BcPGPContentVerifierBuilderProvider(), pub.publicKey)
        assertTrue(binding.verifyCertification(pub.publicKey, sub))
        val embedded = binding.hashedSubPackets.embeddedSignatures
        assertTrue("a signing subkey carries the 0x19 back-signature", embedded.size() > 0)
        val back = embedded[0]
        assertEquals(PGPSignature.PRIMARYKEY_BINDING, back.signatureType)
        back.init(BcPGPContentVerifierBuilderProvider(), sub)
        assertTrue("the back-signature verifies with the new subkey", back.verifyCertification(pub.publicKey, sub))
        assertStubsKept(f, edit.secretRing)
    }

    @Test
    fun `add a User ID with a stub primary self-certifies it on the card path`() {
        val f = fixture()
        val uid = "Second Name <second@pgpony.app>"
        val edit = UserIdService.shared.addUserIdWith(f.signer, f.stubRing, f.publicRing, uid, makePrimary = false)
        assertCardSigned(f)

        val primary = reparse(edit.publicRing).publicKey
        assertTrue(primary.userIDs.asSequence().any { it == uid })
        val cert = primary.getSignaturesForID(uid).asSequence()
            .single { it.signatureType == PGPSignature.POSITIVE_CERTIFICATION }
        cert.init(BcPGPContentVerifierBuilderProvider(), primary)
        assertTrue("the 0x13 self-certification verifies", cert.verifyCertification(uid, primary))
        // Every self-certification the edit re-issued verifies too.
        for (id in primary.userIDs) {
            primary.getSignaturesForID(id).asSequence().filter { it.keyID == primary.keyID }.forEach { sig ->
                sig.init(BcPGPContentVerifierBuilderProvider(), primary)
                assertTrue("self-signature on $id verifies", sig.verifyCertification(id, primary))
            }
        }
        assertStubsKept(f, edit.secretRing)
    }

    @Test
    fun `change the expiry with a stub primary re-signs every User ID and the subkey on the card path`() {
        val f = fixture()
        val expiresAt = System.currentTimeMillis() / 1000L + 400L * 24 * 60 * 60
        val edit = KeyExpirationService.shared.setExpirationWith(
            f.signer, f.publicRing, f.stubRing, expiresAt, KeyExpirationService.Target.Primary(currentSubkeys = true)
        )
        val uidCount = f.publicRing.publicKey.userIDs.asSequence().count()
        val subCount = f.publicRing.publicKeys.asSequence().count { !it.isMasterKey }
        // One card signature per User ID and per subkey binding, each its own PSO:CDS.
        assertCardSigned(f, atLeast = uidCount + subCount)

        val ring = reparse(edit.publicRing)
        val primary = ring.publicKey
        assertTrue("the primary now expires", primary.validSeconds > 0L)
        val expectedSeconds = expiresAt - primary.creationTime.time / 1000L
        assertEquals(expectedSeconds, primary.validSeconds)
        for (id in primary.userIDs) {
            val newest = primary.getSignaturesForID(id).asSequence()
                .filter { it.keyID == primary.keyID }.maxByOrNull { it.creationTime }!!
            newest.init(BcPGPContentVerifierBuilderProvider(), primary)
            assertTrue(newest.verifyCertification(id, primary))
        }
        ring.publicKeys.asSequence().filter { !it.isMasterKey }.forEach { sub ->
            val binding = newestBinding(sub)
            binding.init(BcPGPContentVerifierBuilderProvider(), primary)
            assertTrue(binding.verifyCertification(primary, sub))
            assertTrue("subkey ${java.lang.Long.toHexString(sub.keyID)} expires", sub.validSeconds > 0L)
        }
        assertStubsKept(f, edit.secretRing)
    }

    @Test
    fun `change one subkey's expiry on the card path`() {
        val f = fixture()
        val sub = f.publicRing.publicKeys.asSequence().first { !it.isMasterKey }
        val expiresAt = System.currentTimeMillis() / 1000L + 100L * 24 * 60 * 60
        val edit = KeyExpirationService.shared.setExpirationWith(
            f.signer, f.publicRing, f.stubRing, expiresAt, KeyExpirationService.Target.Subkey(sub.keyID)
        )
        assertEquals("only the subkey's binding is signed", 1, f.card.calls)
        val ring = reparse(edit.publicRing)
        val updated = ring.getPublicKey(sub.keyID)
        val binding = newestBinding(updated)
        binding.init(BcPGPContentVerifierBuilderProvider(), ring.publicKey)
        assertTrue(binding.verifyCertification(ring.publicKey, updated))
        assertEquals(expiresAt - updated.creationTime.time / 1000L, updated.validSeconds)
        assertEquals("the primary's expiry is untouched", f.primary.validSeconds, ring.publicKey.validSeconds)
        assertStubsKept(f, edit.secretRing)
    }

    @Test
    fun `refresh re-signs on the card path and keeps every expiry`() {
        val f = fixture()
        val edit = KeyExpirationService.shared.setExpirationWith(
            f.signer, f.publicRing, f.stubRing, null, KeyExpirationService.Target.Refresh
        )
        assertCardSigned(f, atLeast = 2)
        val ring = reparse(edit.publicRing)
        assertEquals(f.primary.validSeconds, ring.publicKey.validSeconds)
        ring.publicKeys.asSequence().filter { !it.isMasterKey }.forEach { sub ->
            val binding = newestBinding(sub)
            binding.init(BcPGPContentVerifierBuilderProvider(), ring.publicKey)
            assertTrue(binding.verifyCertification(ring.publicKey, sub))
        }
    }

    @Test
    fun `revoke a User ID and a subkey on the card path`() {
        val f = fixture()
        val second = "Second Name <second@pgpony.app>"
        val withSecond = UserIdService.shared.addUserIdWith(f.signer, f.stubRing, f.publicRing, second, makePrimary = false)
        val revokedUid = UserIdService.shared.revokeUserIdWith(
            f.signer, withSecond.secretRing, reparse(withSecond.publicRing), second, RevocationReason.USER_ID_INVALID, null
        )
        val primary = reparse(revokedUid.publicRing).publicKey
        assertTrue(UserIdService.shared.isRevoked(primary, second))
        val rev = primary.getSignaturesForID(second).asSequence()
            .single { it.signatureType == PGPSignature.CERTIFICATION_REVOCATION }
        rev.init(BcPGPContentVerifierBuilderProvider(), primary)
        assertTrue("the 0x30 verifies", rev.verifyCertification(second, primary))

        val sub = f.publicRing.publicKeys.asSequence().first { !it.isMasterKey }
        val revokedSub = RevocationService.shared.revokeSubkeyWith(
            f.signer, f.publicRing, f.stubRing, sub.keyID, RevocationReason.RETIRED, null
        )
        val ring = reparse(revokedSub.publicRing)
        val target = ring.getPublicKey(sub.keyID)
        assertTrue(target.hasRevocation())
        val subRev = target.signatures.asSequence().single { it.signatureType == PGPSignature.SUBKEY_REVOCATION }
        subRev.init(BcPGPContentVerifierBuilderProvider(), ring.publicKey)
        assertTrue("the 0x28 verifies", subRev.verifyCertification(ring.publicKey, target))
        assertStubsKept(f, revokedSub.secretRing)
        assertCardSigned(f, atLeast = 3)
    }

    @Test
    fun `the card has to hold the primary in its Signature slot`() {
        val f = fixture()
        val fp = f.primary.fingerprint
        val hex = org.bouncycastle.util.encoders.Hex.toHexString(fp)
        assertTrue(CardPrimarySigner.slotHolds(hex.uppercase(), fp))
        assertTrue(CardPrimarySigner.slotHolds(hex.chunked(4).joinToString(" "), fp))
        val sub = f.publicRing.publicKeys.asSequence().first { !it.isMasterKey }
        assertFalse(CardPrimarySigner.slotHolds(org.bouncycastle.util.encoders.Hex.toHexString(sub.fingerprint), fp))
        assertFalse(CardPrimarySigner.slotHolds(null, fp))
    }

    @Test
    fun `the passphrase path is unchanged for a primary on the phone`() {
        val gen = PGPCryptoService.shared.generateKeyPair(
            "Phone Primary", "phone@pgpony.app", KeyAlgorithm.ED25519_CV25519, passphrase = "pass phrase"
        )
        val secret = PGPSecretKeyRing(ByteArrayInputStream(gen.privateKeyData), JcaKeyFingerprintCalculator())
        val public = PGPPublicKeyRing(ByteArrayInputStream(gen.publicKeyData), JcaKeyFingerprintCalculator())
        val uid = "Other <other@pgpony.app>"
        val updated = UserIdService.shared.addUserId(secret, public, uid, makePrimary = false, passphrase = "pass phrase")
        val primary = updated.publicRing.publicKey
        val cert = primary.getSignaturesForID(uid).asSequence()
            .single { it.signatureType == PGPSignature.POSITIVE_CERTIFICATION }
        cert.init(BcPGPContentVerifierBuilderProvider(), primary)
        assertTrue(cert.verifyCertification(uid, primary))
        assertFalse(OfflineStub.isStub(updated.secretRing.secretKey))
    }
}
