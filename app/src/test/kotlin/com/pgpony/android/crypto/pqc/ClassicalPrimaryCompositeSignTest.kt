// ClassicalPrimaryCompositeSignTest.kt
// PGPony Android, 4.8.0 (item 4j): signing with a composite ML-DSA signing
// subkey on a classical v6 Ed25519 primary.
//
// The subkey composer (and Add Subkey in Key Details) can put an ML-DSA-65 or
// ML-DSA-87 signing subkey on a v6 Ed25519 primary. The key is stored as a
// BouncyCastle ring whose composite subkey is an UnknownBCPGKey, and every sign
// path picks the newest valid signing subkey, which is the composite one.
// The base's own Ed25519 signing subkey is created in the same second as the
// composite one in a fast run, and the pick sorts by creation second, so the
// base is dated a minute back here: on a phone, keygen and Argon2 take long
// enough that the composite subkey is the newer one, which is what users hit.
// These tests sign through the same services the app calls (cleartext and
// detached through SigningService, inline through PGPCryptoService.sign) and
// check the result verifies against the composite subkey, with and without a
// passphrase, for both suites. A wrong passphrase must stay a wrong-passphrase
// error.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.GranularSubkeySpec
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SigningError
import com.pgpony.android.crypto.SigningService
import org.bouncycastle.bcpg.UnknownBCPGKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Date

class ClassicalPrimaryCompositeSignTest {

    private val svc = PGPCryptoService.shared
    private val signing = SigningService.shared
    private val pass = "correct horse"

    private fun composerKey(suite: CompositeSignSuite, passphrase: String?): PGPSecretKeyRing =
        svc.assembleGranularV6Ring(
            "Composer <composer@example.test>",
            includeDefaultEncryptionSubkey = true,
            subkeys = listOf(GranularSubkeySpec(AddSubkeyChoice.PqSigning(suite), null)),
            passphrase = passphrase,
            creationDate = Date(System.currentTimeMillis() - 60_000L)
        )

    private fun compositeSubkeyPublic(ring: PGPSecretKeyRing, suite: CompositeSignSuite): ByteArray {
        val sub = ring.publicKeys.asSequence().first { !it.isMasterKey && it.algorithm == suite.algId }
        return (sub.publicKeyPacket.key as UnknownBCPGKey).encoded
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }

    /** The signature verifies in CompositeSignerGate, the check the app, provider and share target run, credited to the subkey and its primary. */
    private fun assertGate(what: String, ring: PGPSecretKeyRing, suite: CompositeSignSuite, g: CompositeSignerGate.Graded) {
        val sub = ring.publicKeys.asSequence().first { !it.isMasterKey && it.algorithm == suite.algId }
        assertTrue("$what verifies in the gate: ${g.status}", g.verified)
        assertEquals("$what is credited to the composite subkey", hex(sub.fingerprint), g.signingKeyFingerprint)
        assertEquals("$what is credited to the Ed25519 primary", hex(ring.publicKey.fingerprint), g.signerPrimaryFingerprint)
    }

    private fun cert(ring: PGPSecretKeyRing): ByteArray = PGPPublicKeyRing(ring.publicKeys.asSequence().toList()).encoded

    private fun signsAndVerifies(suite: CompositeSignSuite, passphrase: String?) {
        val ring = composerKey(suite, passphrase)
        val subPublic = compositeSubkeyPublic(ring, suite)
        val certs = listOf(cert(ring))
        assertTrue("the stored certificate counts as a composite signer", CompositeSignerGate.hasCompositeSigningKey(certs[0]))
        assertEquals(
            "$suite the automatic pick is the composite subkey",
            suite.algId,
            svc.pickSigningSecretKey(ring)?.publicKey?.algorithm
        )
        val text = "Signed by the composite subkey.\n-a dash line\nlast line"
        val data = text.toByteArray(Charsets.UTF_8)

        val clear = signing.signClear(text, ring, passphrase)
        assertTrue(
            "$suite cleartext verifies against the composite subkey",
            CompositeDocumentVerifier.verifyCleartext(subPublic, clear).valid
        )
        assertGate("$suite cleartext", ring, suite, CompositeSignerGate.verifyCleartext(certs, clear))

        val detached = signing.signDetached(data, ring, passphrase, armor = false)
        assertTrue(
            "$suite detached verifies against the composite subkey",
            CompositeDocumentVerifier.verifyDetached(subPublic, detached, data).valid
        )
        assertGate("$suite detached", ring, suite, CompositeSignerGate.verifyDetached(certs, detached, data))

        val inline = svc.sign(data, ring, passphrase ?: "", detached = false, armor = false)
        assertTrue(
            "$suite inline verifies against the composite subkey",
            CompositeDocumentVerifier.verifyInline(subPublic, inline).valid
        )
        assertGate("$suite inline", ring, suite, CompositeSignerGate.verifyInline(certs, inline))

        val pub = PGPPublicKeyRing(ring.publicKeys.asSequence().toList())
        val encrypted = svc.encrypt(data, listOf(pub), signingSecretKey = ring, passphrase = passphrase, armor = false)
        val opened = svc.decrypt(encrypted, listOf(ring), passphrase)
        assertArrayEquals("$suite encrypt and sign decrypts", data, opened.data)
        val inner = opened.compositeInlineBytes
        assertTrue("$suite encrypt and sign carries a composite signature", opened.compositeInline && inner != null)
        assertGate("$suite encrypt and sign", ring, suite, CompositeSignerGate.verifyInline(certs, inner!!))
    }

    @Test
    fun `ML-DSA-87 + Ed448 subkey signs, no passphrase`() = signsAndVerifies(CompositeSignSuite.MLDSA87_ED448, null)

    @Test
    fun `ML-DSA-87 + Ed448 subkey signs, with passphrase`() = signsAndVerifies(CompositeSignSuite.MLDSA87_ED448, pass)

    @Test
    fun `ML-DSA-65 + Ed25519 subkey signs, no passphrase`() = signsAndVerifies(CompositeSignSuite.MLDSA65_ED25519, null)

    @Test
    fun `ML-DSA-65 + Ed25519 subkey signs, with passphrase`() = signsAndVerifies(CompositeSignSuite.MLDSA65_ED25519, pass)

    @Test
    fun `a wrong passphrase stays a wrong-passphrase error`() {
        val ring = composerKey(CompositeSignSuite.MLDSA87_ED448, pass)
        try {
            signing.signClear("text", ring, "wrong")
            fail("a wrong passphrase must not sign")
        } catch (e: SigningError.InvalidPassphrase) {
        }
    }
}
