// CompositeAnonymousPkeskTest.kt
// PGPony Android, 4.2.0 RC2 workstream B (§3.4)
//
// Regression net for the composite wildcard trial: an anonymous (`gpg -R`
// style) PKESK for an IETF (algo 35/36) or LibrePGP (algo 8) composite
// recipient carries no identifying field, so the only way to resolve it is
// to trial every held composite secret key, exactly as the classical
// (RSA/ECDH) wildcard path in PGPCryptoService.resolvePkesk already does.
// Before this change both composite decryptors threw NoMatchingKey the
// instant they saw an anonymous PKESK, with no trial attempted at all.
//
// These tests exercise CompositeDecryptor/CompositeLibrePGPDecryptor at
// the recoverSessionKey level, using hand-built anonymous PKESK bytes (the
// same technique ProbeV4CompositeTest uses for its synthetic packets) so
// no encrypted body is needed: recoverSessionKey reads the ESK region
// alone.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

class CompositeAnonymousPkeskTest {

    private val svc = PGPCryptoService.shared
    private val rnd = SecureRandom()
    private val calc = JcaKeyFingerprintCalculator()

    private val sessionKey = ByteArray(32) { (it * 7 + 3).toByte() }

    private class Party(val pubRing: PGPPublicKeyRing, val secRing: PGPSecretKeyRing)

    private fun party(name: String, email: String, algo: KeyAlgorithm): Party {
        val k = svc.generateKeyPair(name, email, algo, null, null)
        return Party(
            PGPPublicKeyRing(ByteArrayInputStream(k.publicKeyData), calc),
            PGPSecretKeyRing(ByteArrayInputStream(k.privateKeyData), calc)
        )
    }

    // ── packet framing (new-format header, same shape as
    //    ProbeV4CompositeTest's, generalized to any tag/body) ───────────

    private fun uint32(v: Int) = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )

    private fun packet(tag: Int, body: ByteArray): ByteArray {
        val hdr = when {
            body.size < 192 -> byteArrayOf((0xC0 or tag).toByte(), body.size.toByte())
            body.size < 8384 -> {
                val l = body.size - 192
                byteArrayOf((0xC0 or tag).toByte(), (0xC0 or (l shr 8)).toByte(), (l and 0xFF).toByte())
            }
            else -> byteArrayOf((0xC0 or tag).toByte(), 0xFF.toByte()) + uint32(body.size)
        }
        return hdr + body
    }

    // ── IETF composite (algo 35, v6) ─────────────────────────────────

    /** An anonymous v6 algo-35 PKESK (CompositePkesk.PKESK_TAG), wrapping
     *  [sessionKey] for [party]'s composite subkey. */
    private fun anonymousIetfPkesk(party: Party): ByteArray {
        val sub = party.pubRing.publicKeys.asSequence().first { CompositeSuite.ietfFor(it.algorithm) != null }
        val (xPub, mPub) = CompositeKeyMaterial.publicMaterial(sub)!!
        val enc = CompositeKem.encapsulate(xPub, mPub, rnd, CompositeSuite.IETF_768)
        val wrapped = CompositeKem.wrapSessionKey(enc.kek, sessionKey)
        val body = CompositePkesk.encodeBody(
            ByteArray(0), enc.ephemeralX25519, enc.mlkemCiphertext, wrapped, CompositeSuite.IETF_768
        )
        return packet(CompositePkesk.PKESK_TAG, body)
    }

    @Test
    fun `IETF anonymous PKESK trials the one held key that opens it`() {
        val alice = party("Alice", "alice@pgpony.test", KeyAlgorithm.MLKEM768_X25519_V6)
        val pkesk = anonymousIetfPkesk(alice)

        val session = CompositeDecryptor.recoverSessionKey(pkesk, listOf(alice.secRing), passphrase = null)
        assertArrayEquals(sessionKey, session!!.key)
        assertEquals(SymmetricKeyAlgorithmTags.AES_256, session.algorithm)
    }

    @Test
    fun `IETF anonymous PKESK skips a stranger's key and throws NoMatchingKey`() {
        val alice = party("Alice", "alice@pgpony.test", KeyAlgorithm.MLKEM768_X25519_V6)
        val bob = party("Bob", "bob@pgpony.test", KeyAlgorithm.MLKEM768_X25519_V6)
        val pkesk = anonymousIetfPkesk(alice)

        try {
            CompositeDecryptor.recoverSessionKey(pkesk, listOf(bob.secRing), passphrase = null)
            fail("expected NoMatchingKey")
        } catch (e: CompositeDecryptor.NoMatchingKey) {
            // expected
        }
    }

    @Test
    fun `IETF anonymous PKESK finds the right key after skipping a wrong one first`() {
        val alice = party("Alice", "alice@pgpony.test", KeyAlgorithm.MLKEM768_X25519_V6)
        val bob = party("Bob", "bob@pgpony.test", KeyAlgorithm.MLKEM768_X25519_V6)
        val pkesk = anonymousIetfPkesk(alice)

        // Bob's ring is tried first and must be silently skipped, not
        // treated as a failure that aborts the scan.
        val session = CompositeDecryptor.recoverSessionKey(
            pkesk, listOf(bob.secRing, alice.secRing), passphrase = null
        )
        assertArrayEquals(sessionKey, session!!.key)
    }

    // ── LibrePGP composite (algo 8, v3/v5) ───────────────────────────

    private fun anonymousLibrePgpPkesk(party: Party): ByteArray {
        val sub = party.pubRing.publicKeys.asSequence()
            .first { it.algorithm == CompositeLibrePGPKeyMaterial.ALGORITHM_ID && it.version == 5 }
        val packet = sub.encoded
        val suite = CompositeLibrePGPKeyMaterial.suiteOf(packet)
        val (xPub, kyberPub) = CompositeLibrePGPKeyMaterial.publicMaterial(packet)
        val v5fp = CompositeLibrePGPKeyMaterial.v5Fingerprint(packet)
        val symAlgo = SymmetricKeyAlgorithmTags.AES_256
        val fixedInfo = CompositeKemLibrePGP.fixedInfo(symAlgo, v5fp)
        val enc = CompositeKemLibrePGP.encapsulate(xPub, kyberPub, fixedInfo, rnd, suite)
        val wrapped = CompositeKemLibrePGP.wrapSessionKey(enc.kek, sessionKey)

        val out = ByteArrayOutputStream()
        out.write(3) // v3 PKESK
        out.write(ByteArray(8)) // wildcard key id, GnuPG's `gpg -R` shape
        out.write(CompositeLibrePGPKeyMaterial.ALGORITHM_ID)
        val bits = enc.eccEphemeral.size * 8
        out.write((bits ushr 8) and 0xFF)
        out.write(bits and 0xFF)
        out.write(enc.eccEphemeral)
        val kLen = enc.kyberCiphertext.size
        out.write(uint32(kLen))
        out.write(enc.kyberCiphertext)
        out.write(symAlgo)
        out.write(wrapped.size)
        out.write(wrapped)
        return packet(1, out.toByteArray())
    }

    @Test
    fun `LibrePGP anonymous PKESK trials the one held key that opens it`() {
        val alice = party("Alice", "alice@pgpony.test", KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
        val pkesk = anonymousLibrePgpPkesk(alice)

        val session = CompositeLibrePGPDecryptor.recoverSessionKey(pkesk, listOf(alice.secRing), null)
        assertArrayEquals(sessionKey, session!!.key)
        assertEquals(SymmetricKeyAlgorithmTags.AES_256, session.algorithm)
    }

    @Test
    fun `LibrePGP anonymous PKESK skips a stranger's key and throws NoMatchingKey`() {
        val alice = party("Alice", "alice@pgpony.test", KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
        val bob = party("Bob", "bob@pgpony.test", KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
        val pkesk = anonymousLibrePgpPkesk(alice)

        try {
            CompositeLibrePGPDecryptor.recoverSessionKey(pkesk, listOf(bob.secRing), null)
            fail("expected NoMatchingKey")
        } catch (e: CompositeLibrePGPDecryptor.NoMatchingKey) {
            // expected
        }
    }

    @Test
    fun `LibrePGP anonymous PKESK finds the right key after skipping a wrong one first`() {
        val alice = party("Alice", "alice@pgpony.test", KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
        val bob = party("Bob", "bob@pgpony.test", KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
        val pkesk = anonymousLibrePgpPkesk(alice)

        val session = CompositeLibrePGPDecryptor.recoverSessionKey(
            pkesk, listOf(bob.secRing, alice.secRing), null
        )
        assertArrayEquals(sessionKey, session!!.key)
    }
}
