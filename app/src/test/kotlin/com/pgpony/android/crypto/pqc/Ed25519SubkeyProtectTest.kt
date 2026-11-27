// Ed25519SubkeyProtectTest.kt
// PGPony Android 4.8.2 (item 2): an Ed25519 subkey on a protected composite
// ML-DSA key. CompositeSecretProtection.protect picked the key to encrypt by
// algorithm alone, so for an Ed25519 subkey (algorithm 27) it encrypted the
// throwaway Ed25519 primary it builds, and the subkey's own secret was lost.
// The next re-protect (Add User ID, reported by email on 4.8.1) failed on it.
// Now the subkey keeps its secret, and a key damaged the old way can still be
// edited once the passphrase has opened the primary.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.SecretKeyUnlock
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

class Ed25519SubkeyProtectTest {

    private val pass = "correct horse".toCharArray()

    private fun keyWithEd25519Subkey(suite: CompositeSignSuite): ByteArray {
        val base = CompositeKeyFacade.reprotect(CompositePrimaryKeyGen.assemble("Rep <rep@pgpony.app>", suite), null, pass)
        return CompositeKeyFacade.reprotect(
            CompositePrimaryKeyGen.addClassicalSubkey(base, ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH, null, pass),
            pass, pass
        )
    }

    /** The Ed25519 subkey opens with the passphrase and its secret matches its public key. */
    private fun assertSubkeySecretIntact(ring: ByteArray) {
        val carrier = CompositeKeyFacade.classicalAuthRing(ring)
        assertNotNull(carrier)
        val sub = carrier!!.secretKeys.asSequence().first { !it.isMasterKey && it.publicKey.algorithm == 27 }
        val priv = SecretKeyUnlock.extract(sub, pass)
        assertNotNull(priv)
        val params = BcPGPKeyConverter().getPrivateKey(priv) as Ed25519PrivateKeyParameters
        val pubMaterial = sub.publicKey.publicKeyPacket.encodedContents.let { it.copyOfRange(it.size - 32, it.size) }
        assertArrayEquals(pubMaterial, params.generatePublicKey().encoded)
    }

    @Test
    fun `the reported sequence keeps the subkey secret and Add User ID works`() {
        for (suite in listOf(CompositeSignSuite.MLDSA65_ED25519, CompositeSignSuite.MLDSA87_ED448)) {
            val ring = keyWithEd25519Subkey(suite)
            assertSubkeySecretIntact(ring)
            val edited = CompositeKeyFacade.reprotect(CompositePrimaryKeyGen.addUserId(ring, "Second <second@pgpony.app>", pass), pass, pass)
            assertSubkeySecretIntact(edited)
            val again = CompositeKeyFacade.reprotect(edited, pass, "new pass".toCharArray())
            assertTrue(CompositeKeyFacade.isProtected(again))
        }
    }

    /** A key as 4.8.1 left it: the Ed25519 subkey's secret region replaced by
     *  one that belongs to another key, so it never opens again. */
    private fun damaged(ring: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        for (p in CertificateBindings.packets(ring)) {
            val alg = if (p.tag == 7) p.body[5].toInt() and 0xFF else -1
            if (p.tag == 7 && alg == 27) {
                val pubLen = 1 + 4 + 1 + 4 + 32
                val other = Ed25519PrivateKeyParameters(SecureRandom())
                val otherPub = p.body.copyOfRange(0, pubLen).also {
                    other.generatePublicKey().encoded.copyInto(it, pubLen - 32)
                }
                val region = CompositeSecretProtection.protect(otherPub, other.encoded, pass)
                out.write(CertificateBindings.frame(7, p.body.copyOfRange(0, pubLen) + region))
            } else {
                out.write(CertificateBindings.frame(p.tag, p.body))
            }
        }
        return out.toByteArray()
    }

    @Test
    fun `a key damaged before the fix can still be edited with the right passphrase`() {
        val broken = damaged(keyWithEd25519Subkey(CompositeSignSuite.MLDSA65_ED25519))
        val edited = CompositeKeyFacade.reprotect(CompositePrimaryKeyGen.addUserId(broken, "Fixed <fixed@pgpony.app>", pass), pass, pass)
        assertTrue(CompositeKeyFacade.isProtected(edited))
        try {
            CompositeKeyFacade.reprotect(broken, "wrong".toCharArray(), pass)
            fail("a wrong passphrase must still fail")
        } catch (_: Exception) {
        }
    }
}
