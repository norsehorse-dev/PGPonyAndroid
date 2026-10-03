// V6KeyIdV3PkeskTest.kt
// PGPony Android 4.6.3 (#73): a v3 PKESK names its recipient by 8-octet key
// ID, and for a v6 key that is the FIRST 8 octets of the 32-octet fingerprint
// (RFC 9580 5.5.4.3). The composite lookup took the last 8 for every key, so a
// message GpgFrontend's rPGP engine encrypted to a PGPony ML-DSA-65 v6 key
// (v3 PKESK, SEIPDv1) failed with "no held composite secret key".
//
// Built from an in-test key: no reporter key material is used here.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream

class V6KeyIdV3PkeskTest {

    private val sessionKey = ByteArray(32) { (it * 5 + 1).toByte() }

    @Test
    fun keyIdOfFingerprint_followsTheKeyVersion() {
        val v4 = ByteArray(20) { it.toByte() }
        val v6 = ByteArray(32) { (0x40 + it).toByte() }
        assertArrayEquals(v4.copyOfRange(12, 20), CompositeDecryptor.keyIdOfFingerprint(v4))
        assertArrayEquals(v6.copyOfRange(0, 8), CompositeDecryptor.keyIdOfFingerprint(v6))
    }

    /** A v3 PKESK (RFC 9980 4.3.1) for [sub], naming it by [keyId]. */
    private fun v3Pkesk(sub: CompositeKeyFacade.SubkeyInfo, keyId: ByteArray): ByteArray {
        val suite = CompositeSuite.ietfFor(sub.algId)!!
        val (xPub, mPub) = CompositeKem.splitPublic(sub.publicMaterial, suite)
        val enc = CompositeKem.encapsulate(xPub, mPub, suite = suite)
        val wrapped = CompositeKem.wrapSessionKey(enc.kek, sessionKey)
        val body = ByteArrayOutputStream().apply {
            write(3)
            write(keyId)
            write(sub.algId)
            write(enc.ephemeralX25519)
            write(enc.mlkemCiphertext)
            write(1 + wrapped.size)
            write(SymmetricKeyAlgorithmTags.AES_256)
            write(wrapped)
        }.toByteArray()
        val len = body.size - 192
        return byteArrayOf(0xC1.toByte(), (0xC0 or (len shr 8)).toByte(), (len and 0xFF).toByte()) + body
    }

    @Test
    fun aV3PkeskNamingAV6SubkeyByItsKeyId_decrypts() {
        val raw = CompositePrimaryKeyGen.assemble("KeyId <keyid@pgpony.app>", CompositeSignSuite.MLDSA65_ED25519)
        val sub = CompositeKeyFacade.parse(raw).encryptionSubkey!!
        assertEquals(32, sub.fingerprint.size)
        val pkesk = v3Pkesk(sub, sub.fingerprint.copyOfRange(0, 8))

        val session = CompositeDecryptor.recoverSessionKey(pkesk, emptyList(), listOf(raw))
        assertArrayEquals(sessionKey, session!!.key)
        assertEquals(SymmetricKeyAlgorithmTags.AES_256, session.algorithm)
    }

    @Test
    fun theLastEightOctetsOfAV6Fingerprint_areNotItsKeyId() {
        val raw = CompositePrimaryKeyGen.assemble("KeyId <keyid@pgpony.app>", CompositeSignSuite.MLDSA65_ED25519)
        val sub = CompositeKeyFacade.parse(raw).encryptionSubkey!!
        val fp = sub.fingerprint
        val pkesk = v3Pkesk(sub, fp.copyOfRange(fp.size - 8, fp.size))
        try {
            CompositeDecryptor.recoverSessionKey(pkesk, emptyList(), listOf(raw))
            fail("a v3 PKESK naming the wrong key ID must not match")
        } catch (e: CompositeDecryptor.NoMatchingKey) {
            // expected
        }
    }
}
