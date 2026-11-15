// SubkeyKeepTest.kt
// PGPony Android, 4.8.1 (#119): a write of a stored certificate keeps every
// subkey the stored copy binds, unless Remove subkey names it.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.pqc.CompositePrimaryKeyGen
import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class SubkeyKeepTest {

    private val svc = PGPCryptoService.shared

    private fun fps(raw: ByteArray) = SubkeyAdmission.subkeyFingerprints(raw)

    /** An Ed25519 key pair's public copy with its encryption subkey and an added authentication subkey. */
    private fun twoSubkeys(): ByteArray {
        val k = svc.generateKeyPair("Keep", "keep@pgpony.test", KeyAlgorithm.ED25519_CV25519, null)
        val sec = svc.importKeyData(k.privateKeyData).secretKeyRing!!
        val more = ClassicalSubkeyGen.addSubkey(sec, ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH, null)
        return CertificateBindings.sanitized(PGPPublicKeyRing(more.publicKeys.asSequence().toList()).encoded)
    }

    private fun withoutSubkeys(raw: ByteArray): ByteArray {
        var ring = svc.importKeyData(raw).publicKeyRing!!
        ring.publicKeys.asSequence().filter { !it.isMasterKey }.toList().forEach { ring = PGPPublicKeyRing.removePublicKey(ring, it) }
        return ring.encoded
    }

    @Test
    fun `a copy without its subkeys gets them back`() {
        val stored = twoSubkeys()
        assertEquals(2, fps(stored).size)
        val r = SubkeyKeep.keepBound(stored, withoutSubkeys(stored))
        assertEquals(fps(stored), r.kept.toSet())
        assertEquals(fps(stored), fps(r.bytes))
        val report = CertificateBindings.analyze(r.bytes)!!
        assertTrue(report.subkeys.all { it.bound })
        assertEquals(fps(stored), fps(CertificateBindings.sanitized(r.bytes)))
    }

    @Test
    fun `Remove subkey takes out only the one named`() {
        val stored = twoSubkeys()
        val gone = fps(stored).first()
        val r = SubkeyKeep.keepBound(stored, withoutSubkeys(stored), drop = setOf(gone.lowercase()))
        assertEquals(fps(stored) - gone, fps(r.bytes))
    }

    @Test
    fun `a complete copy is stored as it is`() {
        val stored = twoSubkeys()
        val r = SubkeyKeep.keepBound(stored, stored)
        assertTrue(r.kept.isEmpty())
        assertSame(stored, r.bytes)
    }

    @Test
    fun `another key's copy is not touched`() {
        val a = twoSubkeys()
        val b = withoutSubkeys(twoSubkeys())
        val r = SubkeyKeep.keepBound(a, b)
        assertTrue(r.kept.isEmpty())
        assertSame(b, r.bytes)
    }

    @Test
    fun `an ML-DSA key keeps its ML-KEM subkey`() {
        val secret = CompositePrimaryKeyGen.assemble("Keep <keep@pgpony.app>", CompositeSignSuite.MLDSA87_ED448)
        val stored = CompositeKeyFacade.publicRingOf(secret)
        val sub = CompositeKeyFacade.listSubkeys(stored).single().fingerprintHex
        val hex = ByteArray(sub.length / 2) { sub.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        val partial = CompositeKeyFacade.publicRingOf(CompositePrimaryKeyGen.removeSubkey(secret, hex))
        val r = SubkeyKeep.keepBound(stored, partial)
        assertEquals(listOf(sub.uppercase()), r.kept)
        assertEquals(1, CompositeKeyFacade.listSubkeys(r.bytes).size)
    }
}
