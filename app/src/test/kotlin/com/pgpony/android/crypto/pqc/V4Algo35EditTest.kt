// V4Algo35EditTest.kt
// PGPony Android, 4.6.0 (item 19 follow-ups)
//
// Expiry, revocation and removal reach the v4 ML-KEM subkeys Bouncy Castle
// cannot load, and the signatures made for them verify under the primary.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.RevocationReason
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class V4Algo35EditTest {

    private val svc = PGPCryptoService.shared

    private fun v4Key(): CompositeKeyGen.V4Algo35Rings {
        val gen = svc.generateKeyPair("V4", "v4@example.test", KeyAlgorithm.ED25519_CV25519, null)
        return CompositeKeyGen.addV4Algo35SubkeyRings(svc.importKeyData(gen.privateKeyData).secretKeyRing!!)
    }

    private fun priv(ring: PGPSecretKeyRing, pass: String = "") =
        ring.secretKey.extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(pass.toCharArray()))

    private fun kem(raw: ByteArray) = CertificateBindings.analyze(raw)!!.subkeys.single { it.algorithm == 35 }

    @Test
    fun `an expiry change re-signs the ML-KEM binding`() {
        val k = v4Key()
        val ring = svc.importKeyData(k.secretRaw).secretKeyRing!!
        val body = V4Algo35Edit.publicBodies(k.publicRaw).single()
        assertNull(kem(k.publicRaw).expiresAtMs)
        val expiry = System.currentTimeMillis() / 1000 + 86_400L * 365
        val sig = V4Algo35Edit.binding(ring, priv(ring), body, expiry)
        val pub = V4Algo35Edit.edit(k.publicRaw, body, replaceBinding = sig)
        val sec = V4Algo35Edit.edit(k.secretRaw, body, replaceBinding = sig)
        val s = kem(pub)
        assertTrue(s.bound)
        assertEquals(expiry * 1000, s.expiresAtMs)
        assertEquals(12, s.keyFlags)
        // One binding, not two, and the secret copy got the same edit.
        val sigsAfter = { raw: ByteArray ->
            val pk = CertificateBindings.packets(raw)
            val i = pk.indexOfFirst { (it.tag == 14 || it.tag == 7) && it.body[5].toInt() == 35 }
            pk.drop(i + 1).takeWhile { it.tag == 2 }.size
        }
        assertEquals(1, sigsAfter(pub))
        assertEquals(1, sigsAfter(sec))
        assertEquals(expiry * 1000, kem(sec).expiresAtMs)
        // Back to "never".
        val never = V4Algo35Edit.edit(pub, body, replaceBinding = V4Algo35Edit.binding(ring, priv(ring), body, null))
        assertNull(kem(never).expiresAtMs)
    }

    @Test
    fun `an ML-KEM subkey can be revoked`() {
        val k = v4Key()
        val ring = svc.importKeyData(k.secretRaw).secretKeyRing!!
        val body = V4Algo35Edit.publicBodies(k.publicRaw).single()
        val fp = V4Algo35Edit.fingerprintHex(body)
        assertEquals(body.toList(), V4Algo35Edit.find(k.publicRaw, fp.lowercase())!!.toList())
        val rev = V4Algo35Edit.revocation(ring, priv(ring), body, RevocationReason.RETIRED, "rotated")
        val pub = V4Algo35Edit.edit(k.publicRaw, body, addSignature = rev)
        assertTrue(kem(pub).revoked)
        assertFalse(kem(k.publicRaw).revoked)
        val report = CertificateBindings.analyze(pub)!!
        assertFalse(report.isUsableEncryptionKey(fp, System.currentTimeMillis()))
    }

    @Test
    fun `an ML-KEM subkey can be removed and the rest of the key is intact`() {
        val k = v4Key()
        val body = V4Algo35Edit.publicBodies(k.publicRaw).single()
        val pub = V4Algo35Edit.edit(k.publicRaw, body, remove = true)
        val sec = V4Algo35Edit.edit(k.secretRaw, body, remove = true)
        assertTrue(V4Algo35Edit.publicBodies(pub).isEmpty())
        assertFalse(CompositeKeyFacade.hasV4Algo35Subkey(sec))
        val r = CertificateBindings.analyze(pub)!!
        assertEquals(listOf(18), r.subkeys.map { it.algorithm })
        assertTrue(r.subkeys.single().bound)
        assertEquals(2, svc.importKeyData(sec).secretKeyRing!!.secretKeys.asSequence().count())
    }

    @Test
    fun `signatures verify on the RFC 9980 v4 sample key too`() {
        val sec = javaClass.getResourceAsStream("/pqc/rfc9980-a2-v4-ed25519-mlkem768-sec.asc")!!
            .readBytes().let { ArmoredInputStream(it.inputStream()).readBytes() }
        val ring = svc.importKeyData(sec).secretKeyRing!!
        val body = V4Algo35Edit.publicBodies(sec).single()
        val expiry = System.currentTimeMillis() / 1000 + 86_400L * 30
        val edited = V4Algo35Edit.edit(sec, body, replaceBinding = V4Algo35Edit.binding(ring, priv(ring), body, expiry))
        val s = kem(edited)
        assertTrue(s.bound)
        assertEquals(expiry * 1000, s.expiresAtMs)
    }
}
