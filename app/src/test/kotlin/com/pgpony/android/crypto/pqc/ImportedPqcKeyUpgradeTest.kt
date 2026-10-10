// ImportedPqcKeyUpgradeTest.kt
// PGPony Android 4.7.0 (item 26, #67): desk reproduction for an all-PQ v6
// ML-DSA key imported by 4.5.x that fails as a recipient after upgrading.
//
// The stored form of such a key depends on the version that imported it:
//   * 4.5.x stored the dearmored bytes as they came (public ring from
//     publicRingOf, secret ring raw). 4.6.0's one-time re-validation rewrote
//     the PUBLIC copy through CertificateBindings.sanitized, never the secret.
//   * 4.6.x and later sanitize the whole import first, so both copies are
//     sanitized.
// Each sq fixture is put through every shape and the current loaders, then a
// full encrypt to it, sign with it, decrypt and verify. A shape that fails
// here, and not the others, is the bug. All green means the stored key bytes
// are not the cause for these keys, and the reporter's own key (or device
// state) is needed. A second test checks that a message sq 1.5.0 encrypted
// and signed decrypts and verifies, and that sq's public certificate alone,
// stored the way a contact is, gives a recipient.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ArmoredInputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class ImportedPqcKeyUpgradeTest {

    private val svc = PGPCryptoService.shared

    private class Fixture(val name: String, val passphrase: String?)

    private val fixtures = listOf(
        Fixture("sq-sec.pgp", null),
        Fixture("sq-sec-protected.pgp", "pgpony-test"),
        Fixture("sq-1024-sec.asc", "SEZAM"),
        // sq 1.5.0 (sequoia-openpgp 2.4.1, RFC 9980 final), generated Oct 2026:
        // the default mldsa65-ed25519 key, the same with a passphrase, and the
        // default key with an extra ML-DSA-65 signing subkey or an extra
        // ML-KEM-768 encryption subkey added later with `sq key subkey add`.
        Fixture("sq15-sec.pgp", null),
        Fixture("sq15-sec-protected.pgp", "pgpony-test"),
        Fixture("sq15-sec-extra.pgp", null),
        Fixture("sq15-sec-extraenc.pgp", null)
    )

    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    private fun deArmor(bytes: ByteArray): ByteArray =
        if (bytes.isNotEmpty() && bytes[0].toInt() == '-'.code)
            ArmoredInputStream(ByteArrayInputStream(bytes)).use { it.readBytes() }
        else bytes

    /** name -> (stored public, stored secret). */
    private fun shapes(raw: ByteArray): Map<String, Pair<ByteArray, ByteArray>> {
        val clean = CertificateBindings.sanitized(raw)
        val rawPublic = CompositeKeyFacade.publicRingOf(raw)
        return linkedMapOf(
            "4.5.x import, before re-validation" to (rawPublic to raw),
            "4.5.x import, after 4.6.0 re-validation" to (CertificateBindings.sanitized(rawPublic) to raw),
            "4.6.x import" to (CompositeKeyFacade.publicRingOf(clean) to clean)
        )
    }

    @Test
    fun `every stored shape of an imported sq key encrypts, signs, decrypts and verifies`() {
        var ran = 0
        val failures = ArrayList<String>()
        for (fx in fixtures) {
            val raw = res(fx.name)?.let { deArmor(it) } ?: continue
            ran++
            val clean = CertificateBindings.sanitized(raw)
            println("[item 26] ${fx.name}: raw ${raw.size} octets, sanitized ${clean.size} octets" +
                if (raw.contentEquals(clean)) " (identical)" else " (DIFFERENT)")
            for ((shape, stored) in shapes(raw)) {
                val (pub, sec) = stored
                val label = "${fx.name} / $shape"
                try {
                    val recipient = CompositeKeyFacade.encryptionSubkeyRing(pub)
                    assertNotNull("$label: no recipient ring from the stored public key", recipient)
                    val info = CompositeKeyFacade.parse(sec, fx.passphrase?.toCharArray(), unlockSigner = true)
                    assertNotNull("$label: signing secret did not unlock", info.signingSecret)
                    val plaintext = "item 26 $label".toByteArray()
                    val message = svc.encrypt(
                        plaintext, listOf(recipient!!),
                        compositeSignSuite = info.signingSuite,
                        compositeSignSecret = info.signingSecret,
                        compositeSignerFingerprint = info.signingFingerprint
                    )
                    val result = svc.decrypt(
                        message, secretKeyRings = emptyList(), passphrase = fx.passphrase,
                        compositePrimaryRings = listOf(sec)
                    )
                    assertArrayEquals("$label: plaintext", plaintext, result.data)
                    val inline = result.compositeInlineBytes
                    assertNotNull("$label: no composite signature came back", inline)
                    val graded = CompositeSignerGate.verifyInline(listOf(pub), inline!!)
                    assertTrue("$label: signature graded ${graded.status}", graded.verified)
                    println("[item 26] $label: OK")
                } catch (e: Throwable) {
                    println("[item 26] $label: FAILED ${e::class.java.simpleName}: ${e.message}")
                    failures.add("$label: ${e::class.java.simpleName}: ${e.message}")
                }
            }
        }
        assumeTrue("no sq fixtures present", ran > 0)
        assertTrue("shapes that failed:\n" + failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun `an sq 1_5 message decrypts and verifies, and its public certificate is a recipient`() {
        val sec = res("sq15-sec-extra.pgp")?.let { deArmor(it) }
        val cert = res("sq15-extra-cert.pgp")?.let { deArmor(it) }
        val msg = res("sq15-msg.pgp")
        assumeTrue("sq 1.5 fixtures absent", sec != null && cert != null && msg != null)

        val result = svc.decrypt(msg!!, secretKeyRings = emptyList(), passphrase = null, compositePrimaryRings = listOf(sec!!))
        assertArrayEquals("item 26 sq 1.5 interop\n".toByteArray(), result.data)
        val inline = result.compositeInlineBytes
        assertNotNull("sq's ML-DSA signature came back", inline)
        val graded = CompositeSignerGate.verifyInline(listOf(cert!!), inline!!)
        assertTrue("sq signature graded ${graded.status}", graded.verified)

        for ((shape, pub) in listOf(
            "contact, 4.5.x import" to CompositeKeyFacade.publicRingOf(cert),
            "contact, after re-validation" to CertificateBindings.sanitized(CompositeKeyFacade.publicRingOf(cert)),
            "contact, 4.6.x import" to CompositeKeyFacade.publicRingOf(CertificateBindings.sanitized(cert))
        )) {
            val recipient = CompositeKeyFacade.encryptionSubkeyRing(pub)
            assertNotNull("$shape: no recipient ring", recipient)
            val plaintext = "to sq, $shape".toByteArray()
            val back = svc.decrypt(
                svc.encrypt(plaintext, listOf(recipient!!)),
                secretKeyRings = emptyList(), passphrase = null, compositePrimaryRings = listOf(sec)
            )
            assertArrayEquals("$shape: round trip", plaintext, back.data)
        }
    }

    @Test
    fun `an sq key signs with its signing subkey, a PGPony key with its primary`() {
        for (fx in fixtures) {
            val raw = res(fx.name)?.let { deArmor(it) } ?: continue
            val info = CompositeKeyFacade.parse(raw, fx.passphrase?.toCharArray(), unlockSigner = true)
            assertFalse(
                "${fx.name}: sq's primary is certify-only, so a subkey must sign",
                info.signingFingerprint.contentEquals(info.fingerprint)
            )
            assertTrue(
                "${fx.name}: the signer is one of the key's composite signing subkeys",
                info.compositeSigners.any { it.fingerprintHex.equals(info.signingFingerprint.joinToString("") { b -> "%02x".format(b) }, ignoreCase = true) }
            )
            assertNotNull("${fx.name}: signing secret", info.signingSecret)
        }
        val own = CompositePrimaryKeyGen.assemble("PGPony key <own@pgpony.app>")
        val ownInfo = CompositeKeyFacade.parse(own, null, unlockSigner = true)
        assertArrayEquals("a PGPony key signs with its primary", ownInfo.fingerprint, ownInfo.signingFingerprint)
        assertArrayEquals(ownInfo.compositeSecret, ownInfo.signingSecret)
    }
}
