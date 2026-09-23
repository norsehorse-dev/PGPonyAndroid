// KeyResponseTest.kt
// PGPony Android, 4.6.0 (item 18)
//
// A key server or WKD answer becomes "Key Found" only when it is public key
// material for the query. An HTML page, a message or a secret key is a miss.

package com.pgpony.android.network

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class KeyResponseTest {

    private val svc = PGPCryptoService.shared
    private val alice by lazy { svc.generateKeyPair("Alice", "alice@example.org", KeyAlgorithm.ED25519_CV25519, null) }
    private val bob by lazy { svc.generateKeyPair("Bob", "bob@example.org", KeyAlgorithm.ED25519_CV25519, null) }

    private fun ring(k: com.pgpony.android.crypto.GeneratedKeyResult) = PGPPublicKeyRing(k.publicKeyData, BcKeyFingerprintCalculator())
    private fun hex(fp: ByteArray) = fp.joinToString("") { "%02X".format(it) }

    private fun armored(bytes: ByteArray): String {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { it.write(bytes) }
        return out.toString("UTF-8")
    }

    private val html = """<!DOCTYPE html><html><head><title>Not Found</title></head>
        <body><h1>Oops</h1><p>That page does not exist.</p></body></html>""".trimIndent()

    @Test
    fun `an HTML page with status 200 is not a key`() {
        assertNull(KeyResponse.validate(html, "text/html; charset=utf-8"))
        assertNull("no content type", KeyResponse.validate(html, null))
        assertNull("mislabelled", KeyResponse.validate(html, "application/octet-stream"))
    }

    @Test
    fun `a real key served as text html is still refused`() {
        assertNull(KeyResponse.validate(armored(alice.publicKeyData), "text/html"))
    }

    @Test
    fun `a PGP MESSAGE is not a key`() {
        val msg = svc.encrypt("hi".toByteArray(), listOf(ring(alice)))
        val text = String(msg)
        assertTrue(text.contains("BEGIN PGP MESSAGE"))
        assertNull(KeyResponse.validate(text))
        assertNull("binary message", KeyResponse.validate(ArmoredInputStream(text.byteInputStream()).readBytes()))
    }

    @Test
    fun `a key block alongside a message block is refused whole`() {
        val msg = svc.encrypt("hi".toByteArray(), listOf(ring(alice)))
        val text = String(msg)
        assertNull(KeyResponse.validate(armored(alice.publicKeyData) + "\n" + text))
    }

    @Test
    fun `a secret key is not offered as a lookup result`() {
        assertNull(KeyResponse.validate(alice.privateKeyData))
        assertNull(KeyResponse.validate(armored(alice.privateKeyData)))
    }

    @Test
    fun `garbage armored as a public key block is refused`() {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { it.write(html.toByteArray()) }
        val fake = out.toString("UTF-8").replace(Regex("BEGIN PGP [A-Z ]+-----"), "BEGIN PGP PUBLIC KEY BLOCK-----")
            .replace(Regex("END PGP [A-Z ]+-----"), "END PGP PUBLIC KEY BLOCK-----")
        assertNull(KeyResponse.validate(fake))
    }

    @Test
    fun `a genuine key passes, binary or armored, and comes back as a public key block`() {
        for (body in listOf(alice.publicKeyData, armored(alice.publicKeyData).toByteArray())) {
            val out = KeyResponse.validate(body, "application/pgp-keys")
            assertNotNull(out)
            assertTrue(out!!.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
            val back = PGPPublicKeyRing(ArmoredInputStream(out.byteInputStream()).readBytes(), BcKeyFingerprintCalculator())
            assertTrue(back.publicKey.fingerprint.contentEquals(ring(alice).publicKey.fingerprint))
        }
    }

    @Test
    fun `a by-fingerprint answer must hold the fingerprint asked for`() {
        val aliceFp = hex(ring(alice).publicKey.fingerprint)
        assertNotNull(KeyResponse.validate(alice.publicKeyData, null, KeyResponse.Query.Fingerprint(aliceFp)))
        assertNotNull("lowercase with spaces", KeyResponse.validate(alice.publicKeyData, null,
            KeyResponse.Query.Fingerprint(aliceFp.lowercase().chunked(4).joinToString(" "))))
        assertNull("a different key", KeyResponse.validate(bob.publicKeyData, null, KeyResponse.Query.Fingerprint(aliceFp)))
    }

    @Test
    fun `a subkey fingerprint or key ID matches its certificate`() {
        val sub = ring(alice).publicKeys.asSequence().first { !it.isMasterKey }
        assertNotNull(KeyResponse.validate(alice.publicKeyData, null, KeyResponse.Query.Fingerprint(hex(sub.fingerprint))))
        assertNotNull(KeyResponse.validate(alice.publicKeyData, null, KeyResponse.Query.KeyId("%016X".format(sub.keyID))))
        assertNull(KeyResponse.validate(bob.publicKeyData, null, KeyResponse.Query.KeyId("%016X".format(sub.keyID))))
    }

    @Test
    fun `a bundle keeps only the matching certificate`() {
        val both = alice.publicKeyData + bob.publicKeyData
        val bobFp = hex(ring(bob).publicKey.fingerprint)
        val out = KeyResponse.validate(both, null, KeyResponse.Query.Fingerprint(bobFp))!!
        val certs = KeyResponse.certificates(out.toByteArray())!!
        assertEquals(1, certs.size)
        assertTrue(PGPPublicKeyRing(certs[0], BcKeyFingerprintCalculator()).publicKey.fingerprint
            .contentEquals(ring(bob).publicKey.fingerprint))
    }

    @Test
    fun `v6 and post-quantum keys pass with every subkey matchable`() {
        // RFC 9980 A.2: a v4 Ed25519 primary with an ML-KEM-768+X25519
        // (algo 35) subkey; generation of that shape is import only.
        val rfcV4 = javaClass.getResourceAsStream("/pqc/rfc9980-a2-v4-ed25519-mlkem768-pub.asc")!!
            .readBytes().let { ArmoredInputStream(it.inputStream()).readBytes() }
        val samples = listOf(KeyAlgorithm.V6_ED25519, KeyAlgorithm.MLKEM768_X25519_V6)
            .map { it.name to svc.generateKeyPair("Pq", "pq@example.org", it, null).publicKeyData } +
            ("RFC9980_A2_V4" to rfcV4)
        for ((name, data) in samples) {
            val certs = KeyResponse.certificates(data)
            assertNotNull(name, certs)
            val parsed = com.pgpony.android.crypto.CertificateBindings.parse(certs!![0])!!
            val subs = parsed.components.filter { com.pgpony.android.crypto.CertificateBindings.isSubkeyTag(it.tag) }
            assertTrue(name, subs.isNotEmpty())
            for (c in subs) {
                val fp = com.pgpony.android.crypto.CertificateBindings.KeyBody(c.body).fingerprintHex
                assertNotNull("$name $fp", KeyResponse.validate(armored(data), null, KeyResponse.Query.Fingerprint(fp)))
            }
        }
    }

    @Test
    fun `a WKD answer that is a web page is a miss`() {
        assertNull(WkdService().filterToAddress(html.toByteArray(), "alice@example.org"))
    }
}
