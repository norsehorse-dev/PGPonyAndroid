// UrlKeyFetcherTest.kt
// PGPony Android, 4.6.0 (item 2)
//
// Import from a link: https only (http for .onion), and only validated public
// key material comes back, whether the link is a raw key or a web page.

package com.pgpony.android.network

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlKeyFetcherTest {

    private val svc = PGPCryptoService.shared
    private val k by lazy { svc.generateKeyPair("Web", "web@example.org", KeyAlgorithm.ED25519_CV25519, null) }
    private val armored by lazy { svc.exportArmoredPublicKey(PGPPublicKeyRing(k.publicKeyData, BcKeyFingerprintCalculator())) }

    @Test
    fun `only https, or http to an onion address`() {
        assertNotNull(UrlKeyFetcher.allowedUri("https://example.org/key.asc"))
        assertNotNull(UrlKeyFetcher.allowedUri("  https://example.org/key.asc  "))
        assertNull(UrlKeyFetcher.allowedUri("http://example.org/key.asc"))
        assertNotNull(UrlKeyFetcher.allowedUri("http://abcdefghij234567.onion/key.asc"))
        assertNull(UrlKeyFetcher.allowedUri("file:///sdcard/key.asc"))
        assertNull(UrlKeyFetcher.allowedUri("ftp://example.org/key.asc"))
        assertNull(UrlKeyFetcher.allowedUri("not a url"))
    }

    @Test
    fun `a raw asc and a binary key both come back as a public key block`() {
        for (body in listOf(armored.toByteArray(), k.publicKeyData)) {
            val out = UrlKeyFetcher.keysFrom(body)!!
            assertTrue(out.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        }
    }

    @Test
    fun `a key shown on a web page is found, markup and all`() {
        val htmlBlock = armored.lines().joinToString("<br>\n") { "  " + it.replace("+", "&#43;") }
        val page = """<!DOCTYPE html><html><body><h1>My key</h1><p>Fingerprint below.</p>
            <pre><code>$htmlBlock</code></pre><footer>bye</footer></body></html>""".trimIndent()
        val out = UrlKeyFetcher.keysFrom(page.toByteArray())
        assertNotNull(out)
        val certs = KeyResponse.certificates(out!!.toByteArray())!!
        assertEquals(1, certs.size)
        assertTrue(PGPPublicKeyRing(certs[0], BcKeyFingerprintCalculator()).publicKey.fingerprint
            .contentEquals(PGPPublicKeyRing(k.publicKeyData, BcKeyFingerprintCalculator()).publicKey.fingerprint))
    }

    @Test
    fun `a page without a key, or with only a private key, is a miss`() {
        assertNull(UrlKeyFetcher.keysFrom("<html><body>404 not found</body></html>".toByteArray()))
        assertNull(UrlKeyFetcher.keysFrom(svc.exportArmoredPrivateKey(
            org.bouncycastle.openpgp.PGPSecretKeyRing(k.privateKeyData, BcKeyFingerprintCalculator())).toByteArray()))
        assertNull(UrlKeyFetcher.keysFrom(ByteArray(0)))
    }
}
