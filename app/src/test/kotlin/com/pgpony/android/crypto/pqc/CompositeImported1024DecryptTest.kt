// CompositeImported1024DecryptTest.kt
// PGPony Android — 4.5.0 (item 12 / #36, Umotas): the ML-KEM-1024+X448 variant.
//
// Umotas's failing case: a v6 cert with a composite ML-DSA-87+Ed448 (algo 31)
// primary and an ML-KEM-1024+X448 (algo 36) encryption subkey, generated in sq,
// imported into PGPony, cannot decrypt an sq-encrypted file. Item 12's working
// fixtures are the SMALLER suite (ML-DSA-65+Ed25519 / ML-KEM-768+X25519), so this
// is the same raw composite-primary path at the 1024 level, which is untested.
//
// findRawComposite wraps CompositeKeyFacade.parse in runCatching, so a size or
// suite bug at the 1024 level is swallowed into a plain "no held composite
// secret key". The first test therefore calls parse DIRECTLY so the real
// exception surfaces; the second runs the full decrypt. sq round-trips this
// key, so any failure here is PGPony's.
//
// Fixtures: sq key generate --profile rfc9580 --cipher-suite mldsa87-ed448
//   --encryption-algorithm mlkem1024-x448 ; passphrase "SEZAM".

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ArmoredInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class CompositeImported1024DecryptTest {

    private val svc = PGPCryptoService.shared
    private val pass = "SEZAM"

    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    private fun deArmor(b: ByteArray): ByteArray =
        if (b.isNotEmpty() && b[0].toInt() == '-'.code)
            ArmoredInputStream(ByteArrayInputStream(b)).use { it.readBytes() } else b

    @Test
    fun `facade parses the 1024 composite ring and finds the algo-36 subkey`() {
        val sec = res("sq-1024-sec.asc")
        assumeTrue("pqc/sq-1024-sec.asc absent", sec != null)
        val info = CompositeKeyFacade.parse(deArmor(sec!!), pass.toCharArray())
        assertEquals("primary is ML-DSA-87+Ed448 (algo 31)", 31, info.primaryAlgId)
        val sub = info.encryptionSubkey
        assertNotNull("must find the ML-KEM-1024+X448 encryption subkey", sub)
        assertEquals("encryption subkey is algo 36", 36, sub!!.algId)
        assertNotNull(
            "encryption subkey secret must unlock with the passphrase",
            sub.secretMaterial
        )
    }

    @Test
    fun `sq 1024 composite key decrypts via the STREAMING file path`() {
        // The actual Umotas failure: opening a .gpg as a file streams it, and
        // decryptStream never threaded the raw composite-primary rings, so it
        // failed with "no held composite secret key" while in-memory decrypt
        // worked. This exercises decryptStream with the composite ring.
        val sec = res("sq-1024-sec.asc")
        val msg = res("sq-1024-msg.gpg")
        assumeTrue("fixtures absent", sec != null && msg != null)
        val out = java.io.ByteArrayOutputStream()
        svc.decryptStream(
            input = java.io.ByteArrayInputStream(msg!!),
            output = out,
            secretKeyRings = emptyList(),
            passphrase = pass,
            compositePrimaryRings = listOf(deArmor(sec!!))
        )
        assertEquals("hello pgpony 1024 test", String(out.toByteArray()).trim())
    }

    @Test
    fun `sq 1024 composite key decrypts the sq-encrypted file`() {
        val sec = res("sq-1024-sec.asc")
        val msg = res("sq-1024-msg.gpg")
        assumeTrue("fixtures absent", sec != null && msg != null)
        val result = svc.decrypt(
            msg!!, secretKeyRings = emptyList(), passphrase = pass,
            compositePrimaryRings = listOf(deArmor(sec!!))
        )
        assertEquals("hello pgpony 1024 test", String(result.data).trim())
    }
}
