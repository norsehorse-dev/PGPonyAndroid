// CompositeRfc9980A2Test.kt
// PGPony Android — 4.5.0 (item 14 / #56): RFC 9980 Appendix A.2 conformance.
//
// The authoritative interop check for the v4 Ed25519 + ML-KEM-768+X25519
// (algorithm 35) shape: decrypt the RFC's OWN sample messages with the RFC's
// OWN sample secret key (Appendix A.2). No shipping tool implements algo-35 yet
// (gpg follows LibrePGP's codepoints; mainline Sequoia has not added 35), so the
// spec's test vectors are the real conformance test.
//
// A.2.4 is a v6-PKESK / SEIPDv2 message, exactly the framing PGPony emits and
// decrypts. A.2.3 is a v3-PKESK / SEIPDv1 message — a second, equally valid
// algo-35 encoding the RFC defines, where the recipient is addressed by 8-octet
// key ID and the symmetric-algorithm octet rides in the PKESK. PGPony decrypts
// both.
//
// The sample key's primary (algo 27, Ed25519) and its algo-35 subkey are both
// unprotected (s2k usage 0), so the raw v4 decrypt path opens them directly.
// Plaintext per the RFC is "Testing\n".

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ArmoredInputStream
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class CompositeRfc9980A2Test {

    private val svc = PGPCryptoService.shared

    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    private fun deArmor(bytes: ByteArray): ByteArray =
        if (bytes.isNotEmpty() && bytes[0].toInt() == '-'.code)
            ArmoredInputStream(ByteArrayInputStream(bytes)).use { it.readBytes() }
        else bytes

    @Test
    fun `RFC 9980 A_2_4 SEIPDv2 message decrypts to the sample plaintext`() {
        val sk = res("rfc9980-a2-v4-ed25519-mlkem768-sec.asc")
        val msg = res("rfc9980-a2-v4-ed25519-mlkem768-msg-v2.asc")
        assumeTrue("RFC 9980 A.2 fixtures absent", sk != null && msg != null)

        val result = svc.decrypt(
            msg!!, secretKeyRings = emptyList(), passphrase = null,
            compositePrimaryRings = listOf(deArmor(sk!!))
        )
        assertEquals(
            "PGPony must recover the RFC 9980 A.2.4 plaintext from the RFC's own sample",
            "Testing\n", String(result.data)
        )
    }

    @Test
    fun `RFC 9980 A_2_3 SEIPDv1 message decrypts to the sample plaintext`() {
        val sk = res("rfc9980-a2-v4-ed25519-mlkem768-sec.asc")
        val msg = res("rfc9980-a2-v4-ed25519-mlkem768-msg-v1.asc")
        assumeTrue("RFC 9980 A.2 fixtures absent", sk != null && msg != null)

        val result = svc.decrypt(
            msg!!, secretKeyRings = emptyList(), passphrase = null,
            compositePrimaryRings = listOf(deArmor(sk!!))
        )
        assertEquals(
            "PGPony must recover the RFC 9980 A.2.3 plaintext (v3 PKESK / SEIPDv1)",
            "Testing\n", String(result.data)
        )
    }
}
