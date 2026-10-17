// CompositeLibrePGPEncryptTest.kt
// PGPony Android — 4.0.0 Phase 2b (LibrePGP composite, algorithm 8 — encrypt)
//
// Encrypt a message to a real GnuPG 2.5.21 LibrePGP composite (algo 8)
// PUBLIC key and write the armored output to a file, so GnuPG can decrypt
// it. Because the KMAC256 combiner is symmetric, a successful `gpg
// --decrypt` proves the entire LibrePGP encrypt stack (encapsulation, KEK
// derivation, session-key wrap, v3 PKESK, container) is byte-correct — no
// need to parse gpg's proprietary secret-key export.
//
// Fixture: librepgp-clean-sec.asc (gpg exports the public half in standard
// form even though the secret is a gcrypt s-expr). We build a public ring
// from it and encrypt to the algo-8 subkey.
//
// This test also structurally self-checks that our output leads with a
// v3 / algo-8 PKESK, then writes the artifact and prints its path. Validate
// with:  gpg --pinentry-mode loopback --passphrase '' --decrypt <path>

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNoException
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File

class CompositeLibrePGPEncryptTest {
    @get:Rule val temporary = TemporaryFolder()

    // Preserve intentional external export without writing artifacts into user.home during CI.
    private val artifactDirectory by lazy {
        System.getenv("PGPONY_INTEROP_OUTPUT_DIR")?.let { File(it, "pgpony-interop").apply { mkdirs() } }
            ?: temporary.newFolder("pgpony-interop")
    }


    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    @Test
    fun `PGPony encrypts a LibrePGP composite message for gpg`() {
        // Use the standard-form PUBLIC cert (derived from the gpg key): the
        // secret ring can't be used here because gpg exports the algo-8
        // secret as a gcrypt s-expr, which makes BC drop the subkey. The
        // public half is standard OpenPGP and parses cleanly.
        val pub = res("librepgp-clean-pub.asc")
        assumeTrue("pqc/librepgp-clean-pub.asc absent", pub != null)

        val pubRing = try {
            PGPPublicKeyRing(PGPUtil.getDecoderStream(ByteArrayInputStream(pub!!)), JcaKeyFingerprintCalculator())
        } catch (e: java.io.IOException) {
            assumeNoException("BC 1.85 could not parse the gpg v5 public cert", e)
            return
        }

        val armored = PGPCryptoService.shared.encrypt("librepgp interop test".toByteArray(), listOf(pubRing))

        // Structural self-check: first packet is a v3 / algo-8 PKESK.
        val bin = ArmoredInputStream(ByteArrayInputStream(armored)).use { it.readBytes() }
        val h = firstPacket(bin)
        assertEquals("first packet must be a PKESK (tag 1)", 1, h.tag)
        assertEquals("PKESK version", 3, bin[h.bodyStart].toInt() and 0xFF)
        assertEquals("PKESK algorithm", 8, bin[h.bodyStart + 9].toInt() and 0xFF)

        val out = File(artifactDirectory, "pgpony-librepgp-out.asc")
        out.writeBytes(armored)
        println("[librepgp] wrote ${out.absolutePath} — validate with: gpg --decrypt ${out.absolutePath}")
        assertTrue(out.length() > 0)
    }

    private class H(val tag: Int, val bodyStart: Int)

    private fun firstPacket(data: ByteArray): H {
        val c = data[0].toInt() and 0xFF
        var i = 1
        val tag: Int
        if (c and 0x40 != 0) {
            tag = c and 0x3F
            val l0 = data[i++].toInt() and 0xFF
            when {
                l0 < 192 -> {}
                l0 < 224 -> i += 1
                l0 == 255 -> i += 4
            }
        } else {
            tag = (c shr 2) and 0x0F
            i += when (c and 0x03) { 0 -> 1; 1 -> 2; 2 -> 4; else -> 0 }
        }
        return H(tag, i)
    }
}
