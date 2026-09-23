// StreamArgon2GuardTest.kt
// PGPony Android, 4.6.0 (item 17.5)
//
// An Argon2 SKESK pushed behind a bulk ESK packet, past the streaming path's
// 64 KiB head scan, must still be refused before the KDF runs: the policy is
// now enforced where Bouncy Castle derives the key, not only in the head scan.

package com.pgpony.android.crypto

import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class StreamArgon2GuardTest {

    private fun newPkt(tag: Int, body: ByteArray): ByteArray {
        val n = body.size
        val hdr = when {
            n < 192 -> byteArrayOf(n.toByte())
            n < 8384 -> { val v = n - 192; byteArrayOf(((v shr 8) + 192).toByte(), (v and 0xFF).toByte()) }
            else -> byteArrayOf(0xFF.toByte(), (n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())
        }
        return byteArrayOf((0xC0 or tag).toByte()) + hdr + body
    }

    /** A v3 RSA PKESK for a key id nobody holds; an MPI tops out near 8 KiB,
     *  so several of these push the SKESK past the 64 KiB head. */
    private fun decoyPkesk(mpiBytes: Int): ByteArray {
        val b = ByteArrayOutputStream()
        b.write(3); repeat(8) { b.write(0x42) }; b.write(1)
        val bits = mpiBytes * 8
        b.write(bits ushr 8); b.write(bits and 0xFF)
        repeat(mpiBytes) { b.write(0x7F) }
        return newPkt(1, b.toByteArray())
    }

    private fun decoys(): ByteArray = (1..12).fold(ByteArray(0)) { acc, _ -> acc + decoyPkesk(8000) }

    private fun argonSkesk(memExp: Int): ByteArray {
        val b = ByteArrayOutputStream()
        b.write(4); b.write(9); b.write(4)
        repeat(16) { b.write(0x11) }
        b.write(1); b.write(1); b.write(memExp)
        return newPkt(3, b.toByteArray())
    }

    private fun dummySeipd(): ByteArray = newPkt(18, ByteArray(40).also { it[0] = 1 })

    @Test
    fun `an Argon2 SKESK beyond the sniff head is refused before the KDF`() {
        val msg = decoys() + argonSkesk(30) + dummySeipd()
        assertThrows(PGPCryptoError.ResourceLimitExceeded::class.java) {
            PGPCryptoService.shared.decryptStream(
                ByteArrayInputStream(msg), ByteArrayOutputStream(), emptyList(), "pw"
            )
        }
    }

    @Test
    fun `the same message through the in-memory decrypt is refused too`() {
        val msg = decoys() + argonSkesk(30) + dummySeipd()
        assertThrows(PGPCryptoError.ResourceLimitExceeded::class.java) {
            PGPCryptoService.shared.decrypt(msg, emptyList(), passphrase = "pw")
        }
    }
}
