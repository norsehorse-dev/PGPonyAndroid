// S2kPolicy.kt
// PGPony Android, 4.6.0 (item 17.6): the iterated + salted S2K used to protect
// v4 (and LibrePGP v5) secret keys with a passphrase.
//
// Bouncy Castle's two-argument BcPBESecretKeyEncryptorBuilder defaults to a
// coded count of 0x60 (65,536 octets hashed), about a thousandth of what
// GnuPG calibrates, so an exported or backed-up protected key was cheap to
// brute force. Every v4 protection site now goes through [v4EncryptorBuilder]:
// SHA-256 with a coded count calibrated once per process to roughly 200 ms of
// hashing on this device, never below 0xE0 (16,777,216 octets) and at most
// 0xFF (65,011,712 octets, GnuPG's ceiling). v6 keys use Argon2id and are not
// affected. Existing keys keep their old S2K until the passphrase is changed.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider

object S2kPolicy {

    const val MIN_CODED_COUNT = 0xE0
    const val MAX_CODED_COUNT = 0xFF
    private const val TARGET_MS = 200.0

    /** Octets hashed for coded count [c] (RFC 9580 3.7.1.3). */
    fun octetsFor(c: Int): Long = (16L + (c and 15)) shl ((c shr 4) + 6)

    /** The coded count for this device, calibrated on first use. */
    val codedCount: Int by lazy { calibrate() }

    private fun calibrate(): Int = runCatching {
        val d = org.bouncycastle.crypto.digests.SHA256Digest()
        val buf = ByteArray(1 shl 16)
        val out = ByteArray(32)
        // Warm up, then time 8 MiB.
        repeat(16) { d.update(buf, 0, buf.size) }; d.doFinal(out, 0)
        val start = System.nanoTime()
        repeat(128) { d.update(buf, 0, buf.size) }
        d.doFinal(out, 0)
        val ms = (System.nanoTime() - start) / 1_000_000.0
        val octetsPerMs = (128.0 * buf.size) / maxOf(ms, 0.001)
        val want = (octetsPerMs * TARGET_MS).toLong()
        var c = MIN_CODED_COUNT
        while (c < MAX_CODED_COUNT && octetsFor(c) < want) c++
        c
    }.getOrDefault(MIN_CODED_COUNT)

    /** The encryptor builder every v4 / v5 secret-key protection site uses. */
    fun v4EncryptorBuilder(): BcPBESecretKeyEncryptorBuilder =
        BcPBESecretKeyEncryptorBuilder(
            SymmetricKeyAlgorithmTags.AES_256,
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256),
            codedCount
        )
}
