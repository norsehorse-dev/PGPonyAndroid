// MixedRecipientFixtureDumpTest.kt
// PGPony Android, for iOS 8.3.0 build 2 (planning 4.4 step 5).
//
// Generator, not a test of anything: produces fresh keys, encrypts one message
// per cell of the multi-recipient matrix through PGPCryptoService (the exact
// wire shapes 4.5.x writes), asserts every holder decrypts here, and writes
// the messages plus each holder's secret key into a temporary test directory.
// Set PGPONY_INTEROP_OUTPUT_DIR for a deliberate persistent export to the iOS fixtures.
// The round-trip assertions run in the default suite; artifacts are cleaned up afterwards.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File

class MixedRecipientFixtureDumpTest {
    @get:Rule val temporary = TemporaryFolder()

    // Default runs are hermetic; deliberate external exports can select a persistent directory.
    private val artifactDirectory by lazy {
        System.getenv("PGPONY_INTEROP_OUTPUT_DIR")?.let { File(it, "android-mixed").apply { mkdirs() } }
            ?: temporary.newFolder("android-mixed")
    }


    private val svc = PGPCryptoService.shared
    private val plaintext = "Android 4.5.x mixed-recipient fixture for PGPony iOS 8.3.0 build 2.".toByteArray()
    private val outDir get() = artifactDirectory

    private class Holder(val name: String, val sec: PGPSecretKeyRing, val pub: PGPPublicKeyRing, val armoredSecret: String)

    private fun secretRing(bytes: ByteArray): PGPSecretKeyRing =
        PGPSecretKeyRing(PGPUtil.getDecoderStream(ByteArrayInputStream(bytes)), JcaKeyFingerprintCalculator())

    private fun holder(name: String, algorithm: KeyAlgorithm): Holder {
        val gen = svc.generateKeyPair(name, "$name@pgpony.test", algorithm, null)
        val sec = secretRing(gen.privateKeyData)
        val pub = PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
        return Holder(name, sec, pub, gen.armoredPrivateKey)
    }

    @Test
    fun dumpMixedRecipientFixtures() {
        val composite768 = holder("composite768", KeyAlgorithm.MLKEM768_X25519_V6)
        val composite1024 = holder("composite1024", KeyAlgorithm.MLKEM1024_X448_V6)
        val classical = holder("classical", KeyAlgorithm.ED25519_CV25519)
        val v6classical = holder("v6classical", KeyAlgorithm.V6_ED25519)
        val librepgp = holder("librepgp", KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
        val librepgp1024 = holder("librepgp1024", KeyAlgorithm.MLKEM1024_X448_LIBREPGP)
        val rsa = holder("rsa", KeyAlgorithm.RSA_2048)

        val cells = listOf(
            "composite-and-classical" to listOf(composite768, classical),
            "composite-and-v6classical" to listOf(composite768, v6classical),
            "composite-and-rsa" to listOf(composite768, rsa),
            "two-composites" to listOf(composite768, composite1024),
            "composite-and-librepgp" to listOf(composite768, librepgp),
            "librepgp-and-classical" to listOf(librepgp, classical),
            "two-librepgp" to listOf(librepgp, librepgp1024),
            "all-mixed" to listOf(classical, librepgp, rsa, composite768)
        )

        File(outDir, "plaintext.txt").writeBytes(plaintext)
        for ((caseName, holders) in cells) {
            val message = svc.encrypt(plaintext, holders.map { it.pub })
            for (h in holders) {
                val out = svc.decrypt(message, listOf(h.sec), passphrase = null)
                assertArrayEquals("$caseName as ${h.name}", plaintext, out.data)
                File(outDir, "$caseName.${h.name}.sec.asc").writeText(h.armoredSecret)
            }
            File(outDir, "$caseName.msg.asc").writeText(String(message, Charsets.US_ASCII))
        }
        println("Mixed-recipient fixtures written to ${outDir.absolutePath}")
    }
}
