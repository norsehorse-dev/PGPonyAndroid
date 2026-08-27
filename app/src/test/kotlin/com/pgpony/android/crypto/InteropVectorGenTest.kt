package com.pgpony.android.crypto

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * Throwaway generator for the Crake interop test vectors. Not a real test of
 * anything; it produces fresh PGPony-native v6 and v4 keys, encrypts through
 * PGPCryptoService, and asserts each round-trips. Delete after use.
 * Output: ~/pony-interop-vectors
 */
class InteropVectorGenTest {

    private val plaintext =
        "Crake <> Pony interop test vector. If you can read this, decryption works."

    private val outDir =
        File(System.getProperty("user.home"), "pony-interop-vectors").apply { mkdirs() }

    @Test
    fun generatePgpVectors() {
        val svc = PGPCryptoService.shared
        val specs = listOf(
            Triple("v6", KeyAlgorithm.V6_ED25519, "v6@pony.invalid"),
            Triple("v4", KeyAlgorithm.ED25519_CV25519, "v4@pony.invalid")
        )
        for ((tag, algo, email) in specs) {
            val gen = svc.generateKeyPair("Pony Interop $tag Test", email, algo, null)
            val pub = svc.importArmoredKey(gen.armoredPublicKey).publicKeyRing!!
            val sec = svc.importArmoredKey(gen.armoredPrivateKey).secretKeyRing!!
            val ct = svc.encryptMessage(plaintext, listOf(pub))
            assertEquals(plaintext, svc.decryptArmored(ct, listOf(sec), null).plaintext)
            File(outDir, "pgp_${tag}_public.asc").writeText(gen.armoredPublicKey)
            File(outDir, "pgp_${tag}_secret.asc").writeText(gen.armoredPrivateKey)
            File(outDir, "pgp_${tag}_hello.asc").writeText(ct)
        }
        println("PGPony vectors written to ${outDir.absolutePath}")
    }
}
