// ClassicalSubkeyGen.kt
// PGPony Android — 4.2.0 RC3 workstream H (§17.2)
//
// Add a classical (RSA / Ed25519 / X25519) subkey to an EXISTING v4
// secret key ring. Companion to CompositeKeyGen.addCompositeSubkey,
// which handles the two post-quantum composite cases (algo 35/36/8);
// this handles the three classical cases §17.2 H calls for: RSA
// 2048/4096 (sign or encrypt, user's choice), Ed25519 (sign only,
// matching how the primary itself is generated), X25519 (encrypt
// only). Unlike the composite path, BC natively understands all three
// wire formats, so there is no hand-rolled packet framing here.
//
// The BC idiom used is PGPKeyRingGenerator's "existing ring" constructor
// (PGPSecretKeyRing, PBESecretKeyDecryptor, PGPDigestCalculator,
// PGPContentSignerBuilder, PBESecretKeyEncryptor): it wraps an already-
// serialized ring without touching the primary's own self-certification,
// so the primary's fingerprint and existing self-signatures are
// untouched, then addSubKey() emits a correctly-bound, correctly-
// protected new subkey through the same code path BC's own from-scratch
// keygen uses. This is the same reason CompositeKeyGen's composite path
// can graft onto a classical ring without disturbing it: only new
// packets are appended, nothing already on disk gets rewritten.
//
// v6 additions (RFC 9580, BC's high-level OpenPGPKeyGenerator) are a
// separate, materially different API surface and are NOT handled here;
// see §17.2 H's note that v6 rides that path instead. This file is v4
// rings only, matching the primary-key generators in PGPCryptoService
// (buildRSAKeyRingGenerator, buildEd25519KeyRingGenerator) whose
// algorithm tags and key-flag conventions it mirrors exactly, so an
// added subkey looks the same to gpg as one PGPony would have generated
// the key with from the start.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags as PGPKeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

object ClassicalSubkeyGen {

    /**
     * The classical subkey shapes §17.2 H asks for. RSA is offered at
     * both bit sizes with either capability since OpenPGP RSA subkeys
     * can do either; Ed25519/X25519 are single-capability by curve, the
     * same restriction the primary-key generators already encode.
     */
    enum class Capability { SIGN, ENCRYPT, AUTHENTICATE }

    enum class ClassicalSubkeyType(val displayName: String, val capability: Capability) {
        RSA_2048_SIGN("RSA 2048 (Sign)", Capability.SIGN),
        RSA_2048_ENCRYPT("RSA 2048 (Encrypt)", Capability.ENCRYPT),
        RSA_4096_SIGN("RSA 4096 (Sign)", Capability.SIGN),
        RSA_4096_ENCRYPT("RSA 4096 (Encrypt)", Capability.ENCRYPT),
        RSA_2048_AUTH("RSA 2048 (Authenticate)", Capability.AUTHENTICATE),
        RSA_4096_AUTH("RSA 4096 (Authenticate)", Capability.AUTHENTICATE),
        ED25519_SIGN("Ed25519 (Sign)", Capability.SIGN),
        ED25519_AUTH("Ed25519 (Authenticate)", Capability.AUTHENTICATE),
        X25519_ENCRYPT("X25519 (Encrypt)", Capability.ENCRYPT)
    }

    class SubkeyAddError(message: String, cause: Throwable? = null) : Exception(message, cause)

    /**
     * Add [type] as a new subkey of [secretRing], bound and protected the
     * same way the primary's own subkeys are. [passphrase] must match the
     * ring's existing protection (empty string if the ring is
     * unprotected) — it both unlocks the primary to sign the binding and
     * protects the new subkey's secret material identically.
     */
    fun addSubkey(
        secretRing: PGPSecretKeyRing,
        type: ClassicalSubkeyType,
        passphrase: String?,
        expirationSeconds: Long? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date()
    ): PGPSecretKeyRing {
        val primarySec = secretRing.secretKey

        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
            .build((passphrase ?: "").toCharArray())
        val checksumCalc = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        val certSigGen = BcPGPContentSignerBuilder(primarySec.publicKey.algorithm, HashAlgorithmTags.SHA256)
        val encryptor = passphrase?.takeIf { it.isNotEmpty() }?.let {
            BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setSecureRandom(random)
                .build(it.toCharArray())
        }

        val gen = try {
            PGPKeyRingGenerator(secretRing, decryptor, checksumCalc, certSigGen, encryptor)
        } catch (e: PGPException) {
            throw SubkeyAddError("Could not unlock the primary key to bind the new subkey: ${e.message}", e)
        }

        val subKeyPair = buildKeyPair(type, random, creationTime)

        val hashedGen = PGPSignatureSubpacketGenerator()
        hashedGen.setKeyFlags(
            false,
            when (type.capability) {
                Capability.SIGN -> PGPKeyFlags.SIGN_DATA
                Capability.ENCRYPT -> PGPKeyFlags.ENCRYPT_COMMS or PGPKeyFlags.ENCRYPT_STORAGE
                // #49: SSH-via-gpg-agent needs an authentication-capable subkey.
                Capability.AUTHENTICATE -> PGPKeyFlags.AUTHENTICATION
            }
        )
        hashedGen.setIssuerFingerprint(false, primarySec.publicKey)
        if (expirationSeconds != null) {
            hashedGen.setKeyExpirationTime(false, expirationSeconds)
        }
        val unhashedGen = PGPSignatureSubpacketGenerator()

        try {
            gen.addSubKey(subKeyPair, hashedGen.generate(), unhashedGen.generate())
        } catch (e: PGPException) {
            throw SubkeyAddError("Could not bind the new subkey: ${e.message}", e)
        }

        return gen.generateSecretKeyRing()
    }

    private fun buildKeyPair(
        type: ClassicalSubkeyType,
        random: SecureRandom,
        creationTime: Date
    ): PGPKeyPair = when (type) {
        ClassicalSubkeyType.RSA_2048_SIGN, ClassicalSubkeyType.RSA_2048_ENCRYPT,
        ClassicalSubkeyType.RSA_2048_AUTH ->
            rsaKeyPair(2048, random, creationTime)
        ClassicalSubkeyType.RSA_4096_SIGN, ClassicalSubkeyType.RSA_4096_ENCRYPT,
        ClassicalSubkeyType.RSA_4096_AUTH ->
            rsaKeyPair(4096, random, creationTime)
        ClassicalSubkeyType.ED25519_SIGN, ClassicalSubkeyType.ED25519_AUTH -> {
            // Matches PGPCryptoService.buildEd25519KeyRingGenerator's
            // primary: BC lightweight Ed25519 + EDDSA_LEGACY (algo 22).
            val edGen = Ed25519KeyPairGenerator()
            edGen.init(Ed25519KeyGenerationParameters(random))
            BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, edGen.generateKeyPair(), creationTime)
        }
        ClassicalSubkeyType.X25519_ENCRYPT -> {
            // Matches the same generator's encryption subkey: BC
            // lightweight X25519 + ECDH (algo 18).
            val xGen = X25519KeyPairGenerator()
            xGen.init(X25519KeyGenerationParameters(random))
            BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, xGen.generateKeyPair(), creationTime)
        }
    }

    private fun rsaKeyPair(bits: Int, random: SecureRandom, creationTime: Date): PGPKeyPair {
        val rsaGen = RSAKeyPairGenerator()
        rsaGen.init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), random, bits, 80))
        return BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsaGen.generateKeyPair(), creationTime)
    }
}
