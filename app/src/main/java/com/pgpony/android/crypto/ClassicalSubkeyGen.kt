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
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.PublicSubkeyPacket
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
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
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

    /**
     * 4.8.0 RC10 (#109): the ECDSA (sign, authenticate) and ECDH (encrypt)
     * entries carry their [curve], one of KeyAlgorithm.generatableEcdsa. They
     * are v4 only, like the keys PGPony generates on those curves, and are
     * made with the same curve parameters (EcdsaKeygen). An Authenticate
     * subkey on brainpool or secp256k1 is for a security key's AUT slot: SSH
     * has no key type for those curves, so SshAuth passes it over.
     */
    enum class ClassicalSubkeyType(
        val displayName: String,
        val capability: Capability,
        val curve: KeyAlgorithm? = null
    ) {
        RSA_2048_SIGN("RSA 2048 (Sign)", Capability.SIGN),
        RSA_2048_ENCRYPT("RSA 2048 (Encrypt)", Capability.ENCRYPT),
        RSA_4096_SIGN("RSA 4096 (Sign)", Capability.SIGN),
        RSA_4096_ENCRYPT("RSA 4096 (Encrypt)", Capability.ENCRYPT),
        RSA_2048_AUTH("RSA 2048 (Authenticate)", Capability.AUTHENTICATE),
        RSA_4096_AUTH("RSA 4096 (Authenticate)", Capability.AUTHENTICATE),
        ED25519_SIGN("Ed25519 (Sign)", Capability.SIGN),
        ED25519_AUTH("Ed25519 (Authenticate)", Capability.AUTHENTICATE),
        X25519_ENCRYPT("X25519 (Encrypt)", Capability.ENCRYPT),
        // 4.8.0 RC10 (#109)
        ECDSA_P256_SIGN("ECDSA NIST P-256 (Sign)", Capability.SIGN, KeyAlgorithm.ECDSA_NIST_P256),
        ECDSA_P256_AUTH("ECDSA NIST P-256 (Authenticate)", Capability.AUTHENTICATE, KeyAlgorithm.ECDSA_NIST_P256),
        ECDH_P256_ENCRYPT("ECDH NIST P-256 (Encrypt)", Capability.ENCRYPT, KeyAlgorithm.ECDSA_NIST_P256),
        ECDSA_P384_SIGN("ECDSA NIST P-384 (Sign)", Capability.SIGN, KeyAlgorithm.ECDSA_NIST_P384),
        ECDSA_P384_AUTH("ECDSA NIST P-384 (Authenticate)", Capability.AUTHENTICATE, KeyAlgorithm.ECDSA_NIST_P384),
        ECDH_P384_ENCRYPT("ECDH NIST P-384 (Encrypt)", Capability.ENCRYPT, KeyAlgorithm.ECDSA_NIST_P384),
        ECDSA_P521_SIGN("ECDSA NIST P-521 (Sign)", Capability.SIGN, KeyAlgorithm.ECDSA_NIST_P521),
        ECDSA_P521_AUTH("ECDSA NIST P-521 (Authenticate)", Capability.AUTHENTICATE, KeyAlgorithm.ECDSA_NIST_P521),
        ECDH_P521_ENCRYPT("ECDH NIST P-521 (Encrypt)", Capability.ENCRYPT, KeyAlgorithm.ECDSA_NIST_P521),
        ECDSA_BP256_SIGN("ECDSA brainpoolP256r1 (Sign)", Capability.SIGN, KeyAlgorithm.ECDSA_BRAINPOOL_P256),
        ECDSA_BP256_AUTH("ECDSA brainpoolP256r1 (Authenticate)", Capability.AUTHENTICATE, KeyAlgorithm.ECDSA_BRAINPOOL_P256),
        ECDH_BP256_ENCRYPT("ECDH brainpoolP256r1 (Encrypt)", Capability.ENCRYPT, KeyAlgorithm.ECDSA_BRAINPOOL_P256),
        ECDSA_BP384_SIGN("ECDSA brainpoolP384r1 (Sign)", Capability.SIGN, KeyAlgorithm.ECDSA_BRAINPOOL_P384),
        ECDSA_BP384_AUTH("ECDSA brainpoolP384r1 (Authenticate)", Capability.AUTHENTICATE, KeyAlgorithm.ECDSA_BRAINPOOL_P384),
        ECDH_BP384_ENCRYPT("ECDH brainpoolP384r1 (Encrypt)", Capability.ENCRYPT, KeyAlgorithm.ECDSA_BRAINPOOL_P384),
        ECDSA_BP512_SIGN("ECDSA brainpoolP512r1 (Sign)", Capability.SIGN, KeyAlgorithm.ECDSA_BRAINPOOL_P512),
        ECDSA_BP512_AUTH("ECDSA brainpoolP512r1 (Authenticate)", Capability.AUTHENTICATE, KeyAlgorithm.ECDSA_BRAINPOOL_P512),
        ECDH_BP512_ENCRYPT("ECDH brainpoolP512r1 (Encrypt)", Capability.ENCRYPT, KeyAlgorithm.ECDSA_BRAINPOOL_P512),
        ECDSA_SECP256K1_SIGN("ECDSA secp256k1 (Sign)", Capability.SIGN, KeyAlgorithm.ECDSA_SECP256K1),
        ECDSA_SECP256K1_AUTH("ECDSA secp256k1 (Authenticate)", Capability.AUTHENTICATE, KeyAlgorithm.ECDSA_SECP256K1),
        ECDH_SECP256K1_ENCRYPT("ECDH secp256k1 (Encrypt)", Capability.ENCRYPT, KeyAlgorithm.ECDSA_SECP256K1);

        companion object {
            /** 4.8.0 RC10 (#109): the ECDSA or ECDH entry for [curve] and [capability], or null. */
            fun ecdsa(curve: KeyAlgorithm, capability: Capability): ClassicalSubkeyType? =
                entries.firstOrNull { it.curve == curve && it.capability == capability }
        }
    }

    class SubkeyAddError(message: String, cause: Throwable? = null) : Exception(message, cause)

    /**
     * 4.6.0 (item 16): the SSH authentication subkey keygen adds to a new key
     * of [algorithm]. An RSA key gets an RSA subkey (2048 for RSA 2048, 4096
     * for larger sizes) so it stays all-RSA for servers and policies that
     * expect it; every other key gets Ed25519. 4.8.0 RC10 (#109): a NIST
     * ECDSA key gets ECDSA on its curve.
     */
    fun sshAuthTypeFor(algorithm: KeyAlgorithm): ClassicalSubkeyType = when (algorithm) {
        KeyAlgorithm.RSA_2048 -> ClassicalSubkeyType.RSA_2048_AUTH
        KeyAlgorithm.RSA_3072, KeyAlgorithm.RSA_4096, KeyAlgorithm.RSA_8192 -> ClassicalSubkeyType.RSA_4096_AUTH
        // 4.8.0 RC10 (#109): a NIST ECDSA key gets an ECDSA subkey on its own
        // curve, which SSH takes; brainpool and secp256k1 have no SSH type, so
        // they keep Ed25519 for SSH.
        KeyAlgorithm.ECDSA_NIST_P256 -> ClassicalSubkeyType.ECDSA_P256_AUTH
        KeyAlgorithm.ECDSA_NIST_P384 -> ClassicalSubkeyType.ECDSA_P384_AUTH
        KeyAlgorithm.ECDSA_NIST_P521 -> ClassicalSubkeyType.ECDSA_P521_AUTH
        else -> ClassicalSubkeyType.ED25519_AUTH
    }

    /**
     * Add [type] as a new subkey of [secretRing], bound and protected the
     * same way the primary's own subkeys are. [passphrase] must match the
     * ring's existing protection (empty string if the ring is
     * unprotected) — it both unlocks the primary to sign the binding and
     * protects the new subkey's secret material identically.
     */
    /**
     * item 16 (#54): remove a subkey (local delete, no revocation) from a v4 or
     * v6 secret ring. Strips the secret subkey and its binding; the caller
     * derives the public ring from the result. BC's removeSecretKey handles
     * both v4 and v6 rings, so no version split is needed. Throws SubkeyAddError
     * if [subkeyId] is the primary or is not present on the ring.
     */
    fun removeSubkey(secretRing: PGPSecretKeyRing, subkeyId: Long): PGPSecretKeyRing {
        if (subkeyId == secretRing.secretKey.keyID) {
            throw SubkeyAddError("Cannot remove the primary key; only subkeys can be removed")
        }
        val target = secretRing.getSecretKey(subkeyId)
            ?: throw SubkeyAddError("Subkey not found on this key")
        return PGPSecretKeyRing.removeSecretKey(secretRing, target)
            ?: throw SubkeyAddError("Removing the subkey would leave no keys on the ring")
    }

    fun addSubkey(
        secretRing: PGPSecretKeyRing,
        type: ClassicalSubkeyType,
        passphrase: String?,
        expirationSeconds: Long? = null,
        random: SecureRandom = SecureRandom(),
        creationTime: Date = Date()
    ): PGPSecretKeyRing {
        val primarySec = secretRing.secretKey
        OfflineStub.requireSecret(primarySec) // 4.7.0 (item 22): the binding needs the primary

        val decryptor = com.pgpony.android.crypto.SecretKeyUnlock.decryptor(passphrase)
        val checksumCalc = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        // 4.8.0 (4l, #109): an ECDSA primary signs with a hash as long as its curve.
        val certSigGen = BcPGPContentSignerBuilder(
            primarySec.publicKey.algorithm,
            EcCurveOid.signatureHash(primarySec.publicKey, HashAlgorithmTags.SHA256)
        )
        val encryptor = passphrase?.takeIf { it.isNotEmpty() }?.let {
            S2kPolicy.v4EncryptorBuilder() // 4.6.0 (item 17.6)
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

        // 4.7.0 (item 39): a signing subkey needs the 0x19 back-signature
        // made by the new subkey itself (RFC 9580 5.2.1); the three-argument
        // addSubKey left it out, so gpg reported a signing subkey added here as
        // not cross-certified and PGPony's own binding check did not count it
        // as a signer. BC embeds the back-signature when given the subkey's
        // signer builder.
        // 4.8.0 RC10 (#109): an ECDSA subkey's back-signature uses a hash as long as its curve.
        val backSigner = if (type.capability == Capability.SIGN) {
            BcPGPContentSignerBuilder(
                subKeyPair.publicKey.algorithm,
                EcCurveOid.signatureHash(subKeyPair.publicKey, HashAlgorithmTags.SHA256)
            )
        } else null
        try {
            gen.addSubKey(subKeyPair, hashedGen.generate(), unhashedGen.generate(), backSigner)
        } catch (e: PGPException) {
            throw SubkeyAddError("Could not bind the new subkey: ${e.message}", e)
        }

        return gen.generateSecretKeyRing()
    }

    /** 4.8.0 (#71): a key other than v4 takes no subkey through [addSubkeyWith]. */
    const val V4_ONLY_MESSAGE = "Only a v4 key can take a subkey signed on the security key"

    /**
     * 4.8.0 (#71): add [type] as a new subkey of the v4 [secretRing] when the
     * primary signs through [signer] instead of from the ring, as when the
     * stored primary is a divert-to-card stub and the primary sits in the
     * card's Signature slot. [addSubkey] cannot: Bouncy Castle's
     * PGPKeyRingGenerator unlocks the primary from the ring.
     *
     * The subkey ([pair], made with [newSubkeyPair] before the card is tapped,
     * or here) stays on the phone, protected with [passphrase], which is
     * required (see [ringPassphrase]). The binding (0x18) is the one
     * signature the primary makes. A signing subkey also gets the embedded
     * 0x19 back-signature, made by the new subkey itself, as in [addSubkey].
     * Every other key in [secretRing] is kept as it is, so stubs stay stubs.
     */
    fun addSubkeyWith(
        signer: PrimarySigner,
        secretRing: PGPSecretKeyRing,
        publicRing: PGPPublicKeyRing,
        type: ClassicalSubkeyType,
        passphrase: String?,
        expirationSeconds: Long? = null,
        random: SecureRandom = SecureRandom(),
        pair: PGPKeyPair = buildKeyPair(type, random, Date())
    ): SignedEdit {
        val primaryPub = publicRing.publicKey
        if (primaryPub.version != PublicKeyPacket.VERSION_4) throw SubkeyAddError(V4_ONLY_MESSAGE)
        if (primaryPub.keyID != signer.publicKey.keyID || secretRing.publicKey.keyID != primaryPub.keyID) {
            throw SubkeyAddError("The signer is not this key's primary key")
        }
        val protectWith = ringPassphrase(secretRing, passphrase)

        // The subkey's public key as a subkey packet (tag 14) from the start, so
        // Bouncy Castle treats it as a subkey when it is inserted into the ring.
        val subPacket = PublicSubkeyPacket(
            PublicKeyPacket.VERSION_4, pair.publicKey.algorithm, pair.publicKey.creationTime,
            pair.publicKey.publicKeyPacket.key
        )
        val subPub = PGPPublicKey(subPacket, BcKeyFingerprintCalculator())
        val subPriv = PGPPrivateKey(subPub.keyID, subPacket, pair.privateKey.privateKeyDataPacket)

        val hashedGen = PGPSignatureSubpacketGenerator()
        hashedGen.setKeyFlags(
            false,
            when (type.capability) {
                Capability.SIGN -> PGPKeyFlags.SIGN_DATA
                Capability.ENCRYPT -> PGPKeyFlags.ENCRYPT_COMMS or PGPKeyFlags.ENCRYPT_STORAGE
                Capability.AUTHENTICATE -> PGPKeyFlags.AUTHENTICATION
            }
        )
        hashedGen.setIssuerFingerprint(false, primaryPub)
        if (expirationSeconds != null) {
            hashedGen.setKeyExpirationTime(false, expirationSeconds)
        }
        if (type.capability == Capability.SIGN) {
            // 4.7.0 (item 39): the back-signature is made by the new subkey.
            // 4.8.0 RC10 (#109): as long as an ECDSA subkey's curve.
            val back = PonySigGen(
                BcPGPContentSignerBuilder(subPub.algorithm, EcCurveOid.signatureHash(subPub, HashAlgorithmTags.SHA256)),
                subPub
            )
            back.init(PGPSignature.PRIMARYKEY_BINDING, subPriv)
            hashedGen.setEmbeddedSignature(false, back.generateCertification(primaryPub, subPub))
        }

        val bindGen = signer.generator(PGPSignature.SUBKEY_BINDING)
        bindGen.setHashedSubpackets(hashedGen.generate())
        val binding = bindGen.generateCertification(primaryPub, subPub)
        val boundPub = PGPPublicKey.addCertification(subPub, binding)

        val checksumCalc = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        val encryptor = S2kPolicy.v4EncryptorBuilder() // 4.6.0 (item 17.6)
            .setSecureRandom(random)
            .build(protectWith.toCharArray())
        val secret = PGPSecretKey(subPriv, boundPub, checksumCalc, false, encryptor)
        // Parsed back from their octets, so the new subkey reads like any other.
        val ring = PGPSecretKeyRing(
            PGPSecretKeyRing.insertSecretKey(secretRing, secret).encoded, BcKeyFingerprintCalculator()
        )
        val newPublic = ring.getPublicKey(subPub.keyID)
            ?: throw SubkeyAddError("Could not bind the new subkey")
        val pubRing = PGPPublicKeyRing(
            PGPPublicKeyRing.insertPublicKey(publicRing, newPublic).encoded, BcKeyFingerprintCalculator()
        )
        return SignedEdit.of(pubRing, ring)
    }

    /**
     * 4.8.0 (#71): a new key pair of [type] for [addSubkeyWith], made before the
     * security key is tapped: an RSA 4096 key can take many seconds, longer
     * than a card should be held to the phone.
     */
    fun newSubkeyPair(type: ClassicalSubkeyType): PGPKeyPair = buildKeyPair(type, SecureRandom(), Date())

    /**
     * 4.8.0 (#71): the passphrase the new subkey is protected with. When a
     * secret with material in [secretRing] is protected, [passphrase] has to
     * unlock it, so the key keeps one passphrase. When the phone holds no
     * protected secret for the key (every secret on the card, or only
     * unprotected ones here), [passphrase] is a new one chosen for the new
     * subkey and is required: its secret is never stored unprotected.
     */
    private fun ringPassphrase(secretRing: PGPSecretKeyRing, passphrase: String?): String {
        if (passphrase.isNullOrEmpty()) throw SubkeyAddError(PASSPHRASE_REQUIRED_MESSAGE)
        val held = secretRing.secretKeys.asSequence()
            .firstOrNull { !OfflineStub.isStub(it) && it.s2KUsage.toInt() != 0 }
            ?: return passphrase
        val unlocked = try {
            SecretKeyUnlock.extract(held, passphrase.toCharArray())
        } catch (e: PGPException) {
            null
        }
        if (unlocked == null) throw SubkeyAddError("Incorrect passphrase for key")
        return passphrase
    }

    /** 4.8.0 (#71): [addSubkeyWith] was given no passphrase for the new subkey. */
    const val PASSPHRASE_REQUIRED_MESSAGE = "Passphrase is required for this key"

    private fun buildKeyPair(
        type: ClassicalSubkeyType,
        random: SecureRandom,
        creationTime: Date
    ): PGPKeyPair {
        // 4.8.0 RC10 (#109): ECDSA or ECDH on one of the generated curves.
        type.curve?.let { return ecKeyPair(it, type.capability == Capability.ENCRYPT, random, creationTime) }
        return classicalKeyPair(type, random, creationTime)
    }

    /**
     * 4.8.0 RC10 (#109): an ECDSA (algo 19) or ECDH (algo 18) v4 key pair on
     * [curve], with the curve parameters and ECDH KDF of a generated key on
     * that curve (EcdsaKeygen), so an added subkey matches one PGPony would
     * have generated.
     */
    private fun ecKeyPair(curve: KeyAlgorithm, encrypt: Boolean, random: SecureRandom, creationTime: Date): PGPKeyPair {
        val params = EcdsaKeygen.curveFor(curve)
            ?: throw SubkeyAddError("Cannot make a subkey on ${curve.shortName}")
        val pair = EcdsaKeygen.generateKeyPair(params, random)
        return if (encrypt) {
            BcPGPKeyPair(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.ECDH, EcdsaKeygen.kdfParameters(params), pair, creationTime)
        } else {
            BcPGPKeyPair(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.ECDSA, pair, creationTime)
        }
    }

    private fun classicalKeyPair(
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
        else -> throw SubkeyAddError("Unsupported subkey type ${type.displayName}")
    }

    private fun rsaKeyPair(bits: Int, random: SecureRandom, creationTime: Date): PGPKeyPair {
        val rsaGen = RSAKeyPairGenerator()
        rsaGen.init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), random, bits, 80))
        return BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsaGen.generateKeyPair(), creationTime)
    }
}
