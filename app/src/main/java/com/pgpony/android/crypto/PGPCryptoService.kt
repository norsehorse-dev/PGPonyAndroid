// PGPCryptoService.kt
// PGPony Android
//
// Core cryptographic service wrapping Bouncy Castle for all OpenPGP operations.
// This is the Android equivalent of iOS PGPService.swift + OpenPGPPacketParser +
// OpenPGPPacketBuilder + Cv25519ECDHService + AEADService + Argon2Service.
//
// Bouncy Castle handles natively what iOS needed 5+ custom services for:
//   - RSA, Ed25519, Cv25519 key gen/import/export
//   - SEIPD v1 (CFB) and SEIPDv2 (AEAD OCB) decrypt
//   - Argon2id S2K (type 4) for v6 keys
//   - Ed25519 signing with issuer fingerprint subpacket
//   - Cv25519 MPI byte ordering (no manual reversal needed)
//   - AES Key Wrap for ECDH session keys
//   - Zlib/BZip2 decompression

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.IssuerFingerprint
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import com.pgpony.android.crypto.card.CardPGPContentSignerBuilder
import com.pgpony.android.crypto.card.OpenPgpCardSession
import com.pgpony.android.data.ArmorCommentHeader
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.security.Security
import java.util.Date

// ── Phase A7 Fix: ASCII armor configuration ────────────────────────────

/**
 * Strip the default "Version: BCPG v@RELEASE_NAME@" header from an
 * ArmoredOutputStream and apply the user-configured "Comment:" header.
 *
 * Why the Version strip is needed: bcpg-jdk18on:1.78.1 emits a Version
 * header in every armored block, populated from its build-time
 * RELEASE_NAME substitution. That substitution doesn't actually run for
 * the published JAR, so the literal placeholder string ends up in our
 * output. GnuPG warns ("invalid armor header") but still accepts the
 * key; cosmetically it looks broken. We always remove it.
 *
 * The Comment header is now user-configurable (Settings → "Include
 * comment in PGP output"). ArmorCommentHeader.current holds the
 * already-validated value, or null when the user has turned the comment
 * off or cleared it — in which case no Comment header is written. RFC
 * 4880 §6.2 allows arbitrary Comment headers; GnuPG, Sequoia, and
 * ProtonMail all parse (and ignore) them without complaint, and the
 * blank-line separator after the headers is emitted unconditionally by
 * bcpg 1.78.1, so an empty header set is still valid armor.
 *
 * Applied at every MESSAGE-style ArmoredOutputStream construction site
 * in this file (encrypt / sign / encrypt-and-sign). Exported keys use
 * stripVersionClean() instead — they must stay comment-free.
 *
 * NOTE: RevocationService.kt keeps its own copy of the version-strip
 * extension to avoid an inter-file dependency for a small helper; that
 * path is not affected by this user setting.
 */
private fun ArmoredOutputStream.stripVersion(): ArmoredOutputStream = apply {
    setHeader("Version", null)
    val comment = ArmorCommentHeader.current
    if (!comment.isNullOrEmpty()) {
        setHeader("Comment", comment)
    } else {
        // Defensive: ensure no Comment header survives from any prior
        // configuration of this stream. A null value removes the entry.
        setHeader("Comment", null)
    }
}

/**
 * Strip BOTH the Version and Comment headers, producing clean armor with
 * no provenance metadata. Used only for EXPORTED keys (public + secret
 * key rings). Exported public keys frequently go to keyservers, so they
 * must never carry the user's message-comment setting — keep them
 * pristine. The blank-line separator after the (now empty) header block
 * is still written by bcpg 1.78.1, so GnuPG parses the result cleanly.
 */
private fun ArmoredOutputStream.stripVersionClean(): ArmoredOutputStream = apply {
    setHeader("Version", null)
    setHeader("Comment", null)
}

// ── Error Types ────────────────────────────────────────────────────────

sealed class PGPCryptoError(message: String) : Exception(message) {
    class KeyGenerationFailed(msg: String) : PGPCryptoError("Key generation failed: $msg")
    class EncryptionFailed(msg: String) : PGPCryptoError("Encryption failed: $msg")
    class DecryptionFailed(msg: String) : PGPCryptoError("Decryption failed: $msg")
    class SigningFailed(msg: String) : PGPCryptoError("Signing failed: $msg")
    class VerificationFailed(msg: String) : PGPCryptoError("Verification failed: $msg")
    class KeyNotFound : PGPCryptoError("Key not found in keyring")
    class InvalidKeyData : PGPCryptoError("Invalid key data")
    class ImportFailed(msg: String) : PGPCryptoError("Key import failed: $msg")
    class ExportFailed(msg: String) : PGPCryptoError("Key export failed: $msg")
    class PassphraseRequired : PGPCryptoError("Passphrase is required for this key")
    class InvalidPassphrase : PGPCryptoError("Incorrect passphrase")
    // Raised when a decrypted message's integrity protection is absent or fails
    // (SEIPDv1 MDC mismatch, SEIPDv2 AEAD tag mismatch, or a legacy unprotected
    // packet). Kept distinct from DecryptionFailed so the symmetric-path
    // wrong-passphrase remapping never masks a genuine tamper/no-MDC result.
    class IntegrityCheckFailed(msg: String) : PGPCryptoError(msg)
}

// ── Result Types ───────────────────────────────────────────────────────

data class GeneratedKeyResult(
    val fingerprint: String,
    val armoredPublicKey: String,
    val armoredPrivateKey: String,
    val publicKeyData: ByteArray,
    val privateKeyData: ByteArray,
    val keyPair: PGPKeyPair? = null
)

data class DecryptResult(
    val plaintext: String,
    val data: ByteArray,
    val signatureVerified: Boolean = false,
    val signerKeyID: String? = null,
    val filename: String? = null
)

data class VerifyResult(
    val isValid: Boolean,
    val signerKeyID: String?,
    val signatureDate: Date?
)

data class ImportResult(
    val fingerprint: String,
    val userID: String,
    val algorithm: KeyAlgorithm,
    val hasPrivateKey: Boolean,
    val creationDate: Date,
    val publicKeyRing: PGPPublicKeyRing?,
    val secretKeyRing: PGPSecretKeyRing?
)

// ── Crypto Service ─────────────────────────────────────────────────────

class PGPCryptoService private constructor() {

    companion object {
        val shared = PGPCryptoService()

        init {
            // Register Bouncy Castle as a security provider
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }
    }

    // ── Key Generation ─────────────────────────────────────────────────

    /**
     * Generate a PGP key pair.
     *
     * For RSA: generates RSA signing key + RSA encryption subkey.
     * For Ed25519: generates Ed25519 signing key + Cv25519 (X25519) encryption subkey.
     *
     * Matches iOS PGPService.generateKeyPair behavior.
     */
    fun generateKeyPair(
        name: String,
        email: String,
        algorithm: KeyAlgorithm,
        passphrase: String?,
        expirationSeconds: Long? = null
    ): GeneratedKeyResult {
        val userID = "$name <$email>"
        val creationDate = Date()

        // Each branch yields the (secret, public) key rings. RSA/Ed25519 (v4)
        // still go through their PGPKeyRingGenerator builders unchanged; v6
        // uses BC 1.84's high-level OpenPGPKeyGenerator and returns rings
        // directly (see buildV6Ed25519X25519KeyRings).
        val (secretKeyRing, publicKeyRing) = when (algorithm) {
            KeyAlgorithm.RSA_2048 ->
                buildRSAKeyRingGenerator(userID, 2048, passphrase, creationDate, expirationSeconds).let {
                    it.generateSecretKeyRing() to it.generatePublicKeyRing()
                }
            KeyAlgorithm.RSA_4096 ->
                buildRSAKeyRingGenerator(userID, 4096, passphrase, creationDate, expirationSeconds).let {
                    it.generateSecretKeyRing() to it.generatePublicKeyRing()
                }
            KeyAlgorithm.ED25519_CV25519 ->
                buildEd25519KeyRingGenerator(userID, passphrase, creationDate, expirationSeconds).let {
                    it.generateSecretKeyRing() to it.generatePublicKeyRing()
                }
            KeyAlgorithm.V6_ED25519 ->
                buildV6Ed25519X25519KeyRings(userID, passphrase, creationDate, expirationSeconds)
            else -> throw PGPCryptoError.KeyGenerationFailed("Cannot generate ${algorithm.displayName} keys — import only")
        }

        val fingerprint = fingerprintHex(publicKeyRing.publicKey)
        val armoredPublic = armorPublicKeyRing(publicKeyRing)
        val armoredPrivate = armorSecretKeyRing(secretKeyRing)

        val publicBytes = publicKeyRing.encoded
        val privateBytes = secretKeyRing.encoded

        return GeneratedKeyResult(
            fingerprint = fingerprint,
            armoredPublicKey = armoredPublic,
            armoredPrivateKey = armoredPrivate,
            publicKeyData = publicBytes,
            privateKeyData = privateBytes
        )
    }

    private fun buildRSAKeyRingGenerator(
        userID: String,
        bits: Int,
        passphrase: String?,
        creationDate: Date,
        expirationSeconds: Long?
    ): PGPKeyRingGenerator {
        val rsaGen = org.bouncycastle.crypto.generators.RSAKeyPairGenerator()
        rsaGen.init(org.bouncycastle.crypto.params.RSAKeyGenerationParameters(
            java.math.BigInteger.valueOf(65537), SecureRandom(), bits, 80
        ))

        val masterBcKeyPair = rsaGen.generateKeyPair()
        val masterKeyPair = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, masterBcKeyPair, creationDate)

        // Encryption subkey
        val encBcKeyPair = rsaGen.generateKeyPair()
        val encKeyPair = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, encBcKeyPair, creationDate)

        val sigHashGen = PGPSignatureSubpacketGenerator()
        sigHashGen.setKeyFlags(false,
            PGPKeyFlags.CAN_SIGN or PGPKeyFlags.CAN_CERTIFY)
        sigHashGen.setPreferredSymmetricAlgorithms(false, intArrayOf(
            SymmetricKeyAlgorithmTags.AES_256,
            SymmetricKeyAlgorithmTags.AES_192,
            SymmetricKeyAlgorithmTags.AES_128
        ))
        sigHashGen.setPreferredHashAlgorithms(false, intArrayOf(
            HashAlgorithmTags.SHA256,
            HashAlgorithmTags.SHA384,
            HashAlgorithmTags.SHA512
        ))
        if (expirationSeconds != null) {
            sigHashGen.setKeyExpirationTime(false, expirationSeconds)
        }

        val encHashGen = PGPSignatureSubpacketGenerator()
        encHashGen.setKeyFlags(false,
            PGPKeyFlags.CAN_ENCRYPT_COMMS or PGPKeyFlags.CAN_ENCRYPT_STORAGE)

        val encryptor = passphrase?.let {
            org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .build(it.toCharArray())
        }

        val certSigGen = org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(
            masterKeyPair.publicKey.algorithm,
            HashAlgorithmTags.SHA256
        )

        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            masterKeyPair,
            userID,
            org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                .get(HashAlgorithmTags.SHA1),
            sigHashGen.generate(),
            null,
            certSigGen,
            encryptor
        )

        gen.addSubKey(encKeyPair, encHashGen.generate(), null, certSigGen)
        return gen
    }

    private fun buildEd25519KeyRingGenerator(
        userID: String,
        passphrase: String?,
        creationDate: Date,
        expirationSeconds: Long?
    ): PGPKeyRingGenerator {
        // Ed25519 signing key (primary) — BC lightweight + EDDSA_LEGACY (algo 22)
        val edGen = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
        edGen.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
        val masterKeyPair = BcPGPKeyPair(
            PublicKeyAlgorithmTags.EDDSA_LEGACY,  // 22
            edGen.generateKeyPair(),
            creationDate
        )

        // X25519 encryption subkey — BC lightweight + ECDH (algo 18)
        val xGen = org.bouncycastle.crypto.generators.X25519KeyPairGenerator()
        xGen.init(org.bouncycastle.crypto.params.X25519KeyGenerationParameters(SecureRandom()))
        val encKeyPair = BcPGPKeyPair(
            PublicKeyAlgorithmTags.ECDH,  // 18
            xGen.generateKeyPair(),
            creationDate
        )

        val sigHashGen = PGPSignatureSubpacketGenerator()
        sigHashGen.setKeyFlags(false,
            PGPKeyFlags.CAN_SIGN or PGPKeyFlags.CAN_CERTIFY)
        sigHashGen.setPreferredSymmetricAlgorithms(false, intArrayOf(
            SymmetricKeyAlgorithmTags.AES_256,
            SymmetricKeyAlgorithmTags.AES_192,
            SymmetricKeyAlgorithmTags.AES_128
        ))
        sigHashGen.setPreferredHashAlgorithms(false, intArrayOf(
            HashAlgorithmTags.SHA256,
            HashAlgorithmTags.SHA384,
            HashAlgorithmTags.SHA512
        ))
        sigHashGen.setIssuerFingerprint(false, masterKeyPair.publicKey)
        if (expirationSeconds != null) {
            sigHashGen.setKeyExpirationTime(false, expirationSeconds)
        }

        val encHashGen = PGPSignatureSubpacketGenerator()
        encHashGen.setKeyFlags(false,
            PGPKeyFlags.CAN_ENCRYPT_COMMS or PGPKeyFlags.CAN_ENCRYPT_STORAGE)

        // All-Bc operator stack for Ed25519
        val sha1Calc = org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
            .get(HashAlgorithmTags.SHA1)
        val certSigGen = org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(
            masterKeyPair.publicKey.algorithm,
            HashAlgorithmTags.SHA256
        )
        val encryptor = passphrase?.let {
            org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256
            ).build(it.toCharArray())
        }

        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            masterKeyPair,
            userID,
            sha1Calc,
            sigHashGen.generate(),
            null,
            certSigGen,
            encryptor
        )

        gen.addSubKey(encKeyPair, encHashGen.generate(), null)
        return gen
    }

    /**
     * Build an RFC 9580 v6 key using BouncyCastle 1.84's high-level
     * OpenPGPKeyGenerator (the same API that produced the v6 keys V6-2
     * decrypts and verifies against). The shape matches the modern Sequoia
     * layout MINUS the authentication subkey (deferred to the SSH-auth phase):
     *
     *   - Ed25519 (algo 27) certification-only primary key
     *   - Ed25519 (algo 27) dedicated signing subkey
     *   - X25519  (algo 25) dedicated encryption subkey
     *
     * Why the high-level API instead of hand-assembling packets like the v4
     * builders above: v6 keys carry details that are easy to get subtly wrong
     * by hand (salted v6 binding signatures, the v6 secret-key checksum,
     * subkey back-signatures). The high-level generator — written by the
     * author of BC's RFC 9580 support — handles those correctly.
     *
     * Passphrase: follows the v4 procedure — unprotected when `passphrase`
     * is null/blank (build()), otherwise protected via build(passphrase),
     * with a v6-appropriate S2K chosen by BC. aead=false keeps the SECRET
     * KEY's at-rest encryption CFB-based for portability if a user ever
     * exports the private key; this is independent of message encryption
     * (SEIPDv2 outbound is V6-4).
     *
     * Expiration: the high-level builder bakes a 5-year default into the
     * primary's direct-key self-signature. The primary-signature callback
     * below overrides it from `expirationSeconds` — setting the chosen
     * lifetime, or removing the Key Expiration Time subpacket entirely for
     * "never" (expirationSeconds null or <= 0). Per Utils.getPgpSignatureGenerator,
     * the callback's hashed-subpackets function runs AFTER the default 5-year
     * set, so setKeyExpirationTime / removePacketsOfType here is authoritative.
     */
    private fun buildV6Ed25519X25519KeyRings(
        userID: String,
        passphrase: String?,
        creationDate: Date,
        expirationSeconds: Long?
    ): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val implementation = org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation()
        val generator = org.bouncycastle.openpgp.api.OpenPGPKeyGenerator(
            implementation,
            org.bouncycastle.bcpg.PublicKeyPacket.VERSION_6,
            false, // aead=false -> CFB-based secret-key protection (portable export)
            creationDate
        )

        val expirationCallback =
            org.bouncycastle.openpgp.api.SignatureParameters.Callback.Util.modifyHashedSubpackets(
                org.bouncycastle.openpgp.api.SignatureSubpacketsFunction { subpackets ->
                    if (expirationSeconds != null && expirationSeconds > 0L) {
                        subpackets.setKeyExpirationTime(false, expirationSeconds)
                    } else {
                        // "never" — drop the generator's default 5-year expiry
                        subpackets.removePacketsOfType(
                            org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_EXPIRE_TIME
                        )
                    }
                    subpackets
                }
            )

        // Mirrors OpenPGPKeyGenerator.ed25519x25519Key(userId), but routes the
        // primary through our expiration callback instead of the canned 5-year.
        val key = generator.withPrimaryKey(
            org.bouncycastle.openpgp.api.KeyPairGeneratorCallback { gen -> gen.generateEd25519KeyPair() },
            expirationCallback
        )
            .addSigningSubkey(
                org.bouncycastle.openpgp.api.KeyPairGeneratorCallback { gen -> gen.generateEd25519KeyPair() }
            )
            .addEncryptionSubkey(
                org.bouncycastle.openpgp.api.KeyPairGeneratorCallback { gen -> gen.generateX25519KeyPair() }
            )
            .addUserId(userID)
            .let { builder ->
                if (passphrase.isNullOrEmpty()) builder.build()
                else builder.build(passphrase.toCharArray())
            }

        return key.getPGPSecretKeyRing() to key.toCertificate().getPGPPublicKeyRing()
    }

    // ── Import ─────────────────────────────────────────────────────────

    /**
     * Import an armored PGP key (public or private).
     * Handles RSA, Ed25519+Cv25519 (v4), and v6 keys.
     * Bouncy Castle parses all formats natively — no manual packet parsing needed.
     */
    fun importArmoredKey(armoredText: String): ImportResult {
        val inputStream = ArmoredInputStream(ByteArrayInputStream(armoredText.toByteArray()))

        // Try as secret key ring first
        try {
            val secretRing = PGPSecretKeyRing(inputStream, JcaKeyFingerprintCalculator())
            val masterKey = secretRing.publicKey
            val fingerprint = fingerprintHex(masterKey)
            val userID = masterKey.userIDs.asSequence().firstOrNull() ?: "Unknown"
            val algorithm = detectAlgorithm(masterKey)
            val publicRing = PGPPublicKeyRing(
                secretRing.publicKeys.asSequence().map { it }.toList()
            )

            return ImportResult(
                fingerprint = fingerprint,
                userID = userID,
                algorithm = algorithm,
                hasPrivateKey = true,
                creationDate = masterKey.creationTime,
                publicKeyRing = publicRing,
                secretKeyRing = secretRing
            )
        } catch (_: Exception) {
            // Not a secret key — try public
        }

        // Re-open stream for public key attempt
        val inputStream2 = ArmoredInputStream(ByteArrayInputStream(armoredText.toByteArray()))
        try {
            val publicRing = PGPPublicKeyRing(inputStream2, JcaKeyFingerprintCalculator())
            val masterKey = publicRing.publicKey
            val fingerprint = fingerprintHex(masterKey)
            val userID = masterKey.userIDs.asSequence().firstOrNull() ?: "Unknown"
            val algorithm = detectAlgorithm(masterKey)

            return ImportResult(
                fingerprint = fingerprint,
                userID = userID,
                algorithm = algorithm,
                hasPrivateKey = false,
                creationDate = masterKey.creationTime,
                publicKeyRing = publicRing,
                secretKeyRing = null
            )
        } catch (e: Exception) {
            throw PGPCryptoError.ImportFailed(e.message ?: "Unknown error")
        }
    }

    /**
     * Import raw (non-armored) key data.
     */
    fun importKeyData(data: ByteArray): ImportResult {
        val armored = isArmored(data)
        if (armored) {
            return importArmoredKey(String(data))
        }

        // Try binary secret key ring
        try {
            val secretRing = PGPSecretKeyRing(data, JcaKeyFingerprintCalculator())
            val masterKey = secretRing.publicKey
            val publicRing = PGPPublicKeyRing(
                secretRing.publicKeys.asSequence().map { it }.toList()
            )
            return ImportResult(
                fingerprint = fingerprintHex(masterKey),
                userID = masterKey.userIDs.asSequence().firstOrNull() ?: "Unknown",
                algorithm = detectAlgorithm(masterKey),
                hasPrivateKey = true,
                creationDate = masterKey.creationTime,
                publicKeyRing = publicRing,
                secretKeyRing = secretRing
            )
        } catch (_: Exception) { }

        // Try binary public key ring
        try {
            val publicRing = PGPPublicKeyRing(data, JcaKeyFingerprintCalculator())
            val masterKey = publicRing.publicKey
            return ImportResult(
                fingerprint = fingerprintHex(masterKey),
                userID = masterKey.userIDs.asSequence().firstOrNull() ?: "Unknown",
                algorithm = detectAlgorithm(masterKey),
                hasPrivateKey = false,
                creationDate = masterKey.creationTime,
                publicKeyRing = publicRing,
                secretKeyRing = null
            )
        } catch (e: Exception) {
            throw PGPCryptoError.ImportFailed(e.message ?: "Unknown error")
        }
    }

    // ── Export ──────────────────────────────────────────────────────────

    fun exportArmoredPublicKey(publicKeyRing: PGPPublicKeyRing): String {
        return armorPublicKeyRing(publicKeyRing)
    }

    fun exportArmoredPrivateKey(secretKeyRing: PGPSecretKeyRing): String {
        return armorSecretKeyRing(secretKeyRing)
    }

    // ── Encrypt ────────────────────────────────────────────────────────

    /**
     * Encrypt data to one or more recipients.
     *
     * Bouncy Castle handles RSA, Ed25519+Cv25519 (v4 ECDH), and v6 X25519
     * all through the same API — no routing needed (unlike iOS).
     */
    fun encrypt(
        data: ByteArray,
        recipientPublicKeys: List<PGPPublicKeyRing>,
        signingSecretKey: PGPSecretKeyRing? = null,
        passphrase: String? = null,
        // HW Phase 3 (encrypt-and-sign with a card key). When cardSession is
        // non-null the signature leg is produced on the card instead of from
        // a software secret key: the whole encrypt MUST run inside an active
        // NFC operation (card present) because CardPGPContentSigner taps the
        // card to sign. signingSecretKey/passphrase are ignored in that case.
        cardSession: OpenPgpCardSession? = null,
        cardPin: ByteArray? = null,
        cardSigningPublicKey: PGPPublicKey? = null,
        filename: String? = null,
        armor: Boolean = true
    ): ByteArray {
        val outputStream = ByteArrayOutputStream()
        val armoredOut = if (armor) ArmoredOutputStream(outputStream).stripVersion() else null
        val targetOut = armoredOut ?: outputStream

        try {
            // Encrypted data generator. V6-4: emit RFC 9580 SEIPDv2 (AEAD / OCB)
            // when EVERY recipient is a v6 key, otherwise SEIPDv1 (AES-256-CFB +
            // MDC). The SEIPD version is a single per-message choice — all
            // recipients share one container — so it is all-or-nothing: the
            // moment any recipient is v4 (the common case for existing keys), the
            // whole message falls back to SEIPDv1 so the v4 recipient can still
            // decrypt. v6 keys always support SEIPDv2, so the all-v6 gate never
            // produces a container a recipient can't read. This mirrors BouncyCastle's
            // own high-level negotiation (setWithAEAD(OCB, 6) + setUseV6AEAD()), and
            // v6 PKESKs are emitted automatically for the v6 recipient keys by
            // PGPEncryptedDataGenerator under v6 AEAD.
            //
            // Capability is keyed off the primary key version (v6 => SEIPDv2-capable).
            // This is deliberately conservative: a v4 key that advertises SEIPDv2
            // support via its Features subpacket still gets SEIPDv1 here, which it
            // can read fine. A Features-based predicate is a possible later refinement.
            val allRecipientsV6 = recipientPublicKeys.isNotEmpty() &&
                recipientPublicKeys.all {
                    it.publicKey.version == org.bouncycastle.bcpg.PublicKeyPacket.VERSION_6
                }
            val encBuilder = org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256
            )
            val encGen = if (allRecipientsV6) {
                encBuilder
                    .setWithAEAD(org.bouncycastle.bcpg.AEADAlgorithmTags.OCB, 6)
                    .setUseV6AEAD()
                    .setSecureRandom(SecureRandom())
            } else {
                encBuilder
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(SecureRandom())
            }

            val encryptedGen = PGPEncryptedDataGenerator(encGen)

            // Add each recipient's encryption subkey
            for (ring in recipientPublicKeys) {
                val encKey = findEncryptionKey(ring)
                    ?: throw PGPCryptoError.EncryptionFailed("No encryption subkey found for ${fingerprintHex(ring.publicKey)}")
                encryptedGen.addMethod(
                    org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator(encKey)
                )
            }

            val encryptedOut = encryptedGen.open(targetOut, ByteArray(4096))

            // Compressed data generator
            val compGen = PGPCompressedDataGenerator(PGPCompressedData.ZLIB)
            val compOut = compGen.open(encryptedOut)

            // Optional signature
            var sigGen: PGPSignatureGenerator? = null
            // Phase A3 fix: the prior guard was `signingSecretKey != null
            // && passphrase != null`, which silently skipped signing whenever
            // the signing key was unprotected (no passphrase). Result: the
            // "Also sign this message" toggle had no effect on Ed25519 keys
            // generated without a passphrase, since this app's generator
            // creates passphrase-less keys by default. Drop the passphrase
            // half of the guard so any non-null signing key gets signed; the
            // null-passphrase case is handled by passing an empty char array
            // to BcPBESecretKeyDecryptorBuilder.build(), which BC accepts
            // for keys whose s2KUsage indicates unencrypted storage.
            //
            // Phase A10b Fix1: extractPrivateKey wrapped in its own
            // try/catch that translates BC's generic PGPException
            // ("checksum mismatch at  in checksum of 20 bytes") into
            // typed SigningError.PassphraseRequired / InvalidPassphrase
            // so the encrypt+sign UI path can prompt for a passphrase
            // the way signOnly already does. Disambiguation rule
            // copies SigningService.buildSignatureGenerator(): if
            // s2KUsage is 0 the secret material is unencrypted so the
            // failure can't be passphrase-related; non-zero means it
            // IS encrypted and passphrase is the likely culprit.
            // The outer `catch (e: SigningError)` clause below the
            // body lets these typed errors bubble past the generic
            // EncryptionFailed wrap.
            if (cardSession != null && cardSigningPublicKey != null && cardPin != null) {
                // Card-backed signature. The content signer taps the card to
                // sign the SHA-256 digest; BC assembles the one-pass-sig +
                // signature packets around the literal data exactly as for a
                // software key. Mirrors CardSigningService.buildGenerator: a
                // stub PGPPrivateKey carries only the key ID — the card does
                // the actual signing.
                // V6-5: pass the card's signing public key so BC selects the
                // signature version from it (v6 key => v6 signature). For v6 BC
                // generates the salt and writes it into the content signer's
                // output stream first, so CardPGPContentSigner (which hashes
                // everything written) signs the correct salted v6 digest. No-op
                // for v4 card keys.
                sigGen = PGPSignatureGenerator(
                    CardPGPContentSignerBuilder(cardSession, cardPin, cardSigningPublicKey),
                    cardSigningPublicKey
                )
                sigGen.init(
                    PGPSignature.BINARY_DOCUMENT,
                    PGPPrivateKey(cardSigningPublicKey.keyID, cardSigningPublicKey.publicKeyPacket, null)
                )
                val cardSubpackets = PGPSignatureSubpacketGenerator()
                cardSubpackets.setIssuerFingerprint(false, cardSigningPublicKey)
                sigGen.setHashedSubpackets(cardSubpackets.generate())
                sigGen.generateOnePassVersion(false).encode(compOut)
            } else if (signingSecretKey != null) {
                val signingKey = pickSigningSecretKey(signingSecretKey)
                    ?: throw SigningError.NoSigningKey()
                val privateKey = try {
                    signingKey.extractPrivateKey(
                        org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                            org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                        ).build((passphrase ?: "").toCharArray())
                    )
                } catch (e: PGPException) {
                    if (signingKey.s2KUsage.toInt() != 0) {
                        if (passphrase.isNullOrEmpty()) throw SigningError.PassphraseRequired()
                        throw SigningError.InvalidPassphrase()
                    }
                    throw SigningError.SigningFailed(e.message ?: "Failed to unlock signing key")
                }

                sigGen = PGPSignatureGenerator(
                    org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(
                        signingKey.publicKey.algorithm, HashAlgorithmTags.SHA256
                    ),
                    signingKey.publicKey
                )
                sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey)

                // Add issuer fingerprint subpacket — matches iOS Ed25519 behavior
                val subpacketGen = PGPSignatureSubpacketGenerator()
                subpacketGen.setIssuerFingerprint(false, signingKey.publicKey)
                sigGen.setHashedSubpackets(subpacketGen.generate())

                sigGen.generateOnePassVersion(false).encode(compOut)
            }

            // Literal data
            val litGen = PGPLiteralDataGenerator()
            val litOut = litGen.open(
                compOut,
                if (filename != null) PGPLiteralData.BINARY else PGPLiteralData.UTF8,
                filename ?: "",
                data.size.toLong(),
                Date()
            )

            litOut.write(data)
            litOut.close()
            litGen.close()

            // Finalize signature — update with the data that was signed
            if (sigGen != null) {
                sigGen.update(data)
                sigGen.generate().encode(compOut)
            }

            compOut.close()
            compGen.close()
            encryptedOut.close()
            encryptedGen.close()

            armoredOut?.close()
        } catch (e: PGPCryptoError) {
            throw e
        } catch (e: SigningError) {
            // Phase A10b Fix1: signing-key unlock failure (passphrase
            // needed / wrong passphrase / unprotected-but-corrupt).
            // Re-throw so EncryptDecryptViewModel can route this to a
            // passphrase prompt instead of the generic "Encryption
            // failed: checksum mismatch at  in checksum of 20 bytes"
            // error that BouncyCastle emits and the previous catch
            // wrapped into EncryptionFailed.
            throw e
        } catch (e: Exception) {
            throw PGPCryptoError.EncryptionFailed(e.message ?: "Unknown error")
        }

        return outputStream.toByteArray()
    }

    /**
     * Encrypt a text message and return armored output.
     */
    fun encryptMessage(
        message: String,
        recipientPublicKeys: List<PGPPublicKeyRing>,
        signingSecretKey: PGPSecretKeyRing? = null,
        passphrase: String? = null
    ): String {
        val encrypted = encrypt(
            data = message.toByteArray(Charsets.UTF_8),
            recipientPublicKeys = recipientPublicKeys,
            signingSecretKey = signingSecretKey,
            passphrase = passphrase,
            armor = true
        )
        return String(encrypted, Charsets.UTF_8)
    }

    // ── Symmetric / passphrase-only encryption (Phase A1) ──────────────

    /**
     * Encrypt [data] to a passphrase ONLY — no recipient keypair. This is
     * the Android equivalent of `gpg -c` (OpenPGP password-encrypted
     * message: a Symmetric-Key Encrypted Session Key packet, tag 3,
     * wrapping a SEIPD body). iOS hand-builds the SKESK + SEIPD; on
     * Android BouncyCastle owns the packet bytes via
     * PGPEncryptedDataGenerator.addMethod(BcPBEKeyEncryptionMethodGenerator).
     *
     * Defaults (see PHASE_A1_NOTES.md and the master plan §10.2):
     *
     *   - [useAead] = false  → **SEIPDv1** (AES-256-CFB + MDC). This is the
     *     broadest-interop container for `gpg -c` consumers, including
     *     GnuPG 2.2.x. true → SEIPDv2 (RFC 9580 tag-18 v2, AEAD/OCB),
     *     matching the v6 posture but only readable by GnuPG 2.4+ / Sequoia.
     *
     *   - [useArgon2] = true → **Argon2id S2K** (RFC 9580 type 4), matching
     *     the app's v6 Argon2id posture. CRITICAL: we use BouncyCastle's
     *     `Argon2Params.memoryConstrainedParameters()` (Argon2id, 3 passes,
     *     4 lanes, **64 MiB**). The no-arg `Argon2Params()` default is
     *     2 GiB (memSizeExp=21) and would OOM most phones — never use it
     *     here. Argon2 S2K requires GnuPG 2.4+ on the consuming side; set
     *     [useArgon2] = false for an iterated-salted SHA-256 S2K (type 3)
     *     that GnuPG 2.2.x can also read.
     *
     * [filename], when non-null, marks the literal packet BINARY (file
     * mode) and embeds the name; null produces a UTF-8 text literal —
     * mirroring [encrypt]. The literal/compressed pipeline is identical to
     * the recipient path; only the session-key method differs (password
     * instead of public-key).
     */
    fun encryptSymmetric(
        data: ByteArray,
        passphrase: String,
        filename: String? = null,
        armor: Boolean = true,
        useAead: Boolean = false,
        useArgon2: Boolean = true
    ): ByteArray {
        if (passphrase.isEmpty()) {
            throw PGPCryptoError.EncryptionFailed("Passphrase must not be empty")
        }

        val outputStream = ByteArrayOutputStream()
        val armoredOut = if (armor) ArmoredOutputStream(outputStream).stripVersion() else null
        val targetOut = armoredOut ?: outputStream

        try {
            val encBuilder = org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256
            ).setSecureRandom(SecureRandom())

            if (useAead) {
                // SEIPDv2 (RFC 9580) — AEAD/OCB, v6 framing. Mirrors the
                // recipient path's all-v6 branch.
                encBuilder.setWithAEAD(org.bouncycastle.bcpg.AEADAlgorithmTags.OCB, 6)
                    .setUseV6AEAD()
            } else {
                // SEIPDv1 — AES-256-CFB + MDC. Maximal interop for `gpg -c`.
                encBuilder.setWithIntegrityPacket(true)
            }

            val encryptedGen = PGPEncryptedDataGenerator(encBuilder)

            val method = if (useArgon2) {
                // Argon2id S2K (type 4). 64 MiB memory-constrained params —
                // NOT the 2 GiB no-arg default. A fresh 16-byte salt is
                // generated inside Argon2Params from the platform SecureRandom.
                org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator(
                    passphrase.toCharArray(),
                    org.bouncycastle.bcpg.S2K.Argon2Params.memoryConstrainedParameters()
                )
            } else {
                // Iterated-salted SHA-256 S2K (type 3) at the max single-byte
                // count (0xFF) for GnuPG 2.2.x-compatible output.
                org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator(
                    passphrase.toCharArray(),
                    org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                        .get(HashAlgorithmTags.SHA256),
                    0xFF
                )
            }
            encryptedGen.addMethod(method)

            val encryptedOut = encryptedGen.open(targetOut, ByteArray(4096))

            val compGen = PGPCompressedDataGenerator(PGPCompressedData.ZLIB)
            val compOut = compGen.open(encryptedOut)

            val litGen = PGPLiteralDataGenerator()
            val litOut = litGen.open(
                compOut,
                if (filename != null) PGPLiteralData.BINARY else PGPLiteralData.UTF8,
                filename ?: "",
                data.size.toLong(),
                Date()
            )
            litOut.write(data)
            litOut.close()
            litGen.close()

            compOut.close()
            compGen.close()
            encryptedOut.close()
            encryptedGen.close()

            armoredOut?.close()
        } catch (e: PGPCryptoError) {
            throw e
        } catch (e: Exception) {
            throw PGPCryptoError.EncryptionFailed(e.message ?: "Unknown error")
        }

        return outputStream.toByteArray()
    }

    /**
     * Text convenience wrapper around [encryptSymmetric] returning armored
     * output, mirroring [encryptMessage] for the recipient path.
     */
    fun encryptSymmetricMessage(
        message: String,
        passphrase: String,
        useAead: Boolean = false,
        useArgon2: Boolean = true
    ): String {
        val encrypted = encryptSymmetric(
            data = message.toByteArray(Charsets.UTF_8),
            passphrase = passphrase,
            filename = null,
            armor = true,
            useAead = useAead,
            useArgon2 = useArgon2
        )
        return String(encrypted, Charsets.UTF_8)
    }

    // ── Decrypt ────────────────────────────────────────────────────────

    /**
     * Decrypt an encrypted PGP message.
     *
     * On Bouncy Castle 1.84 this path handles, via BC's high-level API:
     *   - SEIPD v1 (AES-256-CFB + MDC, continuous CFB — no §13.9 resync bug)
     *   - SEIPD v2 (RFC 9580 tag-18 version-2 AEAD; OCB is the mandatory
     *     mode). This is the v6 encryption container — distinct from the
     *     deprecated LibrePGP "tag 20" OCB packet, which BC will also read
     *     if a GnuPG 2.4-style message presents one.
     *   - RSA session-key unwrap
     *   - ECDH session-key unwrap: Cv25519 (v4) and native X25519 (v6,
     *     RFC 9580) — EC point byte-ordering handled inside BC
     *   - Zlib/BZip2 decompression
     *   - S2K types 0/1/3 (simple/salted/iterated) + type 4 (Argon2id);
     *     Argon2 requires BC >= 1.79, and we ship 1.84
     *
     * Recipient and signer keys are resolved by BC numeric key ID
     * throughout (findSecretKey / findPublicKey), which derives v6 key IDs
     * from the LEADING fingerprint bytes and searches subkeys — so v6 keys
     * and modern split-subkey layouts resolve here without any v4-specific
     * string handling.
     */
    fun decrypt(
        encryptedData: ByteArray,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String?,
        verificationKeys: List<PGPPublicKeyRing>? = null
    ): DecryptResult {
        // Hoisted above the try so the catch blocks can read it: true once
        // we've committed to the symmetric (SKESK) path, which changes how a
        // failure is interpreted (bad passphrase vs. genuine corruption).
        var usedSymmetric = false
        // The SEIPD object we actually decrypted, kept so its integrity
        // protection can be verified AFTER the plaintext stream is fully read
        // (BC validates SEIPDv1's MDC only on an explicit verify(); without it,
        // CFB-malleable ciphertext and legacy unprotected packets slip through).
        var integrityObj: org.bouncycastle.openpgp.PGPEncryptedData? = null
        try {
            val inputStream = if (isArmored(encryptedData)) {
                ArmoredInputStream(ByteArrayInputStream(encryptedData))
            } else {
                ByteArrayInputStream(encryptedData)
            }

            val pgpFactory = JcaPGPObjectFactory(inputStream)
            val encData = findEncryptedData(pgpFactory)
                ?: throw PGPCryptoError.DecryptionFailed("No encrypted data found in message")

            // Find matching secret key and decrypt session key. A message
            // may carry public-key (PKESK) and/or password (SKESK) session
            // keys; iterate once, take the first PKESK we hold a key for,
            // and remember any SKESK as the symmetric fallback.
            var decryptedStream: java.io.InputStream? = null
            var pbeData: PGPPBEEncryptedData? = null
            for (obj in encData.encryptedDataObjects) {
                when (obj) {
                    is PGPPublicKeyEncryptedData -> {
                        if (decryptedStream != null) continue
                        val secretKey = findSecretKey(obj.keyID, secretKeyRings)
                        if (secretKey != null) {
                            val decryptor = org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                                org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                            ).build(passphrase?.toCharArray() ?: charArrayOf())
                            val privateKey = secretKey.extractPrivateKey(decryptor)

                            decryptedStream = obj.getDataStream(
                                org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory(privateKey)
                            )
                            integrityObj = obj
                        }
                    }
                    is PGPPBEEncryptedData -> {
                        if (pbeData == null) pbeData = obj
                    }
                }
            }

            // Phase A1: symmetric / passphrase-only message (`gpg -c`). When
            // no held key matched a PKESK but the message has an SKESK, the
            // same `passphrase` argument is the MESSAGE passphrase (there is
            // no secret key to unlock here). An absent passphrase is the
            // signal for the UI to prompt — surfaced as PassphraseRequired so
            // the Decrypt screen shows the password prompt rather than a
            // generic failure. BC reads the embedded S2K (incl. Argon2 type 4)
            // automatically.
            if (decryptedStream == null && pbeData != null) {
                if (passphrase.isNullOrEmpty()) throw PGPCryptoError.PassphraseRequired()
                // Commit to the symmetric path BEFORE the BC call: SEIPDv1's
                // quick-check (and SEIPDv2's AEAD tag) reject a wrong passphrase
                // inside getDataStream itself, so the flag must already be set
                // for the catch blocks to map that to InvalidPassphrase.
                usedSymmetric = true
                decryptedStream = pbeData.getDataStream(
                    org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory(
                        passphrase.toCharArray(),
                        org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                    )
                )
                integrityObj = pbeData
            }

            if (decryptedStream == null) {
                throw PGPCryptoError.DecryptionFailed("No matching decryption key found")
            }

            // Parse the decrypted content
            val plainFactory = JcaPGPObjectFactory(decryptedStream)
            val result = processDecryptedContent(plainFactory, verificationKeys)

            // INTEGRITY GATE. processDecryptedContent has now fully consumed the
            // plaintext stream, so the SEIPD integrity protection can be checked:
            //   - isIntegrityProtected() is false for a legacy unprotected SED
            //     packet (tag 9) -> reject; tampering would be undetectable.
            //   - verify() validates SEIPDv1's trailing MDC (and confirms
            //     SEIPDv2's AEAD tag, already enforced during the read). A false
            //     return or PGPException means the ciphertext was altered.
            // Thrown as IntegrityCheckFailed so the symmetric wrong-passphrase
            // remapping below leaves it untouched. The plaintext is never
            // returned when this fails.
            integrityObj?.let { io ->
                val protected = io.isIntegrityProtected()
                val intact = protected && try { io.verify() } catch (ie: PGPException) { false }
                if (!intact) {
                    throw PGPCryptoError.IntegrityCheckFailed(
                        if (!protected) "Message has no integrity protection and was rejected"
                        else "Integrity check failed - the message may have been tampered with"
                    )
                }
            }
            return result

        } catch (e: PGPCryptoError) {
            // A symmetric decrypt with a wrong passphrase produces garbage that
            // typically fails deep in content parsing — e.g. "No literal data
            // found" — which arrives here as a DecryptionFailed thrown by
            // processDecryptedContent. Remap that to InvalidPassphrase. Other
            // typed errors (incl. PassphraseRequired, which is thrown BEFORE
            // usedSymmetric is set) pass through unchanged.
            if (usedSymmetric && e is PGPCryptoError.DecryptionFailed) {
                throw PGPCryptoError.InvalidPassphrase()
            }
            throw e
        } catch (e: PGPException) {
            // For a symmetric (SKESK) message, once we've committed to that
            // path any failure here is overwhelmingly a wrong passphrase: the
            // wrong key yields garbage that fails as an integrity/MDC error, an
            // AEAD tag mismatch, a malformed-packet parse, or a decompression
            // error — the exact wording varies by BC version and container, so
            // we don't gate on the message text. Map it straight to the clean
            // InvalidPassphrase path.
            if (usedSymmetric) throw PGPCryptoError.InvalidPassphrase()
            // Public-key path: a key-unlock passphrase problem shows up as a
            // checksum/secret-key error.
            val msg = e.message ?: ""
            if (msg.contains("checksum", ignoreCase = true) ||
                msg.contains("passphrase", ignoreCase = true) ||
                msg.contains("secret key", ignoreCase = true)
            ) {
                throw PGPCryptoError.InvalidPassphrase()
            }
            throw PGPCryptoError.DecryptionFailed(msg)
        } catch (e: Exception) {
            // A wrong symmetric passphrase can also throw a plain (non-PGP)
            // exception while reading the corrupted stream.
            if (usedSymmetric) throw PGPCryptoError.InvalidPassphrase()
            throw PGPCryptoError.DecryptionFailed(e.message ?: "Unknown error")
        }
    }

    /**
     * Decrypt an armored message.
     */
    fun decryptArmored(
        armoredMessage: String,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String?,
        verificationKeys: List<PGPPublicKeyRing>? = null
    ): DecryptResult {
        return decrypt(
            armoredMessage.toByteArray(Charsets.UTF_8),
            secretKeyRings,
            passphrase,
            verificationKeys
        )
    }

    /**
     * Inspect an (armored or binary) encrypted message and return the key
     * IDs of its public-key recipients, WITHOUT decrypting. Used by the
     * Decrypt tab to detect when a message is addressed to a hardware-key
     * (the matching key ID belongs to a card-backed key's encryption
     * subkey) so it can offer the PIN+tap flow instead of a passphrase.
     * Returns an empty list for non-encrypted or unparseable input.
     */
    fun recipientKeyIDs(armoredMessage: String): List<Long> =
        recipientKeyIDs(armoredMessage.toByteArray(Charsets.UTF_8))

    /**
     * ByteArray overload of [recipientKeyIDs] for file-mode decrypt, where
     * the input may be binary (armor=false) rather than ASCII text. isArmored
     * sniffs the format so both encodings work.
     */
    fun recipientKeyIDs(encryptedData: ByteArray): List<Long> {
        return try {
            val input = if (isArmored(encryptedData)) {
                ArmoredInputStream(ByteArrayInputStream(encryptedData))
            } else {
                ByteArrayInputStream(encryptedData)
            }
            val encData = findEncryptedData(JcaPGPObjectFactory(input)) ?: return emptyList()
            val ids = mutableListOf<Long>()
            for (obj in encData.encryptedDataObjects) {
                if (obj is PGPPublicKeyEncryptedData) ids.add(obj.keyID)
            }
            ids
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Result of [inspectEncryptedMessage]: which session-key methods a
     * message carries, without decrypting. Lets the Decrypt UI pick the
     * right prompt — select a key, tap a card, or (Phase A1) ask for a
     * message passphrase.
     */
    data class MessageEncryptionInfo(
        /** Key IDs of public-key (PKESK) recipients; empty if none. */
        val publicKeyIDs: List<Long>,
        /** True when the message carries a password (SKESK) session key. */
        val isPasswordEncrypted: Boolean
    ) {
        /** No public-key recipients, only a passphrase — a `gpg -c` message. */
        val isSymmetricOnly: Boolean get() = publicKeyIDs.isEmpty() && isPasswordEncrypted
    }

    /**
     * Inspect an (armored or binary) encrypted message and report whether it
     * is addressed to public keys, to a passphrase (SKESK), or both —
     * WITHOUT decrypting. Phase A1: the Decrypt tab calls this to route a
     * password-encrypted message to the passphrase prompt instead of the
     * key picker. Returns no recipients / not-password for unparseable input.
     */
    fun inspectEncryptedMessage(encryptedData: ByteArray): MessageEncryptionInfo {
        return try {
            val input = if (isArmored(encryptedData)) {
                ArmoredInputStream(ByteArrayInputStream(encryptedData))
            } else {
                ByteArrayInputStream(encryptedData)
            }
            val encData = findEncryptedData(JcaPGPObjectFactory(input))
                ?: return MessageEncryptionInfo(emptyList(), false)
            val ids = mutableListOf<Long>()
            var hasPbe = false
            for (obj in encData.encryptedDataObjects) {
                when (obj) {
                    is PGPPublicKeyEncryptedData -> ids.add(obj.keyID)
                    is PGPPBEEncryptedData -> hasPbe = true
                }
            }
            MessageEncryptionInfo(ids, hasPbe)
        } catch (e: Exception) {
            MessageEncryptionInfo(emptyList(), false)
        }
    }

    private fun processDecryptedContent(
        factory: JcaPGPObjectFactory,
        verificationKeys: List<PGPPublicKeyRing>?
    ): DecryptResult {
        var literalData: ByteArray? = null
        var filename: String? = null
        var signatureVerified = false
        var signerKeyID: String? = null
        var onePassSig: PGPOnePassSignature? = null

        var obj = factory.nextObject()
        while (obj != null) {
            when (obj) {
                is PGPCompressedData -> {
                    val compFactory = JcaPGPObjectFactory(obj.dataStream)
                    return processDecryptedContent(compFactory, verificationKeys)
                }
                is PGPOnePassSignatureList -> {
                    if (obj.size() > 0 && verificationKeys != null) {
                        val ops = obj[0]
                        val signerPubKey = findPublicKey(ops.keyID, verificationKeys)
                        if (signerPubKey != null) {
                            ops.init(
                                org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider(),
                                signerPubKey
                            )
                            onePassSig = ops
                            signerKeyID = String.format("%016X", ops.keyID)
                        }
                    }
                }
                is PGPLiteralData -> {
                    filename = obj.fileName.takeIf { it.isNotEmpty() }
                    val litStream = obj.inputStream
                    val buffer = ByteArrayOutputStream()
                    val buf = ByteArray(4096)
                    var len: Int
                    while (litStream.read(buf).also { len = it } >= 0) {
                        buffer.write(buf, 0, len)
                        onePassSig?.update(buf, 0, len)
                    }
                    literalData = buffer.toByteArray()
                }
                is PGPSignatureList -> {
                    if (onePassSig != null && obj.size() > 0) {
                        signatureVerified = onePassSig.verify(obj[0])
                    }
                }
            }
            obj = factory.nextObject()
        }

        val data = literalData
            ?: throw PGPCryptoError.DecryptionFailed("No literal data found in decrypted message")

        val plaintext = try {
            String(data, Charsets.UTF_8)
        } catch (_: Exception) {
            "" // Binary data — caller should use DecryptResult.data
        }

        return DecryptResult(
            plaintext = plaintext,
            data = data,
            signatureVerified = signatureVerified,
            signerKeyID = signerKeyID,
            filename = filename
        )
    }

    // ── Sign ───────────────────────────────────────────────────────────

    /**
     * Sign data with a private key.
     * Returns armored signed message (inline signature).
     *
     * For Ed25519: Bouncy Castle includes issuer fingerprint subpacket (type 33)
     * automatically when configured — matching iOS behavior.
     */
    fun sign(
        data: ByteArray,
        secretKeyRing: PGPSecretKeyRing,
        passphrase: String,
        detached: Boolean = false,
        armor: Boolean = true
    ): ByteArray {
        try {
            val signingKey = pickSigningSecretKey(secretKeyRing)
                ?: throw SigningError.NoSigningKey()
            val privateKey = signingKey.extractPrivateKey(
                org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                    org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                ).build(passphrase.toCharArray())
            )

            val sigGen = PGPSignatureGenerator(
                org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(
                    signingKey.publicKey.algorithm, HashAlgorithmTags.SHA256
                ),
                signingKey.publicKey
            )
            sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey)

            // Add issuer fingerprint subpacket
            val subpacketGen = PGPSignatureSubpacketGenerator()
            subpacketGen.setIssuerFingerprint(false, signingKey.publicKey)
            sigGen.setHashedSubpackets(subpacketGen.generate())

            val outputStream = ByteArrayOutputStream()
            val armoredOut = if (armor) ArmoredOutputStream(outputStream).stripVersion() else null
            val targetOut = armoredOut ?: outputStream

            if (detached) {
                sigGen.update(data)
                sigGen.generate().encode(targetOut)
            } else {
                // Inline signature: OnePassSig + LiteralData + Signature
                val compGen = PGPCompressedDataGenerator(PGPCompressedData.ZLIB)
                val compOut = compGen.open(targetOut)

                sigGen.generateOnePassVersion(false).encode(compOut)

                val litGen = PGPLiteralDataGenerator()
                val litOut = litGen.open(compOut, PGPLiteralData.UTF8, "", data.size.toLong(), Date())
                litOut.write(data)
                litOut.close()

                sigGen.update(data)
                sigGen.generate().encode(compOut)

                compOut.close()
                compGen.close()
            }

            armoredOut?.close()
            return outputStream.toByteArray()
        } catch (e: Exception) {
            throw PGPCryptoError.SigningFailed(e.message ?: "Unknown error")
        }
    }

    // ── Verify ─────────────────────────────────────────────────────────

    /**
     * Verify an inline-signed message.
     */
    fun verify(
        signedData: ByteArray,
        verificationKeys: List<PGPPublicKeyRing>
    ): VerifyResult {
        try {
            val inputStream = if (isArmored(signedData)) {
                ArmoredInputStream(ByteArrayInputStream(signedData))
            } else {
                ByteArrayInputStream(signedData)
            }

            val factory = JcaPGPObjectFactory(inputStream)
            var obj = factory.nextObject()

            while (obj != null) {
                when (obj) {
                    is PGPCompressedData -> {
                        val compFactory = JcaPGPObjectFactory(obj.dataStream)
                        return verifyFromFactory(compFactory, verificationKeys)
                    }
                    is PGPOnePassSignatureList -> {
                        return verifyFromFactory(factory, verificationKeys, obj)
                    }
                }
                obj = factory.nextObject()
            }

            throw PGPCryptoError.VerificationFailed("No signature found in message")
        } catch (e: PGPCryptoError) {
            throw e
        } catch (e: Exception) {
            throw PGPCryptoError.VerificationFailed(e.message ?: "Unknown error")
        }
    }

    private fun verifyFromFactory(
        factory: JcaPGPObjectFactory,
        verificationKeys: List<PGPPublicKeyRing>,
        opsList: PGPOnePassSignatureList? = null
    ): VerifyResult {
        var onePassSig: PGPOnePassSignature? = null
        var signerKeyID: String? = null

        val ops = opsList ?: (factory.nextObject() as? PGPOnePassSignatureList)
        if (ops != null && ops.size() > 0) {
            val opsEntry = ops[0]
            val signerPubKey = findPublicKey(opsEntry.keyID, verificationKeys)
            if (signerPubKey != null) {
                opsEntry.init(
                    org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider(),
                    signerPubKey
                )
                onePassSig = opsEntry
                signerKeyID = String.format("%016X", opsEntry.keyID)
            }
        }

        // Read literal data
        val litData = factory.nextObject() as? PGPLiteralData
            ?: throw PGPCryptoError.VerificationFailed("No literal data in signed message")

        val litStream = litData.inputStream
        val buf = ByteArray(4096)
        var len: Int
        while (litStream.read(buf).also { len = it } >= 0) {
            onePassSig?.update(buf, 0, len)
        }

        // Read signature
        val sigList = factory.nextObject() as? PGPSignatureList
            ?: throw PGPCryptoError.VerificationFailed("No signature packet found")

        val verified = onePassSig?.verify(sigList[0]) ?: false

        return VerifyResult(
            isValid = verified,
            signerKeyID = signerKeyID,
            signatureDate = sigList[0].creationTime
        )
    }

    // ── Algorithm Detection ────────────────────────────────────────────

    /**
     * Detect the KeyAlgorithm from a PGP public key.
     * Maps BC algorithm tags to our KeyAlgorithm enum.
     */
    fun detectAlgorithm(publicKey: PGPPublicKey): KeyAlgorithm {
        val algoId = publicKey.algorithm
        val version = publicKey.version

        return KeyAlgorithm.from(algoId, version) ?: when (algoId) {
            PublicKeyAlgorithmTags.RSA_GENERAL,
            PublicKeyAlgorithmTags.RSA_ENCRYPT,
            PublicKeyAlgorithmTags.RSA_SIGN -> {
                if (publicKey.bitStrength >= 4096) KeyAlgorithm.RSA_4096
                else KeyAlgorithm.RSA_2048
            }
            else -> KeyAlgorithm.RSA_4096 // Fallback
        }
    }

    // ── Helper Functions ───────────────────────────────────────────────

    /** Format a public key fingerprint as uppercase hex string. */
    fun fingerprintHex(publicKey: PGPPublicKey): String {
        return publicKey.fingerprint.joinToString("") { String.format("%02X", it) }
    }

    /**
     * Find the encryption key to address a message to in [ring].
     *
     * BC's PGPPublicKey.isEncryptionKey is ALGORITHM-level: for RSA it is
     * true for any RSA key, including an RSA primary that only carries the
     * [SC] (sign + certify) key flags. Because ring.publicKeys yields the
     * primary first, the old "first isEncryptionKey" rule picked that
     * primary as the recipient for RSA [SC]+[E] keys, so messages were
     * encrypted to the wrong key and the holder (card or gpg) could not
     * decrypt with the [E] subkey. ECC keys were never affected because an
     * Ed25519 primary is not encryption-capable at the algorithm level, so
     * the Cv25519 subkey was the only match. This was the iOS HW-R2.3 bug.
     *
     * Fix (Phase AR-V): among algorithm-encryption-capable keys, honor the
     * Encrypt KEY_FLAG via SubkeyCapability and PREFER a subkey. Fall back
     * to an encryption-capable primary when no subkey qualifies, and finally
     * to the prior algorithm-only match so keys with no usable key-flags do
     * not regress.
     */
    private fun findEncryptionKey(ring: PGPPublicKeyRing): PGPPublicKey? {
        var primaryCandidate: PGPPublicKey? = null
        var algorithmFallback: PGPPublicKey? = null
        ring.publicKeys.forEach { key ->
            if (!key.isEncryptionKey) return@forEach
            if (algorithmFallback == null) algorithmFallback = key
            val caps = SubkeyCapability.fromPgpPublicKey(key, detectAlgorithm(key), key.isMasterKey)
            if (SubkeyCapability.hasCapability(caps, SubkeyCapability.Encrypt)) {
                if (!key.isMasterKey) return key            // prefer an encryption subkey
                if (primaryCandidate == null) primaryCandidate = key
            }
        }
        return primaryCandidate ?: algorithmFallback
    }

    /**
     * Pick the secret key in [ring] that should produce a *data* signature.
     * Prefers a signing-capable subkey (the Sign key flag) and only falls back
     * to the primary if the primary itself advertises Sign. Returns null when
     * no key in the ring is signing-capable.
     *
     * V6-5: PGPony's v4 keys (ED25519_CV25519) carry Sign on the *primary*, so
     * the previous "always use the primary" behaviour happened to work. v6 keys
     * follow the sq layout — a cert-only primary plus a dedicated Ed25519 signing
     * subkey — so signing with the primary produced a v6 signature that sq
     * rejects as "key is not signing capable". Selecting by key flags fixes v6
     * and is correct for any key whose signing capability lives on a subkey.
     * BC has no isSigningKey() (unlike isEncryptionKey), so capability comes from
     * SubkeyCapability, which reads each key's KEY_FLAGS self/binding signature.
     */
    internal fun pickSigningSecretKey(ring: PGPSecretKeyRing): PGPSecretKey? {
        var primaryCandidate: PGPSecretKey? = null
        val iterator = ring.secretKeys
        while (iterator.hasNext()) {
            val secretKey = iterator.next()
            val pub = secretKey.publicKey
            val caps = SubkeyCapability.fromPgpPublicKey(pub, detectAlgorithm(pub), pub.isMasterKey)
            if (SubkeyCapability.hasCapability(caps, SubkeyCapability.Sign)) {
                if (!pub.isMasterKey) return secretKey       // prefer a signing subkey
                if (primaryCandidate == null) primaryCandidate = secretKey
            }
        }
        return primaryCandidate
    }

    /** Find a secret key by key ID across multiple key rings. */
    private fun findSecretKey(keyID: Long, rings: List<PGPSecretKeyRing>): PGPSecretKey? {
        for (ring in rings) {
            val key = ring.getSecretKey(keyID)
            if (key != null) return key
        }
        return null
    }

    /** Find a public key by key ID across multiple key rings. */
    private fun findPublicKey(keyID: Long, rings: List<PGPPublicKeyRing>): PGPPublicKey? {
        for (ring in rings) {
            val key = ring.getPublicKey(keyID)
            if (key != null) return key
        }
        return null
    }

    /** Find encrypted data in a PGP object factory. */
    private fun findEncryptedData(factory: JcaPGPObjectFactory): PGPEncryptedDataList? {
        var obj = factory.nextObject()
        while (obj != null) {
            if (obj is PGPEncryptedDataList) return obj
            obj = factory.nextObject()
        }
        return null
    }

    /** Check if data starts with ASCII armor header. */
    private fun isArmored(data: ByteArray): Boolean {
        if (data.size < 5) return false
        val header = String(data, 0, minOf(50, data.size), Charsets.US_ASCII)
        return header.contains("-----BEGIN PGP")
    }

    /** Armor a public key ring to ASCII. */
    private fun armorPublicKeyRing(ring: PGPPublicKeyRing): String {
        val out = ByteArrayOutputStream()
        // Exported keys stay comment-free (often pushed to keyservers).
        val armoredOut = ArmoredOutputStream(out).stripVersionClean()
        ring.encode(armoredOut)
        armoredOut.close()
        return out.toString(Charsets.UTF_8.name())
    }

    /** Armor a secret key ring to ASCII. */
    private fun armorSecretKeyRing(ring: PGPSecretKeyRing): String {
        val out = ByteArrayOutputStream()
        // Exported keys stay comment-free.
        val armoredOut = ArmoredOutputStream(out).stripVersionClean()
        ring.encode(armoredOut)
        armoredOut.close()
        return out.toString(Charsets.UTF_8.name())
    }
}
