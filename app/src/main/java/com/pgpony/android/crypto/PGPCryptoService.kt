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
import com.pgpony.android.crypto.pqc.CompositeKeyGen
import com.pgpony.android.crypto.pqc.LibrePGPGnuSecretExport
import com.pgpony.android.crypto.pqc.LibrePGPV5Interop
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

/**
 * 4.0.0 Phase 9b (iOS 7.1.x parity) — strip the Version header and apply
 * the user's PUBKEY-export Comment setting. Used ONLY by
 * [PGPCryptoService.exportArmoredPublicKeyForSharing], i.e. the
 * user-facing copy / share / save of a public key. Keyserver uploads, QR
 * codes, and internal armored caches keep stripVersionClean() so they
 * stay comment-free (matching the iOS footer: "Keyserver uploads and QR
 * codes stay comment-free").
 */
private fun ArmoredOutputStream.stripVersionShareComment(): ArmoredOutputStream = apply {
    setHeader("Version", null)
    val comment = ArmorCommentHeader.pubkeyCurrent
    if (!comment.isNullOrEmpty()) {
        setHeader("Comment", comment)
    } else {
        setHeader("Comment", null)
    }
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

    /**
     * 4.1.0 - nothing on the ring opened the message's session-key packets.
     *
     * Split out of [DecryptionFailed] because the UI has something useful to
     * do with it. [hiddenRecipient] is true when the message carried a
     * wildcard PKESK (`gpg -R`): the recipient is undisclosed, so the keys
     * were TRIALLED rather than looked up, and a card-backed key - which has
     * no local private material to trial with - is the only candidate left to
     * offer the user. Sibling of DecryptionFailed rather than a subclass, so
     * the symmetric wrong-passphrase remapping in [decrypt] leaves it alone;
     * any existing `catch (e: Exception)` behaves exactly as before.
     */
    class NoMatchingKey(val hiddenRecipient: Boolean = false) : PGPCryptoError(
        if (hiddenRecipient)
            "Decryption failed: this message hides its recipient, and none of your keys opened it"
        else
            "Decryption failed: No matching decryption key found"
    )
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
    val filename: String? = null,
    // ── 4.0.0 Phase P2b-1 (additive) — provider signature-state fields ──
    //
    // The OpenPGP API's OpenPgpSignatureResult needs to distinguish
    // "message carries no signature" from "signed by a key we don't
    // hold" (RESULT_NO_SIGNATURE vs RESULT_KEY_MISSING — the unknown-
    // signer badge in Thunderbird), and needs the signing key id even
    // when the signer is unheld. The pre-existing fields can't express
    // that: signerKeyID is only set when the signer's key IS held.
    // Both fields default so every existing call site and consumer
    // compiles unchanged.
    /** True when the decrypted stream carried signature packets at all
     *  (OnePassSignature and/or Signature), verified or not. */
    val hasSignature: Boolean = false,
    /** Raw 64-bit key id from the signature packets — populated even
     *  when the signer's key is not in the keyring. */
    val signatureKeyIDRaw: Long? = null
)

/**
 * 4.0.0 Phase P2d — result of [PGPCryptoService.decryptStream]: the
 * plaintext went to the caller's OutputStream, so this carries only
 * the byte count plus the same metadata/signature fields as
 * [DecryptResult].
 */
data class DecryptStreamResult(
    val bytesWritten: Long,
    val filename: String?,
    val signatureVerified: Boolean,
    val signerKeyID: String?,
    val hasSignature: Boolean,
    val signatureKeyIDRaw: Long?
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

/** §4.5 (#22): a signing-capable key the user can choose in SignAsSheet. */
data class SigningKeyOption(
    val keyId: Long,
    val keyIdHex: String,
    val isPrimary: Boolean,
    val algorithmLabel: String
)

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
            KeyAlgorithm.MLKEM768_X25519_V6 -> {
                // IETF composite (v6). CompositeKeyGen protects the composite
                // subkey when a passphrase is supplied (AEAD/OCB + Argon2id, S2K
                // usage 253) — round-trip tested — so protected keygen is
                // supported end to end.
                val base = buildV6Ed25519X25519KeyRings(userID, passphrase, creationDate, expirationSeconds)
                val ring = com.pgpony.android.crypto.pqc.CompositeKeyGen.addCompositeSubkey(
                    base.first, com.pgpony.android.crypto.pqc.CompositeKeyGen.Scheme.IETF_V6,
                    passphrase, creationTime = creationDate, expirationSeconds = expirationSeconds
                )
                ring to com.pgpony.android.crypto.pqc.CompositeKeyGen.publicRingOf(ring)
            }
            KeyAlgorithm.MLKEM768_X25519_LIBREPGP -> {
                // LibrePGP composite (v5): CompositeKeyGen protects the subkey
                // (AES-256-CFB, S2K usage 254) when a passphrase is supplied.
                val baseSec = buildEd25519KeyRingGenerator(userID, passphrase, creationDate, expirationSeconds)
                    .generateSecretKeyRing()
                val ring = com.pgpony.android.crypto.pqc.CompositeKeyGen.addCompositeSubkey(
                    baseSec, com.pgpony.android.crypto.pqc.CompositeKeyGen.Scheme.LIBREPGP_V5,
                    passphrase, creationTime = creationDate
                )
                ring to com.pgpony.android.crypto.pqc.CompositeKeyGen.publicRingOf(ring)
            }
            KeyAlgorithm.MLKEM1024_X448_V6 -> {
                // IETF composite (v6), ML-KEM-1024 + X448 (algo 36). Same graft
                // as the 768 case, driven by the IETF_1024 suite.
                val base = buildV6Ed25519X25519KeyRings(userID, passphrase, creationDate, expirationSeconds)
                val ring = com.pgpony.android.crypto.pqc.CompositeKeyGen.addCompositeSubkey(
                    base.first, com.pgpony.android.crypto.pqc.CompositeSuite.IETF_1024,
                    passphrase, creationTime = creationDate, expirationSeconds = expirationSeconds
                )
                ring to com.pgpony.android.crypto.pqc.CompositeKeyGen.publicRingOf(ring)
            }
            KeyAlgorithm.MLKEM1024_X448_LIBREPGP -> {
                // LibrePGP composite (v5), Kyber-1024 + X448, driven by the
                // LIBREPGP_1024 suite (v4 EdDSA primary + v5 composite subkey).
                val baseSec = buildEd25519KeyRingGenerator(userID, passphrase, creationDate, expirationSeconds)
                    .generateSecretKeyRing()
                val ring = com.pgpony.android.crypto.pqc.CompositeKeyGen.addCompositeSubkey(
                    baseSec, com.pgpony.android.crypto.pqc.CompositeSuite.LIBREPGP_1024,
                    passphrase, creationTime = creationDate
                )
                ring to com.pgpony.android.crypto.pqc.CompositeKeyGen.publicRingOf(ring)
            }
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
                    // Always drop the generator's default 5-year expiry FIRST.
                    // Otherwise setKeyExpirationTime appends a second
                    // KEY_EXPIRE_TIME subpacket and getValidSeconds() reads the
                    // stale default (the v6 custom-expiry bug). Then add our own
                    // only when a custom expiry is requested; "never" leaves none.
                    subpackets.removePacketsOfType(
                        org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_EXPIRE_TIME
                    )
                    if (expirationSeconds != null && expirationSeconds > 0L) {
                        subpackets.setKeyExpirationTime(false, expirationSeconds)
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
            // issue #4 (SecTec): the expiry must be written onto the subkey
            // binding signatures too. BC sets no Key Expiration Time on subkeys
            // by default, so without these callbacks the signing and encryption
            // subkeys carry no expiry of their own. addSigningSubkey takes a
            // binding-signature callback plus a back-signature callback (null =
            // BC default); addEncryptionSubkey takes the binding callback.
            .addSigningSubkey(
                org.bouncycastle.openpgp.api.KeyPairGeneratorCallback { gen -> gen.generateEd25519KeyPair() },
                expirationCallback,
                null
            )
            .addEncryptionSubkey(
                org.bouncycastle.openpgp.api.KeyPairGeneratorCallback { gen -> gen.generateX25519KeyPair() },
                expirationCallback
            )
            // getValidSeconds() reads the key expiration from the primary
            // User ID certification (the same place the v4 paths set it), so
            // the expiry MUST go here too — putting it only on the direct-key
            // signature above leaves getValidSeconds() reporting 0 for a
            // custom expiry. Apply the same callback to the UID cert.
            .addUserId(userID, expirationCallback)
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
        // De-armor once to raw binary so we can normalize a v5 LibrePGP
        // composite (algo-8) subkey — its on-the-wire framing (as emitted by
        // GnuPG / sq / PGPony-iOS) omits the condLen + checksum octets that
        // BouncyCastle requires internally. LibrePGPV5Interop.toBcFormat adds
        // them back; it's a byte-exact no-op for every other key type.
        val rawBytes = dearmorToBytes(armoredText)
        val normalizedBytes = LibrePGPV5Interop.toBcFormat(rawBytes)

        // Try as secret key ring first
        try {
            val secretRing = PGPSecretKeyRing(
                ByteArrayInputStream(normalizedBytes), JcaKeyFingerprintCalculator()
            )
            val masterKey = secretRing.publicKey
            val fingerprint = fingerprintHex(masterKey)
            val userID = masterKey.userIDs.asSequence().firstOrNull() ?: "Unknown"
            val publicRing = PGPPublicKeyRing(
                secretRing.publicKeys.asSequence().map { it }.toList()
            )
            val algorithm = detectAlgorithm(masterKey, publicRing)

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

        // Public key attempt — public material never needs normalization, so
        // parse the de-armored bytes directly.
        try {
            val publicRing = PGPPublicKeyRing(
                ByteArrayInputStream(rawBytes), JcaKeyFingerprintCalculator()
            )
            val masterKey = publicRing.publicKey
            val fingerprint = fingerprintHex(masterKey)
            val userID = masterKey.userIDs.asSequence().firstOrNull() ?: "Unknown"
            val algorithm = detectAlgorithm(masterKey, publicRing)

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
                algorithm = detectAlgorithm(masterKey, publicRing),
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
                algorithm = detectAlgorithm(masterKey, publicRing),
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

    /**
     * 4.0.0 Phase 9b (iOS 7.1.x parity) — armor a public key for a
     * USER-FACING copy / share / save, honoring the "Include comment in
     * exported public keys" setting. Everything else (keyserver upload,
     * QR encode, entity armored cache, refresh merges) keeps calling
     * [exportArmoredPublicKey], which stays comment-free.
     */
    fun exportArmoredPublicKeyForSharing(publicKeyRing: PGPPublicKeyRing): String {
        val out = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(out).stripVersionShareComment()
        publicKeyRing.encode(armoredOut)
        armoredOut.close()
        return out.toString(Charsets.UTF_8.name())
    }

    /**
     * RC4 O5 (#16, CertainBot): true when the ring's secret material is
     * already passphrase-protected (S2K usage != 0). Such a ring exports
     * as-is — its own passphrase already guards the file, and we could
     * not re-encrypt it without knowing that passphrase anyway.
     */
    fun isPassphraseProtected(secretKeyRing: PGPSecretKeyRing): Boolean =
        secretKeyRing.secretKey.s2KUsage != 0

    /**
     * RC4 O5 (#16, CertainBot): export an UNPROTECTED secret ring
     * re-encrypted under [exportPassphrase] (AES-256, S2K usage 254 —
     * the same protection CompositeKeyGen applies at generation). The
     * stored ring is untouched; only the export copy is protected.
     * Throws PGPException if the ring is already protected — callers
     * gate on [isPassphraseProtected] first.
     */
    fun exportArmoredPrivateKeyWithPassphrase(
        secretKeyRing: PGPSecretKeyRing,
        exportPassphrase: String
    ): String {
        val digest = org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
            .get(org.bouncycastle.bcpg.HashAlgorithmTags.SHA1)
        val encryptor = org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder(
            org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256, digest
        ).build(exportPassphrase.toCharArray())
        val protectedRing = PGPSecretKeyRing.copyWithNewPassword(secretKeyRing, null, encryptor)
        return exportArmoredPrivateKey(protectedRing)
    }

    /**
     * §1.1 (#26) Change a key's passphrase. Returns a NEW ring re-encrypted
     * under [newPassphrase]; the stored ring is left untouched until the
     * caller persists the result, so a failure mid-change can never leave the
     * key unreadable.
     *
     * Unlike exportArmoredPrivateKeyWithPassphrase (which re-encrypts an
     * UNPROTECTED ring, decryptor = null), this unlocks with [oldPassphrase]
     * first. An empty [oldPassphrase] means the ring is unprotected; an empty
     * [newPassphrase] strips protection (stored cleartext). Both are
     * deliberate directions the caller confirms before calling.
     *
     * Per-key on purpose. The ring-level copyWithNewPassword cannot be used
     * here: it applies one encryptor to every key and re-encodes the whole
     * ring, which breaks on the composite algo-35/36/8 subkeys (BC cannot
     * parse that key material). Instead each secret key is re-protected on its
     * own and re-inserted, exactly as CompositeKeyGen protects the composite
     * subkey at generation:
     *   - v6 keys (RFC 9580, including the IETF composite algos 35/36): AEAD
     *     OCB + Argon2id, S2K usage 253.
     *   - v4 keys and the v5 LibrePGP composite subkey (algo 8): CFB + SHA-1
     *     checksum, S2K usage 254.
     * copyWithNewPassword re-encrypts the raw secret material without parsing
     * the composite key, the property the keygen path already relies on.
     *
     * A wrong [oldPassphrase] makes BC throw PGPException; the caller surfaces
     * that as a retry, not a failure.
     *
     * NOTE (composite): the unlock direction here (a real decryptor on an
     * algo-35/8 subkey) is exercised nowhere else in the tree, so the
     * composite round trip must be proven on device (768 and 1024, both the
     * v6 IETF and v5 LibrePGP forms) before this ships. See the RC matrix.
     */
    fun changePassphrase(
        secretKeyRing: PGPSecretKeyRing,
        oldPassphrase: String,
        newPassphrase: String
    ): PGPSecretKeyRing {
        val oldDecryptor = if (oldPassphrase.isEmpty()) null else
            org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
            ).build(oldPassphrase.toCharArray())

        val sha1 = org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
            .get(org.bouncycastle.bcpg.HashAlgorithmTags.SHA1)
        val random = SecureRandom()
        val newChars = newPassphrase.toCharArray()
        val strip = newPassphrase.isEmpty()

        // Read the key list off the ORIGINAL ring; accumulate into a separate
        // ring so insertSecretKey (replace-by-keyID) rebuilds it cleanly.
        val keys = secretKeyRing.secretKeys.asSequence().toList()
        var ring = secretKeyRing
        for (key in keys) {
            val reprotected = when {
                // Strip: null encryptor removes protection (BC handles v4, v6,
                // and composite alike; the round trip proves it).
                strip ->
                    org.bouncycastle.openpgp.PGPSecretKey.copyWithNewPassword(
                        key, oldDecryptor, null
                    )
                key.publicKey.version == org.bouncycastle.bcpg.PublicKeyPacket.VERSION_6 -> {
                    val encryptor = org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder(
                        org.bouncycastle.bcpg.AEADAlgorithmTags.OCB,
                        org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256,
                        org.bouncycastle.bcpg.S2K.Argon2Params.memoryConstrainedParameters()
                    ).setSecureRandom(random)
                        .build(newChars, key.publicKey.publicKeyPacket)
                    org.bouncycastle.openpgp.PGPSecretKey.copyWithNewPassword(
                        key, oldDecryptor, encryptor
                    )
                }
                else -> {
                    val encryptor = org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder(
                        org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256
                    ).setSecureRandom(random)
                        .build(newChars)
                    org.bouncycastle.openpgp.PGPSecretKey.copyWithNewPassword(
                        key, oldDecryptor, encryptor, sha1
                    )
                }
            }
            ring = PGPSecretKeyRing.insertSecretKey(ring, reprotected)
        }
        return ring
    }

    fun exportArmoredPrivateKey(secretKeyRing: PGPSecretKeyRing): String {
        // Translate a v5 LibrePGP composite (algo-8) subkey from BC's internal
        // framing to the on-the-wire LibrePGP layout GnuPG / sq / PGPony-iOS
        // expect (drop the condLen + checksum octets). No-op for other keys.
        val wireBytes = LibrePGPV5Interop.toLibrePGPFormat(secretKeyRing.encoded)
        return armorSecretKeyBytes(wireBytes)
    }

    /**
     * issue #2 symptom D: export a secret ring in a form GnuPG 2.5.x can
     * import. gpg does not accept a standard OpenPGP v5 algo-8 composite
     * secret; it only reads composite secrets as its native GNU S-expression
     * (full expanded ML-KEM key, not the 64-byte seed). This rewrites the
     * composite (sub)key to that form and leaves all other packets untouched.
     * Only unprotected composite keys are rewritten; pass [passphrase] to
     * unlock a protected composite subkey first. Non-gpg tools (Sequoia,
     * PGPony) read the standard [exportArmoredPrivateKey] output instead.
     */
    fun exportArmoredPrivateKeyGpgCompat(
        secretKeyRing: PGPSecretKeyRing,
        sourcePassphrase: String? = null,
        protectPassphrase: String? = null
    ): String {
        val gnuBytes = LibrePGPGnuSecretExport.toGnuComposite(
            secretKeyRing.encoded,
            sourcePassphrase?.toCharArray(),
            protectPassphrase?.toCharArray()
        )
        return armorSecretKeyBytes(gnuBytes)
    }

    /**
     * 4.0.0 Phase 3 (Succession) — split a key blob into ONE re-armored
     * string per key ring it contains. A single armor block can hold
     * MANY rings (OpenKeychain's backup payload is a public ring + a
     * secret ring + … all under one BEGIN/END), which importArmoredKey
     * (one-ring) would truncate. Iterates the object stream and re-armors
     * each secret/public ring so the caller can merge-import them one by
     * one. Handles armored or binary input; returns [] on parse failure.
     */
    fun explodeToArmoredKeys(data: ByteArray): List<String> {
        return try {
            val input = if (isArmored(data)) {
                ArmoredInputStream(ByteArrayInputStream(data))
            } else {
                ByteArrayInputStream(data)
            }
            val factory = JcaPGPObjectFactory(input)
            val out = ArrayList<String>()
            var obj = factory.nextObject()
            while (obj != null) {
                when (obj) {
                    is PGPSecretKeyRing -> out.add(armorSecretKeyRing(obj))
                    is PGPPublicKeyRing -> out.add(armorPublicKeyRing(obj))
                }
                obj = factory.nextObject()
            }
            out
        } catch (e: Exception) {
            emptyList()
        }
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
        armor: Boolean = true,
        // §4.5 (#22): user-chosen signing subkey; null = automatic pick.
        signingKeyId: Long? = null
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
            val anyCompositeRecipient = recipientPublicKeys.any {
                com.pgpony.android.crypto.pqc.CompositeKeyMaterial.isComposite(it)
            }
            // Composite (ML-KEM+X25519) recipients mandate v6 framing (SEIPDv2),
            // so a composite recipient forces AEAD regardless of the version scan.
            val allRecipientsV6 = anyCompositeRecipient || (recipientPublicKeys.isNotEmpty() &&
                recipientPublicKeys.all {
                    it.publicKey.version == org.bouncycastle.bcpg.PublicKeyPacket.VERSION_6
                })
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
                if (com.pgpony.android.crypto.pqc.CompositeSuite.ietfFor(encKey.algorithm) != null) {
                    encryptedGen.addMethod(
                        com.pgpony.android.crypto.pqc.CompositeEncryptionMethodGenerator(encKey)
                    )
                } else if (encKey.algorithm == com.pgpony.android.crypto.pqc.CompositeKemLibrePGP.ALGORITHM_ID) {
                    encryptedGen.addMethod(
                        com.pgpony.android.crypto.pqc.CompositeLibrePGPEncryptionMethodGenerator(encKey)
                    )
                } else {
                    encryptedGen.addMethod(
                        org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator(encKey)
                    )
                }
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
                val signingKey = pickSigningSecretKey(signingSecretKey, signingKeyId)
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
     * 4.0.0 Phase P2d (additive) — streaming encrypt for the OpenPGP API
     * provider's large-attachment path. Identical packet output shape to
     * [encrypt] (SEIPD v1 / all-v6 SEIPD v2, ZLIB compression, optional
     * inline software signature), but the plaintext flows through in
     * 64 KiB chunks: the literal packet uses partial lengths instead of
     * a declared size, and the signature digest updates per chunk.
     *
     * The signing key is unlocked BEFORE any output byte is written, so
     * SigningError.PassphraseRequired / InvalidPassphrase always fire
     * with a clean (empty) output stream — the provider's passphrase
     * interaction depends on that ordering.
     *
     * Card signing IS supported here (P2c Fix3): pass a non-null
     * [cardSession] + [cardPin] + [cardSigningPublicKey] and the
     * signature leg taps the card at the end, exactly like the buffered
     * [encrypt]. Streaming + [enableCompression]=false is what keeps a
     * large card sign+encrypt fast enough that the NFC tag doesn't go
     * stale ("Tag is out of date") — the card stays connected only for
     * the seconds the AES pass takes, not the minute ZLIB would spend on
     * an incompressible video.
     *
     * The software signing key is unlocked BEFORE any output byte is
     * written, so SigningError.PassphraseRequired / InvalidPassphrase
     * always fire with a clean (empty) output stream — the provider's
     * passphrase interaction depends on that ordering. Does not close
     * [output].
     */
    fun encryptStream(
        input: java.io.InputStream,
        output: java.io.OutputStream,
        recipientPublicKeys: List<PGPPublicKeyRing>,
        signingSecretKey: PGPSecretKeyRing? = null,
        passphrase: String? = null,
        filename: String? = null,
        armor: Boolean = true,
        enableCompression: Boolean = true,
        cardSession: OpenPgpCardSession? = null,
        cardPin: ByteArray? = null,
        cardSigningPublicKey: PGPPublicKey? = null,
        // ── 4.0.4: optional password (SKESK) recipient ────────────────
        //
        // Set to produce a `gpg -c` style message, alone or alongside
        // public-key recipients. The S2K choice mirrors [encryptSymmetric]
        // exactly so the two produce interoperable output: Argon2id (S2K
        // type 4) by default, iterated-salted SHA-256 (type 3) when
        // [useArgon2] is false for readers older than BC 1.79.
        //
        // This exists so the Encrypt tab's Password mode can stream a
        // large file instead of buffering it (issue #6); encryptSymmetric
        // takes and returns whole ByteArrays and cannot.
        messagePassword: String? = null,
        useArgon2: Boolean = true,
        // §4.5 (#22): user-chosen signing subkey; null = automatic pick.
        signingKeyId: Long? = null
    ) {
        // 1) Build the signer FIRST. Software: unlock up front (clean
        //    output guarantee). Card: the content-signer defers the tap
        //    to getSignature() at the very end.
        var sigGen: PGPSignatureGenerator? = null
        if (cardSession != null && cardSigningPublicKey != null && cardPin != null) {
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
        } else if (signingSecretKey != null) {
            val signingKey = pickSigningSecretKey(signingSecretKey, signingKeyId)
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
            val subpacketGen = PGPSignatureSubpacketGenerator()
            subpacketGen.setIssuerFingerprint(false, signingKey.publicKey)
            sigGen.setHashedSubpackets(subpacketGen.generate())
        }

        val armoredOut = if (armor) ArmoredOutputStream(output).stripVersion() else null
        val targetOut = armoredOut ?: output
        try {
            // Same SEIPD negotiation as encrypt().
            val anyCompositeRecipient = recipientPublicKeys.any {
                com.pgpony.android.crypto.pqc.CompositeKeyMaterial.isComposite(it)
            }
            // Composite (ML-KEM+X25519) recipients mandate v6 framing (SEIPDv2),
            // so a composite recipient forces AEAD regardless of the version scan.
            val allRecipientsV6 = anyCompositeRecipient || (recipientPublicKeys.isNotEmpty() &&
                recipientPublicKeys.all {
                    it.publicKey.version == org.bouncycastle.bcpg.PublicKeyPacket.VERSION_6
                })
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
            for (ring in recipientPublicKeys) {
                val encKey = findEncryptionKey(ring)
                    ?: throw PGPCryptoError.EncryptionFailed(
                        "No encryption subkey found for ${fingerprintHex(ring.publicKey)}"
                    )
                if (com.pgpony.android.crypto.pqc.CompositeSuite.ietfFor(encKey.algorithm) != null) {
                    encryptedGen.addMethod(
                        com.pgpony.android.crypto.pqc.CompositeEncryptionMethodGenerator(encKey)
                    )
                } else if (encKey.algorithm == com.pgpony.android.crypto.pqc.CompositeKemLibrePGP.ALGORITHM_ID) {
                    encryptedGen.addMethod(
                        com.pgpony.android.crypto.pqc.CompositeLibrePGPEncryptionMethodGenerator(encKey)
                    )
                } else {
                    encryptedGen.addMethod(
                        org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator(encKey)
                    )
                }
            }

            // 4.0.4 — password (SKESK) recipient, if one was supplied. Added
            // after the public-key methods so a message can carry both.
            if (messagePassword != null) {
                encryptedGen.addMethod(
                    if (useArgon2) {
                        org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator(
                            messagePassword.toCharArray(),
                            org.bouncycastle.bcpg.S2K.Argon2Params.memoryConstrainedParameters()
                        )
                    } else {
                        org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator(
                            messagePassword.toCharArray(),
                            org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                                .get(HashAlgorithmTags.SHA256),
                            0xFF
                        )
                    }
                )
            }

            if (recipientPublicKeys.isEmpty() && messagePassword == null) {
                throw PGPCryptoError.EncryptionFailed("No recipients and no password")
            }

            val encryptedOut = encryptedGen.open(targetOut, ByteArray(1 shl 16))

            // P2c Fix3: compression is optional. Skipping it keeps the
            // card-held time short (no ZLIB over a big incompressible
            // attachment) and, per the OpenPGP API's
            // EXTRA_ENABLE_COMPRESSION, is the client's call for software
            // sends too. When off, packets go straight into the SEIPD.
            val compGen = if (enableCompression) {
                PGPCompressedDataGenerator(PGPCompressedData.ZLIB)
            } else null
            val signAndLitOut: java.io.OutputStream =
                compGen?.open(encryptedOut) ?: encryptedOut

            sigGen?.generateOnePassVersion(false)?.encode(signAndLitOut)

            // Partial-length literal: the buffer overload streams without
            // a declared total size.
            val litGen = PGPLiteralDataGenerator()
            val litOut = litGen.open(
                signAndLitOut,
                if (filename != null) PGPLiteralData.BINARY else PGPLiteralData.UTF8,
                filename ?: "",
                Date(),
                ByteArray(1 shl 16)
            )
            val buf = ByteArray(1 shl 16)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                litOut.write(buf, 0, n)
                sigGen?.update(buf, 0, n)
            }
            litOut.close()
            litGen.close()

            // The card tap happens HERE (getSignature) — after the fast
            // AES pass, so the card was connected only briefly.
            sigGen?.let { it.generate().encode(signAndLitOut) }

            compGen?.close()
            encryptedOut.close()
            encryptedGen.close()
            armoredOut?.close()
        } catch (e: PGPCryptoError) {
            throw e
        } catch (e: SigningError) {
            throw e
        } catch (e: Exception) {
            throw PGPCryptoError.EncryptionFailed(e.message ?: "Unknown error")
        }
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
        // 4.1.0 - hoisted for the same reason as usedSymmetric: the throw
        // site below is outside the block where the PKESK list is built, and
        // "no key matched" reads very differently for an addressed message
        // than for a `gpg -R` one.
        var sawWildcardPkesk = false
        // The SEIPD object we actually decrypted, kept so its integrity
        // protection can be verified AFTER the plaintext stream is fully read
        // (BC validates SEIPDv1's MDC only on an explicit verify(); without it,
        // CFB-malleable ciphertext and legacy unprotected packets slip through).
        var integrityObj: org.bouncycastle.openpgp.PGPEncryptedData? = null
        try {
            // Phase 2b: a composite (ML-KEM+X25519, algo 35) PKESK can't be
            // parsed by BouncyCastle (its PKESK reader throws on the unknown
            // algorithm), so try the hand-rolled composite path first. It
            // returns null when the message carries no composite PKESK, in
            // which case we fall back to BC's normal PKESK/SKESK discovery.
            val composite = com.pgpony.android.crypto.pqc.CompositeDecryptor.tryDecrypt(
                encryptedData, secretKeyRings, passphrase
            )
            // LibrePGP composite (algo 8) is a separate framing; try it when
            // the IETF (algo 35) path declined.
            val librePgp = if (composite == null)
                com.pgpony.android.crypto.pqc.CompositeLibrePGPDecryptor.tryDecrypt(
                    encryptedData, secretKeyRings, passphrase
                ) else null
            var decryptedStream: java.io.InputStream? = composite?.stream ?: librePgp?.stream
            var pbeData: PGPPBEEncryptedData? = null
            if (composite != null) {
                integrityObj = composite.integrity
            } else if (librePgp != null) {
                integrityObj = librePgp.integrity
            } else {
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
                // 4.0.5 — collect first, resolve second. The old form
                // matched a single exact key ID inline, which missed
                // `gpg -R` hidden recipients entirely; see [resolvePkesk].
                val pkesks = mutableListOf<PGPPublicKeyEncryptedData>()
                for (obj in encData.encryptedDataObjects) {
                    when (obj) {
                        is PGPPublicKeyEncryptedData -> {
                            pkesks.add(obj)
                            if (obj.keyID == WILDCARD_KEY_ID) sawWildcardPkesk = true
                        }
                        is PGPPBEEncryptedData -> {
                            if (pbeData == null) pbeData = obj
                        }
                    }
                }
                if (decryptedStream == null) {
                    resolvePkesk(pkesks, secretKeyRings, passphrase)?.let { match ->
                        decryptedStream = match.stream
                        integrityObj = match.data
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
                throw PGPCryptoError.NoMatchingKey(hiddenRecipient = sawWildcardPkesk)
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
// 3.1.0 Phase 7 Fix2 (origin: Token2 test, gpg 2.5 message):
                // GnuPG with AEAD-capable keys emits the LibrePGP "tag 20"
                // OCB packet. BC's isIntegrityProtected() is tag-18-only
                // (false for tag 20) and its verify() THROWS for tag 20 —
                // but AEAD authenticates every chunk during the stream
                // read; a tampered message throws before reaching this
                // gate. So: tag 20 counts as protected, and skips the
                // MDC-oriented verify(). SEIPDv2 (isAEAD + tag 18) keeps
                // using verify(), which BC short-circuits to true.
                val aead = io.isAEAD()
                val protected = io.isIntegrityProtected() || aead
                val intact = protected && try {
                    if (aead && !io.isIntegrityProtected()) true else io.verify()
                } catch (ie: PGPException) { false }
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
     * 4.0.0 Phase P2d (additive) — streaming decrypt for the OpenPGP API
     * provider's large-attachment path. Mirrors [decrypt] exactly (PKESK
     * matching against the supplied rings, SKESK/symmetric fallback with
     * the same wrong-passphrase remapping, decompress-before-verify
     * signature walk, and the mandatory integrity gate) but the literal
     * data flows to [output] in 64 KiB chunks instead of being buffered.
     * Armor detection is handled by PGPUtil.getDecoderStream, which
     * sniffs the stream head. Does not close [input]/[output].
     */
    fun decryptStream(
        input: java.io.InputStream,
        output: java.io.OutputStream,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String?,
        verificationKeys: List<PGPPublicKeyRing>? = null
    ): DecryptStreamResult {
        var usedSymmetric = false
        var integrityObj: org.bouncycastle.openpgp.PGPEncryptedData? = null
        try {
            var decryptedStream: java.io.InputStream? = null
            var pbeData: PGPPBEEncryptedData? = null
            var sawWildcardPkesk = false

            // 4.1.2 (issue #33): the composite (PQC) trial was only ever
            // wired into [decrypt], so a file encrypted to an ML-KEM key
            // arrived here, BC's PKESK parser threw on the unknown
            // algorithm, and the user's own file would not open. BC cannot
            // be handed a composite message at all, so the trial has to
            // happen BEFORE the decoder, and a stream cannot be rewound
            // the way [decrypt]'s byte array can. So: sniff the leading
            // ESK packets from a bounded, resettable head. Only when a
            // composite PKESK is actually present is the whole message
            // buffered and run through the same validated decryptors the
            // text path uses; classical messages keep the true streaming
            // path untouched, and a sniff miss falls through to BC, which
            // fails exactly as it did before this block existed.
            //
            // 4.2.0 workstream A: the buffering this comment used to
            // apologize for is gone. On a sniff hit the leading ESK
            // packets (always definite-length) are consumed from the
            // stream, the session key is recovered from the composite
            // PKESK alone via the validated decryptors, and BC gets the
            // body stream untouched, so the ciphertext is never held in
            // memory. A false-positive sniff stitches the consumed ESK
            // bytes back in front of the stream and falls through to BC.
            val sniffLimit = 1 shl 16
            val buffered = java.io.BufferedInputStream(input, sniffLimit)
            buffered.mark(sniffLimit)
            val head = readHead(buffered, sniffLimit)
            buffered.reset()
            var effectiveInput: java.io.InputStream = buffered
            val sniff = compositeSniffBytes(head)
            if (com.pgpony.android.crypto.pqc.CompositeDecryptor.sniffHead(sniff) ||
                com.pgpony.android.crypto.pqc.CompositeLibrePGPDecryptor.sniffHead(sniff)
            ) {
                // Session-key handoff. Armor decodes on the fly; the
                // decoded stream is buffered so the ESK consumer can
                // mark/reset across packet headers.
                val binaryIn: java.io.InputStream =
                    if (head.isNotEmpty() && head[0].toInt() == '-'.code)
                        java.io.BufferedInputStream(
                            ArmoredInputStream(buffered), DECRYPT_STREAM_CHUNK
                        )
                    else buffered
                val eskRegion = readLeadingEskPackets(binaryIn)
                val session =
                    com.pgpony.android.crypto.pqc.CompositeDecryptor
                        .recoverSessionKey(eskRegion, secretKeyRings, passphrase)
                        ?: com.pgpony.android.crypto.pqc.CompositeLibrePGPDecryptor
                            .recoverSessionKey(eskRegion, secretKeyRings, passphrase)
                if (session != null) {
                    // [binaryIn] now sits at the encrypted body packet,
                    // framing (partial lengths included) intact; BC reads
                    // it natively and streams.
                    val bcpgIn = org.bouncycastle.bcpg.BCPGInputStream(binaryIn)
                    val encList = org.bouncycastle.openpgp.PGPEncryptedDataList(bcpgIn)
                    val sessionEnc = encList.extractSessionKeyEncryptedData()
                    decryptedStream = sessionEnc.getDataStream(
                        org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory(session)
                    )
                    integrityObj = sessionEnc
                } else {
                    // Sniff said composite but neither recoverer found a
                    // composite PKESK: false positive. Reassemble the
                    // consumed ESK bytes in front of the remainder and
                    // fall through to BC, which fails or succeeds exactly
                    // as it would have without the sniff.
                    effectiveInput = java.io.SequenceInputStream(
                        java.io.ByteArrayInputStream(eskRegion), binaryIn
                    )
                }
            }

            if (decryptedStream == null) {
                val decoder = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(effectiveInput)
                val pgpFactory = JcaPGPObjectFactory(decoder)
                val encData = findEncryptedData(pgpFactory)
                    ?: throw PGPCryptoError.DecryptionFailed("No encrypted data found in message")

                // 4.0.5 — same two-pass resolution as [decrypt]; this is the
                // path the OpenPGP API provider and large-file decrypt take, so
                // hidden-recipient messages have to work here too. Trial
                // decryption reads only the session-key packets, so the body
                // stream is untouched and needs no rewind.
                val pkesks = mutableListOf<PGPPublicKeyEncryptedData>()
                for (obj in encData.encryptedDataObjects) {
                    when (obj) {
                        is PGPPublicKeyEncryptedData -> {
                            pkesks.add(obj)
                            if (obj.keyID == WILDCARD_KEY_ID) sawWildcardPkesk = true
                        }
                        is PGPPBEEncryptedData -> {
                            if (pbeData == null) pbeData = obj
                        }
                    }
                }
                resolvePkesk(pkesks, secretKeyRings, passphrase)?.let { match ->
                    decryptedStream = match.stream
                    integrityObj = match.data
                }
                if (decryptedStream == null && pbeData != null) {
                    if (passphrase.isNullOrEmpty()) throw PGPCryptoError.PassphraseRequired()
                    usedSymmetric = true
                    decryptedStream = pbeData.getDataStream(
                        org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory(
                            passphrase.toCharArray(),
                            org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                        )
                    )
                    integrityObj = pbeData
                }
            }
            if (decryptedStream == null) {
                throw PGPCryptoError.NoMatchingKey(hiddenRecipient = sawWildcardPkesk)
            }

            val result = streamDecryptedContent(
                JcaPGPObjectFactory(decryptedStream), verificationKeys, output
            )

            // Integrity gate — same rules as decrypt() (tag-20 AEAD note
            // included via isAEAD()).
            integrityObj?.let { io ->
                val aead = io.isAEAD()
                val protected = io.isIntegrityProtected() || aead
                val intact = protected && try {
                    if (aead && !io.isIntegrityProtected()) true else io.verify()
                } catch (ie: PGPException) { false }
                if (!intact) {
                    throw PGPCryptoError.IntegrityCheckFailed(
                        if (!protected) "Message has no integrity protection and was rejected"
                        else "Integrity check failed - the message may have been tampered with"
                    )
                }
            }
            return result
        } catch (e: PGPCryptoError) {
            if (usedSymmetric && e is PGPCryptoError.DecryptionFailed) {
                throw PGPCryptoError.InvalidPassphrase()
            }
            throw e
        } catch (e: PGPException) {
            if (usedSymmetric) throw PGPCryptoError.InvalidPassphrase()
            val msg = e.message ?: ""
            if (msg.contains("checksum", ignoreCase = true) ||
                msg.contains("passphrase", ignoreCase = true) ||
                msg.contains("secret key", ignoreCase = true)
            ) {
                throw PGPCryptoError.InvalidPassphrase()
            }
            throw PGPCryptoError.DecryptionFailed(msg)
        } catch (e: Exception) {
            if (usedSymmetric) throw PGPCryptoError.InvalidPassphrase()
            throw PGPCryptoError.DecryptionFailed(e.message ?: "Unknown error")
        }
    }

    /** 4.1.2: fill [limit] bytes (or to EOF) from [s] without reading
     *  past them; the caller holds a mark. A plain InputStream.read may
     *  return short counts, hence the loop. */
    private fun readHead(s: java.io.InputStream, limit: Int): ByteArray {
        val buf = ByteArray(limit)
        var off = 0
        while (off < limit) {
            val n = s.read(buf, off, limit - off)
            if (n < 0) break
            off += n
        }
        return buf.copyOf(off)
    }

    /** 4.2.0 workstream A: consume the leading ESK packets (PKESK tag 1 /
     *  SKESK tag 3) from [s], returning them verbatim (headers included)
     *  and leaving the stream positioned at the first non-ESK packet, the
     *  encrypted body. ESK packets always carry definite lengths (the
     *  4.1.2 finding), so this never has to parse a partial length; any
     *  malformed or indeterminate header stops the consume with the
     *  stream reset to that packet's start. [s] must support mark. */
    private fun readLeadingEskPackets(s: java.io.InputStream): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val hdr = ByteArray(6)
        while (true) {
            s.mark(8)
            val first = s.read()
            if (first < 0 || first and 0x80 == 0) { s.reset(); break }
            val tag = if (first and 0x40 != 0) first and 0x3F else (first shr 2) and 0x0F
            if (tag != 1 && tag != 3) { s.reset(); break }
            hdr[0] = first.toByte()
            var hlen = 1
            var bodyLen = -1
            if (first and 0x40 != 0) { // new format
                val l0 = s.read()
                if (l0 >= 0) {
                    hdr[hlen++] = l0.toByte()
                    when {
                        l0 < 192 -> bodyLen = l0
                        l0 < 224 -> {
                            val l1 = s.read()
                            if (l1 >= 0) { hdr[hlen++] = l1.toByte(); bodyLen = ((l0 - 192) shl 8) + l1 + 192 }
                        }
                        l0 == 255 -> {
                            var v = 0; var ok = true
                            repeat(4) {
                                val b = s.read()
                                if (b < 0) ok = false else { hdr[hlen++] = b.toByte(); v = (v shl 8) or b }
                            }
                            if (ok) bodyLen = v
                        }
                        // 224..254 would be a partial length: not legal on an ESK.
                    }
                }
            } else { // old format
                val lt = first and 0x03
                var v = 0; var ok = true
                val n = when (lt) { 0 -> 1; 1 -> 2; 2 -> 4; else -> 0 }
                if (n == 0) ok = false // indeterminate: not legal on an ESK
                repeat(n) {
                    val b = s.read()
                    if (b < 0) ok = false else { hdr[hlen++] = b.toByte(); v = (v shl 8) or b }
                }
                if (ok) bodyLen = v
            }
            if (bodyLen < 0) { s.reset(); break }
            out.write(hdr, 0, hlen)
            var remaining = bodyLen
            val buf = ByteArray(minOf(remaining, 8192).coerceAtLeast(1))
            while (remaining > 0) {
                val n = s.read(buf, 0, minOf(remaining, buf.size))
                if (n < 0) throw PGPCryptoError.DecryptionFailed("Truncated ESK packet")
                out.write(buf, 0, n)
                remaining -= n
            }
            if (out.size() > MAX_ESK_REGION) {
                throw PGPCryptoError.DecryptionFailed("ESK region exceeds sane bounds")
            }
        }
        return out.toByteArray()
    }

    /** 4.1.2: decode an armored head to packet bytes for the composite
     *  sniff. The head is usually truncated mid-armor, so decode errors
     *  are expected; whatever decoded before the failure is returned,
     *  which always covers the leading ESK packets the sniff reads. */
    private fun compositeSniffBytes(head: ByteArray): ByteArray {
        if (head.isEmpty() || head[0].toInt() != '-'.code) return head
        return try {
            val out = java.io.ByteArrayOutputStream()
            val armored = ArmoredInputStream(java.io.ByteArrayInputStream(head))
            val buf = ByteArray(4096)
            while (true) {
                val n = try { armored.read(buf) } catch (e: Exception) { -1 }
                if (n < 0) break
                out.write(buf, 0, n)
            }
            out.toByteArray()
        } catch (e: Exception) {
            ByteArray(0)
        }
    }

    /**
     * P2d — the streaming twin of [processDecryptedContent]: identical
     * packet walk (compressed recursion FIRST, then signature packets —
     * the R5 decompress-before-verify rule) but literal data is written
     * to [output] as it's read instead of being buffered.
     */
    private fun streamDecryptedContent(
        factory: JcaPGPObjectFactory,
        verificationKeys: List<PGPPublicKeyRing>?,
        output: java.io.OutputStream
    ): DecryptStreamResult {
        var bytesWritten = 0L
        var wroteLiteral = false
        var filename: String? = null
        var signatureVerified = false
        var signerKeyID: String? = null
        var onePassSig: PGPOnePassSignature? = null
        var hasSignature = false
        var signatureKeyIDRaw: Long? = null

        var obj = factory.nextObject()
        while (obj != null) {
            when (obj) {
                is PGPCompressedData -> {
                    return streamDecryptedContent(
                        JcaPGPObjectFactory(obj.dataStream), verificationKeys, output
                    )
                }
                is PGPOnePassSignatureList -> {
                    if (obj.size() > 0) {
                        hasSignature = true
                        signatureKeyIDRaw = obj[0].keyID
                    }
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
                    wroteLiteral = true
                    filename = obj.fileName.takeIf { it.isNotEmpty() }
                    val litStream = obj.inputStream
                    val buf = ByteArray(1 shl 16)
                    var len: Int
                    while (litStream.read(buf).also { len = it } >= 0) {
                        output.write(buf, 0, len)
                        onePassSig?.update(buf, 0, len)
                        bytesWritten += len
                    }
                }
                is PGPSignatureList -> {
                    if (obj.size() > 0) {
                        hasSignature = true
                        if (signatureKeyIDRaw == null) signatureKeyIDRaw = obj[0].keyID
                    }
                    if (onePassSig != null && obj.size() > 0) {
                        signatureVerified = onePassSig.verify(obj[0])
                    }
                }
            }
            obj = factory.nextObject()
        }
        if (!wroteLiteral) {
            throw PGPCryptoError.DecryptionFailed("No literal data found in decrypted message")
        }
        return DecryptStreamResult(
            bytesWritten = bytesWritten,
            filename = filename,
            signatureVerified = signatureVerified,
            signerKeyID = signerKeyID,
            hasSignature = hasSignature,
            signatureKeyIDRaw = signatureKeyIDRaw
        )
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
     * 4.1.0 - can any of [secretKeyRings] open [encryptedData]'s public-key
     * session-key packets?
     *
     * Answers the routing question a hidden-recipient (`gpg -R`) message
     * raises: with no recipient key ID to look up, "is this one mine?" can
     * only be settled by trying. [resolvePkesk] already does exactly that and
     * touches only the session-key packets - the message body is never read -
     * so it is cheap enough to ask BEFORE committing to an answer.
     *
     * That ordering is the whole point on the provider path. Once the calling
     * app's output pipe has been handed to [decryptStream] it cannot be
     * reused, so a failure discovered there has nowhere to fall back to.
     * Asking first keeps the card fallback available.
     *
     * A key that is locked with no passphrase to hand counts as a MATCH:
     * "ask the user to unlock this key" is the right next step, not "give up
     * and ask them to tap a card". The caller's own decrypt then raises
     * PassphraseRequired in the ordinary way.
     */
    fun canOpenWithSecretKeys(
        encryptedData: ByteArray,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String?
    ): Boolean {
        if (secretKeyRings.isEmpty()) return false
        return try {
            val input = if (isArmored(encryptedData)) {
                ArmoredInputStream(ByteArrayInputStream(encryptedData))
            } else {
                ByteArrayInputStream(encryptedData)
            }
            val encData = findEncryptedData(JcaPGPObjectFactory(input)) ?: return false
            val pkesks = encData.encryptedDataObjects
                .asSequence()
                .filterIsInstance<PGPPublicKeyEncryptedData>()
                .toList()
            // The stream this hands back is discarded: the real decrypt re-parses
            // from the same bytes. Only the yes/no is wanted here.
            resolvePkesk(pkesks, secretKeyRings, passphrase) != null
        } catch (e: PGPCryptoError.PassphraseRequired) {
            true
        } catch (e: PGPCryptoError.InvalidPassphrase) {
            true
        } catch (e: Exception) {
            false
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

        /**
         * 4.1.0 - the message carries at least one wildcard PKESK (`gpg -R`),
         * so at least one recipient is undisclosed. Callers that route by key
         * ID must treat this as "could be anyone I hold", not "not for me":
         * the wildcard is the one recipient ID that is guaranteed to match
         * nothing on the ring.
         */
        val hasHiddenRecipient: Boolean get() = publicKeyIDs.contains(0L)

        /**
         * Recipient key IDs that can actually be matched against a ring -
         * everything except the wildcard.
         */
        val addressedKeyIDs: List<Long> get() = publicKeyIDs.filter { it != 0L }
    }

    /**
     * Inspect an (armored or binary) encrypted message and report whether it
     * is addressed to public keys, to a passphrase (SKESK), or both —
     * WITHOUT decrypting. Phase A1: the Decrypt tab calls this to route a
     * password-encrypted message to the passphrase prompt instead of the
     * key picker. Returns no recipients / not-password for unparseable input.
     */
    fun inspectEncryptedMessage(encryptedData: ByteArray): MessageEncryptionInfo =
        inspectEncryptedMessage(ByteArrayInputStream(encryptedData))

    /**
     * 4.0.4 — streaming counterpart. The session-key packets (PKESK/SKESK)
     * sit at the very front of an OpenPGP message and BC parses them
     * lazily, so this touches only the head of [input] no matter how large
     * the message is; the SEIPD body is never read. That is what lets the
     * Decrypt tab route a picked file (card recipient vs. passphrase vs.
     * software key) without first pulling the whole thing into memory.
     *
     * Armor detection is PGPUtil.getDecoderStream's job here rather than
     * the ByteArray [isArmored] sniff — it reads the stream head itself,
     * and it is the same detection decryptStream already relies on.
     *
     * Does not close [input]; the caller owns it.
     */
    fun inspectEncryptedMessage(input: java.io.InputStream): MessageEncryptionInfo {
        return try {
            val decoder = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(input)
            val encData = findEncryptedData(JcaPGPObjectFactory(decoder))
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
        // P2b-1: track signature PRESENCE and the raw signing key id
        // independently of whether we hold the signer's key, so the
        // provider can report KEY_MISSING (unknown signer) instead of
        // conflating it with "not signed".
        var hasSignature = false
        var signatureKeyIDRaw: Long? = null

        var obj = factory.nextObject()
        while (obj != null) {
            when (obj) {
                is PGPCompressedData -> {
                    val compFactory = JcaPGPObjectFactory(obj.dataStream)
                    return processDecryptedContent(compFactory, verificationKeys)
                }
                is PGPOnePassSignatureList -> {
                    if (obj.size() > 0) {
                        hasSignature = true
                        signatureKeyIDRaw = obj[0].keyID
                    }
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
                    // P2b-1: a signature packet counts as "signed" even
                    // without a preceding one-pass header (older
                    // sig-then-literal layouts) and even when unheld.
                    if (obj.size() > 0) {
                        hasSignature = true
                        if (signatureKeyIDRaw == null) signatureKeyIDRaw = obj[0].keyID
                    }
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
            filename = filename,
            hasSignature = hasSignature,
            signatureKeyIDRaw = signatureKeyIDRaw
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
    /**
     * 4.0.0 Phase 2b — ring-aware detection: a composite ML-KEM+X25519
     * (algo 35) encryption subkey defines the key's label even though the
     * primary is Ed25519. Otherwise falls back to single-key detection.
     */
    fun detectAlgorithm(masterKey: PGPPublicKey, ring: PGPPublicKeyRing): KeyAlgorithm {
        if (ring.publicKeys.asSequence().any { it.algorithm == 35 }) {
            return KeyAlgorithm.MLKEM768_X25519_V6
        }
        if (ring.publicKeys.asSequence().any { it.algorithm == 36 }) {
            return KeyAlgorithm.MLKEM1024_X448_V6
        }
        ring.publicKeys.asSequence().firstOrNull { it.algorithm == 8 && it.version == 5 }?.let { sub ->
            // algo 8 is a shared code point: the curve OID says which composite.
            // issue #2: suiteOf throws on an unknown/unsupported curve OID, so
            // catch it; a key we cannot model still imports and falls through to
            // primary detection rather than failing the whole import (symptom A).
            val curve = try {
                com.pgpony.android.crypto.pqc.CompositeLibrePGPKeyMaterial.suiteOf(sub.encoded).curve
            } catch (_: Exception) {
                null
            }
            when (curve) {
                com.pgpony.android.crypto.pqc.EccCurve.X448 ->
                    return KeyAlgorithm.MLKEM1024_X448_LIBREPGP
                com.pgpony.android.crypto.pqc.EccCurve.BRAINPOOL_P384R1 ->
                    return KeyAlgorithm.MLKEM1024_BP384_LIBREPGP
                com.pgpony.android.crypto.pqc.EccCurve.X25519 ->
                    return KeyAlgorithm.MLKEM768_X25519_LIBREPGP
                else -> {}
            }
        }
        return detectAlgorithm(masterKey)
    }

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
        // Composite ML-KEM+X25519 (algo 35) subkeys are invisible to BC's
        // isEncryptionKey (unknown algorithm), so surface one explicitly.
        com.pgpony.android.crypto.pqc.CompositeKeyMaterial.encryptionSubkey(ring)?.let { return it }
        // LibrePGP composite (algo 8) subkeys are likewise invisible to BC.
        ring.publicKeys.asSequence().firstOrNull {
            it.algorithm == com.pgpony.android.crypto.pqc.CompositeLibrePGPKeyMaterial.ALGORITHM_ID
        }?.let { return it }
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
    internal fun pickSigningSecretKey(ring: PGPSecretKeyRing, preferredKeyId: Long? = null): PGPSecretKey? {
        // §4.5 (#22): honor a user-chosen signing subkey when it is a
        // signing-capable key on this ring; otherwise fall back to the
        // automatic pick (first signing subkey, else the primary).
        if (preferredKeyId != null) {
            signingSecretKeys(ring).firstOrNull { it.keyID == preferredKeyId }?.let { return it }
        }
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

    /** §4.5 (#22): every signing-capable secret key in [ring], the first
     *  entry being the one [pickSigningSecretKey] auto-selects (signing
     *  subkeys in ring order, then the primary if it can sign). */
    internal fun signingSecretKeys(ring: PGPSecretKeyRing): List<PGPSecretKey> {
        val subs = mutableListOf<PGPSecretKey>()
        var primary: PGPSecretKey? = null
        val it = ring.secretKeys
        while (it.hasNext()) {
            val sk = it.next()
            val pub = sk.publicKey
            val caps = SubkeyCapability.fromPgpPublicKey(pub, detectAlgorithm(pub), pub.isMasterKey)
            if (SubkeyCapability.hasCapability(caps, SubkeyCapability.Sign)) {
                if (pub.isMasterKey) primary = sk else subs.add(sk)
            }
        }
        return if (primary != null) subs + primary else subs
    }

    /** §4.5 (#22): display-ready signing-key choices for [ring]; first entry
     *  is the automatic pick. Size < 2 for the common single-signing-key
     *  case, where the UI shows no picker. */
    internal fun signingKeyOptions(ring: PGPSecretKeyRing): List<SigningKeyOption> =
        signingSecretKeys(ring).map { sk ->
            val pub = sk.publicKey
            SigningKeyOption(
                keyId = pub.keyID,
                keyIdHex = String.format("%016X", pub.keyID),
                isPrimary = pub.isMasterKey,
                algorithmLabel = detectAlgorithm(pub).displayName
            )
        }

    /** Find a secret key by key ID across multiple key rings. */
    /**
     * 4.0.5 — the "hidden recipient" key ID.
     *
     * `gpg -R` (as opposed to `-r`) writes the PKESK with an all-zero key
     * ID so the recipient is not disclosed to anyone who intercepts the
     * message. RFC 9580 §5.1 calls this the wildcard, and says a receiver
     * that sees it should try its own secret keys against the packet.
     */
    private val WILDCARD_KEY_ID = 0L

    /** Buffer size for the armored-decode wrapper on the streaming
     *  composite path (workstream A). */
    private val DECRYPT_STREAM_CHUNK = 1 shl 13

    /** Upper bound on the leading ESK region a message may carry before
     *  the streaming consumer refuses it (a composite PKESK is ~1.7 KB;
     *  this allows hundreds of recipients). */
    private val MAX_ESK_REGION = 1 shl 20

    /** A PKESK we managed to open, with the packet it came from. */
    private class PkeskMatch(
        val stream: java.io.InputStream,
        val data: PGPPublicKeyEncryptedData
    )

    /**
     * 4.0.5 — resolve the message's public-key session-key packets against
     * the keys we hold.
     *
     * Before this, lookup was a single exact match on the packet's key ID.
     * A `gpg -eaR` message carries [WILDCARD_KEY_ID], which matches nothing,
     * so PGPony reported "No matching decryption key found" without having
     * tried anything. The error was literally true and completely unhelpful.
     *
     * Exact matches are tried first, so the common case costs exactly what
     * it did before. Only then are wildcard packets trialled against each
     * key in turn.
     *
     * Trial decryption is cheap and safe here:
     *
     *   - It touches only the session-key packet. `getDataStream` decrypts
     *     the session key and checks its checksum; the message body is not
     *     read, so nothing is consumed and no stream needs rewinding. That
     *     is what lets decryptStream() use this unchanged.
     *   - [secretKeyRings] only ever holds software keys. Card-backed keys
     *     have no local private material — KeyRepository.loadSecretKeyRing
     *     returns null for them — so a wildcard message can never silently
     *     turn into a series of NFC taps.
     *
     * Failure typing is deliberate. A key that cannot be unlocked is a
     * passphrase problem and is reported as one; a key that unlocks but
     * does not open the packet is simply the wrong key, which during a
     * wildcard trial is the expected outcome and must stay silent.
     *
     * Returns null when nothing matched, leaving the caller to fall back to
     * the symmetric path or to report no matching key, which by then is an
     * honest answer.
     */
    private fun resolvePkesk(
        pkesks: List<PGPPublicKeyEncryptedData>,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String?
    ): PkeskMatch? {
        if (pkesks.isEmpty()) return null

        // A candidate we could not unlock, versus one that unlocked and
        // simply was not the right key. Only the first is worth reporting.
        var sawLockedKey = false
        var sawUnlockFailure = false

        fun attempt(obj: PGPPublicKeyEncryptedData, secretKey: PGPSecretKey): PkeskMatch? {
            // 4.0.4's guard, moved in here and made non-fatal: a locked key
            // must not abort the scan, because a later candidate may open
            // the packet without any passphrase at all. If none does, the
            // flag below still produces PassphraseRequired rather than the
            // InvalidPassphrase that BouncyCastle's checksum error would
            // otherwise be mapped to.
            if (secretKey.s2KUsage.toInt() != 0 && passphrase.isNullOrEmpty()) {
                sawLockedKey = true
                return null
            }
            val privateKey = try {
                secretKey.extractPrivateKey(
                    org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                        org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                    ).build(passphrase?.toCharArray() ?: charArrayOf())
                )
            } catch (e: PGPException) {
                // Could not unlock. For a protected key that means the
                // passphrase is wrong, which the caller should surface.
                if (secretKey.s2KUsage.toInt() != 0) sawUnlockFailure = true
                return null
            }
            return try {
                PkeskMatch(
                    obj.getDataStream(
                        org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory(privateKey)
                    ),
                    obj
                )
            } catch (e: PGPException) {
                // Unlocked fine, wrong key for this packet. Expected during
                // a wildcard trial; silent by design.
                null
            }
        }

        // Pass 1 — addressed packets. Unchanged behaviour and cost.
        for (obj in pkesks) {
            if (obj.keyID == WILDCARD_KEY_ID) continue
            val secretKey = findSecretKey(obj.keyID, secretKeyRings) ?: continue
            attempt(obj, secretKey)?.let { return it }
        }

        // Pass 2 — hidden recipients. Try every encryption-capable key we
        // hold against each wildcard packet.
        for (obj in pkesks) {
            if (obj.keyID != WILDCARD_KEY_ID) continue
            for (ring in secretKeyRings) {
                for (candidate in ring.secretKeys) {
                    if (!candidate.publicKey.isEncryptionKey) continue
                    attempt(obj, candidate)?.let { return it }
                }
            }
        }

        if (sawLockedKey) throw PGPCryptoError.PassphraseRequired()
        if (sawUnlockFailure) throw PGPCryptoError.InvalidPassphrase()
        return null
    }

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

    /**
     * Armor already-serialized secret-key packet bytes. Used by the export
     * path after [LibrePGPV5Interop.toLibrePGPFormat] has rewritten the raw
     * bytes — we can't go back through PGPSecretKeyRing.encode() because BC
     * would re-insert the framing octets the transform just removed.
     * ArmoredOutputStream derives the "PGP PRIVATE KEY BLOCK" header from the
     * leading packet tag, so writing raw bytes yields the same armor as encode.
     */
    private fun armorSecretKeyBytes(bytes: ByteArray): String {
        val out = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(out).stripVersionClean()
        armoredOut.write(bytes)
        armoredOut.close()
        return out.toString(Charsets.UTF_8.name())
    }

    /** De-armor an ASCII-armored PGP block to its raw binary packet bytes. */
    private fun dearmorToBytes(armoredText: String): ByteArray {
        val armorIn = ArmoredInputStream(ByteArrayInputStream(armoredText.toByteArray()))
        val out = ByteArrayOutputStream()
        armorIn.copyTo(out)
        armorIn.close()
        return out.toByteArray()
    }
}
