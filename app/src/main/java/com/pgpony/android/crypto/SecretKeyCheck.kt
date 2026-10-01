// SecretKeyCheck.kt
// PGPony Android: two questions about a secret key that its packets alone do
// not answer.
//
//   * isFullyPassphraseProtected: is EVERY secret key packet that carries
//     real material (the primary and every subkey, composite and algo-35
//     subkeys included) protected by a passphrase? A GNU "no private key" or
//     "divert to card" stub has no material and does not count either way. A
//     key with an offline primary stub and unprotected subkeys is NOT
//     protected, although its primary packet says it is.
//
//   * checkSecretForPublic: does a secret-key block really hold the secret of
//     a certificate already stored? Copying the public key packet into a
//     secret-key packet with junk "encrypted" material is easy, so matching
//     public parts are necessary but prove nothing. The secret has to unlock
//     (unprotected, or with the passphrase given) and then make a signature
//     the stored public key verifies (or, for an encryption-only key, decrypt
//     a message encrypted to it). Only then may the stored contact become a
//     key pair.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositeSigVerifier
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSigner
import com.pgpony.android.crypto.pqc.LibrePGPV5Interop
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom

object SecretKeyCheck {

    private const val TAG_SECRET_KEY = 5
    private const val TAG_SECRET_SUBKEY = 7
    private const val S2K_GNU = 101

    /** How one secret key packet keeps its material. */
    enum class Protection {
        /** S2K usage 0: the material is in the clear. */
        UNPROTECTED,
        /** Encrypted under a passphrase (S2K usage 1 to 255, not a stub). */
        PROTECTED,
        /** A GNU extension stub: no material here (offline or on a card). */
        STUB
    }

    /** Outcome of [checkSecretForPublic]. Only [OK] proves the secret. */
    enum class SecretMatch {
        /** Every secret with material unlocked and at least one proved it matches. */
        OK,
        /** The secret is protected and no passphrase was given (its structure is fine). */
        NEEDS_PASSPHRASE,
        /** The passphrase given does not unlock the secret. */
        WRONG_PASSPHRASE,
        /** The block's primary is not the stored certificate's primary. */
        PUBLIC_MISMATCH,
        /** The block cannot be read as a secret key. */
        UNREADABLE,
        /** The secret unlocked but does not belong to the public key. */
        MATERIAL_MISMATCH,
        /** Every secret packet is a stub (or there is none): nothing to prove. */
        NO_SECRET,
        /** Nothing in the key could be put to the test with this app. */
        UNPROVEN
    }

    /**
     * The protection of the secret key packet ([tag] 5 or 7, [body] without
     * header), or null when the packet cannot be read (callers treat that as
     * not protected).
     */
    fun protectionOf(tag: Int, body: ByteArray): Protection? = runCatching {
        if (tag != TAG_SECRET_KEY && tag != TAG_SECRET_SUBKEY) return@runCatching null
        val pub = CertificateBindings.publicPart(tag, body) ?: return@runCatching null
        var i = pub.size
        if (i >= body.size) return@runCatching null
        val version = body[0].toInt() and 0xFF
        val usage = body[i++].toInt() and 0xFF
        when (usage) {
            0 -> Protection.UNPROTECTED
            253, 254, 255 -> {
                val s2kType = if (version == 4) {
                    i += 1 // symmetric algorithm
                    if (usage == 253) i += 1 // AEAD algorithm
                    body[i].toInt() and 0xFF
                } else {
                    i += 1 // count of the following fields
                    i += 1 // symmetric algorithm
                    if (usage == 253) i += 1 // AEAD algorithm
                    if (version == 6) i += 1 // S2K specifier length (v6 only)
                    body[i].toInt() and 0xFF
                }
                if (s2kType == S2K_GNU) Protection.STUB else Protection.PROTECTED
            }
            else -> Protection.PROTECTED // a legacy cipher id (implicit S2K)
        }
    }.getOrNull()

    /**
     * True when every secret key packet in [raw] (binary or armored) that
     * carries material is protected by a passphrase. Stubs are skipped. A
     * packet that cannot be read counts as unprotected. A block with no
     * secret material at all (public only, or only stubs) is true: it holds
     * nothing to protect.
     */
    fun isFullyPassphraseProtected(raw: ByteArray): Boolean {
        val bytes = binary(raw) ?: return false
        for (p in CertificateBindings.packets(bytes)) {
            if (p.tag != TAG_SECRET_KEY && p.tag != TAG_SECRET_SUBKEY) continue
            when (protectionOf(p.tag, p.body)) {
                Protection.PROTECTED, Protection.STUB -> {}
                Protection.UNPROTECTED, null -> return false
            }
        }
        return true
    }

    /** [isFullyPassphraseProtected] for a Bouncy Castle ring. */
    fun isFullyPassphraseProtected(ring: PGPSecretKeyRing): Boolean = isFullyPassphraseProtected(ring.encoded)

    /**
     * Does the secret-key block [secret] (binary or armored) hold the secret
     * of the certificate [storedPublic] (binary or armored)? See the header.
     * [passphrase] unlocks protected material; without it a protected key
     * yields [SecretMatch.NEEDS_PASSPHRASE] once its structure checks out.
     */
    fun checkSecretForPublic(secret: ByteArray, storedPublic: ByteArray, passphrase: CharArray? = null): SecretMatch {
        val sec = binary(secret) ?: return SecretMatch.UNREADABLE
        val pub = binary(storedPublic) ?: return SecretMatch.UNREADABLE
        val secParsed = CertificateBindings.parse(sec) ?: return SecretMatch.UNREADABLE
        val pubParsed = CertificateBindings.parse(pub) ?: return SecretMatch.UNREADABLE
        if (!secParsed.primary.fingerprint.contentEquals(pubParsed.primary.fingerprint)) return SecretMatch.PUBLIC_MISMATCH

        // Structure: every secret packet readable, and some real material.
        val protections = CertificateBindings.packets(sec)
            .filter { it.tag == TAG_SECRET_KEY || it.tag == TAG_SECRET_SUBKEY }
            .map { protectionOf(it.tag, it.body) ?: return SecretMatch.UNREADABLE }
        if (protections.none { it != Protection.STUB }) return SecretMatch.NO_SECRET
        if (passphrase == null && protections.any { it == Protection.PROTECTED }) return SecretMatch.NEEDS_PASSPHRASE

        return if (CompositeSignSuite.forAlgId(secParsed.primary.algorithm) != null) {
            checkComposite(sec, passphrase)
        } else {
            checkClassical(sec, passphrase, keyFingerprints(pubParsed))
        }
    }

    /** Fingerprints (hex uppercase) of the primary and every subkey of [p]. */
    private fun keyFingerprints(p: CertificateBindings.Parsed): Set<String> {
        val out = HashSet<String>()
        out.add(p.primary.fingerprintHex)
        for (c in p.components) {
            if (!CertificateBindings.isSubkeyTag(c.tag)) continue
            val part = CertificateBindings.publicPart(c.tag, c.body) ?: continue
            runCatching { CertificateBindings.KeyBody(part).fingerprintHex }.getOrNull()?.let { out.add(it) }
        }
        return out
    }

    private fun checkComposite(sec: ByteArray, passphrase: CharArray?): SecretMatch {
        val info = try {
            CompositeKeyFacade.parse(sec, passphrase)
        } catch (e: PGPCryptoError.ResourceLimitExceeded) {
            return SecretMatch.UNREADABLE
        } catch (e: Exception) {
            return if (passphrase != null) SecretMatch.WRONG_PASSPHRASE else SecretMatch.UNREADABLE
        }
        val secretMaterial = info.compositeSecret
            ?: return if (passphrase == null) SecretMatch.NEEDS_PASSPHRASE else SecretMatch.WRONG_PASSPHRASE
        val digest = MessageDigest.getInstance("SHA-256").digest(challenge())
        val ok = runCatching {
            val sig = CompositeSigner.sign(info.suite, secretMaterial, digest)
            CompositeSigVerifier.verify(info.suite, info.compositePublic, sig, digest)
        }.getOrDefault(false)
        return if (ok) SecretMatch.OK else SecretMatch.MATERIAL_MISMATCH
    }

    /**
     * Every secret with material must unlock, none may fail its test, and at
     * least one key that the stored certificate itself carries ([storedFps])
     * must pass it. A key the stored certificate does not carry (a subkey
     * added since, or one grafted next to an offline primary stub) proves
     * nothing about the stored contact.
     */
    private fun checkClassical(sec: ByteArray, passphrase: CharArray?, storedFps: Set<String>): SecretMatch {
        var bytes = CertificateBindings.stubStrippedPrimary(sec)
        if (CompositeKeyFacade.hasV4Algo35Subkey(bytes)) {
            bytes = CompositeKeyFacade.v4Algo35BaseBytes(bytes) ?: return SecretMatch.UNREADABLE
        }
        val ring = runCatching {
            PGPSecretKeyRing(ByteArrayInputStream(LibrePGPV5Interop.toBcFormat(bytes)), JcaKeyFingerprintCalculator())
        }.getOrNull() ?: return SecretMatch.UNREADABLE
        var proven = 0
        for (key in ring.secretKeys) {
            if (key.isPrivateKeyEmpty) continue
            val s2k = key.s2K
            if (s2k != null && s2k.type == S2K_GNU) continue
            val protected = key.s2KUsage.toInt() != 0
            val priv = try {
                SecretKeyUnlock.extract(key, if (protected) passphrase else null)
            } catch (e: PGPCryptoError.ResourceLimitExceeded) {
                return SecretMatch.UNREADABLE
            } catch (e: PGPException) {
                return if (protected) SecretMatch.WRONG_PASSPHRASE else SecretMatch.UNREADABLE
            } catch (e: Exception) {
                return SecretMatch.UNREADABLE
            } ?: return SecretMatch.UNREADABLE
            when (prove(key.publicKey, priv)) {
                true -> if (fpHex(key.publicKey) in storedFps) proven++
                false -> return SecretMatch.MATERIAL_MISMATCH
                null -> {}
            }
        }
        return if (proven > 0) SecretMatch.OK else SecretMatch.UNPROVEN
    }

    private val SIGNING = setOf(
        PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_SIGN, PublicKeyAlgorithmTags.DSA,
        PublicKeyAlgorithmTags.ECDSA, PublicKeyAlgorithmTags.EDDSA_LEGACY,
        PublicKeyAlgorithmTags.Ed25519, PublicKeyAlgorithmTags.Ed448
    )
    private val ENCRYPTING = setOf(
        PublicKeyAlgorithmTags.RSA_ENCRYPT, PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, PublicKeyAlgorithmTags.ECDH,
        PublicKeyAlgorithmTags.X25519, PublicKeyAlgorithmTags.X448
    )

    /**
     * True when [priv] demonstrably belongs to [pub], false when it
     * demonstrably does not, null when this algorithm cannot be put to the
     * test here (or the test could not be set up).
     */
    private fun prove(pub: PGPPublicKey, priv: PGPPrivateKey): Boolean? {
        val data = challenge()
        if (pub.algorithm in SIGNING) {
            val sig = try {
                val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(pub.algorithm, HashAlgorithmTags.SHA256), pub)
                gen.init(PGPSignature.BINARY_DOCUMENT, priv)
                gen.update(data)
                gen.generate()
            } catch (e: Exception) {
                // A private key that cannot even sign is not this key's secret.
                return false
            }
            return runCatching {
                sig.init(BcPGPContentVerifierBuilderProvider(), pub)
                sig.update(data)
                sig.verify()
            }.getOrDefault(false)
        }
        if (pub.algorithm in ENCRYPTING) {
            val encrypted = try {
                val gen = PGPEncryptedDataGenerator(
                    BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setWithIntegrityPacket(true).setSecureRandom(SecureRandom())
                )
                gen.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(pub))
                val out = ByteArrayOutputStream()
                gen.open(out, data.size.toLong()).use { it.write(data) }
                out.toByteArray()
            } catch (e: Exception) {
                return null
            }
            return runCatching {
                val list = BcPGPObjectFactory(encrypted).nextObject() as PGPEncryptedDataList
                val pked = list[0] as PGPPublicKeyEncryptedData
                val back = pked.getDataStream(BcPublicKeyDataDecryptorFactory(priv)).use { it.readBytes() }
                back.contentEquals(data) && pked.verify()
            }.getOrDefault(false)
        }
        return null
    }

    private fun fpHex(key: PGPPublicKey): String =
        org.bouncycastle.util.encoders.Hex.toHexString(key.fingerprint).uppercase()

    private fun challenge(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    /** [raw] as binary packets: armored input is de-armored, binary returned as is. */
    private fun binary(raw: ByteArray): ByteArray? {
        val head = String(raw.copyOf(minOf(raw.size, 64)), Charsets.US_ASCII)
        if (!head.trimStart().startsWith("-----BEGIN PGP")) return raw
        return runCatching {
            ArmoredInputStream(ByteArrayInputStream(raw)).use { it.readBytes() }
        }.getOrNull()
    }
}
