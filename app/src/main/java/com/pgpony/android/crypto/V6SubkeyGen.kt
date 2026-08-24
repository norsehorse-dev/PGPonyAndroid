// V6SubkeyGen.kt
// PGPony Android, 4.4.0 RC2 (planning §1.1)
//
// Add a classical v6 subkey (Ed25519 sign, X25519 encrypt) to an EXISTING
// v6 secret key ring. Companion to ClassicalSubkeyGen, which does the same
// for v4 rings; the two split because v6 uses a materially different BC API.
//
// ClassicalSubkeyGen binds through PGPKeyRingGenerator's "existing ring"
// constructor, which emits a v4 binding signature. A v6 primary needs a v6
// binding signature (RFC 9580 framing, salted, and for a signing subkey the
// embedded 0x19 back-signature). BC's high-level OpenPGPKeyEditor produces
// exactly that: it is the editing counterpart of the OpenPGPKeyGenerator
// that already builds PGPony's v6 keys, so an added v6 subkey looks to gpg
// like one PGPony would have generated the key with from the start.
//
// The passphrase (when the key is protected) unlocks the primary to sign the
// binding, via the KeyPassphraseProvider the editor takes. The expiry the
// user chose is written onto the subkey binding through the same hashed-
// subpacket callback the v6 keygen uses, so a v6 add-subkey honors expiry the
// way generation does (issue #4).

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.AEADAlgorithmTags
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKeyEditor
import org.bouncycastle.openpgp.api.KeyPassphraseProvider
import org.bouncycastle.openpgp.api.SignatureParameters
import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder
import java.security.SecureRandom
import java.util.Date

object V6SubkeyGen {

    /**
     * The v6 subkey shapes RC2 offers. v6 keys use modern curves, so there
     * is one algorithm per capability, matching how the v6 primary and its
     * generated subkeys are built (Ed25519 sign, X25519 encrypt).
     */
    enum class V6SubkeyType {
        ED25519_SIGN,
        X25519_ENCRYPT,
        ED25519_AUTH
    }

    /**
     * Append a v6 [type] subkey to [secretRing] and return the updated ring.
     * [passphrase] unlocks the primary when it is protected (empty/null for
     * an unprotected key). [expirationSeconds] > 0 sets the subkey's own
     * expiry; null or 0 leaves it non-expiring. Throws
     * ClassicalSubkeyGen.SubkeyAddError so callers catch v4 and v6 the same
     * way.
     */
    fun addSubkey(
        secretRing: PGPSecretKeyRing,
        type: V6SubkeyType,
        passphrase: String?,
        expirationSeconds: Long? = null,
        creationTime: Date = Date()
    ): PGPSecretKeyRing {
        val impl = BcOpenPGPImplementation()
        val key = OpenPGPKey(secretRing, impl)
        val pp = (passphrase ?: "").toCharArray()

        val editor = try {
            OpenPGPKeyEditor(key, KeyPassphraseProvider { pp }, impl)
        } catch (e: PGPException) {
            throw ClassicalSubkeyGen.SubkeyAddError(
                "Could not unlock the primary key to bind the new subkey: ${e.message}", e
            )
        }

        val generator = impl.pgpKeyPairGeneratorProvider()
            .get(PublicKeyPacket.VERSION_6, creationTime)
        val edited = try {
            when (type) {
                // null back-signature callback = BC generates the required
                // primary-key back-signature (0x19) for a signing or auth
                // subkey itself, the same as the v6 keygen path.
                V6SubkeyType.ED25519_SIGN ->
                    editor.addSigningSubkey(
                        generator.generateEd25519KeyPair(),
                        bindingCallback(expirationSeconds, authenticate = false), null
                    )
                V6SubkeyType.X25519_ENCRYPT ->
                    editor.addEncryptionSubkey(
                        generator.generateX25519KeyPair(),
                        bindingCallback(expirationSeconds, authenticate = false)
                    )
                // #49: an authentication subkey. addSigningSubkey embeds the
                // back-signature; the binding callback rewrites the default
                // signing flag to AUTHENTICATE (SSH via gpg-agent).
                V6SubkeyType.ED25519_AUTH ->
                    editor.addSigningSubkey(
                        generator.generateEd25519KeyPair(),
                        bindingCallback(expirationSeconds, authenticate = true), null
                    )
            }.done()
        } catch (e: PGPException) {
            throw ClassicalSubkeyGen.SubkeyAddError(
                "Could not bind the new v6 subkey: ${e.message}", e
            )
        }

        // BC's editor appends the new subkey to the ring UNPROTECTED, even
        // when the primary is passphrase-protected. Protect it to match, so a
        // key with a passphrase never stores new secret material in the clear:
        // AES-256 AEAD (OCB) + Argon2id, S2K usage 253, the same v6 protection
        // CompositeKeyGen applies and gpg 2.5 reads back.
        var ring = edited.pgpSecretKeyRing
        if (!passphrase.isNullOrEmpty()) {
            val beforeIds = secretRing.secretKeys.asSequence().map { it.keyID }.toSet()
            val plain = ring.secretKeys.asSequence().first { it.keyID !in beforeIds }
            val encryptor = BcAEADSecretKeyEncryptorBuilder(
                AEADAlgorithmTags.OCB,
                SymmetricKeyAlgorithmTags.AES_256,
                S2K.Argon2Params.memoryConstrainedParameters()
            ).setSecureRandom(SecureRandom())
                .build(passphrase.toCharArray(), plain.publicKey.publicKeyPacket)
            val protectedSub = PGPSecretKey.copyWithNewPassword(plain, null, encryptor)
            ring = PGPSecretKeyRing.insertSecretKey(ring, protectedSub)
        }
        return ring
    }

    /**
     * Writes the chosen expiry onto the subkey binding signature. Mirrors the
     * v6 keygen callback: strip any default Key Expiration Time the editor
     * added, then set our own only when a custom expiry is requested. "Never"
     * leaves none. Without the strip, a second KEY_EXPIRE_TIME subpacket would
     * shadow ours and validSeconds() would read the stale default.
     */
    private fun bindingCallback(
        expirationSeconds: Long?,
        authenticate: Boolean
    ): SignatureParameters.Callback =
        SignatureParameters.Callback.Util.modifyHashedSubpackets(
            SignatureSubpacketsFunction { subpackets ->
                if (authenticate) {
                    // Replace the default signing flag with AUTHENTICATE. The
                    // back-signature addSigningSubkey embeds stays intact.
                    subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS)
                    subpackets.setKeyFlags(false, KeyFlags.AUTHENTICATION)
                }
                subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_EXPIRE_TIME)
                if (expirationSeconds != null && expirationSeconds > 0L) {
                    subpackets.setKeyExpirationTime(false, expirationSeconds)
                }
                subpackets
            }
        )
}
