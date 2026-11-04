// CompositeSubkeySigning.kt
// PGPony Android, 4.8.0 (item 4j): signing with a composite ML-DSA signing
// subkey that sits on a classical primary.
//
// The subkey composer and Add Subkey can put an ML-DSA-65 + Ed25519 or
// ML-DSA-87 + Ed448 signing subkey (algorithm 30 or 31) on a v6 Ed25519 key.
// That key is a BouncyCastle ring, so every sign path picks its signing key
// with PGPCryptoService.pickSigningSecretKey, and the newest valid signing
// subkey is the composite one. BouncyCastle can neither unlock nor sign with
// it: a protected key failed as a wrong passphrase, an unprotected one as an
// unknown public key algorithm.
//
// The sign paths ask [forPicked] after the pick. For a composite subkey it
// returns the unlocked signer, and the caller signs through
// CompositeDocumentSigner (or hands the signer to encrypt) the way a composite
// primary already signs. The secret is proved against the subkey's public
// material before it is used, so a wrong passphrase is told apart from any
// other failure even for a key protected without AEAD.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.SigningError
import org.bouncycastle.openpgp.PGPSecretKey
import java.security.SecureRandom

object CompositeSubkeySigning {

    /** An unlocked composite signing subkey, ready for CompositeDocumentSigner. */
    class Signer(
        val suite: CompositeSignSuite,
        val secret: ByteArray,
        val fingerprint: ByteArray,
        val keyId: Long
    )

    /** The composite suite of [key] when it is a composite signing subkey, else null. */
    fun suiteOf(key: PGPSecretKey?): CompositeSignSuite? {
        if (key == null || key.publicKey.isMasterKey) return null
        return CompositeSignSuite.forAlgId(key.publicKey.algorithm)
    }

    /**
     * The unlocked signer for [picked] when it is a composite signing subkey,
     * or null when it is a key BouncyCastle signs with. [passphrase] null or
     * empty means none was given.
     *
     * Throws [SigningError.PassphraseRequired] for a protected subkey with no
     * passphrase, [SigningError.InvalidPassphrase] when the passphrase does not
     * unlock it, and [SigningError.SigningFailed] for anything else.
     */
    fun forPicked(picked: PGPSecretKey?, passphrase: String?): Signer? {
        val suite = suiteOf(picked) ?: return null
        val key = picked!!
        val pass = passphrase?.takeIf { it.isNotEmpty() }?.toCharArray()
        val protected = key.s2KUsage.toInt() != 0
        if (protected && pass == null) throw SigningError.PassphraseRequired()

        val body = secretKeyPacketBody(key.encoded)
            ?: throw SigningError.SigningFailed("the composite signing subkey could not be read")
        val public = publicMaterial(body)
            ?: throw SigningError.SigningFailed("the composite signing subkey could not be read")

        val secret = try {
            CompositeSecretProtection.unlock(body, pass, suite.compositeSecretLen)
        } catch (e: SigningError) {
            throw e
        } catch (e: com.pgpony.android.crypto.PGPCryptoError) {
            throw e
        } catch (e: CompositeSecretProtection.ProtectedKeyException) {
            throw SigningError.SigningFailed(e.message ?: "the composite signing subkey could not be unlocked")
        } catch (e: Exception) {
            if (protected) throw SigningError.InvalidPassphrase()
            throw SigningError.SigningFailed(e.message ?: "the composite signing subkey could not be unlocked")
        }

        if (!provesPublic(suite, secret, public)) {
            if (protected) throw SigningError.InvalidPassphrase()
            throw SigningError.SigningFailed("the composite signing subkey's secret does not match its public key")
        }
        return Signer(suite, secret, key.publicKey.fingerprint, key.keyID)
    }

    /** True when a signature from [secret] verifies under [public]. */
    private fun provesPublic(suite: CompositeSignSuite, secret: ByteArray, public: ByteArray): Boolean = try {
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        CompositeSigVerifier.verify(suite, public, CompositeSigner.sign(suite, secret, challenge), challenge)
    } catch (e: Exception) {
        false
    }

    /**
     * Text signature data (type 0x01) for a detached text signature: line
     * endings in canonical CR LF form (RFC 9580 5.2.1.2). Trailing whitespace
     * is kept; only the cleartext framework strips it.
     */
    fun canonicalText(data: ByteArray): ByteArray = com.pgpony.android.crypto.TextCanonical.crlf(data)

    // The key material sits after version (1), creation time (4), algorithm (1)
    // and the v6 material length (4).
    private fun publicMaterial(keyPacketBody: ByteArray): ByteArray? {
        if (keyPacketBody.size < 10 || keyPacketBody[0].toInt() != 6) return null
        val len = uint32(keyPacketBody, 6)
        if (len < 0 || 10 + len > keyPacketBody.size) return null
        return keyPacketBody.copyOfRange(10, 10 + len)
    }

    /** The body of the first secret key or secret subkey packet in [encoded]. */
    private fun secretKeyPacketBody(encoded: ByteArray): ByteArray? {
        var i = 0
        while (i < encoded.size) {
            val c = encoded[i++].toInt() and 0xFF
            if (c and 0x80 == 0) return null
            val tag: Int
            val len: Int
            if (c and 0x40 != 0) {
                tag = c and 0x3F
                if (i >= encoded.size) return null
                val l0 = encoded[i++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0
                    l0 < 224 -> {
                        if (i >= encoded.size) return null
                        ((l0 - 192) shl 8) + (encoded[i++].toInt() and 0xFF) + 192
                    }
                    l0 == 255 -> {
                        if (i + 4 > encoded.size) return null
                        uint32(encoded, i).also { i += 4 }
                    }
                    else -> return null
                }
            } else {
                tag = (c shr 2) and 0x0F
                len = when (c and 0x03) {
                    0 -> {
                        if (i >= encoded.size) return null
                        encoded[i++].toInt() and 0xFF
                    }
                    1 -> {
                        if (i + 2 > encoded.size) return null
                        (((encoded[i].toInt() and 0xFF) shl 8) or (encoded[i + 1].toInt() and 0xFF)).also { i += 2 }
                    }
                    2 -> {
                        if (i + 4 > encoded.size) return null
                        uint32(encoded, i).also { i += 4 }
                    }
                    else -> return null
                }
            }
            if (len < 0 || i + len > encoded.size) return null
            if (tag == 5 || tag == 7) return encoded.copyOfRange(i, i + len)
            i += len
        }
        return null
    }

    private fun uint32(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)
}
