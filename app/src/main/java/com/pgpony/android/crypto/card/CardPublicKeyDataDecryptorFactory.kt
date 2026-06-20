// CardPublicKeyDataDecryptorFactory.kt
// PGPony Android — HW Phase 3b
//
// The decrypt counterpart to CardPGPContentSigner. BouncyCastle drives the
// message parsing and the symmetric (AES-CFB + MDC) decryption; we only
// take over the ECDH session-key recovery so the private-key step happens
// on the card.
//
// Implementation note — why subclass instead of implement the interface:
// PGPDataDecryptorFactory has several createDataDecryptor overloads (v1
// SEIPD, AEAD/v5, SEIPD-v2/v6) and the set has grown across BC versions.
// Implementing the interface directly risks missing one (cf. the
// getDigest() surprise in the signing bridge). Subclassing
// BcPublicKeyDataDecryptorFactory inherits all of them — built on the
// recovered key bytes, which don't need the private key — so we override
// ONLY recoverSessionData. The stub PGPPrivateKey we pass to super() is
// never used: the base recoverSessionData (which would use it) is the one
// method we replace.
//
// ECDH (cv25519) and RSA (Phase AR-2). The ECDH branch recovers the shared
// secret on the card, then runs the RFC 6637 KDF + AES key unwrap host-side.
// The RSA branch is shorter: the card performs the RSA private operation and
// strips the PKCS#1 padding, returning the OpenPGP session-key block
// directly (symAlgoID ‖ key ‖ checksum), so recoverSessionData returns the
// card output verbatim — no host-side KDF, no unwrap. secKeyData[0] is
// parsed per algorithm: an ECDH point template vs a single RSA cryptogram MPI.

package com.pgpony.android.crypto.card

import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.RSAPublicBCPGKey
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory

class CardPublicKeyDataDecryptorFactory(
    private val session: OpenPgpCardSession,
    private val encryptionKey: PGPPublicKey
) : BcPublicKeyDataDecryptorFactory(
    PGPPrivateKey(encryptionKey.keyID, encryptionKey.publicKeyPacket, null)
) {

    /**
     * Recover the session info (symAlgoID ‖ key ‖ checksum — exactly what
     * BC expects back; it verifies the checksum and extracts the key).
     *
     * secKeyData[0] for ECDH is laid out as BC writes/reads it:
     *   [2-byte MPI bit-length][ephemeral point][1-byte wrapped-len][wrapped key]
     * For cv25519 the point is 0x40‖X (33 bytes).
     *
     * Phase AR-3a — override BOTH overloads. BC 1.84 drives decryption through
     * AbstractPublicKeyDataDecryptorFactory.recoverSessionData(pkesk, encData)
     * (which is final) → the 3-arg recoverSessionData(keyAlgorithm, secKeyData,
     * pkeskVersion), NOT the deprecated 2-arg form this class originally
     * overrode. With only the 2-arg overridden, BC ran the base 3-arg, which
     * calls BcPGPKeyConverter.getPrivateKey() on our stub (null-data) private
     * key and throws "exception constructing key" — breaking every card decrypt
     * (RSA and cv25519) since the 1.78 → 1.84 bump. Both overrides now delegate
     * to recoverCardSessionData so a legacy 2-arg caller still works too.
     *
     * pkeskVersion is intentionally unused: the card returns exactly the bytes
     * the sender encrypted (v3 PKESK → symAlg‖key‖checksum; v6 PKESK →
     * key‖checksum with no symAlg), and the abstract base's
     * prependSKAlgorithmToSessionData prepends the v6 cipher algorithm from the
     * SEIPDv2 packet after we return.
     */
    override fun recoverSessionData(keyAlgorithm: Int, secKeyData: Array<ByteArray>): ByteArray =
        recoverCardSessionData(keyAlgorithm, secKeyData)

    override fun recoverSessionData(
        keyAlgorithm: Int,
        secKeyData: Array<ByteArray>,
        pkeskVersion: Int
    ): ByteArray = recoverCardSessionData(keyAlgorithm, secKeyData)

    private fun recoverCardSessionData(keyAlgorithm: Int, secKeyData: Array<ByteArray>): ByteArray {
        // RSA (algo 1/2/3): the card un-pads and returns the session-key
        // block directly — no point template, no KDF, no AES key unwrap.
        if (CardSigningFormat.isRsa(keyAlgorithm)) {
            return recoverRsaSessionData(secKeyData[0])
        }

        val enc = secKeyData[0]
        val pLen = (((enc[0].toInt() and 0xFF) shl 8) + (enc[1].toInt() and 0xFF) + 7) / 8
        val point = enc.copyOfRange(2, 2 + pLen)
        val wrappedLen = enc[2 + pLen].toInt() and 0xFF
        val wrapped = enc.copyOfRange(2 + pLen + 1, 2 + pLen + 1 + wrappedLen)

        // cv25519: the wire MPI carries the point as 0x40‖X (33 bytes), but
        // the card's X25519 PSO:DECIPHER expects the raw 32-byte
        // u-coordinate in the 86 DO — sending the 0x40 prefix returns
        // 0x6700 (wrong length). Strip it for the native-format prefix;
        // NIST/brainpool points start with 0x04 and are left intact.
        val cardPoint = if (point.isNotEmpty() && (point[0].toInt() and 0xFF) == 0x40) {
            point.copyOfRange(1, point.size)
        } else {
            point
        }

        // ECDH on the card → shared secret.
        val shared = session.decipher(EcdhCipherData.cipherDoForPoint(cardPoint))

        // KDF parameters come from the recipient (card) encryption key.
        val ecdh = encryptionKey.publicKeyPacket.key as ECDHPublicBCPGKey
        val kdfHashId = ecdh.hashAlgorithm.toInt() and 0xFF
        val kekAlgoId = ecdh.symmetricKeyAlgorithm.toInt() and 0xFF
        val recipientFingerprint = encryptionKey.fingerprint   // 20-byte v4 fp

        val param = Rfc6637.kdfParam(Rfc6637.CURVE25519_OID, kdfHashId, kekAlgoId, recipientFingerprint)
        val kek = Rfc6637.deriveKek(shared, param, kdfHashId, kekAlgoId)
        val padded = Rfc6637.aesKeyUnwrap(kek, wrapped)
        return Rfc6637.stripPad(padded)
    }

    /**
     * RSA session-key recovery (Phase AR-2). [mpi] is secKeyData[0]: the RSA
     * cryptogram as a Bouncy Castle MPI — a 2-byte bit length followed by the
     * minimal big-endian cryptogram bytes. We slice out the cryptogram, read
     * the modulus length from the recipient (card) RSA encryption key for
     * left-padding, and hand it to the card. The card returns the OpenPGP
     * session-key block (symAlgoID ‖ key ‖ checksum); BC's caller verifies
     * the checksum and extracts the key, so we return it verbatim.
     */
    private fun recoverRsaSessionData(mpi: ByteArray): ByteArray {
        // Take ALL bytes after the 2-byte MPI length prefix, matching BC's own
        // recoverRSASessionData (processBytes(bi, 2, bi.length - 2)). Slicing a
        // length derived from the MPI bit-length field can truncate a
        // non-minimal MPI and corrupt the cryptogram.
        val cryptogram = mpi.copyOfRange(2, mpi.size)

        val rsa = encryptionKey.publicKeyPacket.key as RSAPublicBCPGKey
        val modulusBytes = (rsa.modulus.bitLength() + 7) / 8

        return try {
            session.decipherRsa(cryptogram, modulusBytes)
        } catch (e: OpenPgpCardException) {
            // The card decrypts with the key in its DECRYPTION slot. If the
            // message was encrypted to a different key (e.g. addressed to the
            // primary/signing key, or to another card), the RSA result fails its
            // PKCS#1 padding check and the card returns 0x6A80. Translate that
            // specific case into a clear message instead of a raw status code.
            throw keyMismatchOrOriginal(rsa.modulus, e)
        }
    }

    /**
     * On a card decipher failure, read the card's DECRYPTION-slot public modulus
     * and compare it to [messageModulus] (the key the message was encrypted to).
     * If they differ, the message wasn't encrypted to this card's decryption key,
     * so return a clear [OpenPgpCardException]; otherwise return [original]. The
     * read (INS 0x47 / P1 0x81) needs no PIN and runs only on the failure path,
     * so a normal decrypt is still a single decipher with no extra round-trip.
     */
    private fun keyMismatchOrOriginal(
        messageModulus: java.math.BigInteger,
        original: OpenPgpCardException
    ): OpenPgpCardException {
        val cardModulus = try {
            session.readPublicKeyMaterial(CardSlot.DECRYPTION).modulus
        } catch (e: Exception) {
            return original
        }
        fun strip(b: ByteArray?): ByteArray? =
            b?.let { if (it.isNotEmpty() && it[0].toInt() == 0) it.copyOfRange(1, it.size) else it }
        val card = strip(cardModulus)
        val message = strip(messageModulus.toByteArray())
        return if (card != null && message != null && !card.contentEquals(message)) {
            OpenPgpCardException.Malformed(
                "This message was encrypted to a different key than the one in this card's decryption slot."
            )
        } else {
            original
        }
    }
}
