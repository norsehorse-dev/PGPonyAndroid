// RecipientPreferences.kt
// PGPony Android, 3.0.0 checkpoint 5d-3: the cipher and hash a message to
// several recipients uses, taken from what the recipients' certificates list.
//
// Decided 2026-09-29: the strongest cipher and the strongest hash that every
// recipient lists. Before this the app always used AES-256 and SHA-256, which
// is fine for nearly everyone but wrong for a recipient whose certificate
// lists only AES-128 or only SHA-384. Rules:
//
//   * Ciphers are chosen from AES-256, AES-192 and AES-128, in that order.
//     AES-128 is always allowed (RFC 9580 makes it mandatory to implement),
//     so a choice always exists.
//   * Hashes for a signature inside an encrypted message are chosen from
//     SHA-512, SHA-384 and SHA-256; SHA-256 is always allowed.
//   * The preferences are read from the recipient's newest verified self-
//     signature over the primary (direct-key or User ID certification). A
//     recipient whose certificate lists no preference puts no limit on the
//     choice, so older keys keep getting AES-256 and SHA-256 as before.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector

object RecipientPreferences {

    private val CIPHERS = listOf(
        SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128
    )
    private val HASHES = listOf(HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256)

    /** The cipher for a message to [recipients]. */
    fun cipherFor(recipients: List<PGPPublicKeyRing>): Int =
        choose(CIPHERS, SymmetricKeyAlgorithmTags.AES_128, recipients) { it.preferredSymmetricAlgorithms }

    /** The hash for a signature inside a message to [recipients]. */
    fun hashFor(recipients: List<PGPPublicKeyRing>): Int =
        choose(HASHES, HashAlgorithmTags.SHA256, recipients) { it.preferredHashAlgorithms }

    private fun choose(
        candidates: List<Int>,
        alwaysAllowed: Int,
        recipients: List<PGPPublicKeyRing>,
        read: (PGPSignatureSubpacketVector) -> IntArray?
    ): Int {
        val lists = recipients.mapNotNull { r -> runCatching { preferences(r, read) }.getOrNull() }
        return candidates.first { c -> c == alwaysAllowed || lists.all { c in it } }
    }

    /** The preference list in [ring]'s newest verified self-signature over the
     *  primary that carries one, or null when none does. */
    internal fun preferences(ring: PGPPublicKeyRing, read: (PGPSignatureSubpacketVector) -> IntArray?): IntArray? {
        val verified = CertificateBindings.verified(ring).ring
        val primary = verified.publicKey
        var newest: PGPSignature? = null
        var newestList: IntArray? = null
        for (sig in primary.signatures.asSequence().filterIsInstance<PGPSignature>()) {
            val self = sig.signatureType == PGPSignature.DIRECT_KEY ||
                sig.signatureType in PGPSignature.DEFAULT_CERTIFICATION..PGPSignature.POSITIVE_CERTIFICATION
            if (!self || sig.keyID != primary.keyID) continue
            val list = sig.hashedSubPackets?.let(read) ?: continue
            if (list.isEmpty()) continue
            if (newest == null || sig.creationTime.after(newest.creationTime)) {
                newest = sig
                newestList = list
            }
        }
        return newestList
    }
}
