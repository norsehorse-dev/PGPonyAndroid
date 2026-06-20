// Phase C1 — routes a pass entry's bytes to decryption. C1 covers the software
// path: gather the user's software keypair secret rings and hand them to
// PGPCryptoService.decrypt, which sniffs armored vs binary and selects the
// matching secret key by PKESK key id. The hardware-key path (routing to
// CardDecryptService) is added in C2.

package com.pgpony.android.crypto.pass

import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.repository.KeyRepository
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import java.io.ByteArrayInputStream

/** How a pass entry should be decrypted, decided by recipient matching. */
sealed interface PassRoute {
    /** A software keypair holds the message's recipient key — decrypt on device. */
    data class Software(val rings: List<PGPSecretKeyRing>) : PassRoute
    /** Only a card-backed key matches — decrypt over NFC (C2). */
    data object Card : PassRoute
    /** No key in the keyring matches the message's recipients. */
    data object NoMatch : PassRoute
}

object PassDecryptCoordinator {

    /**
     * All software-keypair secret rings. BC picks the one matching the message's
     * PKESK key id, so the caller passes them all. Loaded once so a passphrase
     * retry doesn't re-read the keystore.
     */
    suspend fun softwareSecretRings(repo: KeyRepository): List<PGPSecretKeyRing> =
        repo.getAllKeys()
            .filter { it.isKeyPair }
            .mapNotNull { repo.loadSecretKeyRing(it.fingerprint) }

    /** Whether the keyring holds any card-backed key (used by C2 routing / messaging). */
    suspend fun hasCardKey(repo: KeyRepository): Boolean =
        repo.getAllKeys().any { it.isCardBacked }

    /**
     * Decrypt [bytes] with the given software secret [rings]. [passphrase] is null
     * on the first attempt; if the matching key is passphrase-protected the
     * caller catches the failure, prompts, and retries with the passphrase.
     * Returns the decrypted plaintext. Throws on failure (no matching key or
     * wrong passphrase).
     */
    fun decryptSoftware(bytes: ByteArray, rings: List<PGPSecretKeyRing>, passphrase: String?): String =
        PGPCryptoService.shared.decrypt(bytes, rings, passphrase).plaintext

    /**
     * The recipient key ids of an encrypted message (PKESK packets). A 0 id is a
     * hidden/wildcard recipient. Tolerant: returns empty on any parse failure.
     */
    fun messageRecipientKeyIds(bytes: ByteArray): List<Long> {
        return try {
            val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(bytes))
            val factory = JcaPGPObjectFactory(decoder)
            var obj = factory.nextObject()
            while (obj != null && obj !is PGPEncryptedDataList) obj = factory.nextObject()
            val encList = obj as? PGPEncryptedDataList ?: return emptyList()
            encList.encryptedDataObjects.asSequence()
                .filterIsInstance<PGPPublicKeyEncryptedData>()
                .map { it.keyID }
                .toList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Decide how to decrypt [bytes]: prefer a software keypair that holds a
     * recipient key; else a card-backed key; else no match. A ring matches when
     * it contains a key whose id is one of the message's recipients (the same
     * check CardDecryptService uses), or when the message has a wildcard
     * recipient. Software is preferred because it needs no tap.
     */
    suspend fun route(repo: KeyRepository, bytes: ByteArray): PassRoute {
        val ids = messageRecipientKeyIds(bytes)
        val wildcard = ids.contains(0L)
        val keys = repo.getAllKeys()

        fun matches(ring: PGPPublicKeyRing): Boolean =
            wildcard || ids.any { ring.getPublicKey(it) != null }

        val swRings = keys.filter { it.isKeyPair }.mapNotNull { k ->
            val pub = repo.loadPublicKeyRing(k.fingerprint) ?: return@mapNotNull null
            if (matches(pub)) repo.loadSecretKeyRing(k.fingerprint) else null
        }
        if (swRings.isNotEmpty()) return PassRoute.Software(swRings)

        val cardMatch = keys.filter { it.isCardBacked }.any { k ->
            repo.loadPublicKeyRing(k.fingerprint)?.let { matches(it) } == true
        }
        return if (cardMatch) PassRoute.Card else PassRoute.NoMatch
    }
}
