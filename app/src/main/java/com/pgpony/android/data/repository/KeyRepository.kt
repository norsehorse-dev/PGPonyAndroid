// KeyRepository.kt
// PGPony Android
//
// Central repository bridging PGPCryptoService (crypto), SecureKeyStore (key material),
// and PGPKeyDao (Room metadata). This is the single entry point for all key operations.
// ViewModels call this — never the crypto service or storage directly.
//
// Matches iOS pattern: KeychainService + SwiftData model context operations.

package com.pgpony.android.data.repository

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.KeyExpirationService
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.RevocationError
import com.pgpony.android.crypto.RevocationService
import com.pgpony.android.crypto.card.CardInfo
import com.pgpony.android.data.*
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.util.UUID

sealed class KeyRepoError(message: String) : Exception(message) {
    class AlreadyExists(fp: String) : KeyRepoError("Key $fp already exists in keyring")
    class NotFound(fp: String) : KeyRepoError("Key $fp not found")
    class StorageFailed(msg: String) : KeyRepoError("Storage failed: $msg")
}

data class StoredKey(
    val entity: PGPKeyEntity,
    val publicKeyRing: PGPPublicKeyRing?,
    val secretKeyRing: PGPSecretKeyRing?
)

/**
 * Phase A10a — metadata for the Import preview UI before commit.
 *
 * Populated by [KeyRepository.previewArmoredKey] (in-memory parse,
 * no persistence). The UI displays these fields so the user can
 * verify they're about to import what they intended, then taps
 * Import → [KeyRepository.importArmoredKey] is called with
 * [armoredText] to persist.
 *
 * Field map:
 *   • fingerprint, userId, userName, userEmail — same shape as
 *     PGPKeyEntity for direct UI reuse (KeyCard composable).
 *   • algorithmShortName — string like "Ed25519+Cv25519" / "RSA-4096"
 *     for the preview row. Avoids the UI needing to enum-resolve.
 *   • hasPrivateKey — drives the "Key Pair (Public + Private)" vs
 *     "Public Key Only" header on the preview card.
 *   • isDuplicate — true if a row with this fingerprint already
 *     exists in the keyring.
 *   • willUpgradeToKeyPair — true when isDuplicate AND the existing
 *     row is public-only AND the incoming material includes a
 *     private key. The commit will upgrade rather than fail.
 *   • armoredText — original armor, held so the commit re-parses
 *     the exact same input the user previewed.
 */
data class ImportPreview(
    val fingerprint: String,
    val userId: String,
    val userName: String,
    val userEmail: String,
    val algorithmShortName: String,
    val hasPrivateKey: Boolean,
    val isDuplicate: Boolean,
    val willUpgradeToKeyPair: Boolean,
    /** HW Phase 1.5 — true when the duplicate is an unpaired/paired
     *  card-backed record and this import carries the matching public
     *  key, so confirming will pair the key onto the card record (via
     *  importArmoredKey's card branch) rather than collide. Lets the UI
     *  keep the Import button enabled for the pairing case. */
    val willPairWithCard: Boolean = false,
    val armoredText: String
) {
    /** Last 8 hex chars, uppercased — same convention as PGPKeyEntity.shortFingerprint. */
    val shortFingerprint: String get() = fingerprint.takeLast(8).uppercase()
}

class KeyRepository(
    private val dao: PGPKeyDao,
    private val store: SecureKeyStore,
    private val crypto: PGPCryptoService = PGPCryptoService.shared,
    // Phase A6: revocation primitives. Default to the shared instance
    // since RevocationService is stateless; the parameter is here so
    // tests can inject a stub.
    private val revocation: RevocationService = RevocationService.shared,
    private val keyExpiration: KeyExpirationService = KeyExpirationService.shared
) {

    // ── Generate ───────────────────────────────────────────────────────

    suspend fun generateKey(
        name: String,
        email: String,
        algorithm: KeyAlgorithm,
        passphrase: String?,
        expirationSeconds: Long? = null
    ): PGPKeyEntity {
        val result = crypto.generateKeyPair(name, email, algorithm, passphrase, expirationSeconds)

        // Store key material in encrypted storage
        store.storePublicKey(result.fingerprint, result.publicKeyData)
        store.storePrivateKey(result.fingerprint, result.privateKeyData)

        // Determine expiration from the generated key
        val importResult = crypto.importKeyData(result.publicKeyData)
        val masterKey = importResult.publicKeyRing?.publicKey
        val expiresAtMs = masterKey?.let { key ->
            val validSec = key.getValidSeconds()
            if (validSec > 0) (key.creationTime.time + validSec * 1000) else null
        }

        // Phase A6: pre-cache a revocation certificate at generation
        // time, while the passphrase (if any) is still in scope. This
        // gives the user something to fall back on if they later lose
        // access to their passphrase but still want to declare the key
        // revoked. Generated with reason=NO_REASON; revoke-from-UI
        // overwrites this with a user-chosen-reason cert.
        //
        // If pre-cache generation fails (very rare — same crypto path
        // that just succeeded at key generation), we fall back to
        // entity = null cert. The KeyDetailScreen revoke flow can
        // always generate fresh.
        val preCachedRevocationCert: String? = try {
            importResult.secretKeyRing?.let { secRing ->
                revocation.generateRevocationCertificate(
                    secretKeyRing = secRing,
                    reason = RevocationReason.NO_REASON,
                    comment = null,
                    passphrase = passphrase
                )
            }
        } catch (_: RevocationError) {
            // Non-fatal — user can still revoke later via the sheet
            // which generates fresh on demand. Logged-as-null in DB.
            null
        }

        val parsed = PGPKeyEntity.parseUserID("$name <$email>")
        val entity = PGPKeyEntity(
            id = UUID.randomUUID().toString(),
            fingerprint = result.fingerprint,
            userID = "$name <$email>",
            userName = parsed.first,
            userEmail = parsed.second,
            algorithm = algorithm,
            isKeyPair = true,
            createdAt = System.currentTimeMillis(),
            expiresAt = expiresAtMs,
            armoredPublicKey = result.armoredPublicKey,
            // Phase A6: pre-cached cert lives here until revoke time
            revocationCertificate = preCachedRevocationCert
        )

        dao.insert(entity)
        return entity
    }

    // ── Import ─────────────────────────────────────────────────────────

    /**
     * Phase A10a — metadata-only parse for the Import preview UI.
     *
     * Mirrors iOS ImportKeyView.previewArmoredKey: takes armored
     * text, runs the in-memory PGP parse via [PGPCryptoService.importArmoredKey],
     * and returns just the user-visible metadata + a duplicate flag.
     * NO key material is persisted to disk or DB — that happens only
     * when the user confirms via [importArmoredKey].
     *
     * The duplicate flag distinguishes three cases:
     *   • duplicate=false → not in keyring; import will add a new row
     *   • duplicate=true, willUpgrade=true → public key in keyring,
     *     preview text contains a matching private key → import will
     *     upgrade the existing row to a key pair
     *   • duplicate=true, willUpgrade=false → import will throw
     *     AlreadyExists; UI should disable the Import button or warn
     *
     * Returns null only when the parse failed entirely (malformed
     * armor, unsupported key type). Caller surfaces the parse error
     * separately if needed.
     */
    suspend fun previewArmoredKey(armoredText: String): ImportPreview? {
        return try {
            val importResult = crypto.importArmoredKey(armoredText)
            val existing = dao.getByFingerprint(importResult.fingerprint)
            val parsed = PGPKeyEntity.parseUserID(importResult.userID)
            val willUpgrade = existing != null
                    && importResult.hasPrivateKey
                    && !existing.isKeyPair
            // HW Phase 1.5 — a duplicate that's actually a card record we
            // can pair the public key onto (not a true collision).
            val willPairWithCard = existing != null
                    && existing.isCardBacked
                    && importResult.publicKeyRing != null
            ImportPreview(
                fingerprint = importResult.fingerprint,
                userId = importResult.userID,
                userName = parsed.first,
                userEmail = parsed.second,
                algorithmShortName = importResult.algorithm.shortName,
                hasPrivateKey = importResult.hasPrivateKey,
                isDuplicate = existing != null,
                willUpgradeToKeyPair = willUpgrade,
                willPairWithCard = willPairWithCard,
                armoredText = armoredText
            )
        } catch (e: Exception) {
            null
        }
    }

    suspend fun importArmoredKey(armoredText: String): PGPKeyEntity {
        val importResult = crypto.importArmoredKey(armoredText)

        // Check for duplicate
        val existing = dao.getByFingerprint(importResult.fingerprint)
        if (existing != null) {
            // HW Phase 1.5 — pair a real public key onto a card-backed
            // record. A card scanned in Phase 1 is stored as identity +
            // fingerprints only (no key material). When the user then
            // imports the matching public key (exported from gpg, fetched
            // from a keyserver, etc.) we fold it into the existing card
            // row instead of colliding — order-independent with the
            // scan-after-import path in importCardKey. The row STAYS
            // card-backed and public-only (isKeyPair = false): on-card
            // sign/decrypt is Phase 2/3, so even if the imported blob
            // carried a private key we don't store software secret
            // material for a card key. We do refresh the identity
            // (userID/name/email/algorithm/expiry) from the real key,
            // replacing the "<manufacturer> hardware key" placeholder.
            if (existing.isCardBacked) {
                val pub = importResult.publicKeyRing
                    ?: throw KeyRepoError.StorageFailed(
                        "Imported data has no public key to pair with the card"
                    )
                store.storePublicKey(importResult.fingerprint, pub.encoded)
                val parsed = PGPKeyEntity.parseUserID(importResult.userID)
                val masterKey = pub.publicKey
                val expiresAtMs = masterKey?.let { key ->
                    val validSec = key.getValidSeconds()
                    if (validSec > 0) (key.creationTime.time + validSec * 1000) else null
                }
                val merged = existing.copy(
                    userID = importResult.userID,
                    userName = parsed.first,
                    userEmail = parsed.second,
                    algorithm = importResult.algorithm,
                    expiresAt = expiresAtMs,
                    armoredPublicKey = crypto.exportArmoredPublicKey(pub),
                    isKeyPair = false
                )
                dao.update(merged)
                return merged
            }
            // If we're importing a private key for an existing public key, upgrade it
            if (importResult.hasPrivateKey && !existing.isKeyPair) {
                store.storePrivateKey(importResult.fingerprint, importResult.secretKeyRing!!.encoded)
                val upgraded = existing.copy(isKeyPair = true)
                dao.update(upgraded)
                return upgraded
            }
            throw KeyRepoError.AlreadyExists(importResult.fingerprint)
        }

        // Store key material
        if (importResult.publicKeyRing != null) {
            store.storePublicKey(importResult.fingerprint, importResult.publicKeyRing.encoded)
        }
        if (importResult.secretKeyRing != null) {
            store.storePrivateKey(importResult.fingerprint, importResult.secretKeyRing.encoded)
        }

        // Determine expiration
        val masterKey = importResult.publicKeyRing?.publicKey
        val expiresAtMs = masterKey?.let { key ->
            val validSec = key.getValidSeconds()
            if (validSec > 0) (key.creationTime.time + validSec * 1000) else null
        }

        val parsed = PGPKeyEntity.parseUserID(importResult.userID)
        val entity = PGPKeyEntity(
            id = UUID.randomUUID().toString(),
            fingerprint = importResult.fingerprint,
            userID = importResult.userID,
            userName = parsed.first,
            userEmail = parsed.second,
            algorithm = importResult.algorithm,
            isKeyPair = importResult.hasPrivateKey,
            createdAt = importResult.creationDate.time,
            expiresAt = expiresAtMs,
            armoredPublicKey = importResult.publicKeyRing?.let {
                crypto.exportArmoredPublicKey(it)
            }
        )

        dao.insert(entity)
        return entity
    }

    // ── HW Phase 1: Import a hardware-key (OpenPGP card) record ────────

    /**
     * Import (or link) a physical OpenPGP card as a card-backed key.
     *
     * Phase 1 is read-only discovery: no on-card crypto is wired yet, so
     * the resulting row has isKeyPair = false and stores NO private (or
     * public-ring) material in SecureKeyStore. What it does store is the
     * card identity (serial / AID / manufacturer) and the per-slot
     * fingerprints the card reported, plus isCardBacked = true so the
     * future sign/decrypt routing branch can find it.
     *
     * The row is keyed on the signature slot's fingerprint (the card's
     * primary identity); if that slot is empty we fall back to the first
     * populated slot. If no slot has a key, this throws — a blank card
     * has nothing to import.
     *
     * Linking behavior: if a key with the same fingerprint already exists
     * in the keyring (e.g. the user imported the public cert earlier),
     * we stamp the card fields onto that existing row rather than create
     * a duplicate. Otherwise we insert a fresh card-backed contact row.
     */
    suspend fun importCardKey(cardInfo: CardInfo): PGPKeyEntity {
        return importCardKeyInternal(cardInfo)
    }

    /**
     * Persist a key just generated ON a card (Phase B1). [publicKeyBinary] is the
     * assembled transferable public key from CardKeygenService; [cardInfo] is the
     * post-generation card state (carrying the new fingerprints). The generated
     * secret keys live only on the card, so the stored row is public-only and
     * card-backed. Parsing the binary with BC also validates the assembled key
     * before anything is persisted. Reuses the order-independent card pair-up:
     * importCardKey creates/identifies the card-backed row, then importArmoredKey
     * folds the real public key (and UID) onto it.
     */
    suspend fun importGeneratedCardKey(publicKeyBinary: ByteArray, cardInfo: CardInfo): PGPKeyEntity {
        val ring = crypto.importKeyData(publicKeyBinary).publicKeyRing
            ?: throw KeyRepoError.StorageFailed("Generated key produced no public key ring")
        val armored = crypto.exportArmoredPublicKey(ring)
        importCardKeyInternal(cardInfo)
        return importArmoredKey(armored)
    }

    private suspend fun importCardKeyInternal(cardInfo: CardInfo): PGPKeyEntity {
        val primaryFp = cardInfo.primaryFingerprint
            ?: throw KeyRepoError.StorageFailed(
                "No OpenPGP keys found on this card"
            )

        val sigFp = cardInfo.fingerprintFor(com.pgpony.android.crypto.card.CardSlot.SIGNATURE)
        val decFp = cardInfo.fingerprintFor(com.pgpony.android.crypto.card.CardSlot.DECRYPTION)
        val authFp = cardInfo.fingerprintFor(com.pgpony.android.crypto.card.CardSlot.AUTHENTICATION)

        // Link path — fold card identity onto an existing keyring row.
        val existing = dao.getByFingerprint(primaryFp)
        if (existing != null) {
            val linked = existing.copy(
                isCardBacked = true,
                cardSerial = cardInfo.serialHex,
                cardAid = cardInfo.aidHex,
                cardManufacturer = cardInfo.manufacturerName,
                cardSigFingerprint = sigFp,
                cardDecFingerprint = decFp,
                cardAuthFingerprint = authFp
            )
            dao.update(linked)
            return linked
        }

        // Fresh card-backed contact row. No SecureKeyStore writes — the
        // private key lives on the card and there's no cert to cache yet.
        val algorithm = cardInfo.slotFor(com.pgpony.android.crypto.card.CardSlot.SIGNATURE)?.algorithm
            ?: cardInfo.slots.firstOrNull { it.algorithm != null }?.algorithm
            ?: KeyAlgorithm.ED25519_CV25519

        val label = "${cardInfo.manufacturerName} hardware key"
        val entity = PGPKeyEntity(
            id = UUID.randomUUID().toString(),
            fingerprint = primaryFp,
            userID = label,
            userName = label,
            userEmail = "Serial ${cardInfo.serialHex}",
            algorithm = algorithm,
            isKeyPair = false,
            createdAt = cardInfo.slotFor(com.pgpony.android.crypto.card.CardSlot.SIGNATURE)?.generationTime
                ?: System.currentTimeMillis(),
            isCardBacked = true,
            cardSerial = cardInfo.serialHex,
            cardAid = cardInfo.aidHex,
            cardManufacturer = cardInfo.manufacturerName,
            cardSigFingerprint = sigFp,
            cardDecFingerprint = decFp,
            cardAuthFingerprint = authFp
        )
        dao.insert(entity)
        return entity
    }

    // ── Load Key Rings ─────────────────────────────────────────────────

    fun loadPublicKeyRing(fingerprint: String): PGPPublicKeyRing? {
        val data = store.loadPublicKey(fingerprint) ?: return null
        return try {
            crypto.importKeyData(data).publicKeyRing
        } catch (_: Exception) { null }
    }

    fun loadSecretKeyRing(fingerprint: String): PGPSecretKeyRing? {
        val data = store.loadPrivateKey(fingerprint) ?: return null
        return try {
            crypto.importKeyData(data).secretKeyRing
        } catch (_: Exception) { null }
    }

    fun loadStoredKey(entity: PGPKeyEntity): StoredKey {
        return StoredKey(
            entity = entity,
            publicKeyRing = loadPublicKeyRing(entity.fingerprint),
            secretKeyRing = if (entity.isKeyPair) loadSecretKeyRing(entity.fingerprint) else null
        )
    }

    // ── Export ──────────────────────────────────────────────────────────

    fun exportArmoredPublicKey(fingerprint: String): String? {
        val ring = loadPublicKeyRing(fingerprint) ?: return null
        return crypto.exportArmoredPublicKey(ring)
    }

    fun exportArmoredPrivateKey(fingerprint: String): String? {
        val ring = loadSecretKeyRing(fingerprint) ?: return null
        return crypto.exportArmoredPrivateKey(ring)
    }

    // ── Delete ─────────────────────────────────────────────────────────

    suspend fun deleteKey(entity: PGPKeyEntity) {
        store.deleteKeys(entity.fingerprint)
        dao.delete(entity)
    }

    suspend fun deleteByFingerprint(fingerprint: String) {
        store.deleteKeys(fingerprint)
        dao.getByFingerprint(fingerprint)?.let { dao.delete(it) }
    }

    // ── Query ──────────────────────────────────────────────────────────

    suspend fun getAllKeys(): List<PGPKeyEntity> = dao.getAllKeys()
    suspend fun getKeyPairs(): List<PGPKeyEntity> = dao.getKeyPairs()
    suspend fun getByFingerprint(fp: String): PGPKeyEntity? = dao.getByFingerprint(fp)
    suspend fun getByEmail(email: String): List<PGPKeyEntity> = dao.getByEmail(email)
    suspend fun getDefaultKey(): PGPKeyEntity? = dao.getDefaultKey()
    suspend fun keyCount(): Int = dao.count()

    /**
     * Phase AU-1 — record a successful decrypt for [fingerprint], bumping its
     * usage counter so the "Decrypt With" picker can default to the most-used
     * key. No-op if the fingerprint has no row.
     */
    suspend fun incrementDecryptUseCount(fingerprint: String) =
        dao.incrementDecryptUseCount(fingerprint)

    // ── Update ─────────────────────────────────────────────────────────

    suspend fun setDefaultKey(fingerprint: String) {
        // Clear previous default
        dao.getDefaultKey()?.let { old ->
            dao.update(old.copy(isDefault = false))
        }
        dao.getByFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(isDefault = true))
        }
    }

    suspend fun updateTrustLevel(fingerprint: String, trust: TrustLevel) {
        dao.getByFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(trustLevel = trust))
        }
    }

    suspend fun updateNotes(fingerprint: String, notes: String?) {
        dao.getByFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(notes = notes))
        }
    }

    suspend fun markKeyServerUploaded(fingerprint: String) {
        dao.getByFingerprint(fingerprint)?.let { key ->
            // 3.0.0-KS1: also stamp the upload time so the detail screen can
            // show "Last uploaded: <date>".
            dao.update(
                key.copy(
                    keyServerUploaded = true,
                    lastUploadedAt = System.currentTimeMillis(),
                )
            )
        }
    }

    /**
     * 3.0.0-KS1 — record that the user checked/refreshed this key against a
     * keyserver. Drives the "Last checked: <date>" line. Independent of
     * whether the lookup found the key; the timestamp marks the attempt.
     */
    suspend fun markKeyServerChecked(fingerprint: String) {
        dao.getByFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(lastCheckedAt = System.currentTimeMillis()))
        }
    }

    suspend fun updateContactLink(
        fingerprint: String,
        contactId: String?,
        contactName: String?,
        contactPhotoUri: String?
    ) {
        dao.getByFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(
                contactId = contactId,
                contactName = contactName,
                contactPhotoUri = contactPhotoUri
            ))
        }
    }

    // ── Phase A6: Revocation ───────────────────────────────────────────

    /**
     * Apply a revocation to the key with the supplied fingerprint:
     *   1. Generate a fresh armored revocation certificate with the
     *      user-chosen reason + comment.
     *   2. Apply it to the cached public key ring → updated ring carries
     *      the revocation as a self-signature on the primary key.
     *   3. Re-armor the updated ring and write it back to both the
     *      secure key store (as raw bytes) AND the entity's
     *      armoredPublicKey field.
     *   4. Stamp isRevoked / revokedAt / revocationReason /
     *      revocationCertificate on the entity.
     *
     * Returns the armored revocation certificate so the UI can display
     * and offer to share it. Throws RevocationError on crypto failure
     * (passphrase wrong, key not a key pair, etc.).
     */
    suspend fun applyRevocation(
        fingerprint: String,
        reason: RevocationReason,
        comment: String?,
        passphrase: String?
    ): String {
        val entity = dao.getByFingerprint(fingerprint)
            ?: throw KeyRepoError.NotFound(fingerprint)
        if (!entity.isKeyPair) {
            throw RevocationError.UnsupportedKey(
                "Cannot revoke a public-only key — the private key is required to sign"
            )
        }

        val secRing = loadSecretKeyRing(fingerprint)
            ?: throw RevocationError.UnsupportedKey(
                "Secret key ring could not be loaded for $fingerprint"
            )
        val pubRing = loadPublicKeyRing(fingerprint)
            ?: throw RevocationError.UnsupportedKey(
                "Public key ring could not be loaded for $fingerprint"
            )

        // 1. Generate the cert
        val armoredCert = revocation.generateRevocationCertificate(
            secretKeyRing = secRing,
            reason = reason,
            comment = comment,
            passphrase = passphrase
        )

        // 2. Apply it to the public ring
        val revokedRing = revocation.applyRevocation(pubRing, armoredCert)

        // 3. Re-armor + persist. Two writes:
        //    (a) SecureKeyStore — so future loadPublicKeyRing reads
        //        return the post-revocation ring.
        //    (b) Entity.armoredPublicKey — so QR sheets and share
        //        actions surface the post-revocation form too.
        //
        // SecureKeyStore stores raw bytes; PGPPublicKeyRing.encoded
        // gives us the binary serialization directly. Earlier draft
        // round-tripped through importKeyData() but ImportResult exposes
        // `publicKeyRing` not `publicKeyData` — same bytes either way,
        // just less work.
        val updatedArmored = revocation.armorPublicKeyRing(revokedRing)
        store.storePublicKey(fingerprint, revokedRing.encoded)

        // 4. Stamp entity
        dao.update(
            entity.copy(
                armoredPublicKey = updatedArmored,
                isRevoked = true,
                revokedAt = System.currentTimeMillis(),
                revocationReason = reason,
                revocationCertificate = armoredCert
            )
        )

        return armoredCert
    }

    // ── Key expiration editing ──────────────────────────────────────────

    /**
     * Change a software key pair's expiration. [expiresAtEpochSeconds] null
     * = never. Re-signs the self-cert + subkey bindings with the primary
     * secret key (passphrase if protected), then persists the updated
     * secret + public rings and stamps entity.expiresAt. Throws
     * ExpirationError on crypto failure (passphrase, etc.).
     */
    suspend fun setKeyExpirationSoftware(
        fingerprint: String,
        expiresAtEpochSeconds: Long?,
        passphrase: String?
    ) {
        val entity = dao.getByFingerprint(fingerprint)
            ?: throw KeyRepoError.NotFound(fingerprint)
        if (!entity.isKeyPair) {
            throw KeyExpirationService.ExpirationError.UnsupportedKey(
                "Cannot edit expiration on a public-only key — the private key is required to re-sign."
            )
        }
        if (entity.isCardBacked) {
            throw KeyExpirationService.ExpirationError.UnsupportedKey(
                "This key lives on a hardware key — use the card flow to edit its expiration."
            )
        }
        val secRing = loadSecretKeyRing(fingerprint)
            ?: throw KeyExpirationService.ExpirationError.UnsupportedKey(
                "Secret key ring could not be loaded for $fingerprint"
            )
        val pubRing = loadPublicKeyRing(fingerprint)
            ?: throw KeyExpirationService.ExpirationError.UnsupportedKey(
                "Public key ring could not be loaded for $fingerprint"
            )

        val updated = keyExpiration.setExpirationSoftware(
            secretRing = secRing,
            publicRing = pubRing,
            expiresAtEpochSeconds = expiresAtEpochSeconds,
            passphrase = passphrase
        )
        persistExpiration(entity, updated.publicRing, updated.secretRing, expiresAtEpochSeconds)
    }

    /**
     * Persist the result of a card-backed expiration edit. The NFC op (run
     * by the UI) calls KeyExpirationService.setExpirationCard and hands the
     * updated public ring here. No secret ring exists for card keys.
     */
    suspend fun persistCardExpiration(
        fingerprint: String,
        updatedPublicRing: org.bouncycastle.openpgp.PGPPublicKeyRing,
        expiresAtEpochSeconds: Long?
    ) {
        val entity = dao.getByFingerprint(fingerprint)
            ?: throw KeyRepoError.NotFound(fingerprint)
        persistExpiration(entity, updatedPublicRing, null, expiresAtEpochSeconds)
    }

    private suspend fun persistExpiration(
        entity: PGPKeyEntity,
        publicRing: org.bouncycastle.openpgp.PGPPublicKeyRing,
        secretRing: org.bouncycastle.openpgp.PGPSecretKeyRing?,
        expiresAtEpochSeconds: Long?
    ) {
        store.storePublicKey(entity.fingerprint, publicRing.encoded)
        secretRing?.let { store.storePrivateKey(entity.fingerprint, it.encoded) }
        dao.update(
            entity.copy(
                armoredPublicKey = crypto.exportArmoredPublicKey(publicRing),
                expiresAt = expiresAtEpochSeconds?.let { it * 1000L }
            )
        )
    }

    /**
     * Return the stored revocation certificate (either pre-cached at
     * key generation or applied via applyRevocation), or null if none
     * exists. Surfaced in Danger Zone as "Export Revocation Certificate"
     * once the key is revoked.
     */
    suspend fun exportRevocationCertificate(fingerprint: String): String? {
        return dao.getByFingerprint(fingerprint)?.revocationCertificate
    }
}
