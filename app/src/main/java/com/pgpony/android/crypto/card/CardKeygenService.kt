// Phase B1b — on-card key generation orchestration. Ports the iOS
// Ed25519KeyGenerator.generateOnCard flow (verified offline against gpg: the
// public-key bodies + fingerprints built by CardKeyPacketBuilder match gpg
// byte-for-byte). Runs entirely inside one NFC operation (the session is live
// for the duration of a single card tap); persistence happens afterwards in the
// caller using the returned binary public key + CardInfo.
//
// The secret keys are generated ON the card and never leave it — so a key made
// this way CANNOT be backed up. The certification + subkey-binding signatures
// are produced BY the card (PSO:CDS), since the signing key lives there.

package com.pgpony.android.crypto.card

import java.security.MessageDigest

/** Result of an on-card generation: the assembled public key + the card state. */
data class CardKeyGenResult(
    val publicKeyBinary: ByteArray,   // binary transferable public key (tags 6,13,2,14,2)
    val cardInfo: CardInfo,           // re-read post-generation (new fingerprints)
    val primaryFingerprintHex: String,
    val subkeyFingerprintHex: String,
    val creationTime: Long,           // Unix seconds — same value baked into fp + card DOs
    val keyId: ByteArray              // last 8 bytes of the primary fingerprint
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CardKeyGenResult) return false
        return publicKeyBinary.contentEquals(other.publicKeyBinary) &&
            primaryFingerprintHex == other.primaryFingerprintHex &&
            subkeyFingerprintHex == other.subkeyFingerprintHex &&
            creationTime == other.creationTime &&
            keyId.contentEquals(other.keyId)
    }

    override fun hashCode(): Int {
        var result = publicKeyBinary.contentHashCode()
        result = 31 * result + primaryFingerprintHex.hashCode()
        result = 31 * result + subkeyFingerprintHex.hashCode()
        result = 31 * result + creationTime.hashCode()
        result = 31 * result + keyId.contentHashCode()
        return result
    }
}

object CardKeygenService {

    // Algorithm-attributes values: algo id + curve OID.
    private val ED25519_ATTRS = byteArrayOf(CardKeyPacketBuilder.EDDSA_ALGO.toByte()) + CardKeyPacketBuilder.ED25519_OID
    private val CV25519_ATTRS = byteArrayOf(CardKeyPacketBuilder.ECDH_ALGO.toByte()) + CardKeyPacketBuilder.CV25519_OID

    private const val SIG_TYPE_CERT = 0x13   // positive certification
    private const val SIG_TYPE_BIND = 0x18   // subkey binding

    /**
     * Generate an Ed25519 signing primary + Cv25519 ECDH subkey ON [session]'s
     * card and return the assembled, card-signed transferable PUBLIC key.
     * DESTRUCTIVE: overwrites the card's signature + decryption slots. The
     * private keys never leave the card and cannot be backed up.
     *
     * PIN sequence (one tap): PW3 (admin) to set attributes, generate, and write
     * the fingerprints + creation times; then PW1 (signing) re-verified before
     * EACH self-signature — many cards reset PW1 after every PSO:CDS.
     */
    fun generateOnCard(
        session: OpenPgpCardSession,
        name: String,
        email: String,
        expirationSeconds: Long?,
        adminPin: String,
        userPin: String
    ): CardKeyGenResult {
        val creationTime = System.currentTimeMillis() / 1000L
        val adminBytes = adminPin.toByteArray(Charsets.UTF_8)
        val userBytes = userPin.toByteArray(Charsets.UTF_8)

        session.select()

        // ── PW3 (admin): attributes, generate, fingerprints, creation times ──
        session.verify(OpenPgpCard.PW3_ADMIN, adminBytes)
        session.setAlgorithmAttributes(CardSlot.SIGNATURE, ED25519_ATTRS)
        session.setAlgorithmAttributes(CardSlot.DECRYPTION, CV25519_ATTRS)

        val signMaterial = session.generateKeyOnCard(CardSlot.SIGNATURE)
        val decMaterial = session.generateKeyOnCard(CardSlot.DECRYPTION)
        val signPoint = CardKeyPacketBuilder.stripPointPrefix(
            signMaterial.ecPoint ?: throw OpenPgpCardException.Malformed("Signature slot returned no EC point")
        )
        val decPoint = CardKeyPacketBuilder.stripPointPrefix(
            decMaterial.ecPoint ?: throw OpenPgpCardException.Malformed("Decryption slot returned no EC point")
        )

        val primaryBody = CardKeyPacketBuilder.buildEdDSAPublicKeyBody(creationTime, signPoint)
        val subkeyBody = CardKeyPacketBuilder.buildECDHPublicKeyBody(creationTime, decPoint)
        val primaryFp = CardKeyPacketBuilder.fingerprint(primaryBody)
        val subkeyFp = CardKeyPacketBuilder.fingerprint(subkeyBody)
        val keyId = CardKeyPacketBuilder.keyId(primaryFp)

        session.writeFingerprint(CardSlot.SIGNATURE, primaryFp)
        session.writeFingerprint(CardSlot.DECRYPTION, subkeyFp)
        // iOS omits these; we write them so gpg --card-status shows the correct
        // "created" date and the B3 status row shows a real date. The gen-time DO
        // is read independently of the fingerprint DO, so it cannot affect the
        // fingerprint match.
        session.writeGenerationTime(CardSlot.SIGNATURE, creationTime)
        session.writeGenerationTime(CardSlot.DECRYPTION, creationTime)

        // ── PW1 (signing): the two card-produced self-signatures ──
        val userIdBytes = "$name <$email>".toByteArray(Charsets.UTF_8)

        val certHashed = CardKeyPacketBuilder.certificationHashedSubpackets(creationTime, expirationSeconds)
        val certHashData = CardKeyPacketBuilder.buildCertificationHashData(
            primaryBody, userIdBytes, SIG_TYPE_CERT, certHashed
        )
        val certDigest = sha256(certHashData)
        session.verify(OpenPgpCard.PW1_SIGN, userBytes)
        val certSig64 = session.signDigest(certDigest)
        val certSig = CardKeyPacketBuilder.assembleEdDSASignaturePacket(
            SIG_TYPE_CERT,
            certHashed,
            CardKeyPacketBuilder.issuerUnhashedSubpackets(keyId),
            certDigest.copyOfRange(0, 2),
            certSig64
        )

        val bindHashed = CardKeyPacketBuilder.bindingHashedSubpackets(creationTime)
        val bindHashData = CardKeyPacketBuilder.buildSubkeyBindingHashData(
            primaryBody, subkeyBody, SIG_TYPE_BIND, bindHashed
        )
        val bindDigest = sha256(bindHashData)
        session.verify(OpenPgpCard.PW1_SIGN, userBytes)
        val bindSig64 = session.signDigest(bindDigest)
        val bindSig = CardKeyPacketBuilder.assembleEdDSASignaturePacket(
            SIG_TYPE_BIND,
            bindHashed,
            CardKeyPacketBuilder.issuerUnhashedSubpackets(keyId),
            bindDigest.copyOfRange(0, 2),
            bindSig64
        )

        // ── assemble the transferable public key (no secret packets) ──
        val binary = CardKeyPacketBuilder.buildPacket(6, primaryBody) +
            CardKeyPacketBuilder.buildPacket(13, userIdBytes) +
            CardKeyPacketBuilder.buildPacket(2, certSig) +
            CardKeyPacketBuilder.buildPacket(14, subkeyBody) +
            CardKeyPacketBuilder.buildPacket(2, bindSig)

        // Re-read the card so the returned CardInfo carries the new fingerprints
        // (the caller links them onto the keyring row).
        val cardInfo = session.readCardInfo()

        return CardKeyGenResult(
            publicKeyBinary = binary,
            cardInfo = cardInfo,
            primaryFingerprintHex = hex(primaryFp),
            subkeyFingerprintHex = hex(subkeyFp),
            creationTime = creationTime,
            keyId = keyId
        )
    }

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02X".format(it) }
}
