// CertificationService.kt
// PGPony Android 4.7.0 (item 31, #79): certify other people's User IDs with
// your own key, like gpg's --sign-key and --lsign-key, and read back who
// certified a key.
//
// A certification is a 0x10 to 0x13 signature by the certifier's primary over
// the target's primary key and one User ID (RFC 9580 5.2.1), with the level
// gpg's --ask-cert-level offers: no claim (0x10, gpg's default), persona,
// casual, positive. A local-only certification carries Exportable
// Certification = false (critical) and is never written into the certificate:
// KeyRepository keeps it in its own blob (SecureKeyStore.storeLocalCertifications),
// which nothing that exports, shares, uploads or pairs a key reads.
// Revoking a certification you made is a 0x30 over the same User ID.
//
// Scope for 4.7.0 RC2: software certifiers and targets that Bouncy Castle
// reads (v4 and v6 classical keys). A composite ML-DSA certifier or target is
// not offered yet: a composite signature inside a classical certificate would
// stop Bouncy Castle from loading that certificate at all.
//
// 4.7.0 RC4 (item 31, card): a certifier whose primary sits in an OpenPGP
// card's signature slot certifies on the card ([certifyOnCard], [revokeOnCard]),
// after the PIN, over NFC or USB, through CardPGPContentSigner (SHA-256, the
// hash the card signer formats; EdDSA and RSA, as the card signer supports).
// The tapped card must hold that primary before any PIN is sent.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.sig.Exportable
import org.bouncycastle.bcpg.sig.RevocationReasonTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import java.io.ByteArrayOutputStream
import java.util.Date

object CertificationService {

    /** gpg's --ask-cert-level choices, by signature type. */
    enum class Level(val sigType: Int) {
        NO_CLAIM(PGPSignature.DEFAULT_CERTIFICATION),
        PERSONA(PGPSignature.NO_CERTIFICATION),
        CASUAL(PGPSignature.CASUAL_CERTIFICATION),
        POSITIVE(PGPSignature.POSITIVE_CERTIFICATION);

        companion object {
            fun ofSigType(type: Int): Level? = entries.firstOrNull { it.sigType == type }
        }
    }

    class CertifyError(message: String) : Exception(message)

    /** One certification made over [userId]. */
    class Made(val userId: String, val signature: PGPSignature)

    /** How a certification checks out against its issuer. */
    enum class Status { VERIFIED, FAILED, SIGNER_UNKNOWN }

    /** A third-party certification of one User ID, as shown in Key Details. */
    data class Certification(
        val userId: String,
        val issuerFingerprint: String?,
        val issuerKeyId: Long,
        val level: Level,
        val createdMs: Long,
        val expiresMs: Long?,
        val exportable: Boolean,
        val status: Status,
        val revoked: Boolean,
        /** 4.7.0 (item 59, #79): a trust signature (gpg tsign, RFC 9580
         *  5.2.3.21): the depth and the trust amount (60 partial, 120 full in
         *  gpg), null when the certification carries none. */
        val trustDepth: Int? = null,
        val trustAmount: Int? = null,
        /** True when a Regular Expression subpacket limits the trust. */
        val trustLimited: Boolean = false
    ) {
        fun expiredAt(nowMs: Long): Boolean = expiresMs != null && nowMs >= expiresMs
    }

    /** True when [ring]'s primary may make certifications: its secret is here,
     *  it carries Certify, and it is not a weak key. */
    fun canCertify(ring: PGPSecretKeyRing): Boolean {
        val primary = ring.secretKey ?: return false
        if (OfflineStub.isStub(primary)) return false
        val pub = primary.publicKey
        if (KeyPolicy.isWeak(pub)) return false
        if (pub.hasRevocation()) return false
        val caps = SubkeyCapability.fromPgpPublicKey(pub, PGPCryptoService.shared.detectAlgorithm(pub), true)
        return SubkeyCapability.hasCapability(caps, SubkeyCapability.Certify)
    }

    /**
     * Certify [userIds] on [target] with [certifier]'s primary. Returns one
     * signature per User ID; the caller adds exportable ones to the
     * certificate ([withSignatures]) and keeps local-only ones apart.
     */
    fun certify(
        certifier: PGPSecretKeyRing,
        passphrase: String?,
        target: PGPPublicKeyRing,
        userIds: List<String>,
        level: Level,
        expirySeconds: Long?,
        exportable: Boolean,
        now: Date = Date()
    ): List<Made> {
        val targetPrimary = target.publicKey
        if (targetPrimary.fingerprint.contentEquals(certifier.publicKey.fingerprint)) {
            throw CertifyError("A key cannot certify itself")
        }
        val available = targetPrimary.userIDs.asSequence().toSet()
        val missing = userIds.filter { it !in available }
        if (userIds.isEmpty() || missing.isNotEmpty()) throw CertifyError("Pick at least one User ID of this key to certify")
        val privateKey = unlockPrimary(certifier, passphrase)
        val signerPub = certifier.publicKey
        return makeCertifications(signerPub, target, userIds, level, expirySeconds, exportable, now) { type ->
            PonySigGen(BcPGPContentSignerBuilder(signerPub.algorithm, HashAlgorithmTags.SHA512), signerPub)
                .apply { init(type, privateKey) }
        }
    }

    /** One signature per User ID by [signerPub], from generators [newGenerator] makes. */
    private fun makeCertifications(
        signerPub: PGPPublicKey,
        target: PGPPublicKeyRing,
        userIds: List<String>,
        level: Level,
        expirySeconds: Long?,
        exportable: Boolean,
        now: Date,
        newGenerator: (Int) -> PonySigGen
    ): List<Made> {
        val targetPrimary = target.publicKey
        return userIds.map { uid ->
            val gen = newGenerator(level.sigType)
            val hashed = PGPSignatureSubpacketGenerator()
            hashed.setSignatureCreationTime(false, now)
            hashed.setIssuerFingerprint(false, signerPub)
            if (expirySeconds != null && expirySeconds > 0) hashed.setSignatureExpirationTime(true, expirySeconds)
            if (!exportable) hashed.setExportable(true, false)
            gen.setHashedSubpackets(hashed.generate())
            Made(uid, gen.generateCertification(uid, targetPrimary))
        }
    }

    // ── 4.7.0 RC4 (item 31): certifying on a card ───────────────────────

    /**
     * True when [certifier]'s primary may certify on a card: it carries
     * Certify, is not revoked or weak, and is an algorithm the card signer
     * handles (EdDSA legacy, RSA).
     */
    fun canCertifyOnCard(certifier: PGPPublicKeyRing): Boolean {
        val pub = certifier.publicKey
        if (KeyPolicy.isWeak(pub)) return false
        if (pub.hasRevocation()) return false
        if (pub.algorithm !in CARD_SIGNER_ALGORITHMS) return false
        val caps = SubkeyCapability.fromPgpPublicKey(pub, PGPCryptoService.shared.detectAlgorithm(pub), true)
        return SubkeyCapability.hasCapability(caps, SubkeyCapability.Certify)
    }

    /** Public key algorithms CardPGPContentSigner turns into signatures. */
    private val CARD_SIGNER_ALGORITHMS = setOf(
        org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EDDSA_LEGACY,
        org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_GENERAL,
        org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_SIGN
    )

    /**
     * Refuse before any PIN reaches the card unless [cardSigFingerprint] (the
     * tapped card's signature slot) is [certifier]'s primary.
     */
    private fun requireCardHolds(certifier: PGPPublicKeyRing, cardSigFingerprint: String?) {
        val want = hex(certifier.publicKey.fingerprint)
        val got = cardSigFingerprint?.filterNot { it.isWhitespace() }?.uppercase()
        if (got != want) throw com.pgpony.android.crypto.card.OpenPgpCardException.Malformed(CARD_MISMATCH_MESSAGE)
    }

    /** The tapped card does not hold the certifying primary in its signature slot. */
    const val CARD_MISMATCH_MESSAGE = "This security key does not hold the key chosen to certify with"

    private fun cardGenerator(
        session: com.pgpony.android.crypto.card.OpenPgpCardSession,
        pin: ByteArray,
        signerPub: PGPPublicKey
    ): (Int) -> PonySigGen = { type ->
        PonySigGen(com.pgpony.android.crypto.card.CardPGPContentSignerBuilder(session, pin, signerPub), signerPub)
            .apply { init(type, org.bouncycastle.openpgp.PGPPrivateKey(signerPub.keyID, signerPub.publicKeyPacket, null)) }
    }

    /**
     * Certify [userIds] on [target] on the card in [session], whose signature
     * slot holds [certifier]'s primary ([cardSigFingerprint], read from the
     * card). Same signatures as [certify], signed with SHA-256 on the card.
     * Runs inside a card operation (NFC or USB).
     */
    fun certifyOnCard(
        session: com.pgpony.android.crypto.card.OpenPgpCardSession,
        cardSigFingerprint: String?,
        pin: ByteArray,
        certifier: PGPPublicKeyRing,
        target: PGPPublicKeyRing,
        userIds: List<String>,
        level: Level,
        expirySeconds: Long?,
        exportable: Boolean,
        now: Date = Date()
    ): List<Made> {
        val targetPrimary = target.publicKey
        if (targetPrimary.fingerprint.contentEquals(certifier.publicKey.fingerprint)) {
            throw CertifyError("A key cannot certify itself")
        }
        val available = targetPrimary.userIDs.asSequence().toSet()
        if (userIds.isEmpty() || userIds.any { it !in available }) {
            throw CertifyError("Pick at least one User ID of this key to certify")
        }
        if (!canCertifyOnCard(certifier)) throw CertifyError("This key cannot certify other keys")
        requireCardHolds(certifier, cardSigFingerprint)
        val signerPub = certifier.publicKey
        return unwrapCard {
            makeCertifications(signerPub, target, userIds, level, expirySeconds, exportable, now, cardGenerator(session, pin, signerPub))
        }
    }

    /** [revoke], signed on the card in [session]; see [certifyOnCard]. */
    fun revokeOnCard(
        session: com.pgpony.android.crypto.card.OpenPgpCardSession,
        cardSigFingerprint: String?,
        pin: ByteArray,
        certifier: PGPPublicKeyRing,
        target: PGPPublicKeyRing,
        userId: String,
        now: Date = Date()
    ): Made {
        if (!canCertifyOnCard(certifier)) throw CertifyError("This key cannot certify other keys")
        requireCardHolds(certifier, cardSigFingerprint)
        val signerPub = certifier.publicKey
        return unwrapCard { revocation(signerPub, target, userId, now, cardGenerator(session, pin, signerPub)) }
    }

    /** A card error (wrong PIN, card gone) surfaces as itself, not as BC's wrapper. */
    private fun <T> unwrapCard(block: () -> T): T = try {
        block()
    } catch (e: PGPException) {
        val cause = e.cause
        if (cause is com.pgpony.android.crypto.card.OpenPgpCardException) throw cause
        throw e
    }

    /** A 0x30 revoking [certifier]'s certification of [userId] on [target]. */
    fun revoke(
        certifier: PGPSecretKeyRing,
        passphrase: String?,
        target: PGPPublicKeyRing,
        userId: String,
        now: Date = Date()
    ): Made {
        val privateKey = unlockPrimary(certifier, passphrase)
        val signerPub = certifier.publicKey
        return revocation(signerPub, target, userId, now) { type ->
            PonySigGen(BcPGPContentSignerBuilder(signerPub.algorithm, HashAlgorithmTags.SHA512), signerPub)
                .apply { init(type, privateKey) }
        }
    }

    private fun revocation(
        signerPub: PGPPublicKey,
        target: PGPPublicKeyRing,
        userId: String,
        now: Date,
        newGenerator: (Int) -> PonySigGen
    ): Made {
        val gen = newGenerator(PGPSignature.CERTIFICATION_REVOCATION)
        val hashed = PGPSignatureSubpacketGenerator()
        hashed.setSignatureCreationTime(false, now)
        hashed.setIssuerFingerprint(false, signerPub)
        hashed.setRevocationReason(false, RevocationReasonTags.NO_REASON, "")
        gen.setHashedSubpackets(hashed.generate())
        return Made(userId, gen.generateCertification(userId, target.publicKey))
    }

    /** [target] with [made] added to its primary's User IDs. */
    fun withSignatures(target: PGPPublicKeyRing, made: List<Made>): PGPPublicKeyRing {
        var primary = target.publicKey
        for (m in made) primary = PGPPublicKey.addCertification(primary, m.userId, m.signature)
        return PGPPublicKeyRing.insertPublicKey(target, primary)
    }

    /** False only when the signature carries Exportable Certification = false. */
    fun isExportable(sig: PGPSignature): Boolean {
        val sp = sig.hashedSubPackets?.getSubpacket(SignatureSubpacketTags.EXPORTABLE) as? Exportable
        return sp?.isExportable ?: true
    }

    /**
     * Every third-party certification of [target]'s User IDs, from the
     * certificate itself and from [local] (local-only ones, keyed by User
     * ID), newest per issuer and User ID. [issuer] resolves an issuer
     * fingerprint (hex, may be null) or key id to its primary public key, or
     * null when it is not in the keyring.
     */
    fun certifications(
        target: PGPPublicKeyRing,
        local: List<Made>,
        issuer: (String?, Long) -> PGPPublicKey?
    ): List<Certification> {
        val primary = target.publicKey
        val out = ArrayList<Certification>()
        val uids = primary.userIDs.asSequence().toList()
        for (uid in uids) {
            val sigs = primary.getSignaturesForID(uid)?.asSequence()?.toList().orEmpty() +
                local.filter { it.userId == uid }.map { it.signature }
            val thirdParty = sigs.filter { s -> s.keyID != primary.keyID && issuerFp(s)?.equals(hex(primary.fingerprint), true) != true }
            val byIssuer = thirdParty.groupBy { issuerFp(it) ?: String.format("%016X", it.keyID) }
            for ((_, group) in byIssuer) {
                val cert = group.filter { Level.ofSigType(it.signatureType) != null }.maxByOrNull { it.creationTime.time } ?: continue
                val fp = issuerFp(cert)
                val signer = issuer(fp, cert.keyID)
                val status = when {
                    signer == null -> Status.SIGNER_UNKNOWN
                    verifies(cert, uid, primary, signer) -> Status.VERIFIED
                    else -> Status.FAILED
                }
                val revoked = signer != null && group.any {
                    it.signatureType == PGPSignature.CERTIFICATION_REVOCATION &&
                        it.creationTime.time >= cert.creationTime.time &&
                        verifies(it, uid, primary, signer)
                }
                val expSeconds = cert.hashedSubPackets?.signatureExpirationTime ?: 0L
                out.add(
                    Certification(
                        userId = uid,
                        issuerFingerprint = fp,
                        issuerKeyId = cert.keyID,
                        level = Level.ofSigType(cert.signatureType)!!,
                        createdMs = cert.creationTime.time,
                        expiresMs = if (expSeconds > 0) cert.creationTime.time + expSeconds * 1000L else null,
                        exportable = isExportable(cert),
                        status = status,
                        revoked = revoked,
                        trustDepth = cert.hashedSubPackets?.trust?.depth,
                        trustAmount = cert.hashedSubPackets?.trust?.trustAmount,
                        trustLimited = cert.hashedSubPackets?.hasSubpacket(
                            org.bouncycastle.bcpg.SignatureSubpacketTags.REG_EXP
                        ) == true
                    )
                )
            }
        }
        return out
    }

    // ── Local-only storage format ───────────────────────────────────────
    // Repeated: 4-octet User ID length, User ID (UTF-8), 4-octet signature
    // length, the signature packet.

    fun encodeLocal(made: List<Made>): ByteArray {
        val out = ByteArrayOutputStream()
        for (m in made) {
            val uid = m.userId.toByteArray(Charsets.UTF_8)
            val sig = m.signature.encoded
            write32(out, uid.size); out.write(uid)
            write32(out, sig.size); out.write(sig)
        }
        return out.toByteArray()
    }

    fun decodeLocal(data: ByteArray?): List<Made> {
        if (data == null || data.isEmpty()) return emptyList()
        val out = ArrayList<Made>()
        var p = 0
        runCatching {
            while (p + 4 <= data.size) {
                val ul = read32(data, p); p += 4
                require(ul in 0..65536 && p + ul <= data.size)
                val uid = String(data, p, ul, Charsets.UTF_8); p += ul
                val sl = read32(data, p); p += 4
                require(sl in 1..1_000_000 && p + sl <= data.size)
                val sigBytes = data.copyOfRange(p, p + sl); p += sl
                val sig = (BcPGPObjectFactory(sigBytes).nextObject() as? PGPSignatureList)?.takeIf { it.size() == 1 }?.get(0)
                if (sig != null) out.add(Made(uid, sig))
            }
        }
        return out
    }

    // ── Internals ───────────────────────────────────────────────────────

    private fun unlockPrimary(certifier: PGPSecretKeyRing, passphrase: String?): org.bouncycastle.openpgp.PGPPrivateKey {
        val primarySec = certifier.secretKey
        OfflineStub.requireSecret(primarySec)
        if (!canCertify(certifier)) throw CertifyError("This key cannot certify other keys")
        enforceArgon2Policy(primarySec.s2K)
        return try {
            primarySec.extractPrivateKey(SecretKeyUnlock.decryptor(passphrase))
                ?: throw CertifyError("This key cannot certify other keys")
        } catch (e: PGPException) {
            if (primarySec.s2KUsage != 0) {
                if (passphrase.isNullOrEmpty()) throw PGPCryptoError.PassphraseRequired()
                throw PGPCryptoError.InvalidPassphrase()
            }
            throw CertifyError("This key cannot certify other keys")
        }
    }

    private fun verifies(sig: PGPSignature, uid: String, target: PGPPublicKey, signer: PGPPublicKey): Boolean = runCatching {
        sig.init(BcPGPContentVerifierBuilderProvider(), signer)
        sig.verifyCertification(uid, target)
    }.getOrDefault(false)

    private fun issuerFp(sig: PGPSignature): String? {
        val fp = sig.hashedSubPackets?.issuerFingerprint ?: sig.unhashedSubPackets?.issuerFingerprint
        return fp?.fingerprint?.let { hex(it) }
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02X".format(it) }

    private fun write32(out: ByteArrayOutputStream, n: Int) {
        out.write((n ushr 24) and 0xFF); out.write((n ushr 16) and 0xFF); out.write((n ushr 8) and 0xFF); out.write(n and 0xFF)
    }

    private fun read32(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)
}
