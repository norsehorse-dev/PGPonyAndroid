// KeyToCardService.kt
// PGPony Android, 4.7.0 RC4 (item 13, #71)
//
// Move to Security Key: write keys of a software key pair into an OpenPGP
// card's slots, the way gpg's keytocard does, inside one card operation (NFC
// tap or USB). With the admin PIN: set each slot's algorithm attributes, import
// the private key (KeyToCard builds the data), and write the slot's
// fingerprint and creation time. Then, with the user PIN, use every written
// slot once and check the result against the key's public part: a signature
// that verifies for the signature slot, a test message that decrypts for the
// decryption slot, an authentication that verifies for the authentication
// slot. Last, the card's fingerprints are read back and compared. Only after
// all of that does the caller change anything on the phone.
//
// Cv25519: cards differ on the byte order of an imported X25519 secret. The
// order OpenPGP stores it in (big-endian, what gpg and ykman send) goes first;
// if the slot does not decrypt the test message, the native RFC 7748 order is
// written instead and tested again.
//
// 4.8.0 (4l, #109): ECDSA and ECDH keys on NIST, brainpool and secp256k1
// curves move as well. Their slot attributes name the curve; a card that does
// not hold that curve refuses the write (UNSUPPORTED_MESSAGE) or fails the
// check, and the phone keeps its keys.
//
// 4.8.0 (4p): a slot's algorithm attributes are only written when the key
// needs them changed (KeyToCard.attributePlan), as gpg does: an RSA slot of
// the key's size keeps its own exponent length and import format. A card whose
// C0 says its attributes cannot change (a YubiKey NEO) is never sent PUT DATA
// C1 to C3, and a key it cannot take is refused before any PIN is sent. A
// refused attribute write or import names the slot, the command and the
// card's status after the usual message (OpenPgpCardException.CardRefused).
//
// The user PIN is checked first, before anything on the card is overwritten,
// so a mistyped user PIN cannot leave freshly written slots unchecked. A wrong
// admin PIN surfaces as WrongAdminPin so the screen can name it.
//
// Every buffer that held private key bytes is wiped once its APDU is sent.

package com.pgpony.android.crypto.card

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import com.pgpony.android.crypto.PonySigGen
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Date

object KeyToCardService {

    /** English messages, localized through ErrorText rules. */
    const val UNSUPPORTED_MESSAGE = "This security key cannot hold one of the chosen keys. Choose another key or slot."
    const val CHECK_FAILED_MESSAGE =
        "The security key did not pass the check after the keys were written, so nothing on this phone was changed. Do not rely on the keys on the security key."

    /** One key to write: [pub] and its unlocked [priv] into [slot]. */
    class Move(val slot: CardSlot, val pub: PGPPublicKey, val priv: PGPPrivateKey)

    /** What was written, for KeyRepository.finishKeyToCard. */
    class Done(val cardInfo: CardInfo, val movedFingerprints: List<String>)

    /**
     * Write [moves] to the card in [session] and check them. [certificate]
     * is the key pair's public certificate (for the decryption test). Throws
     * OpenPgpCardException: wrong PIN, card gone, a key the card cannot hold
     * (UNSUPPORTED_MESSAGE, or CardRefused with the card's answer), a slot
     * that failed its check (CHECK_FAILED_MESSAGE), or, unless [replace], a
     * chosen slot that already holds a different key (SlotsOccupied, before
     * any PIN is sent).
     */
    fun transfer(
        session: OpenPgpCardSession,
        adminPin: ByteArray,
        userPin: ByteArray,
        certificate: PGPPublicKeyRing,
        moves: List<Move>,
        replace: Boolean
    ): Done {
        require(moves.isNotEmpty()) { "nothing to move" }
        require(moves.map { it.slot }.toSet().size == moves.size) { "one key per slot" }
        val kinds = moves.associateWith { m ->
            (KeyToCard.eligibility(m.pub) as? KeyToCard.Eligibility.Movable)
                ?: throw OpenPgpCardException.Malformed(UNSUPPORTED_MESSAGE)
        }

        session.select()
        // 4.8.0 (4p): read before any PIN, for the occupied check and for C0
        // (whether the slots' attributes may change).
        val before = session.getApplicationRelatedData()
        val changeable = before.attributesChangeable
        if (!replace) {
            val occupied = moves.any { m ->
                val held = when (m.slot) {
                    CardSlot.SIGNATURE -> before.sigFingerprint
                    CardSlot.DECRYPTION -> before.decFingerprint
                    CardSlot.AUTHENTICATION -> before.authFingerprint
                }
                held != null && !held.equals(hex(m.pub.fingerprint), ignoreCase = true)
            }
            if (occupied) throw OpenPgpCardException.SlotsOccupied()
        }
        // 4.8.0 (4p): a key a slot cannot take is refused here, before any
        // PIN is sent and before any other slot is written.
        for (m in moves) {
            val current = runCatching { session.readAlgorithmAttributes(m.slot) }.getOrNull()
            val plan = planFor(m, kinds.getValue(m), current, changeable)
            if (plan is KeyToCard.AttributePlan.Refuse) {
                throw OpenPgpCardException.CardRefused("${KeyToCard.statusName(m.slot)}: ${plan.detail}")
            }
        }
        session.verify(OpenPgpCard.PW1_OTHER, userPin)
        verifyAdmin(session, adminPin)
        for (m in moves) write(session, m, kinds.getValue(m), cv25519Native = false, changeable = changeable)

        for (m in moves) {
            if (test(session, m, userPin, certificate)) continue
            val k = kinds.getValue(m)
            if (k.kind == KeyToCard.Kind.CV25519) {
                verifyAdmin(session, adminPin)
                write(session, m, k, cv25519Native = true, changeable = changeable)
                if (test(session, m, userPin, certificate)) continue
            }
            throw OpenPgpCardException.Malformed(CHECK_FAILED_MESSAGE)
        }

        val ard = session.getApplicationRelatedData()
        for (m in moves) {
            val want = hex(m.pub.fingerprint)
            val got = when (m.slot) {
                CardSlot.SIGNATURE -> ard.sigFingerprint
                CardSlot.DECRYPTION -> ard.decFingerprint
                CardSlot.AUTHENTICATION -> ard.authFingerprint
            }
            if (!want.equals(got, ignoreCase = true)) throw OpenPgpCardException.Malformed(CHECK_FAILED_MESSAGE)
        }
        return Done(session.readCardInfo(), moves.map { hex(it.pub.fingerprint) })
    }

    private fun verifyAdmin(session: OpenPgpCardSession, adminPin: ByteArray) {
        try {
            session.verify(OpenPgpCard.PW3_ADMIN, adminPin)
        } catch (e: OpenPgpCardException.WrongPin) {
            throw OpenPgpCardException.WrongAdminPin(e.triesRemaining)
        }
    }

    // ── Writing one slot ────────────────────────────────────────────────

    /** 4.8.0 (4p): the attribute plan for [m] into a slot that reports [current]. */
    private fun planFor(
        m: Move, k: KeyToCard.Eligibility.Movable, current: ByteArray?, changeable: Boolean?
    ): KeyToCard.AttributePlan =
        KeyToCard.attributePlan(
            kind = k.kind,
            rsaBits = k.rsaBits,
            rsaExponentBits = KeyToCard.rsaExponentBits(m.pub),
            current = current,
            changeable = changeable,
            curveOid = k.curveOid
        )

    /**
     * Write [m] into its slot: the attributes only when the plan says so, then
     * the import, the fingerprint and the creation time. [changeable] is the
     * card's C0 flag (null when it reports none). Internal for the JVM tests.
     */
    internal fun write(
        session: OpenPgpCardSession,
        m: Move,
        k: KeyToCard.Eligibility.Movable,
        cv25519Native: Boolean,
        changeable: Boolean?
    ) {
        val current = runCatching { session.readAlgorithmAttributes(m.slot) }.getOrNull()
        val slotName = KeyToCard.statusName(m.slot)
        // 4.8.0 (4p): keep the slot's attributes when they fit the key, as gpg
        // does, and never write them on a card that cannot change them.
        val plan = planFor(m, k, current, changeable)
        val attrs: ByteArray = when (plan) {
            is KeyToCard.AttributePlan.Refuse -> throw OpenPgpCardException.CardRefused("$slotName: ${plan.detail}")
            is KeyToCard.AttributePlan.Keep -> plan.attributes
            is KeyToCard.AttributePlan.Write -> plan.attributes
        }
        var parts: List<KeyToCard.Part> = emptyList()
        var ehl: ByteArray? = null
        try {
            parts = when (k.kind) {
                KeyToCard.Kind.RSA -> {
                    val (e, p, q, d) = KeyToCard.rsaSecret(m.pub, m.priv)
                    // The import uses the exponent length and format of the
                    // plan's attributes: the slot's own when it is kept.
                    val eBits = KeyToCard.rsaExponentBitsOf(attrs) ?: 17
                    val format = KeyToCard.rsaFormatOf(attrs) ?: KeyToCard.RSA_FORMAT_STANDARD
                    KeyToCard.rsaParts(e, p, q, d, k.rsaBits, eBits, format)
                }
                KeyToCard.Kind.ED25519 -> KeyToCard.ecParts(KeyToCard.ed25519Seed(m.priv))
                KeyToCard.Kind.CV25519 -> KeyToCard.ecParts(KeyToCard.cv25519Secret(m.priv, native = cv25519Native))
                // 4.8.0 (4l, #109): the curve goes into the attributes, the
                // field-length scalar into tag 92.
                KeyToCard.Kind.EC_SIGN, KeyToCard.Kind.EC_DECRYPT ->
                    KeyToCard.ecParts(KeyToCard.weierstrassSecret(m.pub, m.priv))
            }
            if (plan is KeyToCard.AttributePlan.Write) {
                try {
                    session.setAlgorithmAttributes(m.slot, attrs)
                } catch (e: OpenPgpCardException.CardStatus) {
                    // 6A80 (wrong data), 6A81, 6A83 or 6D00 (not supported) and
                    // the like: the card cannot hold this key in this slot.
                    throw OpenPgpCardException.CardRefused(
                        "%s: PUT DATA %04X, status %04X".format(slotName, attributesTag(m.slot), e.sw), e
                    )
                }
            }
            ehl = KeyToCard.extendedHeaderList(m.slot, parts)
            try {
                session.importPrivateKey(ehl)
            } catch (e: OpenPgpCardException.CardStatus) {
                val refused = "%s: key import, status %04X".format(slotName, e.sw)
                val retry = KeyToCard.rsaModulusRetryFormat(k.kind, plan, attrs, e.sw)
                    ?: throw OpenPgpCardException.CardRefused(refused, e)
                // 4.8.0 (RC5, found on a Token2): a slot this move turned into
                // RSA gets import format 00 (e, p, q), as gpg would write, but a
                // JavaCard applet that cannot work out n from p and q refuses
                // that import (6984). Write the slot once more as format 03,
                // which carries the CRT values and the modulus, and import again.
                // A card that took format 00 never gets here.
                KeyToCard.wipe(ehl)
                KeyToCard.wipe(parts)
                val (re, rp, rq, rd) = KeyToCard.rsaSecret(m.pub, m.priv)
                val retryAttrs = KeyToCard.attributes(
                    KeyToCard.Kind.RSA, k.rsaBits, KeyToCard.rsaExponentBitsOf(attrs) ?: 17, retry
                )
                parts = KeyToCard.rsaParts(re, rp, rq, rd, k.rsaBits, KeyToCard.rsaExponentBitsOf(retryAttrs) ?: 17, retry)
                try {
                    session.setAlgorithmAttributes(m.slot, retryAttrs)
                } catch (e2: OpenPgpCardException.CardStatus) {
                    throw OpenPgpCardException.CardRefused(
                        "%s, then PUT DATA %04X, status %04X".format(refused, attributesTag(m.slot), e2.sw), e2
                    )
                }
                ehl = KeyToCard.extendedHeaderList(m.slot, parts)
                try {
                    session.importPrivateKey(ehl)
                } catch (e2: OpenPgpCardException.CardStatus) {
                    throw OpenPgpCardException.CardRefused(
                        "%s, then format %02X import, status %04X".format(refused, retry, e2.sw), e2
                    )
                }
            }
        } catch (e: IllegalArgumentException) {
            // A value longer than the slot allows (KeyToCard.fixed).
            throw OpenPgpCardException.Malformed(UNSUPPORTED_MESSAGE, e)
        } finally {
            KeyToCard.wipe(ehl)
            KeyToCard.wipe(parts)
        }
        session.writeFingerprint(m.slot, m.pub.fingerprint)
        session.writeGenerationTime(m.slot, m.pub.creationTime.time / 1000L)
    }

    /** The algorithm attributes DO of [slot], C1 to C3, for the error detail. */
    private fun attributesTag(slot: CardSlot): Int = when (slot) {
        CardSlot.SIGNATURE -> OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_SIG
        CardSlot.DECRYPTION -> OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_DEC
        CardSlot.AUTHENTICATION -> OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_AUTH
    }

    // ── Using one slot ──────────────────────────────────────────────────

    private fun test(session: OpenPgpCardSession, m: Move, userPin: ByteArray, certificate: PGPPublicKeyRing): Boolean =
        try {
            when (m.slot) {
                CardSlot.SIGNATURE -> testSign(session, m.pub, userPin)
                CardSlot.DECRYPTION -> testDecrypt(session, m.pub, userPin, certificate)
                CardSlot.AUTHENTICATION -> testAuthenticate(session, m.pub, userPin)
            }
        } catch (e: OpenPgpCardException.WrongPin) {
            throw e
        } catch (e: OpenPgpCardException.TagLost) {
            throw e
        } catch (e: Exception) {
            false
        }

    private fun challenge(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    /** A signature made in the signature slot verifies under [pub]. */
    private fun testSign(session: OpenPgpCardSession, pub: PGPPublicKey, userPin: ByteArray): Boolean {
        val data = challenge()
        val gen = PonySigGen(CardPGPContentSignerBuilder(session, userPin, pub), pub)
        gen.init(PGPSignature.BINARY_DOCUMENT, PGPPrivateKey(pub.keyID, pub.publicKeyPacket, null))
        gen.update(data)
        val sig = gen.generate()
        // 4.7.3: a v5 key's signature needs the v5 document hashing to verify.
        return com.pgpony.android.crypto.LibrePgpV5Sig.verify(sig, pub, data)
    }

    /** A message encrypted to [pub] decrypts in the decryption slot. */
    private fun testDecrypt(
        session: OpenPgpCardSession,
        pub: PGPPublicKey,
        userPin: ByteArray,
        certificate: PGPPublicKeyRing
    ): Boolean {
        val plain = challenge()
        val out = ByteArrayOutputStream()
        val enc = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(SecureRandom())
        )
        enc.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(pub))
        enc.open(out, ByteArray(1 shl 12)).use { encOut ->
            PGPLiteralDataGenerator().open(encOut, PGPLiteralData.BINARY, "", plain.size.toLong(), Date()).use { it.write(plain) }
        }
        val result = CardDecryptService.shared.decryptBytes(session, certificate, userPin, out.toByteArray())
        return MessageDigest.isEqual(result.data, plain)
    }

    /** An INTERNAL AUTHENTICATE in the authentication slot verifies under [pub]. */
    private fun testAuthenticate(session: OpenPgpCardSession, pub: PGPPublicKey, userPin: ByteArray): Boolean {
        val digest = MessageDigest.getInstance("SHA-256").digest(challenge())
        val rsa = CardSigningFormat.isRsa(pub.algorithm)
        val input = if (rsa) CardSigningFormat.SHA256_DIGESTINFO_PREFIX + digest else digest
        session.verify(OpenPgpCard.PW1_OTHER, userPin)
        val out = session.internalAuthenticate(input)
        return if (rsa) {
            val key = pub.publicKeyPacket.key as org.bouncycastle.bcpg.RSAPublicBCPGKey
            val engine = org.bouncycastle.crypto.encodings.PKCS1Encoding(org.bouncycastle.crypto.engines.RSAEngine())
            engine.init(false, org.bouncycastle.crypto.params.RSAKeyParameters(false, key.modulus, key.publicExponent))
            MessageDigest.isEqual(engine.processBlock(out, 0, out.size), input)
        } else if (pub.algorithm == CardSigningFormat.ECDSA) {
            verifyEcdsa(pub, input, out)
        } else {
            val key = pub.publicKeyPacket.key as org.bouncycastle.bcpg.EdDSAPublicBCPGKey
            val point = key.encodedPoint.toByteArray().let { b ->
                // The EdDSA MPI is 0x40 followed by the 32-octet public key.
                val unsigned = if (b.size > 33 && b[0].toInt() == 0) b.copyOfRange(1, b.size) else b
                unsigned.copyOfRange(unsigned.size - 32, unsigned.size)
            }
            val verifier = org.bouncycastle.crypto.signers.Ed25519Signer()
            verifier.init(false, org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(point, 0))
            verifier.update(input, 0, input.size)
            out.size == 64 && verifier.verifySignature(out)
        }
    }

    /**
     * 4.8.0 (4l, #109): an ECDSA authentication from the card, raw r followed
     * by s (each half the length), verifies over [digest] under [pub].
     */
    private fun verifyEcdsa(pub: PGPPublicKey, digest: ByteArray, raw: ByteArray): Boolean {
        if (raw.isEmpty() || raw.size % 2 != 0) return false
        val key = pub.publicKeyPacket.key as org.bouncycastle.bcpg.ECPublicBCPGKey
        val x9 = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByOID(key.curveOID) ?: return false
        val domain = org.bouncycastle.crypto.params.ECDomainParameters(x9.curve, x9.g, x9.n, x9.h)
        val point = x9.curve.decodePoint(org.bouncycastle.util.BigIntegers.asUnsignedByteArray(key.encodedPoint))
        val half = raw.size / 2
        val r = java.math.BigInteger(1, raw.copyOfRange(0, half))
        val s = java.math.BigInteger(1, raw.copyOfRange(half, raw.size))
        val verifier = org.bouncycastle.crypto.signers.ECDSASigner()
        verifier.init(false, org.bouncycastle.crypto.params.ECPublicKeyParameters(point, domain))
        return verifier.verifySignature(digest, r, s)
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02X".format(it) }
}
