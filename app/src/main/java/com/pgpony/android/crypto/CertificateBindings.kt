// CertificateBindings.kt
// PGPony Android, 4.6.0 (item 17.1): verify the self-signatures that bind a
// certificate's components to its primary key.
//
// Bouncy Castle parses subkeys, User IDs and their signatures but never checks
// that a subkey or identity was actually bound by the primary. Anything that
// reads key flags, expiry or revocation straight off a parsed ring therefore
// trusts packets anyone could have appended. This object works on the raw
// transferable-key octets, so it covers every ring shape the app stores:
// ordinary Bouncy Castle rings, composite ML-DSA primaries (algo 30/31) that
// Bouncy Castle cannot load, and v4 rings carrying an algo-35 subkey that
// Bouncy Castle cannot parse.
//
//   * analyze(): which subkeys carry a verified 0x18 binding from the primary,
//     which of those also carry a verified embedded 0x19 back-signature (needed
//     before a subkey may speak for the primary as a signer), which are revoked
//     by a verified 0x28, which User IDs carry a verified self-certification,
//     and whether the primary is revoked by a verified 0x20.
//   * sanitize(): the same certificate with every component that fails to bind
//     removed: a subkey with no verified 0x18, a User ID or attribute with no
//     verified self-certification, and any primary-issued signature that does
//     not verify. Third-party certifications on identities are kept (they
//     cannot be checked without the issuer's key and carry no self-authority).
//
// Signatures are verified with Bouncy Castle for every classical signer (it
// supplies the algorithm and the v4 / v5 / v6 trailer), fed the key and
// identity framing built here (RFC 9580 5.2.4), so the subkey itself never
// has to be parseable by Bouncy Castle. Composite ML-DSA + EdDSA signers go
// through CompositeSigVerifier over the hand-built v6 digest.
//
// Fail-closed rules: a binding that is present but does not verify, uses an
// unknown signature version, or cannot be parsed counts as absent; a public
// subkey this parser cannot read is dropped; verification work is bounded per
// certificate and a self-signature past the bound counts as failing; state is
// looked up by fingerprint, never by (choosable) key id. The only
// "cannot tell" outcome is a primary whose own algorithm has no verifier here
// (an obsolete algorithm such as Elgamal-sign); analyze() then reports
// supported = false and sanitize() returns the input unchanged, so a key the
// app cannot evaluate is never damaged in storage.
//
// 3.0.0 (checkpoint 5d-1, from the OpenPGP interoperability test suite): the
// report keeps every verified self-signature and revocation with its times, so
// a signer can be judged at the time it signed (Report.signerValidityAt): a
// signature older than its key is rejected, a self-signature must be alive
// then, hard revocations apply at every time and soft ones (superseded,
// retired, User ID no longer valid) only from when they were made. A self-
// signature without a hashed creation time, or with a critical subpacket or
// notation it does not understand, does not verify. An empty key flags
// subpacket grants nothing. sanitize() rejects a certificate carrying an
// unknown critical packet, and skips a classical subkey or a third-party
// certification Bouncy Castle cannot read instead of failing the whole
// certificate.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.pqc.CompositeSigHash
import com.pgpony.android.crypto.pqc.CompositeSigVerifier
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.util.encoders.Hex
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

object CertificateBindings {

    // Packet tags.
    private const val TAG_SIGNATURE = 2
    private const val TAG_SECRET_KEY = 5
    private const val TAG_PUBLIC_KEY = 6
    private const val TAG_SECRET_SUBKEY = 7
    private const val TAG_TRUST = 12
    private const val TAG_USER_ID = 13
    private const val TAG_PUBLIC_SUBKEY = 14
    private const val TAG_USER_ATTRIBUTE = 17

    // Signature types.
    private const val SIG_CERT_GENERIC = 0x10
    private const val SIG_CERT_POSITIVE = 0x13
    private const val SIG_SUBKEY_BINDING = 0x18
    private const val SIG_PRIMARY_BINDING = 0x19
    private const val SIG_DIRECT_KEY = 0x1F
    private const val SIG_KEY_REVOCATION = 0x20
    private const val SIG_SUBKEY_REVOCATION = 0x28
    private const val SIG_CERT_REVOCATION = 0x30

    // Signature subpacket types.
    private const val SP_CREATION_TIME = 2
    private const val SP_SIG_EXPIRATION = 3
    private const val SP_KEY_EXPIRATION = 9
    private const val SP_KEY_FLAGS = 27
    private const val SP_ISSUER_KEY_ID = 16
    private const val SP_NOTATION = 20
    private const val SP_REVOCATION_REASON = 29
    private const val SP_EMBEDDED_SIGNATURE = 32
    private const val SP_ISSUER_FINGERPRINT = 33

    /**
     * 3.0.0 (5d-1): the signature subpacket types this code knows (RFC 9580
     * 5.2.3.7 and the LibrePGP additions). A hashed subpacket marked critical
     * whose type is not listed makes the signature invalid (RFC 9580
     * 5.2.3.7), and so does a critical notation, since no notation name is
     * interpreted here. Unknown types that are not critical are ignored.
     */
    internal val KNOWN_SUBPACKETS = setOf(
        2, 3, 4, 5, 6, 7, 9, 11, 12, 16, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
        34, 35, 37, 38, 39
    )

    /**
     * Revocation reasons that do not reach back in time (RFC 9580 5.2.3.31):
     * superseded (1), retired (3) and User ID no longer valid (32). A key
     * revoked for one of these stays valid for signatures made before the
     * revocation. Every other reason, and no reason at all, is a hard
     * revocation: the key may have been compromised, so it is invalid at every
     * point in time.
     */
    private val SOFT_REVOCATION_REASONS = setOf(1, 3, 32)

    /** Classical public-key algorithms whose key material Bouncy Castle parses. */
    private val BC_CLASSICAL_ALGORITHMS = setOf(1, 2, 3, 16, 17, 18, 19, 20, 22, 25, 26, 27, 28)

    /** Public-key algorithms this object can verify a signature from. */
    private val VERIFIABLE_ALGORITHMS = setOf(1, 3, 17, 19, 22, 27, 28, 30, 31)

    /**
     * Work bounds, so a crafted certificate cannot make one check take long.
     * Keys (the primary's own signatures and every subkey) and identities
     * (User IDs and attributes) each get their own budget, so junk on an
     * identity can never starve the subkey bindings. A budget counts both
     * verifications and octets hashed (an attribute can be megabytes, and
     * every signature over it hashes it again). Within one component only the
     * newest [MAX_SELF_SIGS_PER_COMPONENT] self-signatures are checked. Past
     * any bound a self-signature counts as failing (fail closed). Real
     * certificates stay far inside all of them; third-party certifications
     * are never verified here.
     */
    private const val MAX_VERIFICATIONS = 1000
    private const val MAX_HASHED_BYTES = 32L * 1024 * 1024
    private const val MAX_SELF_SIGS_PER_COMPONENT = 32

    /**
     * 3.0.0 (5d-1): one verified self-signature, kept so validity can be
     * judged at the time a signature was made rather than only now. For a
     * subkey it is a 0x18 binding; for the primary a 0x1F direct-key
     * signature or a User ID self-certification.
     */
    data class SelfSig(
        val createdMs: Long,
        /** Signature expiration (subpacket 3), epoch ms; null = none. */
        val sigExpiresAtMs: Long? = null,
        /** Key expiration this signature sets, epoch ms; null = none. */
        val keyExpiresAtMs: Long? = null,
        /** Key flags (first octet); null = no key flags subpacket, 0 = present but empty. */
        val keyFlags: Int? = null,
        /** Subkey bindings: a verified 0x19 back-signature is embedded. */
        val backSigned: Boolean = false,
        /** Expiration of that back-signature, epoch ms; null = none. */
        val backSigExpiresAtMs: Long? = null
    ) {
        /** Created at or before [t] and not yet expired at [t]. */
        fun aliveAt(t: Long): Boolean = createdMs <= t && (sigExpiresAtMs == null || t < sigExpiresAtMs)
    }

    /** 3.0.0 (5d-1): one verified revocation signature. */
    data class Revocation(
        val createdMs: Long,
        val sigExpiresAtMs: Long? = null,
        /** Reason code (subpacket 29); null = no reason given. */
        val reason: Int? = null
    ) {
        /** A hard revocation (see [SOFT_REVOCATION_REASONS]) applies at every point in time. */
        val hard: Boolean get() = reason !in SOFT_REVOCATION_REASONS

        /** Does this revocation make a key revoked at [t]? A soft one only once
         *  made and while its own signature has not expired. */
        fun inEffectAt(t: Long): Boolean =
            hard || (createdMs <= t && (sigExpiresAtMs == null || t < sigExpiresAtMs))
    }

    /** 3.0.0 (5d-1): a User ID with its verified self-certifications and revocations. */
    data class UserIdState(
        val userId: String,
        val certifications: List<SelfSig>,
        val revocations: List<Revocation>
    ) {
        /** A User ID revocation takes effect when made and ends when its
         *  signature expires, whatever its reason: it withdraws a claim about a
         *  name, never the key material. */
        fun revokedAt(t: Long): Boolean =
            revocations.any { it.createdMs <= t && (it.sigExpiresAtMs == null || t < it.sigExpiresAtMs) }
    }

    /** 3.0.0 (5d-1): the outcome of [Report.signerValidityAt]. */
    enum class SignerValidity {
        VALID,
        /** The signature is older than the key that made it (or its primary). */
        PREDATES_KEY,
        /** No self-signature makes the key valid at that time. */
        NOT_VALID,
        EXPIRED,
        REVOKED,
        /** The key's flags at that time exclude signing. */
        NOT_SIGNING,
        /** A subkey without a verified binding and back-signature at that time. */
        UNBOUND
    }

    data class SubkeyState(
        val fingerprintHex: String,
        val keyId: Long,
        val algorithm: Int,
        /** A 0x18 binding from the primary verifies. */
        val bound: Boolean,
        /** A verified 0x18 embeds a 0x19 back-signature that verifies under the subkey. */
        val backSigned: Boolean,
        /** A 0x28 revocation from the primary verifies and is in effect now. */
        val revoked: Boolean,
        /** Expiry from the newest verified 0x18, epoch ms; null = none. */
        val expiresAtMs: Long? = null,
        /** Key flags (first octet) from the newest verified 0x18; null = no
         *  key flags subpacket, 0 = an empty one. */
        val keyFlags: Int? = null,
        /** Key creation time, epoch ms. */
        val createdAtMs: Long = 0L,
        /** Key packet version (4, 5 or 6). */
        val version: Int = 4,
        /** The subkey's public key packet body, for callers that need to read
         *  its material (a LibrePGP composite's curve, say). */
        val publicBody: ByteArray = ByteArray(0),
        /** 3.0.0 (5d-1): every verified 0x18 binding. */
        val bindings: List<SelfSig> = emptyList(),
        /** 3.0.0 (5d-1): every verified 0x28 revocation. */
        val revocations: List<Revocation> = emptyList()
    )

    data class Report(
        /** False when the primary's algorithm has no verifier here (see header). */
        val supported: Boolean,
        val primaryFingerprintHex: String,
        val primaryKeyId: Long,
        /** A verified 0x20 revocation is in effect now. */
        val primaryRevoked: Boolean,
        val subkeys: List<SubkeyState>,
        /** Raw User ID strings (UTF-8, lenient) that carry a verified
         *  self-certification and no revocation in effect now. */
        val certifiedUserIds: Set<String>,
        /** Primary expiry from its newest verified self-signature, epoch ms; null = none. */
        val primaryExpiresAtMs: Long? = null,
        /** 3.0.0 (5d-1): primary key creation time, epoch ms. */
        val primaryCreatedAtMs: Long = 0L,
        /** 3.0.0 (5d-1): every verified 0x1F direct-key signature. */
        val directKeySigs: List<SelfSig> = emptyList(),
        /** 3.0.0 (5d-1): every verified 0x20 revocation. */
        val primaryRevocations: List<Revocation> = emptyList(),
        /** 3.0.0 (5d-1): every User ID with at least one verified self-signature. */
        val userIds: List<UserIdState> = emptyList()
    ) {
        /** Subkey state by fingerprint (hex, any case). Key IDs are not used:
         *  a v3 key ID is attacker-choosable, fingerprints are not. */
        fun subkeyByFingerprint(fpHex: String): SubkeyState? =
            subkeys.firstOrNull { it.fingerprintHex.equals(fpHex, ignoreCase = true) }

        fun isPrimary(fpHex: String): Boolean = primaryFingerprintHex.equals(fpHex, ignoreCase = true)

        /** The primary is not revoked and not expired at [nowMs]. */
        fun isPrimaryUsable(nowMs: Long): Boolean =
            !primaryRevoked && (primaryExpiresAtMs == null || nowMs < primaryExpiresAtMs)

        /** May the key with fingerprint [fpHex] receive a message at [nowMs]? The
         *  primary must be usable; a subkey must also be bound, unrevoked and
         *  unexpired, and its key flags must allow encryption (3.0.0: a key
         *  flags subpacket without either encryption flag, including an empty
         *  one, rules the subkey out). Unsupported primaries are left to the
         *  caller. */
        fun isUsableEncryptionKey(fpHex: String, nowMs: Long): Boolean {
            if (!supported) return true
            if (!isPrimaryUsable(nowMs)) return false
            if (isPrimary(fpHex)) return flagsAllowEncryption(activePrimarySig(nowMs)?.keyFlags)
            val s = subkeyByFingerprint(fpHex) ?: return false
            return s.bound && !s.revoked && (s.expiresAtMs == null || nowMs < s.expiresAtMs) &&
                flagsAllowEncryption(s.keyFlags)
        }

        /**
         * 3.0.0 (5d-1): may the secret half of [fpHex] decrypt a message
         * addressed to it? Revocation and expiry do not matter here (old mail
         * must stay readable), but the key must be one the certificate marks
         * for encryption: a subkey needs a verified binding, and a key flags
         * subpacket that names neither encryption flag rules the key out. A
         * key with no key flags subpacket at all (older software) is allowed.
         * A subkey this parser could not read is left to the caller.
         */
        fun mayDecryptWith(fpHex: String): Boolean {
            if (!supported) return true
            if (isPrimary(fpHex)) {
                val newest = (directKeySigs + userIds.flatMap { it.certifications }).maxByOrNull { it.createdMs }
                return flagsAllowEncryption(newest?.keyFlags)
            }
            val s = subkeyByFingerprint(fpHex) ?: return true
            return s.bound && flagsAllowEncryption(s.keyFlags)
        }

        /** A key that may speak for the primary as a signer: the primary, or a
         *  bound, back-signed subkey. */
        fun isValidSignerKey(fpHex: String): Boolean {
            if (!supported) return true
            if (isPrimary(fpHex)) return true
            val s = subkeyByFingerprint(fpHex) ?: return false
            return s.bound && s.backSigned
        }

        /**
         * 3.0.0 (5d-1): the primary self-signature in force at [t]. Direct-key
         * signatures and the certification of every User ID not revoked at [t]
         * compete; the newest one that is alive at [t] wins. Null when none is
         * (the certificate is not valid at [t]).
         */
        fun activePrimarySig(t: Long): SelfSig? {
            val candidates = ArrayList<SelfSig>()
            activeAt(directKeySigs, t)?.let { candidates.add(it) }
            for (u in userIds) {
                if (u.revokedAt(t)) continue
                activeAt(u.certifications, t)?.let { candidates.add(it) }
            }
            return candidates.maxByOrNull { it.createdMs }
        }

        /**
         * 3.0.0 (5d-1): is [fpHex] a valid signer for a signature made at [t]?
         * The key and its primary must exist by [t]; a hard revocation of
         * either rules the key out at every time, a soft one from the moment
         * it was made; a self-signature must make the primary (and a subkey)
         * valid at [t], and the key flags and expiry come from that
         * self-signature; a signing subkey needs a back-signature alive at [t].
         */
        fun signerValidityAt(fpHex: String, t: Long): SignerValidity {
            if (!supported) return SignerValidity.VALID
            if (t < primaryCreatedAtMs) return SignerValidity.PREDATES_KEY
            val sub = if (isPrimary(fpHex)) null else (subkeyByFingerprint(fpHex) ?: return SignerValidity.UNBOUND)
            if (sub != null && t < sub.createdAtMs) return SignerValidity.PREDATES_KEY
            if (primaryRevocations.any { it.inEffectAt(t) }) return SignerValidity.REVOKED
            val primarySig = activePrimarySig(t) ?: return SignerValidity.NOT_VALID
            primarySig.keyExpiresAtMs?.let { if (t >= it) return SignerValidity.EXPIRED }
            if (sub == null) {
                return if (flagsAllowSigning(primarySig.keyFlags)) SignerValidity.VALID else SignerValidity.NOT_SIGNING
            }
            if (sub.revocations.any { it.inEffectAt(t) }) return SignerValidity.REVOKED
            if (sub.bindings.isEmpty()) return SignerValidity.UNBOUND
            val binding = activeAt(sub.bindings, t) ?: return SignerValidity.NOT_VALID
            binding.keyExpiresAtMs?.let { if (t >= it) return SignerValidity.EXPIRED }
            if (!flagsAllowSigning(binding.keyFlags)) return SignerValidity.NOT_SIGNING
            if (!binding.backSigned) return SignerValidity.UNBOUND
            binding.backSigExpiresAtMs?.let { if (t >= it) return SignerValidity.UNBOUND }
            return SignerValidity.VALID
        }
    }

    /**
     * The self-signature among [sigs] in force at [t]: the newest one made at
     * or before [t], which must still be alive then. When every one is newer
     * than [t] (a certificate re-signed later and exported with only its
     * newest self-signatures, as GnuPG's minimal export does), the oldest one
     * stands in for the period before it, as long as it has not expired by
     * [t]; signatures made before the key itself are caught separately.
     */
    private fun activeAt(sigs: List<SelfSig>, t: Long): SelfSig? {
        if (sigs.isEmpty()) return null
        val made = sigs.filter { it.createdMs <= t }
        if (made.isEmpty()) {
            val oldest = sigs.minBy { it.createdMs }
            return oldest.takeIf { it.sigExpiresAtMs == null || t < it.sigExpiresAtMs }
        }
        return made.maxBy { it.createdMs }.takeIf { it.aliveAt(t) }
    }

    /** Key flags allow signing: no key flags subpacket (older software) or the sign flag. */
    private fun flagsAllowSigning(flags: Int?): Boolean = flags == null || flags and 0x02 != 0

    /** Key flags allow encryption: no key flags subpacket, or either encryption flag. */
    private fun flagsAllowEncryption(flags: Int?): Boolean = flags == null || flags and 0x0C != 0

    // ── Packet model ──────────────────────────────────────────────────

    internal class Packet(val tag: Int, val body: ByteArray)

    /** Split binary OpenPGP data into packets. Stops at the first malformed
     *  or truncated header (the remainder is ignored, as BC would fail). */
    internal fun packets(raw: ByteArray): List<Packet> {
        val out = ArrayList<Packet>()
        var i = 0
        while (i < raw.size) {
            val c = raw[i++].toInt() and 0xFF
            if (c and 0x80 == 0) break
            val tag: Int
            val len: Int
            if (c and 0x40 != 0) {
                tag = c and 0x3F
                if (i >= raw.size) break
                val l0 = raw[i++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0
                    l0 < 224 -> {
                        if (i >= raw.size) break
                        ((l0 - 192) shl 8) + (raw[i++].toInt() and 0xFF) + 192
                    }
                    l0 == 255 -> {
                        if (i + 4 > raw.size) break
                        be32(raw, i).also { i += 4 }
                    }
                    else -> break // partial lengths never appear in a certificate
                }
            } else {
                tag = (c shr 2) and 0x0F
                len = when (c and 0x03) {
                    0 -> { if (i >= raw.size) break; raw[i++].toInt() and 0xFF }
                    1 -> {
                        if (i + 2 > raw.size) break
                        (((raw[i].toInt() and 0xFF) shl 8) or (raw[i + 1].toInt() and 0xFF)).also { i += 2 }
                    }
                    2 -> { if (i + 4 > raw.size) break; be32(raw, i).also { i += 4 } }
                    else -> break
                }
            }
            if (len < 0 || i + len > raw.size) break
            out.add(Packet(tag, raw.copyOfRange(i, i + len)))
            i += len
        }
        return out
    }

    /** New-format packet encoding (5-octet length form for anything large). */
    internal fun frame(tag: Int, body: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(body.size + 6)
        out.write(0xC0 or tag)
        val n = body.size
        when {
            n < 192 -> out.write(n)
            n < 8384 -> {
                val v = n - 192
                out.write((v shr 8) + 192); out.write(v and 0xFF)
            }
            else -> {
                out.write(255)
                out.write((n ushr 24) and 0xFF); out.write((n ushr 16) and 0xFF)
                out.write((n ushr 8) and 0xFF); out.write(n and 0xFF)
            }
        }
        out.write(body)
        return out.toByteArray()
    }

    private fun be32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    /** Packet types RFC 9580 defines (4.3), padding included. */
    private val KNOWN_PACKET_TAGS = (1..14).toSet() + (17..21)

    /** An unknown packet type in the critical range (0 to 39). */
    internal fun isCriticalUnknownTag(tag: Int) = tag < 40 && tag !in KNOWN_PACKET_TAGS

    internal fun isKeyTag(tag: Int) = tag == TAG_PUBLIC_KEY || tag == TAG_SECRET_KEY
    internal fun isSubkeyTag(tag: Int) = tag == TAG_PUBLIC_SUBKEY || tag == TAG_SECRET_SUBKEY

    // ── Key packet helpers ────────────────────────────────────────────

    /** A parsed public key packet body: version, algorithm, fingerprint, key id. */
    internal class KeyBody(val body: ByteArray) {
        val version: Int = body[0].toInt() and 0xFF
        val algorithm: Int = body[5].toInt() and 0xFF
        val fingerprint: ByteArray = computeFingerprint(body)
        val fingerprintHex: String = Hex.toHexString(fingerprint).uppercase()
        val keyId: Long = keyIdOf(version, fingerprint)

        /** The octets hashed for this key in a key signature (RFC 9580 5.2.4). */
        fun hashFraming(): ByteArray {
            val out = ByteArrayOutputStream(body.size + 5)
            when (version) {
                4 -> { out.write(0x99); out.write((body.size shr 8) and 0xFF); out.write(body.size and 0xFF) }
                5 -> { out.write(0x9A); write32(out, body.size) }
                6 -> { out.write(0x9B); write32(out, body.size) }
                else -> throw IllegalArgumentException("key version $version")
            }
            out.write(body)
            return out.toByteArray()
        }
    }

    private fun write32(out: ByteArrayOutputStream, n: Int) {
        out.write((n ushr 24) and 0xFF); out.write((n ushr 16) and 0xFF)
        out.write((n ushr 8) and 0xFF); out.write(n and 0xFF)
    }

    private fun computeFingerprint(body: ByteArray): ByteArray = when (body[0].toInt() and 0xFF) {
        4 -> MessageDigest.getInstance("SHA-1").run {
            update(0x99.toByte()); update((body.size shr 8).toByte()); update(body.size.toByte()); digest(body)
        }
        5 -> MessageDigest.getInstance("SHA-256").run {
            update(0x9A.toByte()); update(be32Bytes(body.size)); digest(body)
        }
        6 -> MessageDigest.getInstance("SHA-256").run {
            update(0x9B.toByte()); update(be32Bytes(body.size)); digest(body)
        }
        else -> throw IllegalArgumentException("key version")
    }

    private fun be32Bytes(n: Int) = byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())

    private fun keyIdOf(version: Int, fp: ByteArray): Long {
        // v4: low 64 bits; v5 / v6: high 64 bits.
        val off = if (version == 4) fp.size - 8 else 0
        var id = 0L
        for (k in 0 until 8) id = (id shl 8) or (fp[off + k].toLong() and 0xFF)
        return id
    }

    /**
     * The public part of a key packet body. A public packet is returned as is.
     * A secret packet is cut after its public material: v5 / v6 carry a
     * material length; for v4 Bouncy Castle parses the packet and re-encodes
     * its public half. Null when the body cannot be reduced.
     */
    internal fun publicPart(tag: Int, body: ByteArray): ByteArray? {
        if (tag == TAG_PUBLIC_KEY || tag == TAG_PUBLIC_SUBKEY) return body
        if (body.size < 10) return null
        return when (body[0].toInt() and 0xFF) {
            5, 6 -> {
                val matLen = be32(body, 6)
                if (matLen < 0 || 10 + matLen > body.size) null else body.copyOfRange(0, 10 + matLen)
            }
            // v4 ML-KEM-768 + X25519 (algo 35): fixed 1216-octet material with
            // no length field, and Bouncy Castle cannot parse the packet.
            4 -> if ((body[5].toInt() and 0xFF) == 35) {
                if (body.size < 6 + 1216) null else body.copyOfRange(0, 6 + 1216)
            } else runCatching {
                val ring = org.bouncycastle.openpgp.PGPSecretKeyRing(
                    frame(TAG_SECRET_KEY, body), BcKeyFingerprintCalculator()
                )
                ring.secretKey.publicKey.publicKeyPacket.encodedContents
            }.getOrNull()
            else -> null
        }
    }

    // ── Signature helpers ─────────────────────────────────────────────

    /** The fields of a v4 / v5 / v6 signature packet this file needs. */
    internal class SigBody(val body: ByteArray) {
        val version: Int = body[0].toInt() and 0xFF
        val type: Int
        val pkAlg: Int
        val hashAlg: Int
        val hashed: ByteArray
        val unhashed: ByteArray
        /** v6 salt, empty otherwise. */
        val salt: ByteArray
        /** Signature material after left16 (and the v6 salt). */
        val material: ByteArray

        init {
            require(version == 4 || version == 5 || version == 6) { "sig version $version" }
            type = body[1].toInt() and 0xFF
            pkAlg = body[2].toInt() and 0xFF
            hashAlg = body[3].toInt() and 0xFF
            var p = 4
            val hLen: Int
            if (version == 6) { hLen = be32(body, p); p += 4 } else {
                hLen = ((body[p].toInt() and 0xFF) shl 8) or (body[p + 1].toInt() and 0xFF); p += 2
            }
            require(hLen >= 0 && p + hLen <= body.size)
            hashed = body.copyOfRange(p, p + hLen); p += hLen
            val uLen: Int
            if (version == 6) { uLen = be32(body, p); p += 4 } else {
                uLen = ((body[p].toInt() and 0xFF) shl 8) or (body[p + 1].toInt() and 0xFF); p += 2
            }
            require(uLen >= 0 && p + uLen <= body.size)
            unhashed = body.copyOfRange(p, p + uLen); p += uLen
            p += 2 // left16
            if (version == 6) {
                val sl = body[p].toInt() and 0xFF; p += 1
                require(p + sl <= body.size)
                salt = body.copyOfRange(p, p + sl); p += sl
            } else {
                salt = ByteArray(0)
            }
            require(p <= body.size)
            material = body.copyOfRange(p, body.size)
        }

        /** Issuer fingerprint (subpacket 33) or key id (16), from either area. */
        fun issuerFingerprint(): ByteArray? =
            subpackets(hashed).firstOrNull { it.first == SP_ISSUER_FINGERPRINT }?.second?.let { it.copyOfRange(1, it.size) }
                ?: subpackets(unhashed).firstOrNull { it.first == SP_ISSUER_FINGERPRINT }?.second?.let { it.copyOfRange(1, it.size) }

        fun issuerKeyId(): Long? {
            val raw = subpackets(hashed).firstOrNull { it.first == SP_ISSUER_KEY_ID }?.second
                ?: subpackets(unhashed).firstOrNull { it.first == SP_ISSUER_KEY_ID }?.second
                ?: return null
            if (raw.size != 8) return null
            var id = 0L
            for (b in raw) id = (id shl 8) or (b.toLong() and 0xFF)
            return id
        }

        /** Key flags (hashed subpacket 27), first octet; 0 for an empty
         *  subpacket (3.0.0: an empty one grants nothing), null when absent. */
        val keyFlags: Int? = subpackets(hashed).firstOrNull { it.first == SP_KEY_FLAGS }?.second
            ?.let { if (it.isEmpty()) 0 else it[0].toInt() and 0xFF }

        /** Signature expiration (hashed subpacket 3), seconds after creation; null for none or 0. */
        val sigExpirySeconds: Long? = subpackets(hashed).firstOrNull { it.first == SP_SIG_EXPIRATION }?.second
            ?.takeIf { it.size == 4 }?.let { be32(it, 0).toLong() and 0xFFFFFFFFL }?.takeIf { it > 0 }

        /** Revocation reason code (hashed subpacket 29), or null. */
        val revocationReason: Int? = subpackets(hashed).firstOrNull { it.first == SP_REVOCATION_REASON }?.second
            ?.takeIf { it.isNotEmpty() }?.let { it[0].toInt() and 0xFF }

        /** 3.0.0 (5d-1): a hashed subpacket is marked critical but not
         *  understood here (an unknown type, or any notation). */
        val hasCriticalUnknown: Boolean = criticalHashedTypes(hashed).any { it == SP_NOTATION || it !in KNOWN_SUBPACKETS }

        /** Key expiration (hashed subpacket 9), seconds after key creation, or null. */
        val keyExpirySeconds: Long? = subpackets(hashed).firstOrNull { it.first == SP_KEY_EXPIRATION }?.second
            ?.takeIf { it.size == 4 }?.let { be32(it, 0).toLong() and 0xFFFFFFFFL }

        /** Every issuer fingerprint (subpacket 33) in either area. */
        fun allIssuerFingerprints(): List<ByteArray> =
            (subpackets(hashed) + subpackets(unhashed)).filter { it.first == SP_ISSUER_FINGERPRINT && it.second.size > 1 }
                .map { it.second.copyOfRange(1, it.second.size) }

        /** Every issuer key id (subpacket 16) in either area. */
        fun allIssuerKeyIds(): List<Long> =
            (subpackets(hashed) + subpackets(unhashed)).filter { it.first == SP_ISSUER_KEY_ID && it.second.size == 8 }
                .map { raw -> var id = 0L; for (b in raw.second) id = (id shl 8) or (b.toLong() and 0xFF); id }

        /** Signature creation time (hashed subpacket 2), in ms, or null. */
        val createdMs: Long? = subpackets(hashed).firstOrNull { it.first == SP_CREATION_TIME }?.second
            ?.takeIf { it.size == 4 }?.let { (be32(it, 0).toLong() and 0xFFFFFFFFL) * 1000L }

        /** Embedded signatures (subpacket 32) from either area. GnuPG places
         *  the 0x19 back-signature in the unhashed area; that is safe because
         *  the back-signature authenticates itself (it is verified under the
         *  subkey over the same primary || subkey octets). */
        fun embeddedSignatures(): List<ByteArray> =
            (subpackets(hashed) + subpackets(unhashed)).filter { it.first == SP_EMBEDDED_SIGNATURE }.map { it.second }
    }

    /** Subpacket (type without the critical bit, body) pairs. Malformed tails are dropped. */
    private fun subpackets(area: ByteArray): List<Pair<Int, ByteArray>> =
        rawSubpackets(area).map { (type, body) -> (type and 0x7F) to body }

    /** Types (without the flag) of the subpackets in [area] that carry the critical bit. */
    internal fun criticalHashedTypes(area: ByteArray): List<Int> =
        rawSubpackets(area).filter { it.first and 0x80 != 0 }.map { it.first and 0x7F }

    /** Subpacket (type octet including the critical bit, body) pairs. Malformed tails are dropped. */
    private fun rawSubpackets(area: ByteArray): List<Pair<Int, ByteArray>> {
        val out = ArrayList<Pair<Int, ByteArray>>()
        var i = 0
        while (i < area.size) {
            val l0 = area[i++].toInt() and 0xFF
            val len: Int = when {
                l0 < 192 -> l0
                l0 < 255 -> {
                    if (i >= area.size) return out
                    ((l0 - 192) shl 8) + (area[i++].toInt() and 0xFF) + 192
                }
                else -> {
                    if (i + 4 > area.size) return out
                    be32(area, i).also { i += 4 }
                }
            }
            if (len < 1 || i + len > area.size) return out
            val type = area[i].toInt() and 0xFF
            out.add(type to area.copyOfRange(i + 1, i + len))
            i += len
        }
        return out
    }

    /**
     * Was [sig] (claimed to be) issued by [key]? True when ANY issuer
     * indicator, fingerprint or key id, in either subpacket area names [key],
     * or when there is none at all. A signature treated as third-party must
     * therefore name some other key everywhere, which also keeps Bouncy
     * Castle (which reads the issuer key id) from ever taking it for a
     * self-signature later.
     */
    internal fun issuedBy(sig: SigBody, key: KeyBody): Boolean {
        val fps = sig.allIssuerFingerprints()
        val ids = sig.allIssuerKeyIds()
        if (fps.isEmpty() && ids.isEmpty()) return true
        return fps.any { it.contentEquals(key.fingerprint) } || ids.any { it == key.keyId }
    }

    /** Bounded signature verification (see MAX_VERIFICATIONS / MAX_HASHED_BYTES). */
    private class Budget(var remaining: Int = MAX_VERIFICATIONS, var bytesLeft: Long = MAX_HASHED_BYTES) {
        fun verify(sig: SigBody, signer: KeyBody, prefix: ByteArray): Boolean {
            val cost = prefix.size.toLong() + sig.hashed.size
            if (remaining <= 0 || cost > bytesLeft) return false
            remaining--
            bytesLeft -= cost
            return CertificateBindings.verify(sig, signer, prefix)
        }
    }

    /** Indexes of the self-signatures in [sigs] worth checking: those that
     *  claim [primary] as issuer, newest first, at most MAX_SELF_SIGS_PER_COMPONENT. */
    private fun selfSigsToCheck(sigs: List<ByteArray>, primary: KeyBody): Set<Int> =
        sigs.withIndex().mapNotNull { (i, b) ->
            sigOrNull(b)?.takeIf { issuedBy(it, primary) }?.let { i to (it.createdMs ?: 0L) }
        }.sortedByDescending { it.second }.take(MAX_SELF_SIGS_PER_COMPONENT).map { it.first }.toSet()

    private fun keyCreatedMs(k: KeyBody): Long = (be32(k.body, 1).toLong() and 0xFFFFFFFFL) * 1000L

    private fun expiryOf(created: Long, sig: SigBody?): Long? =
        sig?.keyExpirySeconds?.takeIf { it > 0 }?.let { created + it * 1000L }

    /**
     * Verify [sig] as made by [signer] over [hashPrefix] (the framed key /
     * identity octets that precede the signature trailer). False on any
     * failure, including an unparseable signature or a hash / version mismatch.
     */
    internal fun verify(sig: SigBody, signer: KeyBody, hashPrefix: ByteArray): Boolean = runCatching {
        if (sig.pkAlg != signer.algorithm) return false
        // Signature version must match the key version (v6 keys make v6
        // signatures; v4 keys v4; LibrePGP v5 keys v5 or v4).
        when (signer.version) {
            6 -> if (sig.version != 6) return false
            4 -> if (sig.version != 4) return false
            5 -> if (sig.version != 5 && sig.version != 4) return false
        }
        // 3.0.0 (5d-1): a self-signature needs a hashed creation time, and a
        // critical subpacket it does not understand invalidates it (RFC 9580
        // 5.2.3.7, 5.2.3.11).
        if (sig.createdMs == null) return false
        if (sig.hasCriticalUnknown) return false
        if (!SignaturePolicy.isAcceptableCertificationDigest(sig.hashAlg, sig.createdMs)) return false
        val composite = CompositeSignSuite.forAlgId(signer.algorithm)
        if (composite != null) {
            if (sig.version != 6) return false
            val matLen = be32(signer.body, 6)
            val pub = signer.body.copyOfRange(10, 10 + matLen)
            val digest = CompositeSigHash.v6DocumentDigest(
                hashAlgorithm = sig.hashAlg,
                salt = sig.salt,
                data = hashPrefix,
                signatureType = sig.type,
                publicKeyAlgorithm = sig.pkAlg,
                hashedSubpacketBody = sig.hashed
            )
            return CompositeSigVerifier.verify(composite, pub, sig.material, digest)
        }
        val bcSig = bcSignature(sig.body) ?: return false
        val bcKey = bcKey(signer.body) ?: return false
        bcSig.init(BcPGPContentVerifierBuilderProvider(), bcKey)
        bcSig.update(hashPrefix)
        bcSig.verify()
    }.getOrDefault(false)

    private fun bcSignature(body: ByteArray): PGPSignature? = runCatching {
        val obj = BcPGPObjectFactory(frame(TAG_SIGNATURE, body)).nextObject()
        (obj as? PGPSignatureList)?.takeIf { it.size() == 1 }?.get(0)
    }.getOrNull()

    private fun bcKey(body: ByteArray): PGPPublicKey? = runCatching {
        PGPPublicKeyRing(frame(TAG_PUBLIC_KEY, body), BcKeyFingerprintCalculator()).publicKey
    }.getOrNull()

    private fun idFraming(tag: Int, body: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(body.size + 5)
        out.write(if (tag == TAG_USER_ATTRIBUTE) 0xD1 else 0xB4)
        write32(out, body.size)
        out.write(body)
        return out.toByteArray()
    }

    // ── Certificate walk ──────────────────────────────────────────────

    /** One component of a certificate with the signature packets that follow it. */
    internal class Component(
        val tag: Int,
        val body: ByteArray,
        val sigs: MutableList<ByteArray> = ArrayList(),
        val other: MutableList<Packet> = ArrayList()
    )

    internal class Parsed(val primaryTag: Int, val primary: KeyBody, val primarySigs: List<ByteArray>,
                         val primaryOther: List<Packet>, val components: List<Component>)

    internal fun parse(raw: ByteArray): Parsed? {
        if (raw.isEmpty()) return null
        val pkts = packets(raw)
        val first = pkts.firstOrNull() ?: return null
        if (!isKeyTag(first.tag)) return null
        val primaryPub = publicPart(first.tag, first.body) ?: return null
        val primary = runCatching { KeyBody(primaryPub) }.getOrNull() ?: return null
        val primarySigs = ArrayList<ByteArray>()
        val primaryOther = ArrayList<Packet>()
        val comps = ArrayList<Component>()
        var current: Component? = null
        for (p in pkts.drop(1)) {
            when {
                isKeyTag(p.tag) -> break // a second certificate starts; analyse the first only
                p.tag == TAG_USER_ID || p.tag == TAG_USER_ATTRIBUTE || isSubkeyTag(p.tag) -> {
                    current = Component(p.tag, p.body).also { comps.add(it) }
                }
                p.tag == TAG_SIGNATURE -> (current?.sigs ?: primarySigs).add(p.body)
                p.tag == TAG_TRUST -> Unit // local trust packets are never kept
                else -> (current?.other ?: primaryOther).add(p)
            }
        }
        return Parsed(first.tag, primary, primarySigs, primaryOther, comps)
    }

    internal fun sigOrNull(body: ByteArray): SigBody? = runCatching { SigBody(body) }.getOrNull()

    /** Analyse the certificate in [raw] (binary, public or secret). Null when
     *  the first packet is not a parseable primary key. */
    fun analyze(raw: ByteArray): Report? {
        val k = cacheKey(raw)
        synchronized(reportCache) { if (reportCache.containsKey(k)) return reportCache[k] }
        val r = analyzeUncached(raw)
        synchronized(reportCache) { reportCache[k] = r }
        return r
    }

    private fun analyzeUncached(raw: ByteArray): Report? {
        val parsed = parse(raw) ?: return null
        val primary = parsed.primary
        val supported = primary.algorithm in VERIFIABLE_ALGORITHMS
        val primaryFrame = runCatching { primary.hashFraming() }.getOrNull() ?: return null
        val primaryCreated = keyCreatedMs(primary)
        if (!supported) {
            return Report(
                false, primary.fingerprintHex, primary.keyId, false, emptyList(), emptySet(),
                primaryCreatedAtMs = primaryCreated
            )
        }
        val now = System.currentTimeMillis()
        val keyBudget = Budget()
        val idBudget = Budget()
        // Newest verified self-signature over the primary (direct-key or a User
        // ID certification): where the primary's expiry is read from.
        var newestSelf: SigBody? = null
        fun considerSelf(s: SigBody) {
            val cur = newestSelf
            if (cur == null || (s.createdMs ?: 0L) >= (cur.createdMs ?: 0L)) newestSelf = s
        }
        val directKeySigs = ArrayList<SelfSig>()
        val primaryRevocations = ArrayList<Revocation>()
        val primaryCheck = selfSigsToCheck(parsed.primarySigs, primary)
        for ((i, b) in parsed.primarySigs.withIndex()) {
            if (i !in primaryCheck) continue
            val s = sigOrNull(b) ?: continue
            when (s.type) {
                SIG_KEY_REVOCATION -> if (keyBudget.verify(s, primary, primaryFrame)) primaryRevocations.add(revocationOf(s))
                SIG_DIRECT_KEY -> if (keyBudget.verify(s, primary, primaryFrame)) {
                    considerSelf(s)
                    directKeySigs.add(selfSigOf(s, primaryCreated))
                }
            }
        }
        val subkeys = ArrayList<SubkeyState>()
        val uids = LinkedHashSet<String>()
        val userIds = ArrayList<UserIdState>()
        for (c in parsed.components) {
            if (isSubkeyTag(c.tag)) {
                val pub = publicPart(c.tag, c.body) ?: continue
                val sub = runCatching { KeyBody(pub) }.getOrNull() ?: continue
                val prefix = primaryFrame + (runCatching { sub.hashFraming() }.getOrNull() ?: continue)
                val subCreated = keyCreatedMs(sub)
                var backSigned = false
                var newestBinding: SigBody? = null
                val bindings = ArrayList<SelfSig>()
                val revocations = ArrayList<Revocation>()
                val check = selfSigsToCheck(c.sigs, primary)
                for ((i, b) in c.sigs.withIndex()) {
                    if (i !in check) continue
                    val s = sigOrNull(b) ?: continue
                    when (s.type) {
                        SIG_SUBKEY_BINDING -> if (keyBudget.verify(s, primary, prefix)) {
                            val nb = newestBinding
                            if (nb == null || (s.createdMs ?: 0L) >= (nb.createdMs ?: 0L)) newestBinding = s
                            // The back-signature that verifies; when several do, the
                            // one that stays alive longest.
                            val back = s.embeddedSignatures().mapNotNull { e ->
                                sigOrNull(e)?.takeIf { it.type == SIG_PRIMARY_BINDING && keyBudget.verify(it, sub, prefix) }
                            }.maxByOrNull { sigExpiresAt(it) ?: Long.MAX_VALUE }
                            if (back != null) backSigned = true
                            bindings.add(
                                selfSigOf(s, subCreated).copy(
                                    backSigned = back != null,
                                    backSigExpiresAtMs = back?.let { sigExpiresAt(it) }
                                )
                            )
                        }
                        SIG_SUBKEY_REVOCATION -> if (keyBudget.verify(s, primary, prefix)) revocations.add(revocationOf(s))
                    }
                }
                subkeys.add(
                    SubkeyState(
                        sub.fingerprintHex, sub.keyId, sub.algorithm, bindings.isNotEmpty(), backSigned,
                        revoked = revocations.any { it.inEffectAt(now) },
                        expiresAtMs = expiryOf(subCreated, newestBinding),
                        keyFlags = newestBinding?.keyFlags,
                        createdAtMs = subCreated,
                        version = sub.version,
                        publicBody = pub,
                        bindings = bindings,
                        revocations = revocations
                    )
                )
            } else {
                val prefix = primaryFrame + idFraming(c.tag, c.body)
                val certifications = ArrayList<SelfSig>()
                val revocations = ArrayList<Revocation>()
                val check = selfSigsToCheck(c.sigs, primary)
                for ((i, b) in c.sigs.withIndex()) {
                    if (i !in check) continue
                    val s = sigOrNull(b) ?: continue
                    when (s.type) {
                        in SIG_CERT_GENERIC..SIG_CERT_POSITIVE -> if (idBudget.verify(s, primary, prefix)) {
                            considerSelf(s)
                            certifications.add(selfSigOf(s, primaryCreated))
                        }
                        SIG_CERT_REVOCATION -> if (idBudget.verify(s, primary, prefix)) revocations.add(revocationOf(s))
                    }
                }
                if (c.tag != TAG_USER_ID || certifications.isEmpty()) continue
                val state = UserIdState(String(c.body, Charsets.UTF_8), certifications, revocations)
                userIds.add(state)
                if (!state.revokedAt(now)) uids.add(state.userId)
            }
        }
        return Report(
            true, primary.fingerprintHex, primary.keyId,
            primaryRevoked = primaryRevocations.any { it.inEffectAt(now) },
            subkeys = subkeys,
            certifiedUserIds = uids,
            primaryExpiresAtMs = expiryOf(primaryCreated, newestSelf),
            primaryCreatedAtMs = primaryCreated,
            directKeySigs = directKeySigs,
            primaryRevocations = primaryRevocations,
            userIds = userIds
        )
    }

    /** When [s] itself expires (signature expiration subpacket), epoch ms, or null. */
    private fun sigExpiresAt(s: SigBody): Long? {
        val created = s.createdMs ?: return null
        return s.sigExpirySeconds?.let { created + it * 1000L }
    }

    /** A verified self-signature over a key created at [keyCreated], as a [SelfSig]. */
    private fun selfSigOf(s: SigBody, keyCreated: Long): SelfSig = SelfSig(
        createdMs = s.createdMs ?: 0L,
        sigExpiresAtMs = sigExpiresAt(s),
        keyExpiresAtMs = expiryOf(keyCreated, s),
        keyFlags = s.keyFlags
    )

    private fun revocationOf(s: SigBody): Revocation =
        Revocation(createdMs = s.createdMs ?: 0L, sigExpiresAtMs = sigExpiresAt(s), reason = s.revocationReason)

    /**
     * The certificate in [raw] with every unbound component and every failing
     * primary-issued signature removed (see header). A second certificate
     * concatenated after the first is dropped. When the primary cannot be
     * evaluated at all the input is returned unchanged.
     */
    fun sanitize(raw: ByteArray): ByteArray {
        val parsed = parse(raw) ?: return raw
        // 3.0.0 (5d-1): a packet of an unknown type in the critical range
        // (below 40, RFC 9580 4.3) makes the certificate unreadable; nothing
        // of it is kept. Unknown non-critical packets are carried along.
        if ((parsed.primaryOther + parsed.components.flatMap { it.other }).any { isCriticalUnknownTag(it.tag) }) {
            return ByteArray(0)
        }
        val primary = parsed.primary
        if (primary.algorithm !in VERIFIABLE_ALGORITHMS) return raw
        val primaryFrame = runCatching { primary.hashFraming() }.getOrNull() ?: return raw
        val keyBudget = Budget()
        val idBudget = Budget()
        val out = ByteArrayOutputStream(raw.size)
        out.write(frame(parsed.primaryTag, packets(raw).first().body))
        // Direct-key signatures and key revocations: only those the primary made and that verify.
        val primaryCheck = selfSigsToCheck(parsed.primarySigs, primary)
        for ((i, b) in parsed.primarySigs.withIndex()) {
            if (i !in primaryCheck) continue
            val s = sigOrNull(b) ?: continue
            if ((s.type == SIG_DIRECT_KEY || s.type == SIG_KEY_REVOCATION) &&
                keyBudget.verify(s, primary, primaryFrame)
            ) out.write(frame(TAG_SIGNATURE, b))
        }
        for (p in parsed.primaryOther) out.write(frame(p.tag, p.body))
        for (c in parsed.components) {
            if (isSubkeyTag(c.tag)) {
                val pub = publicPart(c.tag, c.body)
                val sub = pub?.let { runCatching { KeyBody(it) }.getOrNull() }
                val subFrame = sub?.let { runCatching { it.hashFraming() }.getOrNull() }
                if (sub == null || subFrame == null) {
                    // A PUBLIC subkey packet this parser cannot read (a v3 key,
                    // whose key id an attacker can choose, or a truncated one)
                    // is dropped. A SECRET subkey packet is the user's own
                    // material, so it is kept verbatim rather than destroyed;
                    // analyze() does not list it, so no selection accepts it.
                    if (c.tag == TAG_PUBLIC_SUBKEY) continue
                    out.write(frame(c.tag, c.body))
                    c.sigs.forEach { out.write(frame(TAG_SIGNATURE, it)) }
                    c.other.forEach { out.write(frame(it.tag, it.body)) }
                    continue
                }
                // 3.0.0 (5d-1): a public subkey of a classical algorithm whose
                // material Bouncy Castle cannot read (an unknown curve with an
                // opaque encoding, say) is skipped rather than making the whole
                // certificate unreadable. Algorithms the app reads itself
                // (composite ML-KEM and ML-DSA) are not in the set and stay.
                if (c.tag == TAG_PUBLIC_SUBKEY && sub.algorithm in BC_CLASSICAL_ALGORITHMS && bcKey(pub) == null) continue
                val prefix = primaryFrame + subFrame
                val check = selfSigsToCheck(c.sigs, primary)
                val keep = c.sigs.filterIndexed { i, b ->
                    if (i !in check) return@filterIndexed false
                    val s = sigOrNull(b) ?: return@filterIndexed false
                    (s.type == SIG_SUBKEY_BINDING || s.type == SIG_SUBKEY_REVOCATION) &&
                        keyBudget.verify(s, primary, prefix)
                }
                if (keep.none { sigOrNull(it)?.type == SIG_SUBKEY_BINDING }) continue
                out.write(frame(c.tag, c.body))
                keep.forEach { out.write(frame(TAG_SIGNATURE, it)) }
                c.other.forEach { out.write(frame(it.tag, it.body)) }
            } else {
                val prefix = primaryFrame + idFraming(c.tag, c.body)
                val keep = ArrayList<ByteArray>()
                var certified = false
                val check = selfSigsToCheck(c.sigs, primary)
                for ((i, b) in c.sigs.withIndex()) {
                    val s = sigOrNull(b) ?: continue
                    val self = issuedBy(s, primary)
                    when {
                        s.type in SIG_CERT_GENERIC..SIG_CERT_POSITIVE && self ->
                            if (i in check && idBudget.verify(s, primary, prefix)) { keep.add(b); certified = true }
                        s.type == SIG_CERT_REVOCATION && self ->
                            if (i in check && idBudget.verify(s, primary, prefix)) keep.add(b)
                        // Third-party certification or revocation: cannot be
                        // checked here and carries no authority over the
                        // certificate's own capabilities; kept for display.
                        // 3.0.0 (5d-1): unless Bouncy Castle cannot read it (an
                        // unknown public-key algorithm, say), which would make
                        // the whole certificate unreadable; it is dropped.
                        !self && (s.type in SIG_CERT_GENERIC..SIG_CERT_POSITIVE || s.type == SIG_CERT_REVOCATION) ->
                            if (bcSignature(b) != null) keep.add(b)
                    }
                }
                if (!certified) continue
                out.write(frame(c.tag, c.body))
                keep.forEach { out.write(frame(TAG_SIGNATURE, it)) }
                c.other.forEach { out.write(frame(it.tag, it.body)) }
            }
        }
        return out.toByteArray()
    }

    // ── Lookup filtering (4.6.0 item 17.8) ────────────────────────────

    /** Split binary data holding several transferable keys into one per key. */
    fun splitCertificates(raw: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        var cur: ByteArrayOutputStream? = null
        for (p in packets(raw)) {
            if (isKeyTag(p.tag)) {
                cur?.let { out.add(it.toByteArray()) }
                cur = ByteArrayOutputStream()
            }
            cur?.write(frame(p.tag, p.body))
        }
        cur?.let { out.add(it.toByteArray()) }
        return out
    }

    /**
     * 3.0.0 (5d-1): primary fingerprints (hex, uppercase) of the certificates
     * in [raw] (binary) that carry a packet of an unknown type in the critical
     * range. Such a certificate must be rejected as a whole; Bouncy Castle's
     * object factory would otherwise drop the packet silently.
     */
    fun certificatesWithCriticalUnknownPackets(raw: ByteArray): Set<String> =
        splitCertificates(raw).mapNotNull { cert ->
            if (packets(cert).none { isCriticalUnknownTag(it.tag) }) return@mapNotNull null
            parse(cert)?.primary?.fingerprintHex
        }.toSet()

    /**
     * 3.0.0 (5d-1): a transferable secret key whose primary is a Public-Key
     * packet while its subkeys are Secret-Subkey packets (the primary secret
     * kept offline, RFC 9580 10.2 allows the mix) is rewritten so the primary
     * becomes a GNU "no private key" stub, the form Bouncy Castle reads as a
     * secret key ring whose primary cannot be used. Every other certificate
     * in [raw] (binary, possibly several) is passed through unchanged, and the
     * input itself is returned when nothing needed rewriting.
     */
    fun stubStrippedPrimary(raw: ByteArray): ByteArray {
        val certs = splitCertificates(raw)
        if (certs.none { needsStub(it) }) return raw
        val out = ByteArrayOutputStream(raw.size + 32)
        for (cert in certs) {
            if (!needsStub(cert)) { out.write(cert); continue }
            val pkts = packets(cert)
            val body = pkts.first().body
            // S2K usage 254, no cipher, GNU extension (type 101, mode 1). v6
            // frames the fields with a count octet and an S2K length octet.
            val stub = when (body[0].toInt() and 0xFF) {
                6 -> byteArrayOf(0xFE.toByte(), 8, 0, 6, 101, 0, 'G'.code.toByte(), 'N'.code.toByte(), 'U'.code.toByte(), 1)
                else -> byteArrayOf(0xFE.toByte(), 0, 101, 0, 'G'.code.toByte(), 'N'.code.toByte(), 'U'.code.toByte(), 1)
            }
            out.write(frame(TAG_SECRET_KEY, body + stub))
            for (p in pkts.drop(1)) out.write(frame(p.tag, p.body))
        }
        return out.toByteArray()
    }

    /** A v4 or v6 certificate with a public primary and at least one secret subkey. */
    private fun needsStub(cert: ByteArray): Boolean {
        val pkts = packets(cert)
        val first = pkts.firstOrNull() ?: return false
        if (first.tag != TAG_PUBLIC_KEY || first.body.isEmpty()) return false
        val v = first.body[0].toInt() and 0xFF
        return (v == 4 || v == 6) && pkts.any { it.tag == TAG_SECRET_SUBKEY }
    }

    /** The bare address in a User ID ("Name <a@b>" or "a@b"), ASCII-lowercased. */
    fun mailboxOf(userId: String): String {
        val s = if (userId.contains('<')) userId.substringAfterLast('<').substringBefore('>') else userId
        return asciiLower(s.trim())
    }

    /** Lowercase A to Z only, as GnuPG does for WKD and address matching. */
    fun asciiLower(s: String): String =
        buildString(s.length) { for (c in s) append(if (c in 'A'..'Z') (c + 32) else c) }

    /**
     * [raw] (one certificate) sanitized, keeping only the User IDs that
     * [keep] accepts (attributes are dropped). Null when no certified User ID
     * survives, or when the primary cannot be evaluated.
     */
    fun keepUserIds(raw: ByteArray, keep: (String) -> Boolean): ByteArray? {
        val clean = sanitized(raw)
        val parsed = parse(clean) ?: return null
        if (parsed.primary.algorithm !in VERIFIABLE_ALGORITHMS) return null
        val out = ByteArrayOutputStream()
        out.write(frame(parsed.primaryTag, packets(clean).first().body))
        parsed.primarySigs.forEach { out.write(frame(TAG_SIGNATURE, it)) }
        parsed.primaryOther.forEach { out.write(frame(it.tag, it.body)) }
        var kept = 0
        for (c in parsed.components) {
            if (c.tag == TAG_USER_ATTRIBUTE) continue
            if (c.tag == TAG_USER_ID && !keep(String(c.body, Charsets.UTF_8))) continue
            if (c.tag == TAG_USER_ID) kept++
            out.write(frame(c.tag, c.body))
            c.sigs.forEach { out.write(frame(TAG_SIGNATURE, it)) }
            c.other.forEach { out.write(frame(it.tag, it.body)) }
        }
        return if (kept == 0) null else out.toByteArray()
    }

    // ── Cached views ──────────────────────────────────────────────────

    /** A Bouncy Castle ring rebuilt from the sanitized octets, with its report. */
    class Verified(val ring: PGPPublicKeyRing, val report: Report?)

    private const val CACHE_ENTRIES = 256
    private val cache = object : LinkedHashMap<String, Pair<ByteArray, Report?>>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Pair<ByteArray, Report?>>?) =
            size > CACHE_ENTRIES
    }

    private val reportCache = object : LinkedHashMap<String, Report?>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Report?>?) = size > CACHE_ENTRIES
    }

    private fun cacheKey(raw: ByteArray): String =
        Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(raw))

    /** [sanitize] and [analyze] together, memoised by content (loads repeat often). */
    fun sanitizeAndAnalyze(raw: ByteArray): Pair<ByteArray, Report?> {
        val k = cacheKey(raw)
        synchronized(cache) { cache[k]?.let { return it } }
        val clean = runCatching { sanitize(raw) }.getOrDefault(raw)
        val report = runCatching { analyze(clean) }.getOrNull()
        val v = clean to report
        synchronized(cache) { cache[k] = v }
        return v
    }

    /** Memoised [sanitize]. */
    fun sanitized(raw: ByteArray): ByteArray = sanitizeAndAnalyze(raw).first

    /**
     * The verified view of a Bouncy Castle ring: the ring rebuilt from its
     * sanitized encoding (so every self-signature Bouncy Castle later reads for
     * key flags, expiry or revocation has been checked) plus its report. When
     * the sanitized octets do not re-parse, the original ring is returned with
     * a null report and callers fall back to their unverified behaviour only
     * for that case.
     */
    fun verified(ring: PGPPublicKeyRing): Verified {
        val raw = ring.encoded
        val (clean, report) = sanitizeAndAnalyze(raw)
        if (clean.contentEquals(raw)) return Verified(ring, report)
        val rebuilt = runCatching { PGPPublicKeyRing(clean, BcKeyFingerprintCalculator()) }.getOrNull()
            ?: return Verified(ring, null)
        return Verified(rebuilt, report)
    }

    /** Convenience for Bouncy Castle rings: the report for [ring]'s encoding. */
    fun analyze(ring: PGPPublicKeyRing): Report? = sanitizeAndAnalyze(ring.encoded).second
}
