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
    private const val SP_KEY_EXPIRATION = 9
    private const val SP_KEY_FLAGS = 27
    private const val SP_ISSUER_KEY_ID = 16
    private const val SP_EMBEDDED_SIGNATURE = 32
    private const val SP_ISSUER_FINGERPRINT = 33

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

    data class SubkeyState(
        val fingerprintHex: String,
        val keyId: Long,
        val algorithm: Int,
        /** A 0x18 binding from the primary verifies. */
        val bound: Boolean,
        /** A verified 0x18 embeds a 0x19 back-signature that verifies under the subkey. */
        val backSigned: Boolean,
        /** A 0x28 revocation from the primary verifies. */
        val revoked: Boolean,
        /** Expiry from the newest verified 0x18, epoch ms; null = none. */
        val expiresAtMs: Long? = null,
        /** Key flags (first octet) from the newest verified 0x18; null = none. */
        val keyFlags: Int? = null,
        /** Key creation time, epoch ms. */
        val createdAtMs: Long = 0L,
        /** Key packet version (4, 5 or 6). */
        val version: Int = 4,
        /** The subkey's public key packet body, for callers that need to read
         *  its material (a LibrePGP composite's curve, say). */
        val publicBody: ByteArray = ByteArray(0)
    )

    data class Report(
        /** False when the primary's algorithm has no verifier here (see header). */
        val supported: Boolean,
        val primaryFingerprintHex: String,
        val primaryKeyId: Long,
        val primaryRevoked: Boolean,
        val subkeys: List<SubkeyState>,
        /** Raw User ID strings (UTF-8, lenient) that carry a verified
         *  self-certification and no verified revocation. */
        val certifiedUserIds: Set<String>,
        /** Primary expiry from its newest verified self-signature, epoch ms; null = none. */
        val primaryExpiresAtMs: Long? = null
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
         *  unexpired. Unsupported primaries are left to the caller. */
        fun isUsableEncryptionKey(fpHex: String, nowMs: Long): Boolean {
            if (!supported) return true
            if (!isPrimaryUsable(nowMs)) return false
            if (isPrimary(fpHex)) return true
            val s = subkeyByFingerprint(fpHex) ?: return false
            return s.bound && !s.revoked && (s.expiresAtMs == null || nowMs < s.expiresAtMs)
        }

        /** A key that may speak for the primary as a signer: the primary, or a
         *  bound, back-signed subkey. */
        fun isValidSignerKey(fpHex: String): Boolean {
            if (!supported) return true
            if (isPrimary(fpHex)) return true
            val s = subkeyByFingerprint(fpHex) ?: return false
            return s.bound && s.backSigned
        }
    }

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

        /** Key flags (hashed subpacket 27), first octet, or null. */
        val keyFlags: Int? = subpackets(hashed).firstOrNull { it.first == SP_KEY_FLAGS }?.second
            ?.takeIf { it.isNotEmpty() }?.let { it[0].toInt() and 0xFF }

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
    private fun subpackets(area: ByteArray): List<Pair<Int, ByteArray>> {
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
            val type = area[i].toInt() and 0x7F
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
        if (!supported) {
            return Report(false, primary.fingerprintHex, primary.keyId, false, emptyList(), emptySet())
        }
        val keyBudget = Budget()
        val idBudget = Budget()
        val primaryCreated = keyCreatedMs(primary)
        // Newest verified self-signature over the primary (direct-key or a User
        // ID certification): where the primary's expiry is read from.
        var newestSelf: SigBody? = null
        fun considerSelf(s: SigBody) {
            val cur = newestSelf
            if (cur == null || (s.createdMs ?: 0L) >= (cur.createdMs ?: 0L)) newestSelf = s
        }
        var primaryRevoked = false
        val primaryCheck = selfSigsToCheck(parsed.primarySigs, primary)
        for ((i, b) in parsed.primarySigs.withIndex()) {
            if (i !in primaryCheck) continue
            val s = sigOrNull(b) ?: continue
            when (s.type) {
                SIG_KEY_REVOCATION -> if (!primaryRevoked && keyBudget.verify(s, primary, primaryFrame)) primaryRevoked = true
                SIG_DIRECT_KEY -> if (keyBudget.verify(s, primary, primaryFrame)) considerSelf(s)
            }
        }
        val subkeys = ArrayList<SubkeyState>()
        val uids = LinkedHashSet<String>()
        for (c in parsed.components) {
            if (isSubkeyTag(c.tag)) {
                val pub = publicPart(c.tag, c.body) ?: continue
                val sub = runCatching { KeyBody(pub) }.getOrNull() ?: continue
                val prefix = primaryFrame + (runCatching { sub.hashFraming() }.getOrNull() ?: continue)
                var bound = false
                var backSigned = false
                var revoked = false
                var newestBinding: SigBody? = null
                val check = selfSigsToCheck(c.sigs, primary)
                for ((i, b) in c.sigs.withIndex()) {
                    if (i !in check) continue
                    val s = sigOrNull(b) ?: continue
                    when (s.type) {
                        SIG_SUBKEY_BINDING -> if (keyBudget.verify(s, primary, prefix)) {
                            bound = true
                            val nb = newestBinding
                            if (nb == null || (s.createdMs ?: 0L) >= (nb.createdMs ?: 0L)) newestBinding = s
                            if (!backSigned) backSigned = s.embeddedSignatures().any { e ->
                                val back = sigOrNull(e) ?: return@any false
                                back.type == SIG_PRIMARY_BINDING && keyBudget.verify(back, sub, prefix)
                            }
                        }
                        SIG_SUBKEY_REVOCATION -> if (!revoked && keyBudget.verify(s, primary, prefix)) revoked = true
                    }
                }
                subkeys.add(
                    SubkeyState(
                        sub.fingerprintHex, sub.keyId, sub.algorithm, bound, backSigned, revoked,
                        expiresAtMs = expiryOf(keyCreatedMs(sub), newestBinding),
                        keyFlags = newestBinding?.keyFlags,
                        createdAtMs = keyCreatedMs(sub),
                        version = sub.version,
                        publicBody = pub
                    )
                )
            } else {
                val prefix = primaryFrame + idFraming(c.tag, c.body)
                var certified = false
                var uidRevoked = false
                val check = selfSigsToCheck(c.sigs, primary)
                for ((i, b) in c.sigs.withIndex()) {
                    if (i !in check) continue
                    val s = sigOrNull(b) ?: continue
                    when (s.type) {
                        in SIG_CERT_GENERIC..SIG_CERT_POSITIVE -> if (idBudget.verify(s, primary, prefix)) {
                            certified = true
                            considerSelf(s)
                        }
                        SIG_CERT_REVOCATION -> if (!uidRevoked && idBudget.verify(s, primary, prefix)) uidRevoked = true
                    }
                }
                if (certified && !uidRevoked && c.tag == TAG_USER_ID) uids.add(String(c.body, Charsets.UTF_8))
            }
        }
        return Report(
            true, primary.fingerprintHex, primary.keyId, primaryRevoked, subkeys, uids,
            primaryExpiresAtMs = expiryOf(primaryCreated, newestSelf)
        )
    }

    /**
     * The certificate in [raw] with every unbound component and every failing
     * primary-issued signature removed (see header). A second certificate
     * concatenated after the first is dropped. When the primary cannot be
     * evaluated at all the input is returned unchanged.
     */
    fun sanitize(raw: ByteArray): ByteArray {
        val parsed = parse(raw) ?: return raw
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
                        !self && (s.type in SIG_CERT_GENERIC..SIG_CERT_POSITIVE || s.type == SIG_CERT_REVOCATION) ->
                            keep.add(b)
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
