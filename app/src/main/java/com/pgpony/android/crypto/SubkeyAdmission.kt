// SubkeyAdmission.kt
// PGPony Android 4.7.0 (item 40, #82): subkeys on a re-import of your own key
// pair, subkeys an import leaves out or cannot use, and where each subkey's
// secret is.
//
// For a key pair, CertificateMerge never takes a component the stored copy
// lacks (item 24: a key server must not add parts to your own key), and the
// item 22 graft only took a secret whose public part the stored certificate
// already bound. So re-importing your own secret export, with subkeys added in
// gpg since, added nothing, and Key Details listed fewer subkeys than gpg.
//
//   * newBoundSubkeys / withSubkeys: when the import carries secret material,
//     every subkey the stored certificate lacks and the primary verifiably
//     binds (CertificateBindings: a verified 0x18, and for a signing-capable
//     subkey a verified 0x19 back-signature in its newest binding) goes into
//     the certificate, in its sanitized form, so only verified signatures are
//     stored. A public-only import still adds nothing.
//   * graftSecrets: the secret part (or the stub gpg exported) of a subkey the
//     certificate binds goes into the stored secret ring. A secret already
//     held is never replaced; a stub held may be replaced by real material.
//   * issueOf / leftOut: why a subkey is dropped or not usable. The analyser
//     reports a SHA-1 binding made after the cutoff as simply unbound, so
//     weakHashOnly re-checks the raw signatures against SignaturePolicy.
//   * secretLocations / locationFor: on this device, a GNU 1001 stub, a card
//     (GNU 1002, or a card-backed key), or not present.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.io.ByteArrayOutputStream

object SubkeyAdmission {

    /** Why a subkey is left out of an import, or is not used. In the order
     *  checked: the first two make sanitize drop the subkey, the third keeps a
     *  signing subkey from ever signing, the last two only stop its use now. */
    enum class Issue {
        /** Bound (or back-signed) only by SHA-1 or RIPEMD-160 made after the
         *  key-signature cutoff (SignaturePolicy, Feb 2023). */
        WEAK_HASH,
        /** No binding signature from the primary verifies. */
        NO_VALID_BINDING,
        /** A signing-capable subkey whose binding has no valid back-signature. */
        NO_BACK_SIGNATURE,
        REVOKED,
        EXPIRED
    }

    /** Where a subkey's secret is. */
    enum class SecretLocation {
        ON_DEVICE,
        /** A GnuPG stub with no secret (GNU S2K mode 1001). */
        OFFLINE_STUB,
        /** A divert-to-card stub (mode 1002), or a card-backed key. */
        ON_CARD,
        NOT_PRESENT
    }

    /** A subkey of an incoming key that is left out or will not be used. */
    data class LeftOut(val subkey: CertificateBindings.SubkeyState, val issue: Issue)

    private const val TAG_SIGNATURE = 2
    private const val TAG_SECRET_KEY = 5
    private const val TAG_SECRET_SUBKEY = 7
    private const val TAG_TRUST = 12
    private const val TAG_PUBLIC_SUBKEY = 14
    private const val SIG_SUBKEY_BINDING = 0x18
    private const val SIG_PRIMARY_BINDING = 0x19
    private const val KEY_FLAG_SIGN = 0x02

    /** Bounds the raw re-check, as CertificateBindings bounds its own work. */
    private const val MAX_SIGS_CHECKED = 8

    /** Algorithms that can only sign, for a binding without key flags. */
    private val SIGN_ONLY_ALGORITHMS = setOf(17, 19, 22, 27, 28, 30, 31)

    // ── Decisions ─────────────────────────────────────────────────────

    /** The newest verified binding of [s], or null when none verifies. */
    fun newestBinding(s: CertificateBindings.SubkeyState): CertificateBindings.SelfSig? =
        s.bindings.maxByOrNull { it.createdMs }

    /** [s] may sign, by the key flags of its newest binding; without key flags,
     *  by an algorithm that can do nothing else. */
    fun isSigningCapable(s: CertificateBindings.SubkeyState): Boolean {
        val flags = newestBinding(s)?.keyFlags ?: s.keyFlags
        return if (flags != null) flags and KEY_FLAG_SIGN != 0 else s.algorithm in SIGN_ONLY_ALGORITHMS
    }

    /** The primary verifiably binds [s]: a verified binding, and for a
     *  signing-capable subkey a verified back-signature in the newest one. */
    fun isAdmissible(s: CertificateBindings.SubkeyState): Boolean =
        s.bound && (!isSigningCapable(s) || newestBinding(s)?.backSigned == true)

    /**
     * Why [s] is left out or not used at [nowMs], or null when it is usable.
     * [weakBinding] and [weakBackSignature] tell a weak-hash signature apart
     * from a missing or bad one; they are asked only when needed.
     */
    fun issueOf(
        s: CertificateBindings.SubkeyState,
        nowMs: Long,
        weakBinding: () -> Boolean = { false },
        weakBackSignature: () -> Boolean = { false }
    ): Issue? {
        if (!s.bound) return if (weakBinding()) Issue.WEAK_HASH else Issue.NO_VALID_BINDING
        if (isSigningCapable(s) && newestBinding(s)?.backSigned != true) {
            return if (weakBackSignature()) Issue.WEAK_HASH else Issue.NO_BACK_SIGNATURE
        }
        if (s.revoked) return Issue.REVOKED
        val expires = s.expiresAtMs
        if (expires != null && nowMs >= expires) return Issue.EXPIRED
        return null
    }

    /** [issueOf] for the subkey [fpHex] of the certificate [raw] (binary,
     *  public or secret), or null when it is usable or [raw] cannot be
     *  analysed (an unsupported primary vouches for nothing either way). */
    fun issueIn(raw: ByteArray, report: CertificateBindings.Report?, fpHex: String, nowMs: Long): Issue? {
        if (report == null || !report.supported) return null
        val s = report.subkeyByFingerprint(fpHex) ?: return null
        return issueOf(
            s, nowMs,
            weakBinding = { weakHashOnly(raw, s.fingerprintHex, backSignature = false) },
            weakBackSignature = { weakHashOnly(raw, s.fingerprintHex, backSignature = true) }
        )
    }

    /**
     * 4.8.1 (#120): the expiry Key Details shows for the subkey [fpHex]: the
     * one in its newest verified binding, which is what [issueOf] reads, or
     * [fallback] when [report] cannot speak for the subkey (an unsupported
     * primary, or no binding that verifies). The Bouncy Castle rows read the
     * expiry from a different rule (the latest expiry in any binding, verified
     * or not), so a subkey could be labelled expired under a date still to come.
     */
    fun shownExpiry(report: CertificateBindings.Report?, fpHex: String, fallback: Long?): Long? {
        if (report == null || !report.supported) return fallback
        val s = report.subkeyByFingerprint(fpHex)?.takeIf { it.bound } ?: return fallback
        return s.expiresAtMs
    }

    /** Every subkey of the incoming key [raw] (binary, public or secret) that
     *  an import leaves out or cannot use now, with the reason. */
    fun leftOut(raw: ByteArray, nowMs: Long = System.currentTimeMillis()): List<LeftOut> {
        val report = CertificateBindings.analyze(raw) ?: return emptyList()
        if (!report.supported) return emptyList()
        return report.subkeys.mapNotNull { s ->
            issueIn(raw, report, s.fingerprintHex, nowMs)?.let { LeftOut(s, it) }
        }
    }

    /**
     * True when the subkey [fpHex] of [raw] has a binding (or, with
     * [backSignature], a back-signature inside a binding that verifies) that
     * verifies only under the weak-hash rule: SHA-1 or RIPEMD-160 made after
     * the cutoff (SignaturePolicy.isWeakCertificationDigest). Used only to
     * name the reason; nothing is accepted on its strength.
     */
    internal fun weakHashOnly(raw: ByteArray, fpHex: String, backSignature: Boolean): Boolean = runCatching {
        val parsed = CertificateBindings.parse(raw) ?: return false
        val primary = parsed.primary
        val primaryFrame = primary.hashFraming()
        for (c in parsed.components) {
            if (!CertificateBindings.isSubkeyTag(c.tag)) continue
            val pub = CertificateBindings.publicPart(c.tag, c.body) ?: continue
            val sub = runCatching { CertificateBindings.KeyBody(pub) }.getOrNull() ?: continue
            if (!sub.fingerprintHex.equals(fpHex, ignoreCase = true)) continue
            val prefix = primaryFrame + sub.hashFraming()
            val bindings = c.sigs.mapNotNull { CertificateBindings.sigOrNull(it) }
                .filter { it.type == SIG_SUBKEY_BINDING && CertificateBindings.issuedBy(it, primary) }
                .take(MAX_SIGS_CHECKED)
            for (b in bindings) {
                val bindingWeak = isWeak(b)
                if (!backSignature) {
                    if (bindingWeak && CertificateBindings.verify(b, primary, prefix, allowWeakHash = true)) return true
                    continue
                }
                if (!CertificateBindings.verify(b, primary, prefix, allowWeakHash = bindingWeak)) continue
                val weakBack = b.embeddedSignatures().take(MAX_SIGS_CHECKED).any { e ->
                    val back = CertificateBindings.sigOrNull(e)
                    back != null && back.type == SIG_PRIMARY_BINDING && isWeak(back) &&
                        CertificateBindings.verify(back, sub, prefix, allowWeakHash = true)
                }
                if (weakBack) return true
            }
        }
        false
    }.getOrDefault(false)

    private fun isWeak(s: CertificateBindings.SigBody): Boolean =
        SignaturePolicy.isWeakCertificationDigest(s.hashAlg, s.createdMs)

    // ── Re-import of your own key pair ────────────────────────────────

    /** Fingerprints (hex, uppercase) of every subkey packet in [raw]. */
    fun subkeyFingerprints(raw: ByteArray): Set<String> {
        val parsed = CertificateBindings.parse(raw) ?: return emptySet()
        val out = HashSet<String>()
        for (c in parsed.components) {
            if (!CertificateBindings.isSubkeyTag(c.tag)) continue
            val pub = CertificateBindings.publicPart(c.tag, c.body) ?: continue
            runCatching { CertificateBindings.KeyBody(pub).fingerprintHex }.getOrNull()?.let { out.add(it.uppercase()) }
        }
        return out
    }

    /**
     * The subkeys of [incomingPublic] that [storedPublic] lacks and that its
     * primary verifiably binds ([isAdmissible]). Empty unless the import
     * carries secret material ([incomingHasSecret]): a public-only re-import
     * of a key pair adds no components (item 24). Empty as well when either
     * copy cannot be analysed or the primaries differ.
     */
    fun newBoundSubkeys(
        storedPublic: ByteArray,
        incomingPublic: ByteArray,
        incomingHasSecret: Boolean
    ): List<CertificateBindings.SubkeyState> {
        if (!incomingHasSecret) return emptyList()
        val stored = CertificateBindings.analyze(storedPublic) ?: return emptyList()
        if (!stored.supported) return emptyList()
        val incoming = CertificateBindings.analyze(incomingPublic) ?: return emptyList()
        if (!incoming.supported || !incoming.primaryFingerprintHex.equals(stored.primaryFingerprintHex, ignoreCase = true)) {
            return emptyList()
        }
        val held = subkeyFingerprints(storedPublic)
        return incoming.subkeys.filter { it.fingerprintHex.uppercase() !in held && isAdmissible(it) }
    }

    /**
     * [storedPublic] with the subkeys [fingerprints] of [incomingPublic]
     * appended, each as a public subkey packet with only the signatures
     * CertificateBindings.sanitize keeps (verified bindings and revocations).
     * A subkey already in [storedPublic] is never added twice.
     */
    fun withSubkeys(storedPublic: ByteArray, incomingPublic: ByteArray, fingerprints: Set<String>): ByteArray {
        if (fingerprints.isEmpty()) return storedPublic
        val want = fingerprints.map { it.uppercase() }.toSet()
        val clean = CertificateBindings.parse(CertificateBindings.sanitized(incomingPublic)) ?: return storedPublic
        val held = subkeyFingerprints(storedPublic)
        val out = ByteArrayOutputStream(storedPublic.size + 1024)
        out.write(storedPublic)
        for (c in clean.components) {
            if (!CertificateBindings.isSubkeyTag(c.tag)) continue
            val pub = CertificateBindings.publicPart(c.tag, c.body) ?: continue
            val fp = runCatching { CertificateBindings.KeyBody(pub).fingerprintHex.uppercase() }.getOrNull() ?: continue
            if (fp !in want || fp in held) continue
            if (c.sigs.isEmpty()) continue
            out.write(CertificateBindings.frame(TAG_PUBLIC_SUBKEY, pub))
            c.sigs.forEach { out.write(CertificateBindings.frame(TAG_SIGNATURE, it)) }
            c.other.filter { it.tag != TAG_TRUST }.forEach { out.write(CertificateBindings.frame(it.tag, it.body)) }
        }
        return out.toByteArray()
    }

    /**
     * Graft into [stored] the secret subkeys of [incoming] that [certificate]
     * binds and [stored] lacks or holds only as a stub, each with the bound
     * public part from [certificate]. A secret already held is never replaced,
     * and an incoming stub never replaces anything; a stub is taken only for a
     * subkey [stored] does not hold at all, as gpg exported it. Returns the new
     * ring and how many keys were grafted.
     */
    fun graftSecrets(
        stored: PGPSecretKeyRing,
        incoming: PGPSecretKeyRing,
        certificate: PGPPublicKeyRing
    ): Pair<PGPSecretKeyRing, Int> {
        var ring = stored
        var added = 0
        for (sk in incoming.secretKeys.asSequence().toList()) {
            if (sk.publicKey.isMasterKey) continue
            val held: PGPSecretKey? = ring.getSecretKey(sk.keyID)
            if (held != null) {
                if (!held.publicKey.fingerprint.contentEquals(sk.publicKey.fingerprint)) continue
                if (OfflineStub.isStub(sk) || !OfflineStub.isStub(held)) continue
            }
            val bound = certificate.getPublicKey(sk.keyID) ?: continue
            if (!bound.fingerprint.contentEquals(sk.publicKey.fingerprint)) continue
            ring = PGPSecretKeyRing.insertSecretKey(ring, PGPSecretKey.replacePublicKey(sk, bound))
            added++
        }
        return Pair(ring, added)
    }

    // ── 4.7.0 (item 47, #78): replacing held secrets ────────────────────

    /**
     * The secret key packet bodies in [secretRaw] (binary) that carry real
     * material (not a stub), by key fingerprint (hex, uppercase), primary and
     * subkeys both.
     */
    internal fun materialBodies(secretRaw: ByteArray): Map<String, ByteArray> {
        val out = HashMap<String, ByteArray>()
        for (p in CertificateBindings.packets(secretRaw)) {
            if (p.tag != TAG_SECRET_KEY && p.tag != TAG_SECRET_SUBKEY) continue
            if (packetLocation(p.tag, p.body) != SecretLocation.ON_DEVICE) continue
            val pub = CertificateBindings.publicPart(p.tag, p.body) ?: continue
            val fp = runCatching { CertificateBindings.KeyBody(pub).fingerprintHex.uppercase() }.getOrNull() ?: continue
            out[fp] = p.body
        }
        return out
    }

    /**
     * Fingerprints of the keys whose secret both [storedRaw] and [incomingRaw]
     * (binary secret key blocks) carry, with material, but protected
     * differently: another passphrase, or the same one under a new salt (gpg
     * re-protects on every export, so this cannot tell the two apart). These
     * are the secrets a re-import can replace. A stub on either side, or a
     * key only one side holds, is not counted.
     */
    fun replaceableSecrets(storedRaw: ByteArray, incomingRaw: ByteArray): Set<String> {
        val stored = materialBodies(storedRaw)
        val incoming = materialBodies(incomingRaw)
        return incoming.filter { (fp, body) ->
            val held = stored[fp]
            held != null && !held.contentEquals(body)
        }.keys
    }

    /**
     * [stored] with each key in [fingerprints] replaced by its secret from
     * [incoming], under the public part [certificate] binds (the primary's for
     * the primary). Keys [certificate] does not carry are skipped. Returns the
     * new ring and how many keys were replaced. The caller proves first that
     * [incoming] unlocks and holds this key's material (SecretKeyCheck).
     */
    fun replaceSecrets(
        stored: PGPSecretKeyRing,
        incoming: PGPSecretKeyRing,
        certificate: PGPPublicKeyRing,
        fingerprints: Set<String>
    ): Pair<PGPSecretKeyRing, Int> {
        val wanted = fingerprints.map { normalizeFingerprint(it) }.toSet()
        var ring = stored
        var replaced = 0
        for (sk in incoming.secretKeys.asSequence().toList()) {
            val fp = org.bouncycastle.util.encoders.Hex.toHexString(sk.publicKey.fingerprint).uppercase()
            if (fp !in wanted) continue
            if (OfflineStub.isStub(sk) || sk.isPrivateKeyEmpty) continue
            val held = ring.getSecretKey(sk.keyID) ?: continue
            if (!held.publicKey.fingerprint.contentEquals(sk.publicKey.fingerprint)) continue
            val bound = (if (sk.publicKey.isMasterKey) certificate.publicKey else certificate.getPublicKey(sk.keyID))
                ?: continue
            if (!bound.fingerprint.contentEquals(sk.publicKey.fingerprint)) continue
            ring = PGPSecretKeyRing.insertSecretKey(ring, PGPSecretKey.replacePublicKey(sk, bound))
            replaced++
        }
        return Pair(ring, replaced)
    }

    // ── Where the secret is ───────────────────────────────────────────

    /**
     * Where each subkey's secret is in the stored secret key block [secretRaw]
     * (binary), by subkey fingerprint (hex, uppercase). A subkey missing from
     * the map is not present. Read from the packets, so composite and algo-35
     * rings that Bouncy Castle cannot load are covered too.
     */
    fun secretLocations(secretRaw: ByteArray?): Map<String, SecretLocation> {
        if (secretRaw == null || secretRaw.isEmpty()) return emptyMap()
        val parsed = CertificateBindings.parse(secretRaw) ?: return emptyMap()
        val out = HashMap<String, SecretLocation>()
        for (c in parsed.components) {
            if (!CertificateBindings.isSubkeyTag(c.tag)) continue
            val pub = CertificateBindings.publicPart(c.tag, c.body) ?: continue
            val fp = runCatching { CertificateBindings.KeyBody(pub).fingerprintHex.uppercase() }.getOrNull() ?: continue
            out[fp] = packetLocation(c.tag, c.body)
        }
        return out
    }

    /** Where the secret of one key packet ([tag] 5 or 7, [body] without its
     *  header) is: a public packet holds none; a GNU stub is offline (1001)
     *  or on a card (1002); anything else carries the material here. */
    internal fun packetLocation(tag: Int, body: ByteArray): SecretLocation {
        if (tag != TAG_SECRET_KEY && tag != TAG_SECRET_SUBKEY) return SecretLocation.NOT_PRESENT
        if (SecretKeyCheck.protectionOf(tag, body) != SecretKeyCheck.Protection.STUB) return SecretLocation.ON_DEVICE
        val start = CertificateBindings.publicPart(tag, body)?.size ?: return SecretLocation.OFFLINE_STUB
        // The S2K fields after the public part end in "GNU" and the mode octet.
        val end = minOf(body.size - 3, start + 16)
        for (i in start until end) {
            if (body[i] == 'G'.code.toByte() && body[i + 1] == 'N'.code.toByte() && body[i + 2] == 'U'.code.toByte()) {
                return if ((body[i + 3].toInt() and 0xFF) == 2) SecretLocation.ON_CARD else SecretLocation.OFFLINE_STUB
            }
        }
        return SecretLocation.OFFLINE_STUB
    }

    /**
     * Where the secret of subkey [fpHex] is, for Key Details. Null for a
     * public key that is not card-backed (only the "why not usable" part is
     * shown then). A card-backed key's subkey is on the card when it is one
     * of the card's keys ([cardFingerprints]), or when the card's keys are not
     * recorded; otherwise the stored secret ring ([held]) decides.
     */
    fun locationFor(
        fpHex: String,
        isKeyPair: Boolean,
        isCardBacked: Boolean,
        cardFingerprints: Set<String>,
        held: Map<String, SecretLocation>
    ): SecretLocation? {
        val fp = normalizeFingerprint(fpHex)
        val cards = cardFingerprints.map { normalizeFingerprint(it) }.filter { it.isNotEmpty() }.toSet()
        if (isCardBacked && (cards.isEmpty() || fp in cards)) return SecretLocation.ON_CARD
        if (!isKeyPair) return if (isCardBacked) SecretLocation.NOT_PRESENT else null
        return held[fp] ?: SecretLocation.NOT_PRESENT
    }

    private fun normalizeFingerprint(fp: String): String = fp.filter { !it.isWhitespace() }.uppercase()
}
