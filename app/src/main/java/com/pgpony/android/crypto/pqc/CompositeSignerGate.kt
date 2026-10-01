// CompositeSignerGate.kt
// PGPony Android: grade composite ML-DSA + EdDSA document signatures the way
// SignerEvaluator grades classical ones.
//
// A composite signature that passes its math is not yet a trustworthy one.
// This gate adds, in order:
//
//   * the signature's own policy: a v6 document signature (type 0x00 or
//     0x01) with a hashed creation time that is not in the future beyond the
//     clock-skew allowance, no critical subpacket or notation it does not
//     understand, an accepted digest, and a signature expiration (if any)
//     that has not passed (SignaturePolicy);
//   * the signer: the certificate holding the exact key that verified
//     (matched by fingerprint) must make that key a valid signer at the
//     signature's creation time (CertificateBindings.Report.signerValidityAt):
//     not revoked (hard revocations apply at every time), not expired, sign
//     flagged, bound and back-signed. A certificate that cannot be analysed
//     fails closed.
//
// Issuer subpackets are only hints for which key to try first; the key that
// verifies is the signer. When several supplied certificates carry that key,
// the one that validly binds it is the one reported.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.SignaturePolicy
import com.pgpony.android.crypto.SignerEvaluator
import com.pgpony.android.crypto.SignerStatus
import java.util.Date

object CompositeSignerGate {

    private const val TAG_ONE_PASS = 4
    private const val TAG_LITERAL = 11
    private const val TAG_SIGNATURE = 2

    /** Composite keys tried beyond the ones an issuer subpacket names. */
    private const val MAX_TRIAL_KEYS = 64

    /**
     * The graded outcome. Only [status] == VERIFIED may be shown as verified;
     * every other value is a reason not to. [certIndex] points into the
     * certificate list the caller passed in (-1 when no certificate holds a
     * key that verified).
     */
    data class Graded(
        val status: SignerStatus,
        val certIndex: Int = -1,
        /** Fingerprint (hex uppercase) of the key the signature verified under. */
        val signingKeyFingerprint: String? = null,
        /** Primary fingerprint (hex uppercase) of the certificate holding it. */
        val signerPrimaryFingerprint: String? = null,
        /** Issuer fingerprint the signature claims (hex uppercase), a hint only. */
        val claimedFingerprint: String? = null,
        /** Hashed creation time of the signature, epoch ms. */
        val createdMs: Long? = null,
        /** Signature type (0x00 binary, 0x01 text). */
        val sigType: Int? = null,
        /** The signed content (cleartext or inline literal), when the form carries it. */
        val content: ByteArray? = null
    ) {
        val verified: Boolean get() = status == SignerStatus.VERIFIED

        /** Plain-English reason for a non-VERIFIED status. */
        val reason: String get() = SignerEvaluator.reason(status)

        /** The short key ID (16 hex) of the key that verified, or of the claimed issuer. */
        val signerKeyID: String? get() = (signingKeyFingerprint ?: claimedFingerprint)?.take(16)
    }

    /**
     * [g] as the VerificationResult the verify screens and command lines
     * already render. The caller supplies the display identity of the
     * certificate at [Graded.certIndex]. Only VERIFIED becomes Verified; a
     * signature that verified from a key that does not pass becomes Invalid
     * with its [VerificationResult.Invalid.signerStatus] and fingerprints set.
     */
    fun toVerificationResult(
        g: Graded,
        signerName: String?,
        signerEmail: String?,
        signerTrust: com.pgpony.android.data.TrustLevel? = null,
        signedContent: String? = null
    ): com.pgpony.android.crypto.VerificationResult {
        val signing = g.signingKeyFingerprint
        val primary = g.signerPrimaryFingerprint
        return when {
            g.status == SignerStatus.VERIFIED && signing != null && primary != null ->
                com.pgpony.android.crypto.VerificationResult.Verified(
                    signerKeyID = signing.take(16),
                    signerFingerprint = primary,
                    signerName = signerName,
                    signerEmail = signerEmail,
                    signedContent = signedContent,
                    signerTrust = signerTrust,
                    signingKeyFingerprint = signing
                )
            g.status == SignerStatus.UNKNOWN_SIGNER ->
                com.pgpony.android.crypto.VerificationResult.UnknownSigner(
                    signerKeyID = g.claimedFingerprint?.take(16) ?: "",
                    claimedFingerprint = g.claimedFingerprint,
                    signedContent = signedContent
                )
            else -> com.pgpony.android.crypto.VerificationResult.Invalid(
                reason = g.reason,
                signerKeyID = g.signerKeyID,
                signedContent = signedContent,
                signerStatus = if (signing != null) g.status else null,
                signingKeyFingerprint = signing,
                signerFingerprint = primary
            )
        }
    }

    /**
     * The status the signature packet body [sigBody] forces on its own, or
     * null when its policy passes. Checked only from the hashed area.
     */
    fun policyStatus(sigBody: ByteArray, nowMs: Long = System.currentTimeMillis()): SignerStatus? {
        val s = CertificateBindings.sigOrNull(sigBody) ?: return SignerStatus.INVALID
        if (s.version != 6) return SignerStatus.INVALID
        if (s.type != CompositeSigPacket.TYPE_BINARY && s.type != CompositeSigPacket.TYPE_TEXT) return SignerStatus.INVALID
        if (CompositeSignSuite.forAlgId(s.pkAlg) == null) return SignerStatus.INVALID
        val created = s.createdMs ?: return SignerStatus.WEAK_SIGNATURE
        if (s.hasCriticalUnknown) return SignerStatus.WEAK_SIGNATURE
        if (SignaturePolicy.isFromTheFuture(Date(created), Date(nowMs))) return SignerStatus.WEAK_SIGNATURE
        if (SignaturePolicy.isExpiredAt(created, s.sigExpirySeconds ?: 0L, nowMs)) return SignerStatus.EXPIRED_SIGNATURE
        if (!SignaturePolicy.isAcceptableDataDigest(s.hashAlg, created)) return SignerStatus.WEAK_SIGNATURE
        return null
    }

    /**
     * Grade [signerFpHex], a key of the certificate [cert] (binary, public or
     * secret), as the maker of a signature created at [createdMs]. Fails
     * closed (UNBOUND_SIGNER) when the certificate cannot be analysed.
     */
    fun gradeSigner(cert: ByteArray, signerFpHex: String, createdMs: Long): SignerStatus {
        val report = runCatching { CertificateBindings.analyze(cert) }.getOrNull()
            ?: return SignerStatus.UNBOUND_SIGNER
        if (!report.supported) return SignerStatus.UNBOUND_SIGNER
        return when (report.signerValidityAt(signerFpHex, createdMs)) {
            CertificateBindings.SignerValidity.VALID -> SignerStatus.VERIFIED
            CertificateBindings.SignerValidity.PREDATES_KEY -> SignerStatus.PREDATES_KEY
            CertificateBindings.SignerValidity.NOT_VALID -> SignerStatus.NOT_VALID_AT_TIME
            CertificateBindings.SignerValidity.EXPIRED -> SignerStatus.EXPIRED_KEY
            CertificateBindings.SignerValidity.REVOKED -> SignerStatus.REVOKED_KEY
            CertificateBindings.SignerValidity.NOT_SIGNING -> SignerStatus.NOT_SIGNING_KEY
            CertificateBindings.SignerValidity.UNBOUND -> SignerStatus.UNBOUND_SIGNER
        }
    }

    /**
     * A detached composite signature [signature] (armored or binary) over
     * [data], graded against the certificates [certs] (binary transferable
     * keys, as stored). A text signature (0x01) is canonicalized here.
     */
    fun verifyDetached(
        certs: List<ByteArray>,
        signature: ByteArray,
        data: ByteArray,
        nowMs: Long = System.currentTimeMillis()
    ): Graded {
        val raw = runCatching { CompositeDocumentVerifier.rawSignaturePacket(signature) }.getOrNull()
            ?: return Graded(SignerStatus.INVALID)
        return gradeAny(certs, compositeSignatureBodies(raw), data, nowMs, content = null)
    }

    /** A clear-signed composite message, graded against [certs]. */
    fun verifyCleartext(
        certs: List<ByteArray>,
        message: String,
        nowMs: Long = System.currentTimeMillis()
    ): Graded {
        val recovered = CompositeDocumentVerifier.cleartextContent(message) ?: return Graded(SignerStatus.INVALID)
        // The signature block starts at the first line, after the framing
        // line, that is exactly the armor header (a dash-escaped copy of it
        // inside the signed text is not).
        val lines = message.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        val begin = lines.indexOfFirst { it.trim() == "-----BEGIN PGP SIGNED MESSAGE-----" }
        val sigAt = if (begin < 0) -1 else
            (begin + 1 until lines.size).firstOrNull { lines[it].trim() == "-----BEGIN PGP SIGNATURE-----" } ?: -1
        if (sigAt < 0) return Graded(SignerStatus.INVALID, content = recovered.toByteArray(Charsets.UTF_8))
        val sigArmor = lines.subList(sigAt, lines.size).joinToString("\n")
        val text = recovered.toByteArray(Charsets.UTF_8)
        val raw = runCatching { CompositeSigPacket.dearmor(sigArmor) }.getOrNull()
            ?: return Graded(SignerStatus.INVALID, content = text)
        val documentData = CompositeSigPacket.canonicalizeCleartext(recovered)
        return gradeAny(certs, compositeSignatureBodies(raw), documentData, nowMs, content = text)
    }

    /**
     * An inline one-pass composite message [message] (binary, optionally
     * compressed): exactly one literal, the one-pass packets before it, the
     * signatures after it. A composite signature counts only when a v6
     * one-pass packet before the literal states the same type, hash and
     * public-key algorithms, salt and signing key. Graded against [certs].
     * Also the entry point for DecryptResult.compositeInlineBytes.
     */
    fun verifyInline(
        certs: List<ByteArray>,
        message: ByteArray,
        nowMs: Long = System.currentTimeMillis()
    ): Graded {
        val packets = runCatching { CompositeDocumentVerifier.packetsOf(CompositeDocumentVerifier.decompress(message)) }
            .getOrNull() ?: return Graded(SignerStatus.INVALID)
        val literalIdx = packets.indices.filter { packets[it].first == TAG_LITERAL }
        if (literalIdx.size != 1) return Graded(SignerStatus.INVALID)
        val li = literalIdx[0]
        val content = runCatching { CompositeDocumentVerifier.literalContent(packets[li].second) }.getOrNull()
            ?: return Graded(SignerStatus.INVALID)
        val opsBodies = packets.subList(0, li).filter { it.first == TAG_ONE_PASS }.map { it.second }
        val sigs = packets.subList(li + 1, packets.size).filter { it.first == TAG_SIGNATURE }.map { it.second }
            .filter { it.size > 2 && CompositeSignSuite.forAlgId(it[2].toInt() and 0xFF) != null }
        return gradeAny(certs, sigs, content, nowMs, content = content, onePass = opsBodies)
    }

    /**
     * The composite signature packet bodies (algorithm 30 or 31) in [raw], in
     * order. A block signed by several keys may mix composite and classical
     * signatures; only the composite ones are graded here.
     */
    private fun compositeSignatureBodies(raw: ByteArray): List<ByteArray> {
        val packets = runCatching { CompositeDocumentVerifier.packetsOf(raw) }.getOrNull()
            ?: runCatching { listOf(CompositeSigPacket.firstPacket(raw)) }.getOrNull()
            ?: return emptyList()
        return packets.filter { it.first == TAG_SIGNATURE }.map { it.second }
            .filter { it.size > 2 && CompositeSignSuite.forAlgId(it[2].toInt() and 0xFF) != null }
    }

    /** Grade each of [sigs]; the first VERIFIED wins, else the most informative failure. */
    private fun gradeAny(
        certs: List<ByteArray>,
        sigs: List<ByteArray>,
        data: ByteArray,
        nowMs: Long,
        content: ByteArray?,
        onePass: List<ByteArray>? = null
    ): Graded {
        var best: Graded? = null
        for (sig in sigs) {
            val g = grade(certs, sig, data, nowMs, content = content, onePass = onePass)
            if (g.verified) return g
            if (best == null || rank(g.status) > rank(best.status)) best = g
        }
        return best ?: Graded(SignerStatus.INVALID, content = content)
    }

    /** Which of two failing grades is the more informative to report. */
    private fun rank(s: SignerStatus): Int = when (s) {
        SignerStatus.VERIFIED -> 4
        SignerStatus.INVALID -> 1
        SignerStatus.UNKNOWN_SIGNER -> 2
        else -> 3
    }

    private class Candidate(val certIndex: Int, val fpHex: String, val primaryFpHex: String, val material: ByteArray, val algId: Int)

    /** Every composite signing key packet (primary or subkey) of [certs]. */
    private fun candidates(certs: List<ByteArray>): List<Candidate> {
        val out = ArrayList<Candidate>()
        for ((i, cert) in certs.withIndex()) {
            val parsed = runCatching { CertificateBindings.parse(cert) }.getOrNull() ?: continue
            val keys = ArrayList<CertificateBindings.KeyBody>()
            keys.add(parsed.primary)
            for (c in parsed.components) {
                if (!CertificateBindings.isSubkeyTag(c.tag)) continue
                val pub = CertificateBindings.publicPart(c.tag, c.body) ?: continue
                runCatching { CertificateBindings.KeyBody(pub) }.getOrNull()?.let { keys.add(it) }
            }
            for (k in keys) {
                if (CompositeSignSuite.forAlgId(k.algorithm) == null || k.version != 6) continue
                val material = runCatching {
                    val matLen = CompositeSigPacket.beInt(k.body, 6)
                    k.body.copyOfRange(10, 10 + matLen)
                }.getOrNull() ?: continue
                out.add(Candidate(i, k.fingerprintHex, parsed.primary.fingerprintHex, material, k.algorithm))
            }
        }
        return out
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02X".format(it) }

    /**
     * The shared core: policy, then the math against each candidate key
     * (named ones first), then the signer grade for every key that verified.
     */
    private fun grade(
        certs: List<ByteArray>,
        sigBody: ByteArray,
        rawData: ByteArray,
        nowMs: Long,
        content: ByteArray?,
        onePass: List<ByteArray>? = null
    ): Graded {
        val s = CertificateBindings.sigOrNull(sigBody) ?: return Graded(SignerStatus.INVALID, content = content)
        val claimedFps = s.allIssuerFingerprints()
        val claimed = claimedFps.firstOrNull()?.let { hex(it) }
        val base = Graded(SignerStatus.INVALID, claimedFingerprint = claimed, createdMs = s.createdMs, sigType = s.type, content = content)
        val parsed = runCatching { CompositeSigPacket.parse(sigBody) }.getOrNull() ?: return base
        val suite = CompositeSignSuite.forAlgId(parsed.pubAlgo) ?: return base
        // A text signature hashes the CRLF-canonicalized document (idempotent
        // on text that is already canonical, such as cleartext).
        val data = if (parsed.sigType == CompositeSigPacket.TYPE_TEXT) {
            CompositeSigPacket.canonicalizeText(String(rawData, Charsets.UTF_8))
        } else {
            rawData
        }
        val all = candidates(certs).filter { it.algId == parsed.pubAlgo }
        val named = all.filter { c -> claimedFps.any { hex(it).equals(c.fpHex, ignoreCase = true) } }
        val others = all.filter { it !in named }.take(MAX_TRIAL_KEYS)
        val tried = HashSet<String>()
        val signer = (named + others).firstOrNull { c ->
            if (!tried.add(c.fpHex.uppercase())) return@firstOrNull false
            if (onePass != null && !boundToOnePass(onePass, parsed, c.fpHex)) return@firstOrNull false
            runCatching { CompositeSigPacket.verifyDocumentSignature(suite, c.material, parsed, data) }
                .getOrDefault(false)
        } ?: return if (named.isEmpty()) base.copy(status = SignerStatus.UNKNOWN_SIGNER) else base
        // The same key (same fingerprint, so same material) may sit on more
        // than one supplied certificate; each is graded, the binding one wins.
        val verifiedBy = all.filter { it.fpHex.equals(signer.fpHex, ignoreCase = true) }
        val policy = policyStatus(sigBody, nowMs)
        var best: Graded? = null
        for (c in verifiedBy) {
            val status = policy ?: gradeSigner(certs[c.certIndex], c.fpHex, s.createdMs ?: 0L)
            val g = base.copy(
                status = status,
                certIndex = c.certIndex,
                signingKeyFingerprint = c.fpHex.uppercase(),
                signerPrimaryFingerprint = c.primaryFpHex.uppercase()
            )
            if (g.verified) return g
            if (best == null) best = g
        }
        return best ?: base
    }

    /**
     * A v6 one-pass packet among [onePass] states exactly what [sig] is:
     * signature type, hash and public-key algorithms, salt, and the key
     * [fpHex] that verifies it.
     */
    private fun boundToOnePass(onePass: List<ByteArray>, sig: CompositeSigPacket.Parsed, fpHex: String): Boolean =
        onePass.any { b ->
            runCatching {
                if ((b[0].toInt() and 0xFF) != 6) return@runCatching false
                val type = b[1].toInt() and 0xFF
                val hash = b[2].toInt() and 0xFF
                val alg = b[3].toInt() and 0xFF
                val saltLen = b[4].toInt() and 0xFF
                val salt = b.copyOfRange(5, 5 + saltLen)
                val fp = b.copyOfRange(5 + saltLen, 5 + saltLen + 32)
                type == sig.sigType && hash == sig.hashAlgo && alg == sig.pubAlgo &&
                    salt.contentEquals(sig.salt) && hex(fp).equals(fpHex, ignoreCase = true)
            }.getOrDefault(false)
        }
}
