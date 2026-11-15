// SubkeyRows.kt
// PGPony Android, 4.6.0 (item 19): Key Detail subkey rows read straight
// from the certificate octets.
//
// Key Detail listed subkeys through Bouncy Castle unless the primary was a
// composite ML-DSA key. A classical primary carrying a composite ML-KEM
// subkey (the RFC 9980 v4 shape "mlkem-768v4", a v6 Ed25519 primary with an
// ML-KEM subkey, or a LibrePGP v5 Kyber subkey) went down that path, the
// per-subkey mapping threw on algorithm 35 / 36 / 8 and the row was silently
// dropped, so neither the original subkey nor one added later was shown.
// Any key that carries such a subkey is now listed from its certificate via
// CertificateBindings, which reads v4, v5 and v6 packets alike and takes each
// subkey's capabilities, expiry and revocation from its verified binding.

package com.pgpony.android.ui.keyring

import com.pgpony.android.R
import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.SubkeyAdmission
import com.pgpony.android.crypto.SubkeyCapability

internal object SubkeyRows {

    /** Algorithms Bouncy Castle cannot map to a subkey row here. */
    private val COMPOSITE_KEM = setOf(35, 36)
    private const val LIBREPGP_KEM = 8

    /** True when [raw] holds a composite KEM subkey (algo 35 / 36, or a v5 algo 8). */
    fun hasCompositeSubkey(raw: ByteArray): Boolean {
        val parsed = CertificateBindings.parse(raw) ?: return false
        return parsed.components.any { c ->
            if (!CertificateBindings.isSubkeyTag(c.tag)) return@any false
            val pub = CertificateBindings.publicPart(c.tag, c.body) ?: return@any false
            val version = pub[0].toInt() and 0xFF
            val algo = pub.getOrNull(if (version == 4 || version == 5 || version == 6) 5 else -1)
                ?.toInt()?.and(0xFF) ?: return@any false
            algo in COMPOSITE_KEM || (algo == LIBREPGP_KEM && version == 5)
        }
    }

    /**
     * One row per subkey bound to the primary, in certificate order. Null when
     * the certificate cannot be read or its primary cannot be verified here,
     * so the caller can fall back to another source.
     */
    fun fromCertificate(raw: ByteArray, isCardBacked: Boolean): List<SubkeyDisplayInfo>? {
        val report = CertificateBindings.analyze(raw) ?: return null
        if (!report.supported) return null
        return report.subkeys.filter { it.bound }.map { s ->
            val caps = s.keyFlags?.takeIf { it != 0 }?.let { SubkeyCapability.fromBcKeyFlags(it) }
                ?: fallbackCapabilities(s.algorithm)
            SubkeyDisplayInfo(
                fingerprint = s.fingerprintHex.uppercase(),
                keyId = String.format("%016X", s.keyId),
                algorithmLabel = label(s),
                capabilities = caps,
                createdAt = s.createdAtMs,
                expiresAt = s.expiresAtMs,
                isRevoked = s.revoked,
                isCardBacked = isCardBacked
            )
        }
    }

    /** 4.7.0 (item 40, #82): the text for why a subkey is left out or not used. */
    fun issueRes(issue: SubkeyAdmission.Issue): Int = when (issue) {
        SubkeyAdmission.Issue.WEAK_HASH -> R.string.subkey_issue_weak_hash
        SubkeyAdmission.Issue.NO_VALID_BINDING -> R.string.subkey_issue_no_binding
        SubkeyAdmission.Issue.NO_BACK_SIGNATURE -> R.string.subkey_issue_no_back_signature
        SubkeyAdmission.Issue.REVOKED -> R.string.subkey_issue_revoked
        SubkeyAdmission.Issue.EXPIRED -> R.string.subkey_issue_expired
    }

    /** 4.7.0 (item 40, #82): the text for where a subkey's secret is. */
    fun secretLocationRes(location: SubkeyAdmission.SecretLocation): Int = when (location) {
        SubkeyAdmission.SecretLocation.ON_DEVICE -> R.string.key_detail_subkey_secret_on_device
        SubkeyAdmission.SecretLocation.OFFLINE_STUB -> R.string.key_detail_subkey_secret_offline
        SubkeyAdmission.SecretLocation.ON_CARD -> R.string.key_detail_subkey_secret_on_card
        SubkeyAdmission.SecretLocation.NOT_PRESENT -> R.string.key_detail_subkey_secret_not_present
    }

    /** 4.7.0 (item 40): the last 8 hex digits of a key ID, as the preview shows it. */
    fun shortKeyId(keyId: Long): String = String.format("%016X", keyId).takeLast(8)

    /**
     * 4.7.0 (item 40, #82): [rows] with each subkey's status for Key Details:
     * where its secret is ([SubkeyAdmission.locationFor]; null for a public
     * key) and why it is not usable, read from the stored certificate
     * [rawPublic]. A certificate the analyser cannot read leaves the reason
     * out rather than guessing.
     */
    fun withStatus(
        rows: List<SubkeyDisplayInfo>,
        rawPublic: ByteArray?,
        isKeyPair: Boolean,
        isCardBacked: Boolean,
        cardFingerprints: Set<String>,
        held: Map<String, SubkeyAdmission.SecretLocation>,
        nowMs: Long = System.currentTimeMillis()
    ): List<SubkeyDisplayInfo> {
        val report: CertificateBindings.Report? = rawPublic?.let { runCatching { CertificateBindings.analyze(it) }.getOrNull() }
        return rows.map { row ->
            val issue: SubkeyAdmission.Issue? = if (rawPublic != null) {
                runCatching { SubkeyAdmission.issueIn(rawPublic, report, row.fingerprint, nowMs) }.getOrNull()
            } else null
            row.copy(
                secretLocation = SubkeyAdmission.locationFor(row.fingerprint, isKeyPair, isCardBacked, cardFingerprints, held),
                issue = issue,
                // 4.8.1 (#120): the date comes from the same binding as the
                // Expired label, so the two never disagree.
                expiresAt = SubkeyAdmission.shownExpiry(report, row.fingerprint, row.expiresAt)
            )
        }
    }

    private fun fallbackCapabilities(algo: Int): Int = when (algo) {
        35, 36, 25, 26, 18, 8, 16 -> SubkeyCapability.Encrypt.flag
        30, 31, 27, 28, 22, 19, 17 -> SubkeyCapability.Sign.flag
        else -> 0
    }

    internal fun label(s: CertificateBindings.SubkeyState): String = when (s.algorithm) {
        35 -> "ML-KEM-768 + X25519"
        36 -> "ML-KEM-1024 + X448"
        30 -> "ML-DSA-65 + Ed25519"
        31 -> "ML-DSA-87 + Ed448"
        25 -> "X25519"
        26 -> "X448"
        27 -> "Ed25519"
        28 -> "Ed448"
        18 -> "X25519"
        22 -> "Ed25519"
        19 -> "ECDSA"
        16 -> "ElGamal"
        17 -> "DSA"
        1, 2, 3 -> rsaBits(s)?.let { "RSA $it" } ?: "RSA"
        8 -> if (s.version == 5) libreKemLabel(s) else genericLabel()
        else -> genericLabel()
    }

    // 4.6.2: the fallback label is shown on Key Detail, so it is localized.
    // Unit tests have no Application, so they get the English label.
    private fun genericLabel(): String =
        com.pgpony.android.i18n.ErrorText.appContext()
            ?.getString(R.string.key_detail_subkey_label_generic) ?: "Subkey"

    private fun libreKemLabel(s: CertificateBindings.SubkeyState): String {
        val curve = runCatching {
            com.pgpony.android.crypto.pqc.CompositeLibrePGPKeyMaterial
                .suiteOf(CertificateBindings.frame(14, s.publicBody)).curve
        }.getOrNull()
        return when (curve) {
            com.pgpony.android.crypto.pqc.EccCurve.X25519 -> "ML-KEM-768 + X25519"
            com.pgpony.android.crypto.pqc.EccCurve.X448 -> "ML-KEM-1024 + X448"
            com.pgpony.android.crypto.pqc.EccCurve.BRAINPOOL_P384R1 -> "ML-KEM-1024 + brainpoolP384r1"
            com.pgpony.android.crypto.pqc.EccCurve.BRAINPOOL_P256R1 -> "ML-KEM-768 + brainpoolP256r1"
            else -> "ML-KEM (LibrePGP)"
        }
    }

    /** The modulus bit count from an RSA key body: the first MPI after the
     *  algorithm octet (v5 / v6 put a 4-octet material length first). */
    private fun rsaBits(s: CertificateBindings.SubkeyState): Int? {
        val b = s.publicBody
        val at = if (s.version == 4) 6 else 10
        if (b.size < at + 2) return null
        return ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)
    }
}
