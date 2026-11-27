// X25519Subkeys.kt
// PGPony Android 4.8.2 (item 1): which subkeys of a certificate the provider's
// X25519 actions accept.
//
// A subkey qualifies when it is a Curve25519 encryption key
// (X25519Agreement.curve25519Point reads its u-coordinate) and the
// certificate makes it usable now: the primary is not revoked or expired, and
// a binding in force marks the subkey for encryption, or as an additional
// decryption subkey (#108), and it is not revoked or expired. A certificate
// whose primary has no verifier here vouches for nothing. Works on the raw
// certificate octets, so composite ML-DSA and v4 ML-KEM keys are read whole.

package com.pgpony.android.crypto

object X25519Subkeys {

    class Subkey(
        /** Upper-case hex: 40 digits for v4, 64 for v5 and v6. */
        val fingerprintHex: String,
        /** The 32-byte u-coordinate. */
        val point: ByteArray,
        val version: Int
    )

    /** What [classify] found for one fingerprint. */
    sealed class Lookup {
        class Usable(val subkey: Subkey) : Lookup()
        /** The certificate has that subkey, but it is not a Curve25519 encryption key. */
        object NotCurve25519 : Lookup()
        /** A Curve25519 key that is unbound, revoked, expired or not for encryption. */
        object NotUsable : Lookup()
        object Absent : Lookup()
    }

    /** Every subkey of [cert] the X25519 actions accept at [nowMs]. */
    fun usable(cert: ByteArray, nowMs: Long): List<Subkey> {
        val report = CertificateBindings.analyze(cert) ?: return emptyList()
        if (!report.supported) return emptyList()
        return report.subkeys.mapNotNull { s ->
            val point = X25519Agreement.curve25519Point(s.publicBody) ?: return@mapNotNull null
            if (!usableNow(report, s.fingerprintHex, nowMs)) return@mapNotNull null
            Subkey(s.fingerprintHex.uppercase(), point, s.version)
        }
    }

    /** What [cert] says about the subkey [fingerprintHex] at [nowMs]. */
    fun classify(cert: ByteArray, fingerprintHex: String, nowMs: Long): Lookup {
        val report = CertificateBindings.analyze(cert) ?: return Lookup.Absent
        val s = report.subkeyByFingerprint(fingerprintHex)
            ?: return if (report.isPrimary(fingerprintHex)) Lookup.NotCurve25519 else Lookup.Absent
        val point = X25519Agreement.curve25519Point(s.publicBody) ?: return Lookup.NotCurve25519
        if (!report.supported || !usableNow(report, s.fingerprintHex, nowMs)) return Lookup.NotUsable
        return Lookup.Usable(Subkey(s.fingerprintHex.uppercase(), point, s.version))
    }

    private fun usableNow(report: CertificateBindings.Report, fp: String, nowMs: Long): Boolean =
        report.isUsableEncryptionKey(fp, nowMs) || report.isUsableAdsk(fp, nowMs)
}
