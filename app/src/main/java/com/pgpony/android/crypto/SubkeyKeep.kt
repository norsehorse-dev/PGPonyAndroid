// SubkeyKeep.kt
// PGPony Android, 4.8.1 (#119): a stored certificate never loses a subkey its
// primary bound, except through Remove subkey.
//
// A tester's Ed25519 key pair lost every subkey three times on 4.7.2 without
// any edit: Key Details listed only the certify primary and SSH through
// OkcAgent found no authentication key. Importing the owner's own secret
// export brought them back (SubkeyAdmission adds the subkeys the stored copy
// lacks). The write that dropped them was not found, so SecureKeyStore now
// checks every write of a public certificate: a subkey that verifiably bound
// in the stored copy and is missing from the new one is carried over, with
// its signatures, and the write is logged with the caller so the next report
// says where it came from.

package com.pgpony.android.crypto

import java.io.ByteArrayOutputStream

object SubkeyKeep {

    private const val TAG_PUBLIC_SUBKEY = 14
    private const val TAG_SIGNATURE = 2

    /** [bytes] to store, and the fingerprints (uppercase hex) of the subkeys carried over. */
    class Result(val bytes: ByteArray, val kept: List<String>)

    /**
     * [new] with every subkey of [old] that [old]'s primary binds (a verified
     * binding, CertificateBindings) and [new] lacks, appended with its
     * signatures as a public subkey. [drop] names subkeys (uppercase hex
     * fingerprints) a Remove subkey takes out on purpose; those stay out. [new]
     * is returned as it is when either
     * copy cannot be read, the primaries differ, or [old]'s primary cannot be
     * verified here.
     */
    fun keepBound(old: ByteArray, new: ByteArray, drop: Set<String> = emptySet()): Result {
        val unchanged = Result(new, emptyList())
        val o = CertificateBindings.parse(old) ?: return unchanged
        val n = CertificateBindings.parse(new) ?: return unchanged
        if (!o.primary.fingerprint.contentEquals(n.primary.fingerprint)) return unchanged
        val report = CertificateBindings.analyze(old) ?: return unchanged
        if (!report.supported) return unchanged
        val dropped = drop.map { it.uppercase() }.toSet()
        val bound = report.subkeys.filter { it.bound }.map { it.fingerprintHex.uppercase() }.toSet() - dropped
        if (bound.isEmpty()) return unchanged
        val have = subkeyFingerprints(n)
        val kept = ArrayList<String>()
        val out = ByteArrayOutputStream()
        out.write(new)
        for (c in o.components) {
            if (!CertificateBindings.isSubkeyTag(c.tag)) continue
            val pub = CertificateBindings.publicPart(c.tag, c.body) ?: continue
            val fp = runCatching { CertificateBindings.KeyBody(pub).fingerprintHex.uppercase() }.getOrNull() ?: continue
            if (fp !in bound || fp in have || fp in kept) continue
            out.write(CertificateBindings.frame(TAG_PUBLIC_SUBKEY, pub))
            for (s in c.sigs) out.write(CertificateBindings.frame(TAG_SIGNATURE, s))
            kept.add(fp)
        }
        return if (kept.isEmpty()) unchanged else Result(out.toByteArray(), kept)
    }

    private fun subkeyFingerprints(p: CertificateBindings.Parsed): Set<String> =
        p.components.filter { CertificateBindings.isSubkeyTag(it.tag) }.mapNotNull { c ->
            CertificateBindings.publicPart(c.tag, c.body)
                ?.let { runCatching { CertificateBindings.KeyBody(it).fingerprintHex.uppercase() }.getOrNull() }
        }.toSet()
}
