// CertificateMerge.kt
// PGPony Android, 4.6.0 (items 17.1 and 12): merge a fetched copy of a
// certificate into the stored one as a verified union.
//
// Key-server refresh, WKD and re-import used to replace the stored public
// material with whatever was fetched. That both let a server add components
// the owner never bound and let it drop ones the owner did (keys.openpgp.org
// and keys.pgpony.app strip unconfirmed User IDs and third-party
// certifications). The merge is now a union over the sanitized forms of both
// copies (CertificateBindings.sanitize), so only components and signatures
// that verify can arrive:
//
//   * Public-only keys: every stored packet is kept; from the fetched copy a
//     new subkey, a new User ID (unless the user removed it, see
//     RemovedUserIdStore) and any new signature are added.
//   * Key pairs: the local copy is authoritative. A fetched copy contributes
//     only revocations (0x20 on the primary, 0x28 on subkeys, 0x30 on User
//     IDs) and third-party certifications on User IDs already present. It
//     never adds or changes self-certifications, User IDs, subkeys or expiry.
//
// Packet identity: key packets by fingerprint, User IDs and attributes by
// their bytes, signatures by their bytes (a re-encoded copy of the same
// signature is caught by type, issuer, creation time, hashed area and value).

package com.pgpony.android.crypto

import java.io.ByteArrayOutputStream

object CertificateMerge {

    private const val TAG_SIGNATURE = 2
    private const val TAG_PUBLIC_KEY = 6
    private const val TAG_PUBLIC_SUBKEY = 14
    private const val TAG_USER_ID = 13

    private const val SIG_CERT_GENERIC = 0x10
    private const val SIG_CERT_POSITIVE = 0x13
    private const val SIG_KEY_REVOCATION = 0x20
    private const val SIG_SUBKEY_REVOCATION = 0x28
    private const val SIG_CERT_REVOCATION = 0x30

    /**
     * The union of [stored] and [fetched] under the rules in the header, as
     * public certificate octets. Returns [stored] unchanged when either copy
     * cannot be parsed, when the primaries differ, or when the stored primary
     * cannot be evaluated (see CertificateBindings).
     */
    fun merge(
        stored: ByteArray,
        fetched: ByteArray,
        isKeyPair: Boolean,
        removedUserIds: Set<String> = emptySet()
    ): ByteArray {
        // A primary this app cannot verify gets no remote changes at all:
        // nothing from the fetched copy could be checked.
        if (CertificateBindings.analyze(stored)?.supported != true) return stored
        val local = CertificateBindings.parse(CertificateBindings.sanitized(stored)) ?: return stored
        val remote = CertificateBindings.parse(CertificateBindings.sanitized(fetched)) ?: return stored
        if (!local.primary.fingerprint.contentEquals(remote.primary.fingerprint)) return stored
        val primary = local.primary

        fun sigKey(b: ByteArray): String {
            val s = CertificateBindings.sigOrNull(b) ?: return "raw:" + b.contentHashCode()
            val issuer = s.issuerFingerprint()?.let { org.bouncycastle.util.encoders.Hex.toHexString(it) }
                ?: s.issuerKeyId()?.toString(16) ?: "-"
            // The signature value and hashed area identify it; the unhashed
            // area may be re-encoded between copies of the same signature.
            return "${s.type}:$issuer:${s.createdMs}:${s.hashAlg}:" +
                "${s.hashed.contentHashCode()}:${s.material.contentHashCode()}"
        }

        fun isSelf(b: ByteArray): Boolean {
            val s = CertificateBindings.sigOrNull(b) ?: return false
            return CertificateBindings.issuedBy(s, primary)
        }

        fun typeOf(b: ByteArray): Int = CertificateBindings.sigOrNull(b)?.type ?: -1

        fun addSigs(into: MutableList<ByteArray>, from: List<ByteArray>, allow: (ByteArray) -> Boolean) {
            val seen = into.mapTo(HashSet()) { sigKey(it) }
            for (b in from) {
                if (!allow(b)) continue
                if (seen.add(sigKey(b))) into.add(b)
            }
        }

        val out = ByteArrayOutputStream()
        out.write(CertificateBindings.frame(TAG_PUBLIC_KEY, primary.body))

        // Primary-level signatures (direct-key, key revocation).
        val primarySigs = local.primarySigs.toMutableList()
        addSigs(primarySigs, remote.primarySigs) { b ->
            if (isKeyPair) typeOf(b) == SIG_KEY_REVOCATION else true
        }
        primarySigs.forEach { out.write(CertificateBindings.frame(TAG_SIGNATURE, it)) }
        local.primaryOther.forEach { out.write(CertificateBindings.frame(it.tag, it.body)) }

        fun componentId(c: CertificateBindings.Component): String =
            if (CertificateBindings.isSubkeyTag(c.tag)) {
                val pub = CertificateBindings.publicPart(c.tag, c.body)
                val fp = pub?.let { runCatching { CertificateBindings.KeyBody(it).fingerprintHex }.getOrNull() }
                "k:" + (fp ?: org.bouncycastle.util.encoders.Hex.toHexString(c.body))
            } else {
                "u${c.tag}:" + org.bouncycastle.util.encoders.Hex.toHexString(c.body)
            }

        val remoteById = remote.components.associateBy { componentId(it) }
        val localIds = HashSet<String>()

        // Identities first, then subkeys (OpenPGP requires that order): the
        // stored ones with any admissible new signatures, then the new ones.
        for (wantSubkeys in listOf(false, true)) {
            for (c in local.components) {
                if (CertificateBindings.isSubkeyTag(c.tag) != wantSubkeys) continue
                val id = componentId(c)
                localIds.add(id)
                val sigs = c.sigs.toMutableList()
                remoteById[id]?.let { r ->
                    addSigs(sigs, r.sigs) { b ->
                        if (!isKeyPair) return@addSigs true
                        val t = typeOf(b)
                        if (wantSubkeys) t == SIG_SUBKEY_REVOCATION
                        else t == SIG_CERT_REVOCATION ||
                            (!isSelf(b) && t in SIG_CERT_GENERIC..SIG_CERT_POSITIVE)
                    }
                }
                writeComponent(out, c, sigs)
            }
            if (!isKeyPair) {
                for (r in remote.components) {
                    if (CertificateBindings.isSubkeyTag(r.tag) != wantSubkeys) continue
                    val id = componentId(r)
                    if (id in localIds) continue
                    if (r.tag == TAG_USER_ID && String(r.body, Charsets.UTF_8) in removedUserIds) continue
                    writeComponent(out, r, r.sigs)
                }
            }
        }
        return out.toByteArray()
    }

    private fun writeComponent(out: ByteArrayOutputStream, c: CertificateBindings.Component, sigs: List<ByteArray>) {
        // The stored copy is public; a secret subkey packet never reaches here
        // from a fetched copy, but convert defensively so the output stays public.
        val tag = when (c.tag) {
            7 -> TAG_PUBLIC_SUBKEY
            else -> c.tag
        }
        val body = if (c.tag == 7) CertificateBindings.publicPart(c.tag, c.body) ?: return else c.body
        out.write(CertificateBindings.frame(tag, body))
        sigs.forEach { out.write(CertificateBindings.frame(TAG_SIGNATURE, it)) }
        c.other.forEach { out.write(CertificateBindings.frame(it.tag, it.body)) }
    }
}
