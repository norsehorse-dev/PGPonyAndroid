// SshAuth.kt
// PGPony Android, 4.6.0 (item 16, issue #68): SSH authentication with an
// OpenPGP authentication subkey.
//
// What the SSH authentication service (and Key Detail's "Copy SSH public key")
// needs from a key, with no Android dependency so it tests on the JVM:
//
//   * [authSubkey]: the subkey an SSH client should use. It must be bound to
//     the primary by a verified binding with the Authenticate key flag (0x20),
//     unrevoked, unexpired, under an unrevoked, unexpired primary, and of an
//     algorithm SSH has a key type for. The newest such subkey wins. The
//     certificate is read with CertificateBindings, so v4, v5 and v6 keys and
//     composite ML-DSA primaries (whose classical auth subkeys SSH can use)
//     are all handled the same way.
//   * [publicBlob] / [authorizedKeysLine]: the key in SSH wire format
//     (RFC 4253, RFC 5656, RFC 8709) and as an authorized_keys line.
//   * [subjectPublicKeyInfo]: the X.509 encoding the API's GET_PUBLIC_KEY
//     action returns.
//   * [sign]: a challenge signed with the subkey's private key, returned as
//     the full SSH signature blob (string type, string signature) that the
//     SSH authentication API hands back to the agent.
//   * [cardInput] / [blobFromCard]: the same signature made by an OpenPGP
//     card's authentication slot (INTERNAL AUTHENTICATE).
//
// Supported: Ed25519 (legacy EdDSA algo 22 and v6 algo 27), RSA (1, 3) with
// ssh-rsa / rsa-sha2-256 / rsa-sha2-512, and ECDSA (19) on NIST P-256, P-384
// and P-521. Ed448 has no OpenSSH key type and is not offered.

package com.pgpony.android.crypto.ssh

import com.pgpony.android.crypto.CertificateBindings
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.ECNamedDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.crypto.signers.RSADigestSigner
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest

object SshAuth {

    /** The API's hash algorithm codes (SshAuthenticationApi.SHA1 etc.). The
     *  agent passes the SSH sign-request flags here, which line up: 0 is
     *  ssh-rsa (SHA-1), 2 is rsa-sha2-256, 4 is rsa-sha2-512. */
    const val HASH_SHA1 = 0
    const val HASH_SHA256 = 2
    const val HASH_SHA512 = 4

    /** The API's public key algorithm codes for GET_PUBLIC_KEY. */
    const val API_RSA = 0
    const val API_ECDSA = 1
    const val API_EDDSA = 2

    private const val FLAG_AUTHENTICATE = 0x20
    private const val FLAGS_SIGN_OR_CERTIFY = 0x03

    private val ED25519_LEGACY_OID = byteArrayOf(0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA.toByte(), 0x47, 0x0F, 0x01)

    enum class Curve(val sshName: String, val oidDer: ByteArray, val oid: String, val fieldBytes: Int) {
        P256("nistp256", byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07), "1.2.840.10045.3.1.7", 32),
        P384("nistp384", byteArrayOf(0x2B, 0x81.toByte(), 0x04, 0x00, 0x22), "1.3.132.0.34", 48),
        P521("nistp521", byteArrayOf(0x2B, 0x81.toByte(), 0x04, 0x00, 0x23), "1.3.132.0.35", 66);

        fun digest(): Digest = when (this) {
            P256 -> SHA256Digest()
            P384 -> SHA384Digest()
            P521 -> SHA512Digest()
        }
    }

    /** Public key material of an SSH-capable key, parsed from its packet body. */
    sealed class Material {
        class Ed25519(val point: ByteArray) : Material()
        class Rsa(val n: BigInteger, val e: BigInteger) : Material()
        class Ecdsa(val curve: Curve, val q: ByteArray) : Material()

        val sshType: String
            get() = when (this) {
                is Ed25519 -> "ssh-ed25519"
                is Rsa -> "ssh-rsa"
                is Ecdsa -> "ecdsa-sha2-${curve.sshName}"
            }
    }

    /**
     * The authentication subkey to use from [rawCertificate], or null.
     *
     * A subkey that also carries Sign (0x02) or Certify (0x01) is never used:
     * the SSH API signs bytes the caller chooses, so a dual-use subkey could
     * be made to produce a signature OpenPGP would accept as a data or
     * certification signature. Only a dedicated Authenticate subkey signs.
     */
    fun authSubkey(rawCertificate: ByteArray, nowMs: Long = System.currentTimeMillis()): CertificateBindings.SubkeyState? =
        authCandidates(rawCertificate, nowMs)
            ?.filter { (it.keyFlags ?: 0) and FLAGS_SIGN_OR_CERTIFY == 0 }
            ?.maxByOrNull { it.createdAtMs }

    /**
     * True when [rawCertificate] has no usable authentication subkey only
     * because every Authenticate subkey it has can also sign or certify (a
     * GnuPG [SA] subkey, say), so the caller can say what to do about it.
     */
    fun onlyDualUseAuthSubkeys(rawCertificate: ByteArray, nowMs: Long = System.currentTimeMillis()): Boolean {
        val candidates = authCandidates(rawCertificate, nowMs) ?: return false
        return candidates.isNotEmpty() && candidates.all { (it.keyFlags ?: 0) and FLAGS_SIGN_OR_CERTIFY != 0 }
    }

    /** Bound, live, SSH-capable subkeys with the Authenticate flag. */
    private fun authCandidates(rawCertificate: ByteArray, nowMs: Long): List<CertificateBindings.SubkeyState>? {
        val report = CertificateBindings.analyze(rawCertificate) ?: return null
        if (!report.supported || report.primaryRevoked) return null
        if (report.primaryExpiresAtMs != null && report.primaryExpiresAtMs <= nowMs) return null
        return report.subkeys.filter { s ->
            s.bound && !s.revoked &&
                (s.keyFlags ?: 0) and FLAG_AUTHENTICATE != 0 &&
                (s.expiresAtMs == null || s.expiresAtMs > nowMs) &&
                material(s.publicBody) != null
        }
    }

    /** True when [rawCertificate] has a usable authentication subkey. */
    fun hasAuthSubkey(rawCertificate: ByteArray): Boolean = authSubkey(rawCertificate) != null

    /**
     * SSH-usable material from a public key packet body (version, creation
     * time, algorithm, [v5/v6 material length], material), or null when the
     * algorithm or curve has no SSH key type.
     */
    fun material(publicBody: ByteArray): Material? = runCatching {
        val version = publicBody[0].toInt() and 0xFF
        val algo = publicBody[5].toInt() and 0xFF
        var at = if (version == 4) 6 else 10
        when (algo) {
            27 -> Material.Ed25519(publicBody.copyOfRange(at, at + 32))
            22 -> {
                val oidLen = publicBody[at].toInt() and 0xFF
                val oid = publicBody.copyOfRange(at + 1, at + 1 + oidLen)
                if (!oid.contentEquals(ED25519_LEGACY_OID)) return@runCatching null
                at += 1 + oidLen
                val (point, _) = mpi(publicBody, at)
                // Native point encoding: 0x40 prefix + 32 octets.
                if (point.size != 33 || point[0] != 0x40.toByte()) return@runCatching null
                Material.Ed25519(point.copyOfRange(1, 33))
            }
            1, 3 -> {
                val (n, next) = mpi(publicBody, at)
                val (e, _) = mpi(publicBody, next)
                Material.Rsa(BigInteger(1, n), BigInteger(1, e))
            }
            19 -> {
                val oidLen = publicBody[at].toInt() and 0xFF
                val oid = publicBody.copyOfRange(at + 1, at + 1 + oidLen)
                val curve = Curve.entries.firstOrNull { it.oidDer.contentEquals(oid) } ?: return@runCatching null
                at += 1 + oidLen
                val (q, _) = mpi(publicBody, at)
                if (q.isEmpty() || q[0] != 0x04.toByte()) return@runCatching null
                Material.Ecdsa(curve, q)
            }
            else -> null
        }
    }.getOrNull()

    /** The key in SSH public key wire format (the base64 part of a .pub line). */
    fun publicBlob(m: Material): ByteArray = SshWire().apply {
        string(m.sshType)
        when (m) {
            is Material.Ed25519 -> string(m.point)
            is Material.Rsa -> { mpint(m.e); mpint(m.n) }
            is Material.Ecdsa -> { string(m.curve.sshName); string(m.q) }
        }
    }.bytes()

    /** An authorized_keys / .pub line: "type base64 comment". */
    fun authorizedKeysLine(m: Material, comment: String): String {
        val b64 = java.util.Base64.getEncoder().encodeToString(publicBlob(m))
        val c = comment.replace(Regex("[\\r\\n]"), " ").trim()
        return if (c.isEmpty()) "${m.sshType} $b64" else "${m.sshType} $b64 $c"
    }

    /** OpenSSH's SHA256 fingerprint of the key, "SHA256:..." (unpadded base64). */
    fun sshFingerprint(m: Material): String {
        val d = MessageDigest.getInstance("SHA-256").digest(publicBlob(m))
        return "SHA256:" + java.util.Base64.getEncoder().withoutPadding().encodeToString(d)
    }

    /** X.509 SubjectPublicKeyInfo (DER) and the API algorithm code. */
    fun subjectPublicKeyInfo(m: Material): Pair<ByteArray, Int> = when (m) {
        is Material.Ed25519 ->
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(Ed25519PublicKeyParameters(m.point, 0)).encoded to API_EDDSA
        is Material.Rsa ->
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(RSAKeyParameters(false, m.n, m.e)).encoded to API_RSA
        is Material.Ecdsa -> {
            val oid = ASN1ObjectIdentifier(m.curve.oid)
            val x9 = ECNamedCurveTable.getByOID(oid)
            val dom = ECNamedDomainParameters(oid, x9)
            val q = x9.curve.decodePoint(m.q)
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ECPublicKeyParameters(q, dom)).encoded to API_ECDSA
        }
    }

    class UnsupportedHash(message: String) : IllegalArgumentException(message)

    private fun rsaSigName(hash: Int): String = when (hash) {
        HASH_SHA1 -> "ssh-rsa"
        HASH_SHA256 -> "rsa-sha2-256"
        HASH_SHA512 -> "rsa-sha2-512"
        else -> throw UnsupportedHash("RSA signing needs SHA-1, SHA-256 or SHA-512")
    }

    private fun rsaDigest(hash: Int): Digest = when (hash) {
        HASH_SHA1 -> SHA1Digest()
        HASH_SHA256 -> SHA256Digest()
        HASH_SHA512 -> SHA512Digest()
        else -> throw UnsupportedHash("RSA signing needs SHA-1, SHA-256 or SHA-512")
    }

    /**
     * [challenge] signed with [privateKey] (a Bouncy Castle key parameter, as
     * BcPGPKeyConverter returns for the auth subkey), as the SSH signature
     * blob. [hash] matters only for RSA; Ed25519 is PureEdDSA and ECDSA uses
     * the curve's hash (RFC 5656).
     */
    fun sign(m: Material, privateKey: AsymmetricKeyParameter, challenge: ByteArray, hash: Int): ByteArray =
        when (m) {
            is Material.Ed25519 -> {
                val signer = Ed25519Signer()
                signer.init(true, privateKey as Ed25519PrivateKeyParameters)
                signer.update(challenge, 0, challenge.size)
                ed25519Blob(signer.generateSignature())
            }
            is Material.Rsa -> {
                val name = rsaSigName(hash)
                val signer = RSADigestSigner(rsaDigest(hash))
                signer.init(true, privateKey)
                signer.update(challenge, 0, challenge.size)
                rsaBlob(name, signer.generateSignature(), m)
            }
            is Material.Ecdsa -> {
                val d = m.curve.digest()
                val h = ByteArray(d.digestSize)
                d.update(challenge, 0, challenge.size)
                d.doFinal(h, 0)
                val signer = ECDSASigner(HMacDSAKCalculator(m.curve.digest()))
                signer.init(true, privateKey as ECPrivateKeyParameters)
                val rs = signer.generateSignature(h)
                ecdsaBlob(m, rs[0], rs[1])
            }
        }

    // ── OpenPGP card authentication slot ──────────────────────────────

    /** PKCS#1 v1.5 DigestInfo prefixes (RFC 8017 section 9.2, note 1). */
    private val DIGEST_INFO_SHA1 = hex("3021300906052b0e03021a05000414")
    private val DIGEST_INFO_SHA256 = hex("3031300d060960864801650304020105000420")
    private val DIGEST_INFO_SHA512 = hex("3051300d060960864801650304020305000440")

    /**
     * The INTERNAL AUTHENTICATE input for [challenge]: the DigestInfo for RSA
     * (the card adds the padding), the message itself for EdDSA (the card
     * computes PureEdDSA), the curve hash for ECDSA.
     */
    fun cardInput(m: Material, challenge: ByteArray, hash: Int): ByteArray = when (m) {
        is Material.Ed25519 -> challenge
        is Material.Rsa -> {
            rsaSigName(hash)
            val (prefix, alg) = when (hash) {
                HASH_SHA1 -> DIGEST_INFO_SHA1 to "SHA-1"
                HASH_SHA256 -> DIGEST_INFO_SHA256 to "SHA-256"
                else -> DIGEST_INFO_SHA512 to "SHA-512"
            }
            prefix + MessageDigest.getInstance(alg).digest(challenge)
        }
        is Material.Ecdsa -> {
            val d = m.curve.digest()
            val h = ByteArray(d.digestSize)
            d.update(challenge, 0, challenge.size)
            d.doFinal(h, 0)
            h
        }
    }

    /** The SSH signature blob from the card's raw INTERNAL AUTHENTICATE output. */
    fun blobFromCard(m: Material, raw: ByteArray, hash: Int): ByteArray = when (m) {
        is Material.Ed25519 -> {
            require(raw.size == 64) { "Card returned a ${raw.size}-octet Ed25519 signature" }
            ed25519Blob(raw)
        }
        is Material.Rsa -> rsaBlob(rsaSigName(hash), raw, m)
        is Material.Ecdsa -> {
            // The card returns r || s, each the curve's field length.
            require(raw.size % 2 == 0) { "Malformed ECDSA signature from card" }
            val half = raw.size / 2
            ecdsaBlob(m, BigInteger(1, raw.copyOfRange(0, half)), BigInteger(1, raw.copyOfRange(half, raw.size)))
        }
    }

    // ── Blob builders ─────────────────────────────────────────────────

    private fun ed25519Blob(sig: ByteArray): ByteArray =
        SshWire().apply { string("ssh-ed25519"); string(sig) }.bytes()

    private fun rsaBlob(name: String, sig: ByteArray, m: Material.Rsa): ByteArray {
        // RFC 8332: the signature octet string is the modulus length.
        val modLen = (m.n.bitLength() + 7) / 8
        val s = if (sig.size < modLen) ByteArray(modLen - sig.size) + sig else sig
        return SshWire().apply { string(name); string(s) }.bytes()
    }

    private fun ecdsaBlob(m: Material.Ecdsa, r: BigInteger, s: BigInteger): ByteArray {
        val inner = SshWire().apply { mpint(r); mpint(s) }.bytes()
        return SshWire().apply { string(m.sshType); string(inner) }.bytes()
    }

    // ── Helpers ───────────────────────────────────────────────────────

    /** An OpenPGP MPI at [at]: its magnitude octets and the offset after it. */
    private fun mpi(b: ByteArray, at: Int): Pair<ByteArray, Int> {
        val bits = ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)
        val len = (bits + 7) / 8
        return b.copyOfRange(at + 2, at + 2 + len) to (at + 2 + len)
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { i ->
        s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }

    /** Parse an SSH signature blob back into (type, signature octets). For tests. */
    internal fun parseSignatureBlob(blob: ByteArray): Pair<String, ByteArray> {
        val r = SshWire.Reader(blob)
        return String(r.string(), Charsets.US_ASCII) to r.string()
    }
}

/** SSH wire encoding (RFC 4251 section 5). */
class SshWire {
    private val out = ByteArrayOutputStream()

    fun uint32(v: Int) {
        out.write((v ushr 24) and 0xFF); out.write((v ushr 16) and 0xFF)
        out.write((v ushr 8) and 0xFF); out.write(v and 0xFF)
    }

    fun string(b: ByteArray) { uint32(b.size); out.write(b) }
    fun string(s: String) = string(s.toByteArray(Charsets.US_ASCII))

    /** mpint: two's complement, minimal, a zero octet ahead of a set high bit. */
    fun mpint(v: BigInteger) {
        if (v.signum() == 0) { uint32(0); return }
        string(v.toByteArray())
    }

    fun bytes(): ByteArray = out.toByteArray()

    class Reader(private val b: ByteArray) {
        private var at = 0
        fun uint32(): Int {
            val v = ((b[at].toInt() and 0xFF) shl 24) or ((b[at + 1].toInt() and 0xFF) shl 16) or
                ((b[at + 2].toInt() and 0xFF) shl 8) or (b[at + 3].toInt() and 0xFF)
            at += 4
            return v
        }
        fun string(): ByteArray {
            val n = uint32()
            val s = b.copyOfRange(at, at + n)
            at += n
            return s
        }
        val remaining: Int get() = b.size - at
    }
}
