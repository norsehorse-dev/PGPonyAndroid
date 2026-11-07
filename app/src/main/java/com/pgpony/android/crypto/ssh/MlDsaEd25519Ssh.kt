// MlDsaEd25519Ssh.kt
// PGPony Android, 4.8.0 RC7 (item 1): SSH-only keys of the experimental
// composite type ssh-mldsa44-ed25519, which OpenSSH 10.6 turns on by default.
//
// The OpenPGP post-quantum spec has no ML-DSA-44 composite, so this key cannot
// live in the OpenPGP keyring. It is a plain SSH key held on the phone, in the
// same wire format OpenSSH 10.6 uses (ssh-mldsa-eddsa.c, crypto_api.h), which
// follows draft-ietf-sshm-composite-sigs-00 (still the only revision, so the
// type stays experimental):
//
//   public key blob   string(type) + string(ML-DSA-44 pk[1312] || Ed25519 pk[32])
//   private key       ML-DSA-44 seed[32] (FIPS 204 KeyGen_internal xi) ||
//                     Ed25519 seed[32] (RFC 8032); nothing expanded is stored
//   signature blob    string(type) + string(ML-DSA-44 sig[2420] || Ed25519 sig[64])
//
// Both halves sign the same composite input
//   M' = "CompositeAlgorithmSignatures2025" || "COMPSIG-MLDSA44-Ed25519-SHA512"
//        || u8(len(ctx)) || ctx || SHA-512(data)
// where ctx is always empty at the SSH layer. ML-DSA-44 signs M' in pure mode
// with the label as its FIPS 204 context; Ed25519 signs M' plainly. ML-DSA is
// hedged (fresh randomness per signature), as in OpenSSH; a verifier cannot
// tell hedged from deterministic signatures apart.
//
// 4.8.0 RC7 (item 1): names. OpenSSH 10.4 and 10.5 called the type
// ssh-mldsa44-ed25519@openssh.com; 10.6 took the IANA name
// ssh-mldsa44-ed25519 and dropped the old one with no alias, so no OpenSSH
// release reads both. The blob, private section, signature layout and M' did
// not change, only the name string (and so the SHA256 fingerprint, which
// hashes the whole blob). PGPony writes only the new name. The old one is
// read from key files, .pub lines and public blobs, and such a key comes out
// under the new name; a signature must carry the new name, as 10.6 requires.
//
// Pure JVM code (Bouncy Castle 1.85, crypto.params / crypto.signers, not the
// deprecated pqc.crypto.mldsa classes), so all of it tests on the JVM.

package com.pgpony.android.crypto.ssh

import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.params.ParametersWithContext
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.MLDSASigner
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Wire constants and stateless helpers for ssh-mldsa44-ed25519. */
object MlDsaEd25519Ssh {

    /** The name OpenSSH 10.6 and draft-ietf-sshm-composite-sigs-00 use, the
     *  only one 10.6 reads. PGPony writes this one everywhere (public blob,
     *  .pub line, key file, signature blob). */
    const val KEY_TYPE = "ssh-mldsa44-ed25519"

    /** 4.8.0 RC7 (item 1): the vendor name OpenSSH 10.4 and 10.5 used. Read
     *  from key files, .pub lines and public blobs so a key made there still
     *  imports, then re-encoded under [KEY_TYPE]. Never written, and not
     *  accepted on a signature. */
    const val LEGACY_KEY_TYPE = "ssh-mldsa44-ed25519@openssh.com"

    const val MLDSA_PUBLIC_LEN = 1312
    const val ED25519_PUBLIC_LEN = 32
    const val PUBLIC_LEN = MLDSA_PUBLIC_LEN + ED25519_PUBLIC_LEN          // 1344
    const val SEED_LEN = 32
    const val PRIVATE_LEN = 2 * SEED_LEN                                  // 64
    const val MLDSA_SIGNATURE_LEN = 2420
    const val ED25519_SIGNATURE_LEN = 64
    const val SIGNATURE_LEN = MLDSA_SIGNATURE_LEN + ED25519_SIGNATURE_LEN // 2484

    private val PREFIX = "CompositeAlgorithmSignatures2025".toByteArray(Charsets.US_ASCII)
    private val LABEL = "COMPSIG-MLDSA44-Ed25519-SHA512".toByteArray(Charsets.US_ASCII)

    /** True for either name of this key type, as read from a key file, a
     *  .pub line or a public blob (see [LEGACY_KEY_TYPE]). */
    fun isKeyType(name: String): Boolean = name == KEY_TYPE || name == LEGACY_KEY_TYPE

    /** True when [blob] is an SSH public key blob of this type. */
    fun isPublicBlob(blob: ByteArray): Boolean = runCatching { parsePublicBlob(blob) }.isSuccess

    // ── Composite signature primitive ────────────────────────────────

    /**
     * The composite signing input M' for [message] under context [ctx]
     * (OpenSSH 10.6 ssh-mldsa-eddsa.c:99-137, construct_m_prime). [ctx] is
     * empty for SSH; a non-empty one is only for the draft's test vectors.
     */
    fun compositeInput(message: ByteArray, ctx: ByteArray = ByteArray(0)): ByteArray {
        require(ctx.size <= 255) { "Composite context longer than 255 octets" }
        val h = ByteArray(64)
        SHA512Digest().apply { update(message, 0, message.size); doFinal(h, 0) }
        val out = ByteArray(PREFIX.size + LABEL.size + 1 + ctx.size + h.size)
        var at = 0
        System.arraycopy(PREFIX, 0, out, at, PREFIX.size); at += PREFIX.size
        System.arraycopy(LABEL, 0, out, at, LABEL.size); at += LABEL.size
        out[at++] = ctx.size.toByte()
        System.arraycopy(ctx, 0, out, at, ctx.size); at += ctx.size
        System.arraycopy(h, 0, out, at, h.size)
        return out
    }

    /**
     * The 1344-octet composite public key for 64 octets of seeds
     * (ML-DSA-44 seed || Ed25519 seed).
     */
    fun publicKeyFromSeeds(seeds: ByteArray): ByteArray {
        require(seeds.size == PRIVATE_LEN) { "Expected $PRIVATE_LEN seed octets, got ${seeds.size}" }
        val mlSeed = seeds.copyOfRange(0, SEED_LEN)
        val edSeed = seeds.copyOfRange(SEED_LEN, PRIVATE_LEN)
        try {
            val ml = MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, mlSeed)
            val ed = Ed25519PrivateKeyParameters(edSeed)
            val mlPub = ml.publicKey
            check(mlPub.size == MLDSA_PUBLIC_LEN) { "ML-DSA-44 public key is ${mlPub.size} octets" }
            return mlPub + ed.generatePublicKey().encoded
        } finally {
            mlSeed.fill(0)
            edSeed.fill(0)
        }
    }

    /**
     * The raw 2484-octet composite signature of [message] with [seeds].
     * [rng] null signs ML-DSA deterministically (FIPS 204, rnd all zero);
     * otherwise hedged, as OpenSSH does.
     */
    fun compositeSign(
        seeds: ByteArray,
        message: ByteArray,
        ctx: ByteArray = ByteArray(0),
        rng: SecureRandom? = SecureRandom()
    ): ByteArray {
        require(seeds.size == PRIVATE_LEN) { "Expected $PRIVATE_LEN seed octets, got ${seeds.size}" }
        val m = compositeInput(message, ctx)
        val mlSeed = seeds.copyOfRange(0, SEED_LEN)
        val edSeed = seeds.copyOfRange(SEED_LEN, PRIVATE_LEN)
        try {
            val ml = MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, mlSeed)
            val mlParams = if (rng != null) ParametersWithRandom(ml, rng) else ml
            val mlSig = MLDSASigner().run {
                init(true, ParametersWithContext(mlParams, LABEL))
                update(m, 0, m.size)
                generateSignature()
            }
            check(mlSig.size == MLDSA_SIGNATURE_LEN) { "ML-DSA-44 signature is ${mlSig.size} octets" }
            val edSig = Ed25519Signer().run {
                init(true, Ed25519PrivateKeyParameters(edSeed))
                update(m, 0, m.size)
                generateSignature()
            }
            return mlSig + edSig
        } finally {
            mlSeed.fill(0)
            edSeed.fill(0)
        }
    }

    /** True when [signature] (2484 octets) is a valid composite signature of [message]. */
    fun compositeVerify(
        publicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
        ctx: ByteArray = ByteArray(0)
    ): Boolean {
        if (publicKey.size != PUBLIC_LEN || signature.size != SIGNATURE_LEN || ctx.size > 255) return false
        val m = compositeInput(message, ctx)
        val mlOk = runCatching {
            MLDSASigner().run {
                init(false, ParametersWithContext(
                    MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, publicKey.copyOfRange(0, MLDSA_PUBLIC_LEN)),
                    LABEL
                ))
                update(m, 0, m.size)
                verifySignature(signature.copyOfRange(0, MLDSA_SIGNATURE_LEN))
            }
        }.getOrDefault(false)
        val edOk = runCatching {
            Ed25519Signer().run {
                init(false, Ed25519PublicKeyParameters(publicKey, MLDSA_PUBLIC_LEN))
                update(m, 0, m.size)
                verifySignature(signature.copyOfRange(MLDSA_SIGNATURE_LEN, SIGNATURE_LEN))
            }
        }.getOrDefault(false)
        // Both halves must hold; evaluate both so timing does not say which failed.
        return mlOk and edOk
    }

    // ── SSH encodings ────────────────────────────────────────────────

    /** The SSH public key blob (the base64 part of a .pub line). */
    fun publicBlob(publicKey: ByteArray): ByteArray {
        require(publicKey.size == PUBLIC_LEN) { "Expected a $PUBLIC_LEN-octet public key, got ${publicKey.size}" }
        return SshWire().apply { string(KEY_TYPE); string(publicKey) }.bytes()
    }

    /**
     * The 1344-octet public key from an SSH public key blob of either type
     * name ([KEY_TYPE] or [LEGACY_KEY_TYPE]); [publicBlob] re-encodes it under
     * [KEY_TYPE]. Throws [SshFormatException] for any other blob.
     */
    fun parsePublicBlob(blob: ByteArray): ByteArray {
        val r = SshReader(blob)
        val type = r.cstring()
        if (!isKeyType(type)) throw SshFormatException("Not an $KEY_TYPE key: $type")
        val pk = r.string()
        if (pk.size != PUBLIC_LEN) throw SshFormatException("Public key is ${pk.size} octets, expected $PUBLIC_LEN")
        r.requireEnd()
        return pk
    }

    /** An authorized_keys / .pub line: "type base64[ comment]". */
    fun publicKeyLine(publicKey: ByteArray, comment: String = ""): String {
        val b64 = Base64.getEncoder().encodeToString(publicBlob(publicKey))
        val c = comment.replace(Regex("[\\r\\n]"), " ").trim()
        return if (c.isEmpty()) "$KEY_TYPE $b64" else "$KEY_TYPE $b64 $c"
    }

    /**
     * The public key and comment from a .pub line under either type name (the
     * line's name and the blob's must agree). Throws [SshFormatException]
     * when the line is not this key type.
     */
    fun parsePublicKeyLine(line: String): Pair<ByteArray, String> {
        val parts = line.trim().split(Regex("\\s+"), limit = 3)
        if (parts.size < 2 || !isKeyType(parts[0])) throw SshFormatException("Not an $KEY_TYPE public key line")
        val blob = runCatching { Base64.getDecoder().decode(parts[1]) }
            .getOrElse { throw SshFormatException("Public key line is not valid base64") }
        val pk = parsePublicBlob(blob)
        val blobType = SshReader(blob).cstring()
        if (blobType != parts[0]) throw SshFormatException("Key type in the line and in the key differ")
        return pk to (parts.getOrNull(2) ?: "")
    }

    /** OpenSSH's SHA256 fingerprint, as ssh-keygen -l prints it ("SHA256:" + unpadded base64). */
    fun fingerprint(publicKey: ByteArray): String =
        fingerprintOfBlob(publicBlob(publicKey))

    /** The fingerprint of an SSH public key blob as given (any type). */
    fun fingerprintOfBlob(blob: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(blob)
        return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(d)
    }

    /** The SSH signature blob for a raw 2484-octet composite signature. */
    fun signatureBlob(signature: ByteArray): ByteArray {
        require(signature.size == SIGNATURE_LEN) { "Expected a $SIGNATURE_LEN-octet signature, got ${signature.size}" }
        return SshWire().apply { string(KEY_TYPE); string(signature) }.bytes()
    }

    /**
     * The raw composite signature from an SSH signature blob, as OpenSSH
     * 10.6's verifier reads it (ssh-mldsa-eddsa.c:424-432): exactly
     * [KEY_TYPE], exactly 2484 octets, no trailing data.
     * 4.8.0 RC7 (item 1): [LEGACY_KEY_TYPE] is refused here. 10.6 compares
     * the name exactly, so a signature under the old name would fail there.
     */
    fun parseSignatureBlob(blob: ByteArray): ByteArray {
        val r = SshReader(blob)
        val type = r.cstring()
        if (type != KEY_TYPE) throw SshFormatException("Not an $KEY_TYPE signature: $type")
        val sig = r.string()
        if (sig.size != SIGNATURE_LEN) throw SshFormatException("Signature is ${sig.size} octets, expected $SIGNATURE_LEN")
        r.requireEnd()
        return sig
    }

    /** True when the SSH signature [blob] is valid for [data] under [publicKey]. */
    fun verify(publicKey: ByteArray, blob: ByteArray, data: ByteArray): Boolean {
        val sig = runCatching { parseSignatureBlob(blob) }.getOrNull() ?: return false
        return compositeVerify(publicKey, data, sig)
    }
}

/**
 * An ssh-mldsa44-ed25519 private key: the two 32-octet seeds and
 * the public key derived from them. Holds only a copy of the seeds; [close]
 * wipes it. Bouncy Castle key objects (which hold the expanded ML-DSA key) are
 * made per signature and dropped, so the expanded key does not stay in memory.
 */
class MlDsaEd25519Key private constructor(
    private val seeds: ByteArray,
    /** The 1344-octet composite public key. */
    val publicKey: ByteArray
) : AutoCloseable {

    companion object {
        /** From the 64 private octets (ML-DSA-44 seed || Ed25519 seed). The
         *  argument is copied, so the caller wipes its own array. */
        fun fromPrivateBytes(seeds: ByteArray): MlDsaEd25519Key {
            require(seeds.size == MlDsaEd25519Ssh.PRIVATE_LEN) {
                "Expected ${MlDsaEd25519Ssh.PRIVATE_LEN} private octets, got ${seeds.size}"
            }
            val copy = seeds.copyOf()
            return MlDsaEd25519Key(copy, MlDsaEd25519Ssh.publicKeyFromSeeds(copy))
        }

        /** From the two seeds separately. */
        fun fromSeeds(mldsaSeed: ByteArray, ed25519Seed: ByteArray): MlDsaEd25519Key {
            require(mldsaSeed.size == MlDsaEd25519Ssh.SEED_LEN && ed25519Seed.size == MlDsaEd25519Ssh.SEED_LEN) {
                "Each seed must be ${MlDsaEd25519Ssh.SEED_LEN} octets"
            }
            val both = mldsaSeed + ed25519Seed
            try {
                return fromPrivateBytes(both)
            } finally {
                both.fill(0)
            }
        }

        /** A new key from fresh random seeds. */
        fun generate(rng: SecureRandom = SecureRandom()): MlDsaEd25519Key {
            val seeds = ByteArray(MlDsaEd25519Ssh.PRIVATE_LEN).also { rng.nextBytes(it) }
            try {
                return fromPrivateBytes(seeds)
            } finally {
                seeds.fill(0)
            }
        }
    }

    @Volatile
    private var closed = false

    /** The SSH public key blob. */
    val publicBlob: ByteArray get() = MlDsaEd25519Ssh.publicBlob(publicKey)

    /** "SHA256:..." as ssh-keygen -l prints it. */
    val fingerprint: String get() = MlDsaEd25519Ssh.fingerprint(publicKey)

    /** The authorized_keys line with [comment]. */
    fun publicKeyLine(comment: String = ""): String = MlDsaEd25519Ssh.publicKeyLine(publicKey, comment)

    /** A copy of the 64 private octets, for storage and export. The caller wipes it. */
    fun privateBytes(): ByteArray {
        check(!closed) { "Key is closed" }
        return seeds.copyOf()
    }

    /**
     * [data] signed as SSH signs (userauth request, SSHSIG blob, whatever the
     * agent hands over), returned as the full SSH signature blob
     * string(type) + string(sig).
     */
    fun sign(data: ByteArray, rng: SecureRandom? = SecureRandom()): ByteArray {
        check(!closed) { "Key is closed" }
        return MlDsaEd25519Ssh.signatureBlob(MlDsaEd25519Ssh.compositeSign(seeds, data, rng = rng))
    }

    /** True when the SSH signature [blob] is valid for [data] under this key. */
    fun verify(blob: ByteArray, data: ByteArray): Boolean = MlDsaEd25519Ssh.verify(publicKey, blob, data)

    /** Wipes the seed copy. Further [sign] or [privateBytes] calls fail. */
    override fun close() {
        closed = true
        seeds.fill(0)
    }
}

/** A malformed or unexpected SSH encoding. */
class SshFormatException(message: String) : IllegalArgumentException(message)

/**
 * A bounds-checked reader for SSH wire data (RFC 4251 section 5) from files
 * and blobs that may be hostile: every length is checked against what is left,
 * and a short or oversized field throws [SshFormatException] instead of an
 * index error.
 */
internal class SshReader(private val b: ByteArray, private var at: Int = 0) {

    val remaining: Int get() = b.size - at

    fun u32(): Long {
        if (remaining < 4) throw SshFormatException("Truncated SSH data")
        val v = ((b[at].toLong() and 0xFF) shl 24) or ((b[at + 1].toLong() and 0xFF) shl 16) or
            ((b[at + 2].toLong() and 0xFF) shl 8) or (b[at + 3].toLong() and 0xFF)
        at += 4
        return v
    }

    fun raw(n: Int): ByteArray {
        if (n < 0 || n > remaining) throw SshFormatException("Truncated SSH data")
        val out = b.copyOfRange(at, at + n)
        at += n
        return out
    }

    fun string(): ByteArray {
        val n = u32()
        if (n > remaining) throw SshFormatException("SSH string runs past the end of the data")
        return raw(n.toInt())
    }

    /** A string that must be printable ASCII (a type, cipher or KDF name). */
    fun cstring(): String {
        val s = string()
        if (s.any { it < 0x20 || it > 0x7E }) throw SshFormatException("Unexpected characters in an SSH name")
        return String(s, Charsets.US_ASCII)
    }

    fun u8(): Int {
        if (remaining < 1) throw SshFormatException("Truncated SSH data")
        return b[at++].toInt() and 0xFF
    }

    fun requireEnd() {
        if (remaining != 0) throw SshFormatException("Trailing data after the SSH structure")
    }
}
