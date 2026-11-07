// OpenSshKeyFile.kt
// PGPony Android, 4.8.0 RC7 (item 1): read and write OpenSSH private key files
// (openssh-key-v1) for ssh-mldsa44-ed25519 keys.
//
// Layout (OpenSSH 10.6 sshkey.c, sshkey_private_to_blob2 and private2_decrypt):
//
//   "-----BEGIN OPENSSH PRIVATE KEY-----\n" base64 (70 per line) "-----END ...\n"
//   "openssh-key-v1\0"
//   string ciphername      "none" or e.g. "aes256-ctr"
//   string kdfname         "none" or "bcrypt"
//   string kdfoptions      empty, or string(salt[16]) + u32 rounds
//   u32    number of keys  (1)
//   string public key blob
//   string private section (encrypted unless "none"), which holds:
//       u32 check, u32 check (equal; a mismatch means a wrong passphrase)
//       string type, string pk[1344], string sk[64] (the two seeds)
//       string comment
//       padding 1, 2, 3, ... to the cipher block size (8 for "none")
//
// ssh-keygen writes aes256-ctr with bcrypt_pbkdf, a 16-octet salt and 32
// rounds by default (sshkey.c DEFAULT_ROUNDS, 24 before 10.6). bcrypt_pbkdf is Bouncy
// Castle's BCrypt.pbkdfGenerate (bcprov 1.85), the OpenSSH variant, not the
// OpenBSD password hash. Reading takes the AES CTR and CBC ciphers OpenSSH
// offers; chacha20-poly1305@openssh.com and the GCM ciphers are refused with
// a clear error. Any key type other than this one is refused too.
//
// 4.8.0 RC7 (item 1): files are written under the OpenSSH 10.6 name
// ssh-mldsa44-ed25519 only. A file ssh-keygen 10.4 or 10.5 wrote, under
// ssh-mldsa44-ed25519@openssh.com, still reads (the layout is the same), and
// the key comes out under the new name, as everything MlDsaEd25519Key encodes.

package com.pgpony.android.crypto.ssh

import org.bouncycastle.crypto.generators.BCrypt
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object OpenSshKeyFile {

    /** bcrypt_pbkdf rounds ssh-keygen uses when -a is not given.
     *  4.8.0 RC7 (item 1): 32, as OpenSSH 10.6 (sshkey.c DEFAULT_ROUNDS was 24
     *  up to 10.5). */
    const val DEFAULT_ROUNDS = 32

    /** Highest bcrypt_pbkdf round count accepted from a file. A hostile file
     *  could otherwise ask for billions of rounds and hang the import.
     *  4.8.0 RC7 (item 1): lowered from 1000, which took about 7 s on a desktop
     *  JVM and would take far longer on a phone. ssh-keygen writes 32 by
     *  default (24 before 10.6) and -a 100 is a common hardened choice, so 256 leaves room
     *  above both. [inspect] reports a file past it before any passphrase is
     *  asked. */
    const val MAX_ROUNDS = 256

    const val SALT_LEN = 16

    /** The cipher written for a passphrase-protected file. */
    const val DEFAULT_CIPHER = "aes256-ctr"

    private const val BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
    private const val END = "-----END OPENSSH PRIVATE KEY-----"
    private val AUTH_MAGIC = "openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII)
    private const val NONE_BLOCK_SIZE = 8

    /** Why a file could not be read. The message is English, for logs. */
    sealed class ReadError(message: String) : Exception(message) {
        /** Not an OpenSSH private key file, or a damaged one. */
        class Malformed(val reason: String) : ReadError("Not a readable OpenSSH private key: $reason")
        /** A valid file holding some other key type (ssh-ed25519, rsa...). */
        class UnsupportedKeyType(val keyType: String) :
            ReadError("This file holds a $keyType key, not an ${MlDsaEd25519Ssh.KEY_TYPE} key")
        /** Encrypted with a cipher or KDF setting PGPony does not read. */
        class UnsupportedEncryption(val detail: String) : ReadError("Unsupported key file encryption: $detail")
        /** The file is passphrase-protected and no passphrase was given. */
        class PassphraseRequired : ReadError("This key file is protected by a passphrase")
        /** The passphrase did not open the file. */
        class WrongPassphrase : ReadError("Wrong passphrase for this key file")
    }

    /** What the unencrypted part of a file says, read without a passphrase. */
    class Info(
        /** The key type of the public key in the file, as the file names it
         *  (for a 10.4 or 10.5 file, [MlDsaEd25519Ssh.LEGACY_KEY_TYPE]; test
         *  it with [MlDsaEd25519Ssh.isKeyType]). */
        val keyType: String,
        /** True when the private section is encrypted. */
        val encrypted: Boolean,
        val cipher: String,
        val kdf: String,
        /** The 1344-octet public key when [keyType] is this type, else null. */
        val publicKey: ByteArray?,
        /** 4.8.0 RC7 (item 1): the bcrypt_pbkdf rounds in the KDF options, or
         *  null when the file has none or they do not parse. */
        val rounds: Long? = null,
        /** 4.8.0 RC7 (item 1): why [read] would refuse this file's encryption
         *  (an unsupported cipher or KDF, or rounds above [MAX_ROUNDS]), as
         *  [ReadError.UnsupportedEncryption.detail]; null when it can be read.
         *  Known before a passphrase is asked, so the UI refuses first. */
        val unsupportedEncryption: String? = null
    )

    /** A key read from a file, with the file's comment. Close [key] when done. */
    class Decoded(val key: MlDsaEd25519Key, val comment: String)

    private class Envelope(
        val cipher: String,
        val kdf: String,
        val kdfOptions: ByteArray,
        val publicBlob: ByteArray,
        val publicType: String,
        val encryptedLength: Int,
        val privateSection: ByteArray,
        /** Octets after the private section (an AEAD tag; none for the ciphers read here). */
        val trailing: Int
    )

    private class CipherSpec(val name: String, val transform: String, val keyLen: Int, val ivLen: Int, val blockSize: Int)

    private class KdfParams(val salt: ByteArray, val rounds: Long)

    private val CIPHERS = listOf(
        CipherSpec("aes128-ctr", "AES/CTR/NoPadding", 16, 16, 16),
        CipherSpec("aes192-ctr", "AES/CTR/NoPadding", 24, 16, 16),
        CipherSpec("aes256-ctr", "AES/CTR/NoPadding", 32, 16, 16),
        CipherSpec("aes128-cbc", "AES/CBC/NoPadding", 16, 16, 16),
        CipherSpec("aes192-cbc", "AES/CBC/NoPadding", 24, 16, 16),
        CipherSpec("aes256-cbc", "AES/CBC/NoPadding", 32, 16, 16)
    ).associateBy { it.name }

    /** True when [fileBytes] looks like an OpenSSH private key file (by its armor line). */
    fun looksLikeKeyFile(fileBytes: ByteArray): Boolean =
        String(fileBytes, Charsets.UTF_8).contains(BEGIN)

    /**
     * Read the unencrypted header of [fileBytes]: key type and whether a
     * passphrase is needed. Lets a caller refuse another key type, or ask
     * for the passphrase, before running the KDF.
     */
    fun inspect(fileBytes: ByteArray): Info {
        val env = envelope(fileBytes)
        try {
            val pk = if (MlDsaEd25519Ssh.isKeyType(env.publicType)) {
                runCatching { MlDsaEd25519Ssh.parsePublicBlob(env.publicBlob) }.getOrNull()
            } else null
            val rounds = if (env.kdf == "bcrypt") {
                runCatching { parseKdfOptions(env.kdfOptions).rounds }.getOrNull()
            } else null
            // 4.8.0 RC7 (item 1): the same checks read() makes ahead of the KDF,
            // so a file PGPony cannot open is refused before a passphrase prompt.
            // A damaged header (Malformed) is left for read() to report.
            val unsupported = try {
                encryption(env)
                null
            } catch (e: ReadError.UnsupportedEncryption) {
                e.detail
            } catch (e: ReadError.Malformed) {
                null
            }
            return Info(env.publicType, env.cipher != "none", env.cipher, env.kdf, pk, rounds, unsupported)
        } finally {
            // 4.8.0 RC7 (item 1): an unencrypted file's private section holds the seeds.
            env.privateSection.fill(0)
        }
    }

    /**
     * Read an ssh-mldsa44-ed25519 private key from an OpenSSH key file, as
     * ssh-keygen writes it with or without a passphrase. [passphrase] is
     * ignored for an unencrypted file. Throws [ReadError].
     */
    fun read(fileBytes: ByteArray, passphrase: CharArray?): Decoded {
        val env = envelope(fileBytes)
        // 4.8.0 RC7 (item 1): an unencrypted file's private section holds the
        // seeds; it is wiped on every way out, a refusal included.
        try {
            if (!MlDsaEd25519Ssh.isKeyType(env.publicType)) throw ReadError.UnsupportedKeyType(env.publicType)
            val envelopePk = try {
                MlDsaEd25519Ssh.parsePublicBlob(env.publicBlob)
            } catch (e: SshFormatException) {
                throw ReadError.Malformed(e.message ?: "bad public key")
            }

            // 4.8.0 RC7 (item 1): cipher, KDF and rounds are checked before the
            // passphrase, as inspect() does, so a file that would be refused is
            // refused without asking for one.
            val enc = encryption(env)
            val plain: ByteArray = if (enc == null) {
                if (env.trailing != 0) throw ReadError.Malformed("trailing data")
                if (env.encryptedLength < NONE_BLOCK_SIZE || env.encryptedLength % NONE_BLOCK_SIZE != 0) {
                    throw ReadError.Malformed("private section length")
                }
                env.privateSection
            } else {
                val (spec, kdf) = enc
                if (passphrase == null || passphrase.isEmpty()) throw ReadError.PassphraseRequired()
                if (env.trailing != 0) throw ReadError.Malformed("trailing data")
                if (env.encryptedLength < spec.blockSize || env.encryptedLength % spec.blockSize != 0) {
                    throw ReadError.Malformed("encrypted section length")
                }
                crypt(spec, passphrase, kdf.salt, kdf.rounds.toInt(), env.privateSection, encrypt = false)
            }

            try {
                return parsePrivateSection(plain, envelopePk, encrypted = enc != null)
            } finally {
                plain.fill(0)
            }
        } finally {
            env.privateSection.fill(0)
        }
    }

    /**
     * An OpenSSH private key file for [key] with [comment]. With a non-empty
     * [passphrase] the file is encrypted as ssh-keygen does by default
     * (aes256-ctr, bcrypt_pbkdf, 16-octet salt, [rounds] rounds); with none
     * it is written unencrypted, which only a container that is itself
     * encrypted (the app backup) should do.
     */
    fun write(
        key: MlDsaEd25519Key,
        comment: String,
        passphrase: CharArray?,
        rounds: Int = DEFAULT_ROUNDS,
        rng: SecureRandom = SecureRandom()
    ): String {
        require(rounds in 1..MAX_ROUNDS) { "bcrypt rounds must be 1..$MAX_ROUNDS" }
        val encrypt = passphrase != null && passphrase.isNotEmpty()
        val spec = if (encrypt) CIPHERS.getValue(DEFAULT_CIPHER) else null
        val blockSize = spec?.blockSize ?: NONE_BLOCK_SIZE
        val salt = if (encrypt) ByteArray(SALT_LEN).also { rng.nextBytes(it) } else null

        val kdfOptions = if (salt != null) {
            SshWire().apply { string(salt); uint32(rounds) }.bytes()
        } else ByteArray(0)

        // 4.8.0 RC7 (item 1): the private section, and for an unencrypted file
        // the whole file, are built in arrays of their exact final size and
        // wiped after use. A growing buffer (SshWire's ByteArrayOutputStream)
        // would leave copies of the seeds behind that nothing wipes. The
        // returned String still holds them for an unencrypted file; the caller
        // owns that copy.
        val typeBytes = MlDsaEd25519Ssh.KEY_TYPE.toByteArray(Charsets.US_ASCII)
        val pk = key.publicKey
        val commentBytes = comment.replace("\u0000", "").toByteArray(Charsets.UTF_8)
        val check = rng.nextInt()
        val unpadded = 4 + 4 + (4 + typeBytes.size) + (4 + pk.size) +
            (4 + MlDsaEd25519Ssh.PRIVATE_LEN) + (4 + commentBytes.size)
        val pad = (blockSize - unpadded % blockSize) % blockSize
        val plain = ByteArray(unpadded + pad)
        val seeds = key.privateBytes()
        try {
            require(seeds.size == MlDsaEd25519Ssh.PRIVATE_LEN) { "unexpected private key size" }
            val w = ByteBuffer.wrap(plain)
            w.putInt(check)
            w.putInt(check)
            w.putInt(typeBytes.size).put(typeBytes)
            w.putInt(pk.size).put(pk)
            w.putInt(seeds.size).put(seeds)
            w.putInt(commentBytes.size).put(commentBytes)
            for (i in 1..pad) w.put(i.toByte())
        } finally {
            seeds.fill(0)
        }

        val body = if (spec != null && salt != null && passphrase != null) {
            try {
                crypt(spec, passphrase, salt, rounds, plain, encrypt = true)
            } finally {
                plain.fill(0)
            }
        } else plain

        val header = SshWire().apply {
            string(spec?.name ?: "none")
            string(if (encrypt) "bcrypt" else "none")
            string(kdfOptions)
            uint32(1)
            string(key.publicBlob)
            uint32(body.size)
        }.bytes()
        val file = ByteArray(AUTH_MAGIC.size + header.size + body.size)
        var b64: ByteArray? = null
        try {
            System.arraycopy(AUTH_MAGIC, 0, file, 0, AUTH_MAGIC.size)
            System.arraycopy(header, 0, file, AUTH_MAGIC.size, header.size)
            System.arraycopy(body, 0, file, AUTH_MAGIC.size + header.size, body.size)
            val encoded = Base64.getEncoder().encode(file)
            b64 = encoded
            val lines = (encoded.size + 69) / 70
            val out = StringBuilder(BEGIN.length + END.length + 2 + encoded.size + lines)
            out.append(BEGIN).append('\n')
            var at = 0
            while (at < encoded.size) {
                val end = minOf(at + 70, encoded.size)
                for (i in at until end) out.append(encoded[i].toInt().toChar())
                out.append('\n')
                at = end
            }
            out.append(END).append('\n')
            return out.toString()
        } finally {
            body.fill(0)
            file.fill(0)
            b64?.fill(0)
        }
    }

    // ── Internals ────────────────────────────────────────────────────

    /** Strip the armor, decode base64 and parse the plaintext header. */
    private fun envelope(fileBytes: ByteArray): Envelope {
        val text = String(fileBytes, Charsets.UTF_8)
        val begin = text.indexOf(BEGIN)
        if (begin < 0) throw ReadError.Malformed("no BEGIN OPENSSH PRIVATE KEY line")
        val end = text.indexOf(END, begin + BEGIN.length)
        if (end < 0) throw ReadError.Malformed("no END OPENSSH PRIVATE KEY line")
        val b64 = text.substring(begin + BEGIN.length, end).filter { !it.isWhitespace() }
        val decoded = try {
            Base64.getDecoder().decode(b64)
        } catch (e: IllegalArgumentException) {
            throw ReadError.Malformed("bad base64")
        }
        // 4.8.0 RC7 (item 1): for an unencrypted file [decoded] holds the seeds.
        // Everything kept is copied out (SshReader copies), so it is wiped here;
        // the private section copy is wiped by read() and inspect(). The
        // caller's file bytes and the base64 text are not this function's to wipe.
        try {
            if (decoded.size < AUTH_MAGIC.size || !decoded.copyOfRange(0, AUTH_MAGIC.size).contentEquals(AUTH_MAGIC)) {
                throw ReadError.Malformed("not an openssh-key-v1 file")
            }
            val r = SshReader(decoded, AUTH_MAGIC.size)
            val cipher = r.cstring()
            val kdf = r.cstring()
            val kdfOptions = r.string()
            val nkeys = r.u32()
            if (nkeys != 1L) throw ReadError.Malformed("$nkeys keys in one file")
            val publicBlob = r.string()
            val publicType = SshReader(publicBlob).cstring()
            val encryptedLength = r.u32()
            if (encryptedLength > r.remaining.toLong()) throw ReadError.Malformed("private section length")
            val section = r.raw(encryptedLength.toInt())
            return Envelope(cipher, kdf, kdfOptions, publicBlob, publicType, encryptedLength.toInt(), section, r.remaining)
        } catch (e: SshFormatException) {
            throw ReadError.Malformed(e.message ?: "truncated")
        } finally {
            decoded.fill(0)
        }
    }

    /**
     * The cipher and KDF settings of [env], or null for an unencrypted file.
     * 4.8.0 RC7 (item 1): one place for the checks read() and inspect() make
     * before any KDF runs or a passphrase is asked.
     * Throws [ReadError.UnsupportedEncryption] or [ReadError.Malformed].
     */
    private fun encryption(env: Envelope): Pair<CipherSpec, KdfParams>? {
        if (env.cipher == "none" && env.kdf == "none") return null
        if (env.kdf == "none") throw ReadError.Malformed("cipher without a KDF")
        if (env.kdf != "bcrypt") throw ReadError.UnsupportedEncryption("KDF ${env.kdf}")
        val spec = CIPHERS[env.cipher] ?: throw ReadError.UnsupportedEncryption("cipher ${env.cipher}")
        val kdf = parseKdfOptions(env.kdfOptions)
        if (kdf.rounds < 1 || kdf.rounds > MAX_ROUNDS) {
            throw ReadError.UnsupportedEncryption("bcrypt, ${kdf.rounds} rounds, limit $MAX_ROUNDS")
        }
        return spec to kdf
    }

    /** bcrypt KDF options: string salt (not empty), u32 rounds. Throws [ReadError.Malformed]. */
    private fun parseKdfOptions(options: ByteArray): KdfParams {
        val (salt, rounds) = try {
            val k = SshReader(options)
            val s = k.string()
            val r = k.u32()
            k.requireEnd()
            s to r
        } catch (e: SshFormatException) {
            throw ReadError.Malformed("KDF options")
        }
        if (salt.isEmpty()) throw ReadError.Malformed("empty KDF salt")
        return KdfParams(salt, rounds)
    }

    private fun parsePrivateSection(plain: ByteArray, envelopePk: ByteArray, encrypted: Boolean): Decoded {
        val r = SshReader(plain)
        val check1: Long
        val check2: Long
        try {
            check1 = r.u32()
            check2 = r.u32()
        } catch (e: SshFormatException) {
            throw ReadError.Malformed("private section too short")
        }
        if (check1 != check2) {
            if (encrypted) throw ReadError.WrongPassphrase()
            throw ReadError.Malformed("check values differ")
        }
        var seeds: ByteArray? = null
        try {
            val type = r.cstring()
            if (!MlDsaEd25519Ssh.isKeyType(type)) throw ReadError.UnsupportedKeyType(type)
            val pk = r.string()
            seeds = r.string()
            val comment = String(r.string(), Charsets.UTF_8)
            var i = 0
            while (r.remaining > 0) {
                i++
                if (r.u8() != (i and 0xFF)) throw ReadError.Malformed("bad padding")
            }
            if (pk.size != MlDsaEd25519Ssh.PUBLIC_LEN || seeds.size != MlDsaEd25519Ssh.PRIVATE_LEN) {
                throw ReadError.Malformed("unexpected key sizes")
            }
            if (!pk.contentEquals(envelopePk)) throw ReadError.Malformed("public keys in the file differ")
            val key = MlDsaEd25519Key.fromPrivateBytes(seeds)
            // As OpenSSH's sshkey_equal check: the seeds must give the stored public key.
            if (!key.publicKey.contentEquals(pk)) {
                key.close()
                throw ReadError.Malformed("private key does not match its public key")
            }
            return Decoded(key, comment)
        } catch (e: SshFormatException) {
            throw ReadError.Malformed(e.message ?: "truncated private section")
        } finally {
            seeds?.fill(0)
        }
    }

    /** AES (CTR or CBC, no padding) under a bcrypt_pbkdf key and IV. */
    private fun crypt(
        spec: CipherSpec,
        passphrase: CharArray,
        salt: ByteArray,
        rounds: Int,
        input: ByteArray,
        encrypt: Boolean
    ): ByteArray {
        val pw = utf8(passphrase)
        val keyIv = try {
            BCrypt.pbkdfGenerate(pw, salt, rounds, spec.keyLen + spec.ivLen)
        } finally {
            pw.fill(0)
        }
        try {
            val cipher = Cipher.getInstance(spec.transform)
            cipher.init(
                if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
                SecretKeySpec(keyIv, 0, spec.keyLen, "AES"),
                IvParameterSpec(keyIv, spec.keyLen, spec.ivLen)
            )
            return cipher.doFinal(input)
        } finally {
            keyIv.fill(0)
        }
    }

    /** The passphrase as UTF-8, as OpenSSH reads it from a terminal. Caller wipes. */
    private fun utf8(chars: CharArray): ByteArray {
        val buf: ByteBuffer = Charsets.UTF_8.newEncoder().encode(CharBuffer.wrap(chars))
        val out = ByteArray(buf.remaining())
        buf.get(out)
        if (buf.hasArray()) buf.array().fill(0)
        return out
    }
}
