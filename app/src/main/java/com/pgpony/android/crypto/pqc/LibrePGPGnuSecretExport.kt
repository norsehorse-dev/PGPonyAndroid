// LibrePGPGnuSecretExport.kt
// PGPony Android — issue #2 symptom D (gpg-compatible composite secret export)
//
// GnuPG 2.5.x does NOT import a standard OpenPGP v5 algo-8 composite SECRET
// key. gpg stores and imports composite secrets only in its native form: a
// GNU-extension S2K (mode 3) whose body is a libgcrypt canonical S-expression
// carrying the full expanded ML-KEM secret key (not PGPony's 64-byte seed).
// Verified against gpg 2.5.21: a key emitted this way imports and decrypts.
//
// Wrapper (both variants): usage 255, cond-len 7, cipher 0, GNU S2K mode 3,
//   4-octet s-exp length, then the canonical S-expression.
//
// UNPROTECTED (protectPassphrase == null):
//   (composite-key
//     (private-key (ecc (curve <c>)(q <q>)(d <d>)))
//     (private-key (<kyber> (p <p>)(s <s>))))
//
// PROTECTED (protectPassphrase != null) — mirrors gpg exactly: ONLY the ECC
// secret is encrypted (AES-128-OCB), the ML-KEM secret stays cleartext, as gpg
// itself emits:
//   (composite-key
//     (protected-private-key (ecc (curve <c>)(q <q>)
//        (protected openpgp-s2k3-ocb-aes ((sha1 <salt8> <count>) <nonce12>) <ct>)
//        (protected-at <ts>)))
//     (private-key (<kyber> (p <p>)(s <s>))))
//   ct = AES-128-OCB( key = S2K3-SHA1(pass,salt,count),
//                     nonce = <nonce12>, tag = 16,
//                     aad   = "(3:ecc(5:curve...)(1:q...)" || "(12:protected-at...)" || ")",
//                     pt    = "((" || "(1:d..<d>)" || "))" )
// The AAD and plaintext framing were recovered by decrypting a real gpg 2.5.21
// protected export and re-encrypting to a byte-identical ciphertext.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.OCBBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

object LibrePGPGnuSecretExport {

    private const val ALGO_KYBER = 8
    private val GNU_HEADER = byteArrayOf(
        0xFF.toByte(), 0x07, 0x00, 0x65, 0x00, 0x47, 0x4E, 0x55, 0x03
    )
    // gpg's calibrated OpenPGP S2K byte count (any value works as long as the
    // same one is written into the s-expression and used to derive the key).
    private const val S2K_COUNT = 106521600

    private fun curveName(curve: EccCurve): String = when (curve) {
        EccCurve.X448 -> "X448"
        EccCurve.X25519 -> "Curve25519"
        // 4.6.0 (item 13): libgcrypt's names; q is the uncompressed point.
        EccCurve.BRAINPOOL_P256R1 -> "brainpoolP256r1"
        EccCurve.BRAINPOOL_P384R1 -> "brainpoolP384r1"
        else -> throw IllegalArgumentException("no gpg curve name for $curve")
    }

    private fun kyberName(level: MlkemLevel): String =
        if (level == MlkemLevel.MLKEM1024) "kyber1024" else "kyber768"

    /**
     * Rewrite the v5 algo-8 composite secret (sub)keys in [ringBytes] to gpg's
     * native GNU S-expression form. [sourcePassphrase] unlocks a protected
     * source composite; [protectPassphrase], when non-null, AES-128-OCB
     * protects the exported ECC secret exactly as gpg does. Non-composite
     * packets pass through unchanged.
     */
    fun toGnuComposite(
        ringBytes: ByteArray,
        sourcePassphrase: CharArray? = null,
        protectPassphrase: CharArray? = null,
        random: SecureRandom = SecureRandom()
    ): ByteArray {
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < ringBytes.size) {
            val h = header(ringBytes, i) ?: run {
                out.write(ringBytes, i, ringBytes.size - i); return out.toByteArray()
            }
            val rewritten = tryRewrite(ringBytes, h, sourcePassphrase, protectPassphrase, random)
            if (rewritten != null) {
                out.write(newFormatHeader(h.tag, rewritten.size)); out.write(rewritten)
            } else {
                out.write(ringBytes, i, (h.bodyStart - i) + h.bodyLen)
            }
            i = h.bodyStart + h.bodyLen
        }
        return out.toByteArray()
    }

    private fun tryRewrite(
        data: ByteArray, h: Header, sourcePassphrase: CharArray?,
        protectPassphrase: CharArray?, random: SecureRandom
    ): ByteArray? {
        if (h.tag != 5 && h.tag != 7) return null
        val body = data.copyOfRange(h.bodyStart, h.bodyStart + h.bodyLen)
        if (body.size <= 10 || body[0].toInt() != 5 || (body[5].toInt() and 0xFF) != ALGO_KYBER) return null

        val packet = newFormatHeader(h.tag, body.size) + body
        val suite = CompositeLibrePGPKeyMaterial.suiteOf(packet)
        val material = CompositeLibrePGPKeyMaterial.extractFromPacket(packet, sourcePassphrase)
        val (eccPub, kyberPub) = CompositeLibrePGPKeyMaterial.publicMaterial(packet)

        val d = material.x25519Secret
        val s = MLKEMPrivateKeyParameters(suite.mlkem.params, material.kyberSeed).encoded
        val curve = curveName(suite.curve)
        val kyber = kyberName(suite.mlkem)

        val sexp = if (protectPassphrase == null) {
            buildUnprotectedSexp(curve, eccPub, d, kyber, kyberPub, s)
        } else {
            buildProtectedSexp(curve, eccPub, d, kyber, kyberPub, s, protectPassphrase, random)
        }

        val pkMatLen = readUInt32(body, 6)
        val pubPortion = body.copyOfRange(0, 10 + pkMatLen)
        return ByteArrayOutputStream().apply {
            write(pubPortion); write(GNU_HEADER); write(uint32be(sexp.size)); write(sexp)
        }.toByteArray()
    }

    // ── S-expression builders ────────────────────────────────────────

    private fun atom(o: ByteArrayOutputStream, b: ByteArray) {
        o.write(b.size.toString().toByteArray(Charsets.US_ASCII)); o.write(':'.code); o.write(b)
    }
    private fun atom(o: ByteArrayOutputStream, t: String) = atom(o, t.toByteArray(Charsets.US_ASCII))

    private fun buildUnprotectedSexp(
        curve: String, q: ByteArray, d: ByteArray, kyber: String, p: ByteArray, s: ByteArray
    ): ByteArray = ByteArrayOutputStream().apply {
        write('('.code); atom(this, "composite-key")
        write('('.code); atom(this, "private-key")
        write('('.code); atom(this, "ecc")
        write('('.code); atom(this, "curve"); atom(this, curve); write(')'.code)
        write('('.code); atom(this, "q"); atom(this, q); write(')'.code)
        write('('.code); atom(this, "d"); atom(this, d); write(')'.code)
        write(')'.code); write(')'.code)
        writeKyber(this, kyber, p, s)
        write(')'.code)
    }.toByteArray()

    private fun buildProtectedSexp(
        curve: String, q: ByteArray, d: ByteArray, kyber: String, p: ByteArray, s: ByteArray,
        passphrase: CharArray, random: SecureRandom
    ): ByteArray {
        val salt = ByteArray(8).also { random.nextBytes(it) }
        val nonce = ByteArray(12).also { random.nextBytes(it) }
        val ts = timestamp()
        val ct = ocbProtectEccSecret(passphrase, curve, q, d, salt, nonce, S2K_COUNT, ts)

        return ByteArrayOutputStream().apply {
            write('('.code); atom(this, "composite-key")
            write('('.code); atom(this, "protected-private-key")
            write('('.code); atom(this, "ecc")
            write('('.code); atom(this, "curve"); atom(this, curve); write(')'.code)
            write('('.code); atom(this, "q"); atom(this, q); write(')'.code)
            write('('.code); atom(this, "protected"); atom(this, "openpgp-s2k3-ocb-aes")
            write('('.code)
            write('('.code); atom(this, "sha1"); atom(this, salt); atom(this, S2K_COUNT.toString()); write(')'.code)
            atom(this, nonce)
            write(')'.code)
            atom(this, ct)
            write(')'.code)                        // protected
            write('('.code); atom(this, "protected-at"); atom(this, ts); write(')'.code)
            write(')'.code); write(')'.code)       // ecc, protected-private-key
            writeKyber(this, kyber, p, s)
            write(')'.code)                        // composite-key
        }.toByteArray()
    }

    private fun writeKyber(o: ByteArrayOutputStream, kyber: String, p: ByteArray, s: ByteArray) {
        o.write('('.code); atom(o, "private-key")
        o.write('('.code); atom(o, kyber)
        o.write('('.code); atom(o, "p"); atom(o, p); o.write(')'.code)
        o.write('('.code); atom(o, "s"); atom(o, s); o.write(')'.code)
        o.write(')'.code); o.write(')'.code)
    }

    /**
     * AES-128-OCB encrypt the ECC secret [d] exactly as gpg's
     * openpgp-s2k3-ocb-aes protection does. Deterministic in all inputs so a
     * test can reproduce a real gpg ciphertext byte-for-byte. Returns
     * ciphertext || 16-octet tag.
     */
    fun ocbProtectEccSecret(
        passphrase: CharArray, curve: String, q: ByteArray, d: ByteArray,
        salt: ByteArray, nonce: ByteArray, count: Int, ts: ByteArray
    ): ByteArray {
        val key = s2kSha1(charsToBytes(passphrase), salt, count, 16)

        val aad = ByteArrayOutputStream().apply {
            write('('.code); atom(this, "ecc")
            write('('.code); atom(this, "curve"); atom(this, curve); write(')'.code)
            write('('.code); atom(this, "q"); atom(this, q); write(')'.code)
            write('('.code); atom(this, "protected-at"); atom(this, ts); write(')'.code)
            write(')'.code)
        }.toByteArray()

        val pt = ByteArrayOutputStream().apply {
            write('('.code); write('('.code)
            write('('.code); atom(this, "d"); atom(this, d); write(')'.code)
            write(')'.code); write(')'.code)
        }.toByteArray()

        val ocb = OCBBlockCipher(AESEngine.newInstance(), AESEngine.newInstance())
        ocb.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val out = ByteArray(ocb.getOutputSize(pt.size))
        var n = ocb.processBytes(pt, 0, pt.size, out, 0)
        n += ocb.doFinal(out, n)
        return out.copyOf(n)
    }

    /** OpenPGP S2K mode 3 (salted + iterated) with SHA-1, truncated to [keyLen]. */
    fun s2kSha1(passphrase: ByteArray, salt: ByteArray, count: Int, keyLen: Int): ByteArray {
        val data = salt + passphrase
        var cnt = count.toLong()
        if (cnt < data.size) cnt = data.size.toLong()
        val md = MessageDigest.getInstance("SHA-1")
        var written = 0L
        while (written < cnt) {
            val rem = cnt - written
            val take = if (rem >= data.size) data.size else rem.toInt()
            md.update(data, 0, take); written += take
        }
        return md.digest().copyOf(keyLen)
    }

    private fun timestamp(): ByteArray {
        val fmt = SimpleDateFormat("yyyyMMdd'T'HHmmss", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date()).toByteArray(Charsets.US_ASCII)
    }

    private fun charsToBytes(c: CharArray): ByteArray = String(c).toByteArray(Charsets.UTF_8)

    // ── packet framing helpers ───────────────────────────────────────

    private class Header(val tag: Int, val bodyStart: Int, val bodyLen: Int)

    private fun header(data: ByteArray, start: Int): Header? {
        if (start >= data.size) return null
        var i = start
        val c = data[i++].toInt() and 0xFF
        if (c and 0x80 == 0) return null
        val tag: Int; val length: Int
        if (c and 0x40 != 0) {
            tag = c and 0x3F
            val l0 = data[i++].toInt() and 0xFF
            length = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (data[i++].toInt() and 0xFF) + 192
                l0 == 255 -> readUInt32(data, i).also { i += 4 }
                else -> return null
            }
        } else {
            tag = (c shr 2) and 0x0F
            length = when (c and 0x03) {
                0 -> data[i++].toInt() and 0xFF
                1 -> (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> readUInt32(data, i).also { i += 4 }
                else -> data.size - i
            }
        }
        if (i + length > data.size) return null
        return Header(tag, i, length)
    }

    private fun newFormatHeader(tag: Int, bodyLen: Int): ByteArray = when {
        bodyLen < 192 -> byteArrayOf((0xC0 or tag).toByte(), bodyLen.toByte())
        bodyLen < 8384 -> {
            val l = bodyLen - 192
            byteArrayOf((0xC0 or tag).toByte(), (0xC0 or (l shr 8)).toByte(), (l and 0xFF).toByte())
        }
        else -> byteArrayOf((0xC0 or tag).toByte(), 0xFF.toByte()) + uint32be(bodyLen)
    }

    private fun readUInt32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    private fun uint32be(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
}
