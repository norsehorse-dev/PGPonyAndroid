// LibrePgpV5Sig.kt
// PGPony Android, 4.7.3
//
// Verifying LibrePGP v5 signatures over documents (types 0x00 and 0x01), the
// kind GnuPG makes with a v5 key such as an Ed448 one.
//
// For these signatures GnuPG hashes six or more extra octets between the
// hashed subpackets and the 0x05 0xFF trailer (gnupg g10/sign.c,
// hash_sigversion_to_magic): the literal data packet's format octet, its
// file name with a one-octet length, and its four-octet date. A detached
// signature hashes six zero octets in their place, and a cleartext signature
// hashes 't' followed by five zero octets (gnupg g10/sign.c, clearsign_file). Bouncy Castle
// 1.85 leaves that block out, so every such signature failed to verify.
// Key signatures (certifications, bindings) carry no such block and still go
// through Bouncy Castle.
//
// PGPony does not make v5 signatures: Bouncy Castle writes them with a 4-octet
// trailer length and without this block, so GnuPG reports them as bad. See
// PLANNING_4.7.3 item 4.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import java.util.Date

object LibrePgpV5Sig {

    /** A v5 signature over a binary or text document. */
    fun isV5Document(sig: PGPSignature): Boolean =
        sig.version == 5 && (sig.signatureType == PGPSignature.BINARY_DOCUMENT ||
            sig.signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)

    /** What a detached v5 signature hashes in place of literal data fields. */
    val DETACHED_EXTRA: ByteArray get() = ByteArray(6)

    /** What a cleartext v5 signature hashes in place of literal data fields. */
    val CLEARTEXT_EXTRA: ByteArray get() = byteArrayOf('t'.code.toByte(), 0, 0, 0, 0, 0)

    /** The literal data fields an inline v5 signature hashes. */
    fun literalExtra(format: Int, rawFileName: ByteArray, modificationTime: Date): ByteArray {
        val name = if (rawFileName.size > 255) rawFileName.copyOf(255) else rawFileName
        val t = modificationTime.time / 1000
        return byteArrayOf(format.toByte(), name.size.toByte()) + name +
            byteArrayOf((t shr 24).toByte(), (t shr 16).toByte(), (t shr 8).toByte(), t.toByte())
    }

    /**
     * Hashes the signed data as Bouncy Castle would (text signatures get CR LF
     * line ends) and finishes with the v5 document block. Built from the key
     * and algorithms alone, so a one-pass signature can feed it before the
     * signature itself is read.
     */
    class Verifier(key: PGPPublicKey, keyAlgorithm: Int, hashAlgorithm: Int, private val textMode: Boolean) {
        private val verifier = BcPGPContentVerifierBuilderProvider().get(keyAlgorithm, hashAlgorithm).build(key)
        private val out = verifier.outputStream
        private var last = 0

        fun update(buf: ByteArray, off: Int, len: Int) {
            if (!textMode) {
                out.write(buf, off, len)
                return
            }
            for (i in off until off + len) {
                val b = buf[i].toInt() and 0xFF
                when (b) {
                    0x0D -> { out.write(0x0D); out.write(0x0A) }
                    0x0A -> if (last != 0x0D) { out.write(0x0D); out.write(0x0A) }
                    else -> out.write(b)
                }
                last = b
            }
        }

        /** True when [sig] is a v5 document signature over what was fed, with [extra] hashed. */
        fun verify(sig: PGPSignature, extra: ByteArray): Boolean {
            if (!isV5Document(sig)) return false
            val trailer = sig.signatureTrailer
            out.write(trailer, 0, trailer.size - 10)
            out.write(extra)
            out.write(trailer, trailer.size - 10, 10)
            return verifier.verify(sig.signature)
        }
    }

    /**
     * One signature checked over streamed data: Bouncy Castle for everything,
     * this object's [Verifier] for a v5 document signature, finished with
     * [extra] (the detached block unless told otherwise).
     */
    class StreamCheck(val sig: PGPSignature, key: PGPPublicKey, private val extra: ByteArray = DETACHED_EXTRA) {
        private val v5 = if (isV5Document(sig))
            Verifier(key, sig.keyAlgorithm, sig.hashAlgorithm, sig.signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        else null

        init {
            if (v5 == null) sig.init(BcPGPContentVerifierBuilderProvider(), key)
        }

        fun update(buf: ByteArray, off: Int, len: Int) {
            if (v5 != null) v5.update(buf, off, len) else sig.update(buf, off, len)
        }

        fun verify(): Boolean = v5?.verify(sig, extra) ?: sig.verify()
    }

    /** [sig] over [data] by [key]; pass [CLEARTEXT_EXTRA] for a cleartext signature. */
    fun verify(sig: PGPSignature, key: PGPPublicKey, data: ByteArray, extra: ByteArray = DETACHED_EXTRA): Boolean {
        val check = StreamCheck(sig, key, extra)
        check.update(data, 0, data.size)
        return check.verify()
    }
}
