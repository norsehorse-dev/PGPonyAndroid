// VerifiedReleaseSink.kt
// PGPony Android, 4.6.0 (item 17.2): hold decrypted plaintext until the
// message's integrity check has passed.
//
// A SEIPDv1 message (AES-CFB + MDC, the container every v4 recipient gets) is
// only authenticated once the whole body has been read: Bouncy Castle checks
// the MDC on the explicit verify() after the last byte. Anything streamed to a
// consumer before that point is unauthenticated, and a consumer outside the
// app (the OpenPGP API caller's pipe) could read it even when the check then
// fails. This sink sits between the decryptor and such a consumer: plaintext
// is held here (in memory, spilling to an app-private file past a threshold)
// and only copied to the real destination after the caller has run the
// integrity gate. On failure the held bytes are discarded and the spill file
// deleted. AEAD (SEIPDv2) messages authenticate each chunk before releasing
// it and do not need this.

package com.pgpony.android.crypto

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStream

class VerifiedReleaseSink(
    /** Directory for the spill file; null keeps everything in memory. */
    private val spillDir: File?,
    private val memoryThreshold: Int = 4 * 1024 * 1024,
    /** Hard cap on what may be held when there is no spill directory. */
    private val memoryCap: Long = SecurityLimits.MAX_MESSAGE_PLAINTEXT_BYTES
) : OutputStream() {

    private var memory = java.io.ByteArrayOutputStream()
    private var spillFile: File? = null
    private var spill: FileOutputStream? = null
    private var total = 0L

    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun write(b: ByteArray, off: Int, len: Int) {
        try {
            writeHeld(b, off, len)
        } catch (e: java.io.IOException) {
            // A spill failure (storage full) is a resource problem, not a sign
            // of tampering; report it as one so the caller does not say
            // "integrity check failed".
            throw PGPCryptoError.ResourceLimitExceeded("Not enough storage to hold the decrypted message")
        }
    }

    private fun writeHeld(b: ByteArray, off: Int, len: Int) {
        total += len
        val s = spill
        if (s != null) { s.write(b, off, len); return }
        if (memory.size() + len <= memoryThreshold) { memory.write(b, off, len); return }
        if (spillDir == null) {
            if (total > memoryCap) throw PGPCryptoError.ResourceLimitExceeded("decrypted message exceeds size cap")
            memory.write(b, off, len)
            return
        }
        spillDir.mkdirs()
        val f = File.createTempFile("held", ".bin", spillDir)
        spillFile = f
        val out = FileOutputStream(f)
        spill = out
        memory.writeTo(out)
        memory = java.io.ByteArrayOutputStream()
        out.write(b, off, len)
    }

    /** Copy everything held to [dest]. Call only after the integrity gate passed. */
    fun releaseTo(dest: OutputStream) {
        val s = spill
        if (s == null) {
            memory.writeTo(dest)
        } else {
            s.flush(); s.close(); spill = null
            FileInputStream(spillFile!!).use { it.copyTo(dest, 1 shl 16) }
        }
        dest.flush()
    }

    /** Drop the held plaintext and delete any spill file. Safe to call twice. */
    fun discard() {
        runCatching { spill?.close() }
        spill = null
        spillFile?.let { f ->
            // Overwrite before unlinking; the file lives in app-private cache.
            runCatching {
                val len = f.length()
                FileOutputStream(f).use { o ->
                    val zeros = ByteArray(1 shl 16)
                    var left = len
                    while (left > 0) { val n = minOf(left, zeros.size.toLong()).toInt(); o.write(zeros, 0, n); left -= n }
                }
            }
            f.delete()
        }
        spillFile = null
        memory = java.io.ByteArrayOutputStream()
    }

    override fun close() { /* the owner decides between releaseTo and discard */ }
}
