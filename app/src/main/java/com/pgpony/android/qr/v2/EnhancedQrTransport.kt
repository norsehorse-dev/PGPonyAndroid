package com.pgpony.android.qr.v2

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPUtil
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.CRC32

/** Explicitly selected enhanced public-certificate transport. Existing formats remain separate. */
object EnhancedQrEncoder {
    // At most 128 data plus 32 parity shards; bounds also apply before parsing a certificate.
    const val MAX_CERTIFICATE_BYTES = 65536
    const val SHARD_BYTES = 512
    const val MAX_FRAME_CHARACTERS = 867
    internal const val MAX_ARMORED_CHARACTERS = 100000

    /**
     * Decodes armor without re-encoding its packets, then emits the complete binary certificate.
     * Throws [IllegalArgumentException] for malformed, secret, oversized or non-certificate input.
     * Armor formatting and comments are not certificate packets and are not transported.
     */
    fun encode(armoredPublicKey: String): List<String> {
        require(armoredPublicKey.length <= MAX_ARMORED_CHARACTERS) { "Public certificate armor is too large" }
        val bytes = try {
            PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.US_ASCII)).use { stream ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= MAX_CERTIFICATE_BYTES) { "Public certificate is too large" }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid public certificate armor", e)
        }
        return encodeBinary(bytes)
    }

    /** Accepts exactly one binary public certificate; preserves all original packet bytes. */
    fun encodeBinary(publicCertificate: ByteArray): List<String> {
        PublicCertificate.validate(publicCertificate)
        val metadata = Metadata(
            digest(publicCertificate), publicCertificate.size,
            (publicCertificate.size + SHARD_BYTES - 1) / SHARD_BYTES
        )
        val data = Array(metadata.dataCount) { index ->
            ByteArray(SHARD_BYTES).also { shard ->
                val offset = index * SHARD_BYTES
                publicCertificate.copyInto(shard, 0, offset, minOf(offset + SHARD_BYTES, publicCertificate.size))
            }
        }
        return ErasureCode(metadata.dataCount, metadata.parityCount).encode(data).mapIndexed { index, bytes ->
            val header = metadata.header(index)
            header + checksum(header, bytes) + ":" + Base45.encode(bytes)
        }
    }
}

/** Integrity checks detect corruption; neither the digest nor CRC authenticates the key owner. */
sealed interface EnhancedQrResult {
    /** [received] counts distinct valid shards; [required] is the k needed for recovery. */
    data class Progress(val received: Int, val required: Int, val total: Int, val restarted: Boolean = false) : EnhancedQrResult
    /** Recovered armor retains exactly the validated binary packet stream for import preview. */
    data class Complete(val armoredPublicKey: String) : EnhancedQrResult
    /** A malformed frame, conflicting duplicate, invalid recovery or invalid certificate. */
    data object Malformed : EnhancedQrResult
}

/**
 * Bounded single-transfer collector. The caller must serialize all calls, including [reset],
 * and publish state safely if successive calls run on different worker threads.
 * Invalid frames cannot replace the active session. A valid different metadata tuple starts
 * a new session and reports restarted progress; shards from sessions are never combined.
 * A conflicting duplicate or failed recovery discards the active session. A completed
 * result is cached within the armor limit and returned again for valid same-session frames,
 * so a caller can retry delivery after a lifecycle pause. The UI owns exactly-once delivery.
 */
class EnhancedQrCollector {
    private var active: Metadata? = null
    private val shards = linkedMapOf<Int, ByteArray>()
    private var completed: EnhancedQrResult.Complete? = null

    fun reset() {
        active = null
        shards.clear()
        completed = null
    }

    /** Parses and checks resource limits and CRC before allocating any persistent state. */
    fun offer(frame: String): EnhancedQrResult {
        val parsed = parseFrame(frame) ?: return EnhancedQrResult.Malformed
        val restarted = active != null && active != parsed.metadata
        if (active != parsed.metadata) {
            reset()
            active = parsed.metadata
        }
        val metadata = parsed.metadata
        completed?.let { return it }
        val existing = shards[parsed.index]
        if (existing != null && !existing.contentEquals(parsed.bytes)) {
            reset()
            return EnhancedQrResult.Malformed
        }
        if (existing == null) shards[parsed.index] = parsed.bytes
        if (shards.size < metadata.dataCount) return progress(metadata, shards.size, restarted)
        return try {
            val recovered = ErasureCode(metadata.dataCount, metadata.parityCount).recover(shards)
            val padded = ByteArray(metadata.dataCount * EnhancedQrEncoder.SHARD_BYTES)
            recovered.forEachIndexed { index, bytes -> bytes.copyInto(padded, index * EnhancedQrEncoder.SHARD_BYTES) }
            require((metadata.length until padded.size).all { padded[it] == 0.toByte() }) { "Nonzero transport padding" }
            val binary = padded.copyOf(metadata.length)
            require(digest(binary) == metadata.digest) { "Certificate digest mismatch" }
            PublicCertificate.validate(binary)
            val output = ByteArrayOutputStream()
            ArmoredOutputStream(output).use { it.write(binary) }
            val armored = output.toString(Charsets.US_ASCII.name())
            require(armored.length <= EnhancedQrEncoder.MAX_ARMORED_CHARACTERS) { "Recovered armor exceeds cache bound" }
            val result = EnhancedQrResult.Complete(armored)
            completed = result
            shards.clear()
            result
        } catch (_: Exception) {
            reset()
            EnhancedQrResult.Malformed
        }
    }

    private fun progress(metadata: Metadata, received: Int, restarted: Boolean) =
        EnhancedQrResult.Progress(received, metadata.dataCount, metadata.dataCount + metadata.parityCount, restarted)
}

private data class Metadata(val digest: String, val length: Int, val dataCount: Int) {
    val parityCount: Int get() = (dataCount + 3) / 4
    fun header(index: Int): String = "PGPONY2:$digest:$length:$dataCount:$parityCount:$index:"
}
private data class Frame(val metadata: Metadata, val index: Int, val bytes: ByteArray)

private fun parseFrame(text: String): Frame? = try {
    require(text.length <= EnhancedQrEncoder.MAX_FRAME_CHARACTERS)
    // Base45 itself contains ':'. Only the first seven separators have structural meaning.
    val fields = text.split(':', limit = 8)
    require(fields.size == 8 && fields[0] == "PGPONY2")
    require(fields[1].length == 64 && fields[1].all { it in '0'..'9' || it in 'A'..'F' })
    fun decimal(field: String, maximum: Int): Int {
        require(field.length in 1..5 && field.all { it in '0'..'9' })
        val value = field.toInt()
        require(value <= maximum && value.toString() == field)
        return value
    }
    val length = decimal(fields[2], EnhancedQrEncoder.MAX_CERTIFICATE_BYTES)
    require(length > 0)
    val k = decimal(fields[3], 128)
    require(k == (length + EnhancedQrEncoder.SHARD_BYTES - 1) / EnhancedQrEncoder.SHARD_BYTES)
    val metadata = Metadata(fields[1], length, k)
    require(decimal(fields[4], 32) == metadata.parityCount)
    val index = decimal(fields[5], 159)
    require(index < k + metadata.parityCount)
    require(fields[6].length == 8 && fields[6].all { it in '0'..'9' || it in 'A'..'F' })
    require(fields[7].length == 768)
    val bytes = Base45.decode(fields[7])
    require(bytes.size == EnhancedQrEncoder.SHARD_BYTES)
    require(checksum(metadata.header(index), bytes) == fields[6])
    Frame(metadata, index, bytes)
} catch (_: Exception) {
    null
}

private fun checksum(header: String, bytes: ByteArray): String = CRC32().let { crc ->
    crc.update(header.toByteArray(Charsets.US_ASCII))
    crc.update(bytes)
    String.format(Locale.ROOT, "%08X", crc.value)
}
private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
    .joinToString("") { "%02X".format(Locale.ROOT, it.toInt() and 255) }
