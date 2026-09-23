// ProviderCardOpStore.kt
// PGPony Android — 4.0.0 Succession Phase P2c (provider card flow)
//
// In-process hand-off between the provider service and the card
// operation activity. The OpenPGP API's interaction pattern (fail with
// USER_INTERACTION_REQUIRED → client fires PendingIntent → client
// RETRIES the identical call) doesn't carry streams through the
// interaction, so a card operation — which needs the card physically
// present WHILE the crypto runs — works like this:
//
//   1. execute() hits a card-backed key → the full request (params +
//      input bytes) is parked here as a PendingOp, keyed by a content
//      hash of the request (action ‖ key id ‖ flags ‖ recipients ‖
//      input). The client gets the PendingIntent.
//   2. ProviderCardOpActivity performs the WHOLE operation during the
//      NFC session (sign / encrypt / decrypt on the card) and stores
//      the result as a CompletedOp under the same key.
//   3. The client retries the identical call → identical content hash
//      → the service consumes the CompletedOp and returns it.
//
// Everything is memory-only with a 5-minute TTL: process death or an
// abandoned interaction leaves nothing behind, and a consumed result
// is removed immediately (single use). Same posture as the passphrase
// cache — plaintext and card PINs never touch disk or the binder.

package com.pgpony.android.provider

import android.os.SystemClock
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

object ProviderCardOpStore {

    private const val TTL_MS = 5 * 60 * 1000L

    data class PendingOp(
        val opKey: String,
        val action: String,
        val input: ByteArray,
        /** Fingerprint of the card-backed key row driving this op. */
        val cardEntityFingerprint: String,
        val armor: Boolean,
        val filename: String?,
        /** Resolved recipient fingerprints (SIGN_AND_ENCRYPT only). */
        val recipientFingerprints: List<String>,
        /** Sender address for decrypt signature mapping. */
        val senderAddress: String?,
        /** P2c Fix3: compress the payload? Card ops default OFF so a big
         *  attachment doesn't keep the NFC tag connected while ZLIB runs. */
        val enableCompression: Boolean = false,
        /** 4.6.0 (item 16): the SSH API hash code for an SSH sign op, else -1. */
        val sshHash: Int = -1,
        val createdAt: Long = SystemClock.elapsedRealtime()
    )

    sealed class CompletedOp {
        class Stream(val bytes: ByteArray) : CompletedOp()
        /** P2c Fix3: large card results spill to a temp file instead of
         *  a byte array, so a 45 MB sign+encrypt never buffers its output
         *  in memory. The service streams it to the client pipe and
         *  deletes it. */
        class StreamFile(val file: java.io.File) : CompletedOp()
        class Detached(val signature: ByteArray, val micalg: String) : CompletedOp()
        /** 4.6.0 (item 16): an SSH signature blob from the authentication slot. */
        class SshSignature(val blob: ByteArray) : CompletedOp()
        class Decrypted(
            val data: ByteArray,
            val filename: String?,
            val hadSignature: Boolean,
            val signerKnown: Boolean,
            val signatureVerified: Boolean,
            val signerKeyIdRaw: Long?
        ) : CompletedOp()
    }

    private data class Timed<T>(val value: T, val at: Long)

    private val pending = ConcurrentHashMap<String, Timed<PendingOp>>()
    private val completed = ConcurrentHashMap<String, Timed<CompletedOp>>()

    /**
     * Content hash identifying one logical request. The client retries
     * with byte-identical action/extras/input, so hashing them yields a
     * stable key across the interaction round-trip without any state
     * riding on the PendingIntent result.
     */
    fun opKey(
        action: String,
        keyId: Long,
        armor: Boolean,
        filename: String?,
        recipients: List<String>,
        input: ByteArray
    ): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(action.toByteArray())
        md.update(keyId.toString().toByteArray())
        md.update(if (armor) 1 else 0)
        md.update((filename ?: "").toByteArray())
        recipients.sorted().forEach { md.update(it.toByteArray()) }
        md.update(input)
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    fun putPending(op: PendingOp) {
        sweep()
        pending[op.opKey] = Timed(op, SystemClock.elapsedRealtime())
    }

    fun getPending(opKey: String): PendingOp? {
        sweep()
        return pending[opKey]?.value
    }

    fun complete(opKey: String, result: CompletedOp) {
        pending.remove(opKey)
        completed[opKey] = Timed(result, SystemClock.elapsedRealtime())
    }

    /** Single-use: returns and removes the completed result. */
    fun consumeCompleted(opKey: String): CompletedOp? {
        sweep()
        return completed.remove(opKey)?.value
    }

    fun abandon(opKey: String) {
        pending.remove(opKey)
        // Drop any spilled result file for an abandoned interaction.
        completed.remove(opKey)?.value?.let { deleteFileResult(it) }
    }

    private fun deleteFileResult(op: CompletedOp) {
        if (op is CompletedOp.StreamFile) runCatching { op.file.delete() }
    }

    private fun sweep() {
        val now = SystemClock.elapsedRealtime()
        pending.entries.removeIf { now - it.value.at > TTL_MS }
        completed.entries.removeIf { expired ->
            (now - expired.value.at > TTL_MS).also { stale ->
                if (stale) deleteFileResult(expired.value.value)
            }
        }
    }
}
