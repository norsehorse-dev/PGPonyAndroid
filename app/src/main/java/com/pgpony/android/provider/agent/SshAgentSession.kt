// SshAgentSession.kt
// PGPony Android, 4.6.0 (item 16b): the ssh-agent protocol spoken over the
// SSHPony bridge (draft-miller-ssh-agent). No Android dependency, so it
// tests on the JVM against a real OpenSSH client.
//
// Only what a login needs is answered:
//   REQUEST_IDENTITIES (11) -> IDENTITIES_ANSWER (12): the keys PGPony offers
//   SIGN_REQUEST (13)       -> SIGN_RESPONSE (14): a signature by the key
// Everything else (adding or removing keys, locking, extensions such as
// session-bind) gets FAILURE (5), which OpenSSH treats as "not supported".
// Keys live in PGPony and are managed there, never through the agent.

package com.pgpony.android.provider.agent

import com.pgpony.android.crypto.ssh.SshWire
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

class SshAgentSession(private val source: KeySource) {

    /** One key the agent offers: its SSH public key blob and comment. */
    class AgentKey(val blob: ByteArray, val comment: String, val ref: Any?)

    interface KeySource {
        /** The keys offered right now. */
        fun keys(): List<AgentKey>

        /**
         * The SSH signature blob over [data] by [key], or null to refuse
         * (the user cancelled, a prompt timed out, the key is gone). [flags]
         * are the request's flags: 2 asks for rsa-sha2-256, 4 for
         * rsa-sha2-512. May block while the user answers a prompt.
         */
        fun sign(key: AgentKey, data: ByteArray, flags: Int): ByteArray?
    }

    companion object {
        const val SSH_AGENT_FAILURE = 5
        const val SSH_AGENTC_REQUEST_IDENTITIES = 11
        const val SSH_AGENT_IDENTITIES_ANSWER = 12
        const val SSH_AGENTC_SIGN_REQUEST = 13
        const val SSH_AGENT_SIGN_RESPONSE = 14

        const val FLAG_RSA_SHA2_256 = 2
        const val FLAG_RSA_SHA2_512 = 4

        /** Largest message accepted; a sign request is a few KiB at most. */
        const val MAX_MESSAGE = 256 * 1024

        /** The SshAuth hash code for a sign request's [flags]. */
        fun hashFor(flags: Int): Int = when {
            flags and FLAG_RSA_SHA2_512 != 0 -> com.pgpony.android.crypto.ssh.SshAuth.HASH_SHA512
            flags and FLAG_RSA_SHA2_256 != 0 -> com.pgpony.android.crypto.ssh.SshAuth.HASH_SHA256
            else -> com.pgpony.android.crypto.ssh.SshAuth.HASH_SHA1
        }
    }

    private val failure = byteArrayOf(SSH_AGENT_FAILURE.toByte())

    /** The response payload for one request payload. */
    fun handle(request: ByteArray): ByteArray {
        if (request.isEmpty()) return failure
        return try {
            when (request[0].toInt() and 0xFF) {
                SSH_AGENTC_REQUEST_IDENTITIES -> {
                    val keys = source.keys()
                    byteArrayOf(SSH_AGENT_IDENTITIES_ANSWER.toByte()) + SshWire().apply {
                        uint32(keys.size)
                        keys.forEach { string(it.blob); string(it.comment.toByteArray(Charsets.UTF_8)) }
                    }.bytes()
                }
                SSH_AGENTC_SIGN_REQUEST -> {
                    val r = SshWire.Reader(request.copyOfRange(1, request.size))
                    val blob = r.string()
                    val data = r.string()
                    val flags = if (r.remaining >= 4) r.uint32() else 0
                    val key = source.keys().firstOrNull { it.blob.contentEquals(blob) } ?: return failure
                    val sig = source.sign(key, data, flags) ?: return failure
                    byteArrayOf(SSH_AGENT_SIGN_RESPONSE.toByte()) + SshWire().apply { string(sig) }.bytes()
                }
                else -> failure
            }
        } catch (e: IndexOutOfBoundsException) {
            failure
        } catch (e: IllegalArgumentException) {
            failure
        }
    }

    /** Serve framed messages (uint32 length, payload) until the peer closes. */
    fun serve(input: InputStream, output: OutputStream) {
        val din = DataInputStream(input)
        val dout = DataOutputStream(output)
        while (true) {
            val len = try { din.readInt() } catch (e: EOFException) { return }
            if (len < 0 || len > MAX_MESSAGE) return
            val msg = ByteArray(len)
            din.readFully(msg)
            val resp = handle(msg)
            dout.writeInt(resp.size)
            dout.write(resp)
            dout.flush()
        }
    }
}
