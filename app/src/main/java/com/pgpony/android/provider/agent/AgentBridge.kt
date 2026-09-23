// AgentBridge.kt
// PGPony Android, 4.6.0 (item 16b): the ssh-agent bridge for Termux
// (SSHPony).
//
// How a login flows:
//
//   ssh  ->  sshpony-agent (Termux, a Unix socket in SSH_AUTH_SOCK)
//        ->  am broadcast to AgentBridgeReceiver with a localhost port
//        ->  AgentBridgeService connects to 127.0.0.1:<port>
//        ->  pairing handshake (below), then the ssh-agent protocol itself
//            (draft-miller-ssh-agent), answered by SshAgentSession.
//
// The private keys never leave PGPony; the Termux side only relays bytes.
//
// Why a handshake: any app on the phone can send that broadcast with a port
// it listens on, and would then be talking to a signing agent. So the bridge
// only serves a peer that proves it holds the pairing secret, which the user
// moves from PGPony to Termux once ("sshpony pair <code>"). Termux keeps it
// in its private home directory, where other apps cannot read it. Both sides
// prove knowledge of the secret, so the Termux side also knows it reached
// PGPony and not something squatting on its port.
//
//   PGPony -> Termux:  "SPY1" || nP (32 random octets)
//   Termux -> PGPony:  nC (32 random octets) || HMAC(k, "sshpony-client" || nP || nC)
//   PGPony -> Termux:  HMAC(k, "sshpony-server" || nP || nC)
//
// HMAC is HMAC-SHA-256 and k is the 32-octet pairing secret. After that the
// stream carries plain ssh-agent messages both ways.

package com.pgpony.android.provider.agent

import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object AgentBridge {

    /** Bridge protocol version, sent as an extra with the broadcast. */
    const val PROTOCOL = 1

    const val EXTRA_PROTOCOL = "com.pgpony.android.extra.AGENT_PROTOCOL"
    const val EXTRA_PORT = "com.pgpony.android.extra.AGENT_PORT"

    val MAGIC = byteArrayOf('S'.code.toByte(), 'P'.code.toByte(), 'Y'.code.toByte(), '1'.code.toByte())
    const val NONCE_LEN = 32
    const val SECRET_LEN = 32

    private val CLIENT_LABEL = "sshpony-client".toByteArray(Charsets.US_ASCII)
    private val SERVER_LABEL = "sshpony-server".toByteArray(Charsets.US_ASCII)

    fun newSecret(random: SecureRandom = SecureRandom()): ByteArray = ByteArray(SECRET_LEN).also { random.nextBytes(it) }

    fun toHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    fun fromHex(s: String): ByteArray? {
        val t = s.trim().lowercase()
        if (t.length % 2 != 0 || t.any { it !in '0'..'9' && it !in 'a'..'f' }) return null
        return ByteArray(t.length / 2) { i -> t.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    /** What the user runs in Termux to pair. */
    fun pairCommand(secret: ByteArray): String = "sshpony pair ${toHex(secret)}"

    fun clientProof(secret: ByteArray, nP: ByteArray, nC: ByteArray): ByteArray = hmac(secret, CLIENT_LABEL, nP, nC)
    fun serverProof(secret: ByteArray, nP: ByteArray, nC: ByteArray): ByteArray = hmac(secret, SERVER_LABEL, nP, nC)

    private fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach { mac.update(it) }
        return mac.doFinal()
    }

    class HandshakeFailed(message: String) : Exception(message)

    /**
     * PGPony's side of the handshake over a fresh connection. Returns
     * normally when the peer proved the pairing secret; throws
     * [HandshakeFailed] otherwise (the caller closes the socket).
     */
    fun serverHandshake(input: InputStream, output: OutputStream, secret: ByteArray, random: SecureRandom = SecureRandom()) {
        val nP = ByteArray(NONCE_LEN).also { random.nextBytes(it) }
        output.write(MAGIC)
        output.write(nP)
        output.flush()
        val din = DataInputStream(input)
        val nC = ByteArray(NONCE_LEN)
        val proof = ByteArray(32)
        try {
            din.readFully(nC)
            din.readFully(proof)
        } catch (e: java.io.IOException) {
            throw HandshakeFailed("The Termux side closed the connection during pairing")
        }
        if (!MessageDigest.isEqual(proof, clientProof(secret, nP, nC))) {
            throw HandshakeFailed("The Termux side is not paired with PGPony")
        }
        output.write(serverProof(secret, nP, nC))
        output.flush()
    }
}
