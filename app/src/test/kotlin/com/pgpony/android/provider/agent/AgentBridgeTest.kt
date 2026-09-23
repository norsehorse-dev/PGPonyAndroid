// AgentBridgeTest.kt
// PGPony Android, 4.6.0 (item 16b): the SSHPony pairing handshake and the
// ssh-agent protocol handler. The proof vectors are shared with SSHPony's
// own tests (testdata/*.hex there), so both sides agree byte for byte. The
// full chain (sshpony-agent, this handshake, SshAgentSession, OpenSSH
// login and ssh-keygen -Y) was also run end to end during development.

package com.pgpony.android.provider.agent

import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.ssh.SshAuth
import com.pgpony.android.crypto.ssh.SshSigningKey
import com.pgpony.android.crypto.ssh.SshWire
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import kotlin.concurrent.thread

class AgentBridgeTest {

    @Test
    fun `proof vectors match SSHPony`() {
        val k = ByteArray(32) { 7 }
        val nP = ByteArray(32) { 1 }
        val nC = ByteArray(32) { 2 }
        assertEquals(
            "b1f5565c1dd8352145d10eea2989983e5bfc6402e67fa5c90862bd7e21df8826",
            AgentBridge.toHex(AgentBridge.clientProof(k, nP, nC))
        )
        assertEquals(
            "046646c0595c88cb5477c2500b3d04bf1a0671c89e058941a08baccc6f5bc619",
            AgentBridge.toHex(AgentBridge.serverProof(k, nP, nC))
        )
    }

    @Test
    fun `pair command carries the secret as hex`() {
        val s = AgentBridge.newSecret()
        val cmd = AgentBridge.pairCommand(s)
        assertTrue(cmd.startsWith("sshpony pair "))
        assertArrayEquals(s, AgentBridge.fromHex(cmd.removePrefix("sshpony pair ")))
    }

    /** Run the server side against a scripted client over pipes. */
    private fun runHandshake(clientSecret: ByteArray, serverSecret: ByteArray): Pair<Boolean, ByteArray?> {
        val toServer = PipedOutputStream(); val serverIn = PipedInputStream(toServer, 4096)
        val toClient = PipedOutputStream(); val clientIn = PipedInputStream(toClient, 4096)
        var serverProof: ByteArray? = null
        val client = thread {
            val hello = ByteArray(36).also { java.io.DataInputStream(clientIn).readFully(it) }
            val nP = hello.copyOfRange(4, 36)
            val nC = ByteArray(32) { 9 }
            toServer.write(nC + AgentBridge.clientProof(clientSecret, nP, nC))
            toServer.flush()
            serverProof = runCatching {
                ByteArray(32).also { java.io.DataInputStream(clientIn).readFully(it) }
            }.getOrNull()?.takeIf { it.contentEquals(AgentBridge.serverProof(clientSecret, nP, nC)) }
        }
        val ok = try {
            AgentBridge.serverHandshake(serverIn, toClient, serverSecret)
            true
        } catch (e: AgentBridge.HandshakeFailed) {
            toClient.close()
            false
        }
        client.join(5000)
        return ok to serverProof
    }

    @Test
    fun `handshake succeeds only with the same secret, both ways`() {
        val s = AgentBridge.newSecret()
        val (ok, proof) = runHandshake(s, s)
        assertTrue(ok)
        assertTrue("client verified the server", proof != null)
        val (bad, _) = runHandshake(AgentBridge.newSecret(), s)
        assertTrue("an unpaired client is refused", !bad)
    }

    private fun frame(payload: ByteArray): ByteArray =
        SshWire().apply { uint32(payload.size) }.bytes() + payload

    @Test
    fun `agent session lists keys and signs`() {
        val svc = PGPCryptoService.shared
        val g = svc.generateKeyPair("A", "a@example.org", KeyAlgorithm.ED25519_CV25519, null, null)
        val ring = ClassicalSubkeyGen.addSubkey(
            PGPSecretKeyRing(g.privateKeyData, JcaKeyFingerprintCalculator()),
            ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH, null
        )
        val sub = SshAuth.authSubkey(PGPPublicKeyRing(ring.publicKeys.asSequence().toList()).encoded)!!
        val m = SshAuth.material(sub.publicBody)!!
        val key = (SshSigningKey.unlock(ring, sub.keyId, null) as SshSigningKey.Unlock.Ok).key
        val session = SshAgentSession(object : SshAgentSession.KeySource {
            override fun keys() = listOf(SshAgentSession.AgentKey(SshAuth.publicBlob(m), "A <a@example.org>", null))
            override fun sign(key0: SshAgentSession.AgentKey, data: ByteArray, flags: Int) =
                SshAuth.sign(m, key, data, SshAgentSession.hashFor(flags))
        })

        val ids = session.handle(byteArrayOf(11))
        assertEquals(12, ids[0].toInt())
        val r = SshWire.Reader(ids.copyOfRange(1, ids.size))
        assertEquals(1, r.uint32())
        assertArrayEquals(SshAuth.publicBlob(m), r.string())
        assertEquals("A <a@example.org>", String(r.string()))

        val data = "session-id and userauth".toByteArray()
        val req = byteArrayOf(13) + SshWire().apply { string(SshAuth.publicBlob(m)); string(data); uint32(0) }.bytes()
        val resp = session.handle(req)
        assertEquals(14, resp[0].toInt())
        val (type, sig) = SshAuth.parseSignatureBlob(SshWire.Reader(resp.copyOfRange(1, resp.size)).string())
        assertEquals("ssh-ed25519", type)
        val pt = (m as SshAuth.Material.Ed25519).point
        assertTrue(Ed25519Signer().run { init(false, Ed25519PublicKeyParameters(pt, 0)); update(data, 0, data.size); verifySignature(sig) })

        // An unknown key, an unsupported request and junk all get FAILURE.
        val other = byteArrayOf(13) + SshWire().apply { string(ByteArray(10)); string(data); uint32(0) }.bytes()
        assertEquals(5, session.handle(other)[0].toInt())
        assertEquals(5, session.handle(byteArrayOf(17))[0].toInt())
        assertEquals(5, session.handle(byteArrayOf(13, 0, 0))[0].toInt())

        // Framed serving: two requests, then the peer closes.
        val out = ByteArrayOutputStream()
        session.serve(ByteArrayInputStream(frame(byteArrayOf(11)) + frame(byteArrayOf(27))), out)
        val o = SshWire.Reader(out.toByteArray())
        assertEquals(12, o.string()[0].toInt())
        assertEquals(5, o.string()[0].toInt())
    }

    @Test
    fun `sign flags select the RSA hash`() {
        assertEquals(SshAuth.HASH_SHA512, SshAgentSession.hashFor(4))
        assertEquals(SshAuth.HASH_SHA256, SshAgentSession.hashFor(2))
        assertEquals(SshAuth.HASH_SHA1, SshAgentSession.hashFor(0))
    }

    @Test
    fun `an oversized frame ends the session`() {
        val out = ByteArrayOutputStream()
        val session = SshAgentSession(object : SshAgentSession.KeySource {
            override fun keys() = emptyList<SshAgentSession.AgentKey>()
            override fun sign(key: SshAgentSession.AgentKey, data: ByteArray, flags: Int): ByteArray? { fail(); return null }
        })
        session.serve(ByteArrayInputStream(SshWire().apply { uint32(10_000_000) }.bytes()), out)
        assertEquals(0, out.size())
    }
}
