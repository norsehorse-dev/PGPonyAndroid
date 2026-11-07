// SshOnlyKeysTest.kt
// PGPony Android, 4.8.0 RC7 (item 1): what the SSH provider answers for an
// SSH-only ssh-mldsa44-ed25519 key, through the same pure
// functions SshAuthenticationService calls: the routing of key ids (an SSH-only
// id never takes the OpenPGP path), the key_description text, the
// GET_SSH_PUBLIC_KEY line as the clients parse it, and SIGN end to end (sign a
// challenge, verify it with MlDsaEd25519Ssh.verify, whatever hash the client
// sends), plus a key deleted or unreadable after the client stored its id,
// and an id from a build that still used the OpenSSH 10.4 name.

package com.pgpony.android.provider

import com.pgpony.android.crypto.ssh.MlDsaEd25519Ssh
import com.pgpony.android.data.ssh.SshKeyStore
import com.pgpony.android.data.ssh.SshKeyVault
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import kotlin.random.Random

class SshOnlyKeysTest {

    /** An in-memory vault; [secretGone] makes the seeds unreadable while the record stays. */
    private class MemoryVault : SshKeyVault {
        val secrets = LinkedHashMap<String, ByteArray>()
        val metas = LinkedHashMap<String, ByteArray>()
        var secretGone = false
        override fun names(): List<String> = (secrets.keys + metas.keys).distinct()
        override fun readSecret(name: String): ByteArray? = if (secretGone) null else secrets[name]?.copyOf()
        override fun readMeta(name: String): ByteArray? = metas[name]?.copyOf()
        override fun write(name: String, secret: ByteArray, meta: ByteArray) {
            secrets[name] = secret.copyOf(); metas[name] = meta.copyOf()
        }
        override fun writeMeta(name: String, meta: ByteArray) { metas[name] = meta.copyOf() }
        override fun delete(name: String) { secrets.remove(name); metas.remove(name) }
        override fun deleteAll() { secrets.clear(); metas.clear() }
    }

    private var now = 1_700_000_000_000L
    private fun newStore(vault: SshKeyVault = MemoryVault()) = SshKeyStore(vault, clock = { now++ })

    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/openssh-mldsa/$name")!!.use { it.readBytes() }

    // ── Routing ──────────────────────────────────────────────────────

    @Test
    fun route_sendsOnlySshIdsToTheSshStore() {
        assertEquals(SshOnlyKeys.Route.NONE, SshOnlyKeys.route(null))
        assertEquals(SshOnlyKeys.Route.NONE, SshOnlyKeys.route(""))
        assertEquals(SshOnlyKeys.Route.NONE, SshOnlyKeys.route("   "))
        assertEquals(SshOnlyKeys.Route.SSH_ONLY, SshOnlyKeys.route("ssh:SHA256:PwdCORll4fc1VZuqA0RN3k0MLS16G7vc0KffRBzIiHw"))
        assertEquals(SshOnlyKeys.Route.SSH_ONLY, SshOnlyKeys.route("  ssh:SHA256:abc+/  "))
        // What OpenPGP keys use: a primary fingerprint (v4 and v6) or a decimal key id.
        assertEquals(SshOnlyKeys.Route.OPENPGP, SshOnlyKeys.route("AB".repeat(20)))
        assertEquals(SshOnlyKeys.Route.OPENPGP, SshOnlyKeys.route("0x" + "cd".repeat(32)))
        assertEquals(SshOnlyKeys.Route.OPENPGP, SshOnlyKeys.route("-6148914691236517206"))
        // The prefix is the store's, exactly; anything else is looked up as OpenPGP (and not found).
        assertEquals(SshOnlyKeys.Route.OPENPGP, SshOnlyKeys.route("SSH:SHA256:abc"))
        assertEquals(SshOnlyKeys.Route.OPENPGP, SshOnlyKeys.route("SHA256:abc"))
    }

    @Test
    fun sshOnlyId_trimsAndRejectsOpenPgpIds() {
        assertEquals("ssh:SHA256:abc", SshOnlyKeys.sshOnlyId(" ssh:SHA256:abc\n"))
        assertNull(SshOnlyKeys.sshOnlyId(null))
        assertNull(SshOnlyKeys.sshOnlyId(""))
        assertNull(SshOnlyKeys.sshOnlyId("AB".repeat(20)))
        assertNull(SshOnlyKeys.sshOnlyId("12345"))
    }

    @Test
    fun generatedIds_routeToTheSshStore() {
        val store = newStore()
        val e = store.generate("laptop")
        assertEquals(SshOnlyKeys.Route.SSH_ONLY, SshOnlyKeys.route(e.id))
        assertEquals(e.id, SshOnlyKeys.sshOnlyId(e.id))
        assertEquals(e, store.get(SshOnlyKeys.sshOnlyId(" ${e.id} ")!!))
    }

    // ── SELECT_KEY and GET_SSH_PUBLIC_KEY ────────────────────────────

    @Test
    fun description_isTheLabelThenTheType() {
        val store = newStore()
        val named = store.generate("work laptop")
        assertEquals("work laptop (ssh-mldsa44-ed25519)", SshOnlyKeys.description(named))
        val unnamed = store.generate("   ")
        assertEquals("${unnamed.fingerprint} (${MlDsaEd25519Ssh.KEY_TYPE})", SshOnlyKeys.description(unnamed))
    }

    @Test
    fun sshPublicKey_isTypeAndBase64_withNoComment() {
        val store = newStore()
        val e = store.generate("has a comment that must not appear")
        val line = SshOnlyKeys.sshPublicKey(e)
        val parts = line.split(" ")
        assertEquals(2, parts.size)
        assertEquals(MlDsaEd25519Ssh.KEY_TYPE, parts[0])
        // What the OkcAgent fork does with it: everything after the first space, base64-decoded.
        assertArrayEquals(e.publicBlob, Base64.getDecoder().decode(line.substringAfter(' ')))
        assertEquals(e.fingerprint, MlDsaEd25519Ssh.fingerprintOfBlob(e.publicBlob))
    }

    @Test
    fun sshPublicKey_matchesSshKeygensPubFile_withoutItsComment() {
        val store = newStore()
        val e = store.import(resource("mldsa44_ed25519_1")).entry
        val pub = String(resource("mldsa44_ed25519_1.pub"), Charsets.UTF_8).trim().split(" ")
        assertEquals("${pub[0]} ${pub[1]}", SshOnlyKeys.sshPublicKey(e))
        assertEquals("ssh:SHA256:PwdCORll4fc1VZuqA0RN3k0MLS16G7vc0KffRBzIiHw", e.id)
    }

    @Test
    fun legacyKeyFile_isServedUnderTheNewName() {
        // 4.8.0 RC7 (item 1): a key file from ssh-keygen 10.4 is answered as
        // ssh-mldsa44-ed25519, with the id and blob OpenSSH 10.6 would use.
        val store = newStore()
        val e = store.import(resource("legacy-10.4-mldsa44_ed25519_1")).entry
        assertEquals("ssh:SHA256:fotS8vyYfLRDu95aRszDl72PPJ+TBnnJDnd3fhnW3LE", e.id)
        assertEquals("MLDSA44-ED25519 test key #1 (ssh-mldsa44-ed25519)", SshOnlyKeys.description(e))
        val line = SshOnlyKeys.sshPublicKey(e)
        assertTrue(line.startsWith(MlDsaEd25519Ssh.KEY_TYPE + " "))
        assertFalse(line.contains("@openssh.com"))
        val r = SshOnlyKeys.sign(store, e.id, byteArrayOf(9, 8, 7), 0) as SshOnlyKeys.SignResult.Ok
        assertTrue(MlDsaEd25519Ssh.verify(e.publicKey, r.blob, byteArrayOf(9, 8, 7)))
    }

    // ── SIGN ─────────────────────────────────────────────────────────

    @Test
    fun sign_endToEnd_verifiesWithTheKeysPublicKey() {
        val store = newStore()
        val e = store.generate("laptop")
        val other = store.generate("other")
        // An SSH userauth request is a few hundred octets: session id, user, service, key blob.
        val challenge = Random(7).nextBytes(400)
        val r = SshOnlyKeys.sign(store, e.id, challenge, hashAlgorithm = 0)
        assertTrue(r is SshOnlyKeys.SignResult.Ok)
        val blob = (r as SshOnlyKeys.SignResult.Ok).blob
        assertTrue(MlDsaEd25519Ssh.verify(e.publicKey, blob, challenge))
        assertFalse(MlDsaEd25519Ssh.verify(other.publicKey, blob, challenge))
        assertFalse(MlDsaEd25519Ssh.verify(e.publicKey, blob, challenge.copyOf().also { it[0] = (it[0] + 1).toByte() }))
        // The full SSH signature blob: string(type) + string(2484-octet signature).
        assertEquals(MlDsaEd25519Ssh.SIGNATURE_LEN, MlDsaEd25519Ssh.parseSignatureBlob(blob).size)
        assertEquals(4 + MlDsaEd25519Ssh.KEY_TYPE.length + 4 + MlDsaEd25519Ssh.SIGNATURE_LEN, blob.size)
    }

    @Test
    fun sign_ignoresTheHashArgument() {
        val store = newStore()
        val e = store.generate("k")
        val challenge = "session".toByteArray()
        // 0 (the fork's flags for this type), the RSA hash codes and flags,
        // and the service's default when the extra is missing.
        for (hash in listOf(0, 1, 2, 3, 4, 5, -253, Int.MAX_VALUE)) {
            val r = SshOnlyKeys.sign(store, e.id, challenge, hash)
            assertTrue("hash $hash", r is SshOnlyKeys.SignResult.Ok)
            assertTrue("hash $hash", MlDsaEd25519Ssh.verify(e.publicKey, (r as SshOnlyKeys.SignResult.Ok).blob, challenge))
        }
    }

    @Test
    fun sign_withAnSshKeygenKey_verifies() {
        val store = newStore()
        val e = store.import(resource("mldsa44_ed25519_1")).entry
        val challenge = Random(11).nextBytes(256)
        val r = SshOnlyKeys.sign(store, e.id, challenge, 0) as SshOnlyKeys.SignResult.Ok
        assertTrue(MlDsaEd25519Ssh.verify(e.publicKey, r.blob, challenge))
    }

    @Test
    fun sign_keyDeletedAfterTheClientStoredItsId_isNoSuchKey() {
        val store = newStore()
        val e = store.generate("gone soon")
        assertTrue(store.delete(e.id))
        assertNull(store.get(e.id))
        assertTrue(SshOnlyKeys.sign(store, e.id, byteArrayOf(1, 2, 3), 0) is SshOnlyKeys.SignResult.NoSuchKey)
        // An id that never existed, or a garbled one, is the same.
        assertTrue(SshOnlyKeys.sign(store, "ssh:SHA256:nope", byteArrayOf(1), 0) is SshOnlyKeys.SignResult.NoSuchKey)
        assertTrue(SshOnlyKeys.sign(store, "ssh:", byteArrayOf(1), 0) is SshOnlyKeys.SignResult.NoSuchKey)
    }

    @Test
    fun sign_secretNoLongerReadable_isUnreadable_notACrash() {
        val vault = MemoryVault()
        val store = newStore(vault)
        val e = store.generate("wiped by the OS")
        vault.secretGone = true
        assertTrue(SshOnlyKeys.sign(store, e.id, byteArrayOf(1), 0) is SshOnlyKeys.SignResult.Unreadable)
    }

    @Test
    fun sign_idFromAPreRenameBuild_isUnreadable_notACrash() {
        // 4.8.0 RC7 (item 1): an earlier RC7 build stored the key under the
        // hash of its @openssh.com blob, and the agent kept that id. Not
        // migrated (never published): the record no longer matches its
        // storage name, so the key is unreadable, not a crash.
        val vault = MemoryVault()
        val store = newStore(vault)
        val seeds = Random(3).nextBytes(MlDsaEd25519Ssh.PRIVATE_LEN)
        val pk = MlDsaEd25519Ssh.publicKeyFromSeeds(seeds)
        val legacyBlob = com.pgpony.android.crypto.ssh.SshWire().apply {
            string(MlDsaEd25519Ssh.LEGACY_KEY_TYPE); string(pk)
        }.bytes()
        val oldId = SshKeyStore.idForFingerprint(MlDsaEd25519Ssh.fingerprintOfBlob(legacyBlob))
        val name = SshKeyStore.hex(java.security.MessageDigest.getInstance("SHA-256").digest(legacyBlob))
        val meta = "{\"v\":1,\"type\":\"${MlDsaEd25519Ssh.LEGACY_KEY_TYPE}\",\"label\":\"old\"," +
            "\"createdAt\":1,\"publicKey\":\"${Base64.getEncoder().encodeToString(pk)}\"}"
        vault.write(name, seeds, meta.toByteArray())
        assertEquals(SshOnlyKeys.Route.SSH_ONLY, SshOnlyKeys.route(oldId))
        assertTrue(SshOnlyKeys.sign(store, oldId, byteArrayOf(1), 0) is SshOnlyKeys.SignResult.Unreadable)
        assertNull(store.get(oldId))
        assertTrue(store.list().isEmpty())
    }
}
