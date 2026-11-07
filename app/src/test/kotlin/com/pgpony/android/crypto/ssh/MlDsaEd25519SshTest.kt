// MlDsaEd25519SshTest.kt
// PGPony Android, 4.8.0 RC7 (item 1): the ssh-mldsa44-ed25519 composite
// against OpenSSH 10.6's own test data (test resources openssh-mldsa/, see
// the README there):
//
//   * draft-ietf-lamps-pq-composite-sigs.json: the seeds expand to the given
//     public key, and the given signatures verify (empty context and the
//     vector's context), as test_mldsa_eddsa.c checks them;
//   * sshsig-mldsa44-ed25519.sig: a genuine SSHSIG made by ssh-keygen -Y sign
//     over sshsig-signed-data in namespace "unittest", verified end to end
//     (the SSHSIG structure holds SHA-512 of the data, sshsig.c);
//   * our own keys: generate, sign, verify, tamper;
//   * the 10.4 / 10.5 name ssh-mldsa44-ed25519@openssh.com: read in public
//     blobs and lines, never written, refused on a signature.

package com.pgpony.android.crypto.ssh

import org.bouncycastle.crypto.digests.SHA512Digest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64

class MlDsaEd25519SshTest {

    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/openssh-mldsa/$name")!!.use { it.readBytes() }

    private fun text(name: String): String = String(resource(name), Charsets.UTF_8)

    /** One base64 field of the draft's JSON vector (flat object of strings). */
    private fun jsonB64(field: String): ByteArray {
        val m = Regex("\"" + Regex.escape(field) + "\"\\s*:\\s*\"([A-Za-z0-9+/=]*)\"")
            .find(text("draft-ietf-lamps-pq-composite-sigs.json"))
            ?: error("No $field in the vector")
        return Base64.getDecoder().decode(m.groupValues[1])
    }

    // ── Draft composite vector ───────────────────────────────────────

    @Test
    fun compositeVectorSeedsExpandToThePublicKey() {
        val sk = jsonB64("sk")
        assertEquals(MlDsaEd25519Ssh.PRIVATE_LEN, sk.size)
        assertArrayEquals(jsonB64("pk"), MlDsaEd25519Ssh.publicKeyFromSeeds(sk))
        MlDsaEd25519Key.fromPrivateBytes(sk).use { k -> assertArrayEquals(jsonB64("pk"), k.publicKey) }
    }

    @Test
    fun compositeVectorSignatureVerifiesWithEmptyContext() {
        val pk = jsonB64("pk")
        val m = jsonB64("m")
        val s = jsonB64("s")
        assertEquals(MlDsaEd25519Ssh.SIGNATURE_LEN, s.size)
        assertTrue(MlDsaEd25519Ssh.compositeVerify(pk, m, s))
        // Not under the vector's context, and not for another message.
        assertFalse(MlDsaEd25519Ssh.compositeVerify(pk, m, s, jsonB64("ctx")))
        assertFalse(MlDsaEd25519Ssh.compositeVerify(pk, m + 0x00, s))
    }

    @Test
    fun compositeVectorSignatureVerifiesWithContext() {
        assertTrue(MlDsaEd25519Ssh.compositeVerify(jsonB64("pk"), jsonB64("m"), jsonB64("sWithContext"), jsonB64("ctx")))
        assertFalse(MlDsaEd25519Ssh.compositeVerify(jsonB64("pk"), jsonB64("m"), jsonB64("sWithContext")))
    }

    @Test
    fun eitherHalfTamperedFailsVerification() {
        val pk = jsonB64("pk")
        val m = jsonB64("m")
        val s = jsonB64("s")
        val badMl = s.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }
        val badEd = s.copyOf().also { it[MlDsaEd25519Ssh.MLDSA_SIGNATURE_LEN + 5] = (it[MlDsaEd25519Ssh.MLDSA_SIGNATURE_LEN + 5].toInt() xor 1).toByte() }
        assertFalse(MlDsaEd25519Ssh.compositeVerify(pk, m, badMl))
        assertFalse(MlDsaEd25519Ssh.compositeVerify(pk, m, badEd))
        assertFalse(MlDsaEd25519Ssh.compositeVerify(pk, m, s.copyOf(s.size - 1)))
    }

    @Test
    fun ourSignatureOverTheVectorVerifies() {
        val sk = jsonB64("sk")
        val m = jsonB64("m")
        val hedged = MlDsaEd25519Ssh.compositeSign(sk, m)
        assertTrue(MlDsaEd25519Ssh.compositeVerify(jsonB64("pk"), m, hedged))
        // Deterministic ML-DSA (no randomness) repeats exactly.
        val d1 = MlDsaEd25519Ssh.compositeSign(sk, m, rng = null)
        val d2 = MlDsaEd25519Ssh.compositeSign(sk, m, rng = null)
        assertArrayEquals(d1, d2)
        assertTrue(MlDsaEd25519Ssh.compositeVerify(jsonB64("pk"), m, d1))
    }

    // ── Genuine SSHSIG from ssh-keygen ───────────────────────────────

    private class SshSig(val publicBlob: ByteArray, val namespace: String, val hashAlg: String, val signature: ByteArray)

    private fun parseArmoredSshSig(armored: String): SshSig {
        val b64 = armored.substringAfter("-----BEGIN SSH SIGNATURE-----")
            .substringBefore("-----END SSH SIGNATURE-----")
            .filter { !it.isWhitespace() }
        val blob = Base64.getDecoder().decode(b64)
        assertArrayEquals("SSHSIG".toByteArray(), blob.copyOfRange(0, 6))
        val r = SshReader(blob, 6)
        assertEquals(1L, r.u32())
        val pub = r.string()
        val ns = String(r.string(), Charsets.UTF_8)
        assertEquals(0, r.string().size) // reserved
        val hash = String(r.string(), Charsets.UTF_8)
        val sig = r.string()
        r.requireEnd()
        return SshSig(pub, ns, hash, sig)
    }

    /** The SSHSIG structure that is actually signed (sshsig.c sshsig_wrap_sign). */
    private fun sshSigSignedData(namespace: String, data: ByteArray): ByteArray {
        val h = ByteArray(64)
        SHA512Digest().apply { update(data, 0, data.size); doFinal(h, 0) }
        return "SSHSIG".toByteArray() + SshWire().apply {
            string(namespace)
            string(ByteArray(0))
            string("sha512")
            string(h)
        }.bytes()
    }

    @Test
    fun genuineSshSigVerifiesEndToEnd() {
        val sig = parseArmoredSshSig(text("sshsig-mldsa44-ed25519.sig"))
        val namespace = text("sshsig-namespace").trim()
        assertEquals("unittest", namespace)
        assertEquals(namespace, sig.namespace)
        assertEquals("sha512", sig.hashAlg)

        val (pk, _) = MlDsaEd25519Ssh.parsePublicKeyLine(text("sshsig-mldsa44-ed25519.pub"))
        assertArrayEquals(MlDsaEd25519Ssh.publicBlob(pk), sig.publicBlob)
        // The signature blob and the key in it carry OpenSSH 10.6's type name.
        assertEquals("ssh-mldsa44-ed25519", MlDsaEd25519Ssh.KEY_TYPE)
        assertEquals(MlDsaEd25519Ssh.KEY_TYPE, SshReader(sig.signature).cstring())
        assertEquals(MlDsaEd25519Ssh.KEY_TYPE, SshReader(sig.publicBlob).cstring())
        assertEquals("SHA256:D1KmvmjD+up3lg6OFZEnWrmD1UvG8wW+A6i0W1vaSzg", MlDsaEd25519Ssh.fingerprint(pk))

        val signed = sshSigSignedData(namespace, resource("sshsig-signed-data"))
        assertTrue(MlDsaEd25519Ssh.verify(pk, sig.signature, signed))
        // Wrong namespace or data: no.
        assertFalse(MlDsaEd25519Ssh.verify(pk, sig.signature, sshSigSignedData("other", resource("sshsig-signed-data"))))
        assertFalse(MlDsaEd25519Ssh.verify(pk, sig.signature, sshSigSignedData(namespace, resource("sshsig-signed-data") + 0x0A)))
    }

    @Test
    fun sshSigPrivateKeyMatchesAndSignsTheSameStructure() {
        val decoded = OpenSshKeyFile.read(resource("sshsig-mldsa44-ed25519"), null)
        decoded.key.use { key ->
            val (pk, _) = MlDsaEd25519Ssh.parsePublicKeyLine(text("sshsig-mldsa44-ed25519.pub"))
            assertArrayEquals(pk, key.publicKey)
            val signed = sshSigSignedData("unittest", resource("sshsig-signed-data"))
            val blob = key.sign(signed)
            assertTrue(MlDsaEd25519Ssh.verify(pk, blob, signed))
        }
    }

    // ── Our own keys ─────────────────────────────────────────────────

    @Test
    fun generateSignVerifyRoundTrip() {
        MlDsaEd25519Key.generate().use { key ->
            assertEquals(MlDsaEd25519Ssh.PUBLIC_LEN, key.publicKey.size)
            val data = "SSH userauth request stand-in".toByteArray()
            val blob = key.sign(data)
            assertEquals(4 + MlDsaEd25519Ssh.KEY_TYPE.length + 4 + MlDsaEd25519Ssh.SIGNATURE_LEN, blob.size)
            assertEquals(MlDsaEd25519Ssh.KEY_TYPE, SshReader(blob).cstring())
            assertTrue(key.verify(blob, data))
            assertFalse(key.verify(blob, data + 0x01))
            MlDsaEd25519Key.generate().use { other -> assertFalse(other.verify(blob, data)) }
        }
    }

    @Test
    fun seedsRoundTripAndCloseWipes() {
        val key = MlDsaEd25519Key.generate()
        val seeds = key.privateBytes()
        MlDsaEd25519Key.fromPrivateBytes(seeds).use { again -> assertArrayEquals(key.publicKey, again.publicKey) }
        MlDsaEd25519Key.fromSeeds(seeds.copyOfRange(0, 32), seeds.copyOfRange(32, 64)).use { again ->
            assertArrayEquals(key.publicKey, again.publicKey)
        }
        key.close()
        try {
            key.sign(ByteArray(1))
            fail("A closed key must not sign")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun publicLineRoundTripAndLegacyNameRead() {
        MlDsaEd25519Key.generate().use { key ->
            val line = key.publicKeyLine("phone key")
            assertTrue(line.startsWith(MlDsaEd25519Ssh.KEY_TYPE + " "))
            assertTrue(line.endsWith(" phone key"))
            val (pk, comment) = MlDsaEd25519Ssh.parsePublicKeyLine(line)
            assertArrayEquals(key.publicKey, pk)
            assertEquals("phone key", comment)
            assertEquals(MlDsaEd25519Ssh.KEY_TYPE, SshReader(key.publicBlob).cstring())

            // 4.8.0 RC7 (item 1): the 10.4 / 10.5 name reads, in the blob and
            // the line, and re-encodes under the new name.
            val legacyBlob = SshWire().apply { string(MlDsaEd25519Ssh.LEGACY_KEY_TYPE); string(key.publicKey) }.bytes()
            assertTrue(MlDsaEd25519Ssh.isPublicBlob(legacyBlob))
            assertArrayEquals(key.publicKey, MlDsaEd25519Ssh.parsePublicBlob(legacyBlob))
            val legacyLine = MlDsaEd25519Ssh.LEGACY_KEY_TYPE + " " + Base64.getEncoder().encodeToString(legacyBlob) + " old"
            val (legacyPk, legacyComment) = MlDsaEd25519Ssh.parsePublicKeyLine(legacyLine)
            assertArrayEquals(key.publicKey, legacyPk)
            assertEquals("old", legacyComment)
            assertArrayEquals(key.publicBlob, MlDsaEd25519Ssh.publicBlob(legacyPk))
            assertEquals(key.fingerprint, MlDsaEd25519Ssh.fingerprint(legacyPk))
            // The fingerprint hashes the whole blob, so the two names differ.
            assertFalse(key.fingerprint == MlDsaEd25519Ssh.fingerprintOfBlob(legacyBlob))

            // The line's name and the blob's must agree.
            val mixed = MlDsaEd25519Ssh.KEY_TYPE + " " + Base64.getEncoder().encodeToString(legacyBlob)
            try {
                MlDsaEd25519Ssh.parsePublicKeyLine(mixed)
                fail("Expected SshFormatException")
            } catch (_: SshFormatException) {
            }
        }
    }

    @Test
    fun legacyPublicLineFromOpenSsh104Reads() {
        val line = text("legacy-10.4-mldsa44_ed25519_1.pub").trim()
        assertTrue(line.startsWith(MlDsaEd25519Ssh.LEGACY_KEY_TYPE + " "))
        val (pk, comment) = MlDsaEd25519Ssh.parsePublicKeyLine(line)
        assertEquals("MLDSA44-ED25519 test key #1", comment)
        assertEquals("SHA256:fotS8vyYfLRDu95aRszDl72PPJ+TBnnJDnd3fhnW3LE", MlDsaEd25519Ssh.fingerprint(pk))
        assertTrue(MlDsaEd25519Ssh.publicKeyLine(pk, comment).startsWith(MlDsaEd25519Ssh.KEY_TYPE + " "))
    }

    @Test
    fun signatureUnderTheLegacyNameIsRefused() {
        // 4.8.0 RC7 (item 1): OpenSSH 10.6 compares the signature's name
        // exactly, so PGPony neither writes nor accepts the old one there.
        MlDsaEd25519Key.generate().use { key ->
            val data = byteArrayOf(1, 2, 3)
            val blob = key.sign(data)
            assertEquals(MlDsaEd25519Ssh.KEY_TYPE, SshReader(blob).cstring())
            val raw = MlDsaEd25519Ssh.parseSignatureBlob(blob)
            val legacySig = SshWire().apply { string(MlDsaEd25519Ssh.LEGACY_KEY_TYPE); string(raw) }.bytes()
            assertFalse(key.verify(legacySig, data))
            try {
                MlDsaEd25519Ssh.parseSignatureBlob(legacySig)
                fail("Expected SshFormatException")
            } catch (_: SshFormatException) {
            }
            assertTrue(key.verify(blob, data))
        }
    }

    @Test
    fun otherBlobsAreRefused() {
        val ed = SshWire().apply { string("ssh-ed25519"); string(ByteArray(32)) }.bytes()
        assertFalse(MlDsaEd25519Ssh.isPublicBlob(ed))
        val short = SshWire().apply { string(MlDsaEd25519Ssh.KEY_TYPE); string(ByteArray(1343)) }.bytes()
        assertFalse(MlDsaEd25519Ssh.isPublicBlob(short))
        val trailing = SshWire().apply { string(MlDsaEd25519Ssh.KEY_TYPE); string(ByteArray(1344)); uint32(0) }.bytes()
        assertFalse(MlDsaEd25519Ssh.isPublicBlob(trailing))
        // A length field that points past the end.
        val lying = byteArrayOf(0x7F, 0, 0, 0, 1)
        assertFalse(MlDsaEd25519Ssh.isPublicBlob(lying))
    }

    @Test
    fun fingerprintIsOpenSshSha256Form() {
        MlDsaEd25519Key.generate().use { key ->
            val fp = key.fingerprint
            assertTrue(fp.startsWith("SHA256:"))
            assertEquals(7 + 43, fp.length) // 32 octets, unpadded base64
            assertFalse(fp.contains("="))
        }
    }
}
