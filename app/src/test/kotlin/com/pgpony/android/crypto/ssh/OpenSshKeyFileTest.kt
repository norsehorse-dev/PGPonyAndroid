// OpenSshKeyFileTest.kt
// PGPony Android, 4.8.0 RC7 (item 1): openssh-key-v1 files for
// ssh-mldsa44-ed25519, against the files ssh-keygen 10.6 wrote for its own
// regress tests (test resources openssh-mldsa/, see the README):
// mldsa44_ed25519_1 (no passphrase), mldsa44_ed25519_1_pw (aes256-ctr and
// bcrypt_pbkdf, passphrase in "pw"), their .pub line and .fp fingerprint.
// legacy-10.4-mldsa44_ed25519_1 is ssh-keygen 10.4's file under the old
// ssh-mldsa44-ed25519@openssh.com name, for the legacy import.

package com.pgpony.android.crypto.ssh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.SecureRandom
import java.util.Base64

class OpenSshKeyFileTest {

    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/openssh-mldsa/$name")!!.use { it.readBytes() }

    private fun text(name: String): String = String(resource(name), Charsets.UTF_8)

    private val pw: CharArray get() = text("pw").trim().toCharArray()

    @Test
    fun readsUnencryptedFileAndMatchesPubAndFp() {
        OpenSshKeyFile.read(resource("mldsa44_ed25519_1"), null).let { d ->
            d.key.use { key ->
                assertEquals("MLDSA44-ED25519 test key #1", d.comment)
                assertEquals(text("mldsa44_ed25519_1.pub").trim(), key.publicKeyLine(d.comment))
                assertEquals(text("mldsa44_ed25519_1.fp").trim(), key.fingerprint)
            }
        }
        OpenSshKeyFile.read(resource("mldsa44_ed25519_2"), null).key.use { key ->
            assertEquals(text("mldsa44_ed25519_2.fp").trim(), key.fingerprint)
            assertArrayEquals(
                MlDsaEd25519Ssh.parsePublicKeyLine(text("mldsa44_ed25519_2.pub")).first,
                key.publicKey
            )
        }
    }

    @Test
    fun readsPassphraseFileAsTheSameKey() {
        val plain = OpenSshKeyFile.read(resource("mldsa44_ed25519_1"), null)
        val enc = OpenSshKeyFile.read(resource("mldsa44_ed25519_1_pw"), pw)
        plain.key.use { a ->
            enc.key.use { b ->
                assertArrayEquals(a.privateBytes(), b.privateBytes())
                assertEquals(plain.comment, enc.comment)
                assertEquals(text("mldsa44_ed25519_1.fp").trim(), b.fingerprint)
            }
        }
    }

    @Test
    fun inspectTellsEncryptionAndTypeWithoutPassphrase() {
        val info = OpenSshKeyFile.inspect(resource("mldsa44_ed25519_1_pw"))
        assertTrue(info.encrypted)
        assertEquals("aes256-ctr", info.cipher)
        assertEquals("bcrypt", info.kdf)
        assertEquals(MlDsaEd25519Ssh.KEY_TYPE, info.keyType)
        assertEquals(text("mldsa44_ed25519_1.fp").trim(), MlDsaEd25519Ssh.fingerprint(info.publicKey!!))
        // OpenSSH 10.6's test file was made with 24 rounds, before its default became 32.
        assertEquals(24L, info.rounds)
        assertNull(info.unsupportedEncryption)
        val plain = OpenSshKeyFile.inspect(resource("mldsa44_ed25519_1"))
        assertFalse(plain.encrypted)
        assertNull(plain.rounds)
        assertNull(plain.unsupportedEncryption)

        val ed = OpenSshKeyFile.inspect(resource("ed25519_1"))
        assertEquals("ssh-ed25519", ed.keyType)
        assertNull(ed.publicKey)
    }

    @Test
    fun wrongOrMissingPassphraseIsTyped() {
        try {
            OpenSshKeyFile.read(resource("mldsa44_ed25519_1_pw"), "not the passphrase".toCharArray())
            fail("Expected WrongPassphrase")
        } catch (_: OpenSshKeyFile.ReadError.WrongPassphrase) {
        }
        try {
            OpenSshKeyFile.read(resource("mldsa44_ed25519_1_pw"), null)
            fail("Expected PassphraseRequired")
        } catch (_: OpenSshKeyFile.ReadError.PassphraseRequired) {
        }
        try {
            OpenSshKeyFile.read(resource("mldsa44_ed25519_1_pw"), CharArray(0))
            fail("Expected PassphraseRequired")
        } catch (_: OpenSshKeyFile.ReadError.PassphraseRequired) {
        }
    }

    @Test
    fun otherKeyTypeIsRefused() {
        try {
            OpenSshKeyFile.read(resource("ed25519_1"), null)
            fail("Expected UnsupportedKeyType")
        } catch (e: OpenSshKeyFile.ReadError.UnsupportedKeyType) {
            assertEquals("ssh-ed25519", e.keyType)
        }
    }

    @Test
    fun garbageAndTruncationAreMalformed() {
        val cases = listOf(
            "hello".toByteArray(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n!!!!\n-----END OPENSSH PRIVATE KEY-----\n".toByteArray(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n".toByteArray(),
            text("mldsa44_ed25519_1").lines().let { l -> (l.take(10) + l.last { it.startsWith("-----END") }).joinToString("\n") }.toByteArray()
        )
        for (c in cases) {
            try {
                OpenSshKeyFile.read(c, null)
                fail("Expected Malformed")
            } catch (_: OpenSshKeyFile.ReadError.Malformed) {
            }
        }
    }

    @Test
    fun corruptedPrivateSectionIsMalformedNotACrash() {
        // Flip one octet of the seeds inside an unencrypted file: the public key
        // no longer matches the seeds.
        val raw = Base64.getDecoder().decode(
            text("mldsa44_ed25519_1").lines().filter { it.isNotBlank() && !it.startsWith("-----") }.joinToString("")
        )
        val bad = raw.copyOf().also { it[it.size - 60] = (it[it.size - 60].toInt() xor 0x55).toByte() }
        val file = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            Base64.getEncoder().encodeToString(bad).chunked(70).joinToString("\n") +
            "\n-----END OPENSSH PRIVATE KEY-----\n"
        try {
            OpenSshKeyFile.read(file.toByteArray(), null)
            fail("Expected Malformed")
        } catch (_: OpenSshKeyFile.ReadError.Malformed) {
        }
    }

    /** Returns [check] from nextInt so a written file can be compared octet for octet. */
    private class FixedCheck(private val check: Int) : SecureRandom() {
        override fun nextInt(): Int = check
    }

    @Test
    fun unencryptedWriteMatchesSshKeygenExactly() {
        val original = text("mldsa44_ed25519_1")
        val raw = Base64.getDecoder().decode(original.lines().filter { it.isNotBlank() && !it.startsWith("-----") }.joinToString(""))
        // The check value is the first u32 of the private section, after the
        // header: magic(15) + "none"(8) + "none"(8) + kdf(4) + nkeys(4) + blob + len(4).
        val blobLen = (4 + MlDsaEd25519Ssh.KEY_TYPE.length + 4 + MlDsaEd25519Ssh.PUBLIC_LEN)
        val at = 15 + 8 + 8 + 4 + 4 + 4 + blobLen + 4
        val check = SshReader(raw, at).u32().toInt()
        val d = OpenSshKeyFile.read(original.toByteArray(), null)
        d.key.use { key ->
            val written = OpenSshKeyFile.write(key, d.comment, null, rng = FixedCheck(check))
            assertEquals(original, written)
        }
    }

    @Test
    fun encryptedExportThenImportGivesTheSameKey() {
        MlDsaEd25519Key.generate().use { key ->
            val pass = "correct horse battery staple".toCharArray()
            val file = OpenSshKeyFile.write(key, "phone key", pass)
            val info = OpenSshKeyFile.inspect(file.toByteArray())
            assertTrue(info.encrypted)
            assertEquals("aes256-ctr", info.cipher)
            assertEquals("bcrypt", info.kdf)
            // Default rounds and salt length as ssh-keygen 10.6 writes them.
            assertEquals(32, OpenSshKeyFile.DEFAULT_ROUNDS)
            val raw = Base64.getDecoder().decode(file.lines().filter { it.isNotBlank() && !it.startsWith("-----") }.joinToString(""))
            val r = SshReader(raw, 15)
            r.string(); r.string()
            val kdf = SshReader(r.string())
            assertEquals(OpenSshKeyFile.SALT_LEN, kdf.string().size)
            assertEquals(OpenSshKeyFile.DEFAULT_ROUNDS.toLong(), kdf.u32())

            val back = OpenSshKeyFile.read(file.toByteArray(), pass)
            back.key.use { k2 ->
                assertArrayEquals(key.privateBytes(), k2.privateBytes())
                assertEquals("phone key", back.comment)
            }
            try {
                OpenSshKeyFile.read(file.toByteArray(), "wrong".toCharArray())
                fail("Expected WrongPassphrase")
            } catch (_: OpenSshKeyFile.ReadError.WrongPassphrase) {
            }
        }
    }

    @Test
    fun nonAsciiPassphraseAndCommentRoundTrip() {
        MlDsaEd25519Key.generate().use { key ->
            val pass = "contraseña ключ".toCharArray()
            val file = OpenSshKeyFile.write(key, "teléfono", pass, rounds = 4)
            val back = OpenSshKeyFile.read(file.toByteArray(), pass)
            back.key.use { assertArrayEquals(key.publicKey, it.publicKey) }
            assertEquals("teléfono", back.comment)
        }
    }

    /** The passphrase file with its bcrypt rounds set to [rounds]. */
    private fun withRounds(rounds: Int): ByteArray {
        val raw = Base64.getDecoder().decode(
            text("mldsa44_ed25519_1_pw").lines().filter { it.isNotBlank() && !it.startsWith("-----") }.joinToString("")
        )
        // magic(15) + "aes256-ctr"(4+10) + "bcrypt"(4+6) + kdf len(4) + salt string(4+16) -> rounds
        val at = 15 + 14 + 10 + 4 + 20
        assertEquals(24L, SshReader(raw, at).u32())
        val bad = raw.copyOf()
        bad[at] = (rounds ushr 24).toByte(); bad[at + 1] = (rounds ushr 16).toByte()
        bad[at + 2] = (rounds ushr 8).toByte(); bad[at + 3] = rounds.toByte()
        return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            Base64.getEncoder().encodeToString(bad).chunked(70).joinToString("\n") +
            "\n-----END OPENSSH PRIVATE KEY-----\n").toByteArray()
    }

    @Test
    fun excessiveRoundsAreRefusedBeforeTheKdfRuns() {
        val file = withRounds(0x7F000018)
        try {
            OpenSshKeyFile.read(file, pw)
            fail("Expected UnsupportedEncryption")
        } catch (_: OpenSshKeyFile.ReadError.UnsupportedEncryption) {
        }
    }

    @Test
    fun excessiveRoundsAreReportedBeforeAPassphraseIsAsked() {
        // 4.8.0 RC7 (item 1): inspect() reports it, and read() without a
        // passphrase refuses the encryption rather than asking for one.
        val over = withRounds(OpenSshKeyFile.MAX_ROUNDS + 1)
        val info = OpenSshKeyFile.inspect(over)
        assertTrue(info.encrypted)
        assertEquals(OpenSshKeyFile.MAX_ROUNDS + 1L, info.rounds)
        assertTrue(info.unsupportedEncryption!!.contains("${OpenSshKeyFile.MAX_ROUNDS + 1}"))
        try {
            OpenSshKeyFile.read(over, null)
            fail("Expected UnsupportedEncryption")
        } catch (_: OpenSshKeyFile.ReadError.UnsupportedEncryption) {
        }
        assertEquals(256, OpenSshKeyFile.MAX_ROUNDS)
        // At the limit the file is still offered for a passphrase (wrong check
        // values, since the key was derived with 24 rounds).
        val atLimit = withRounds(OpenSshKeyFile.MAX_ROUNDS)
        assertNull(OpenSshKeyFile.inspect(atLimit).unsupportedEncryption)
        try {
            OpenSshKeyFile.read(atLimit, null)
            fail("Expected PassphraseRequired")
        } catch (_: OpenSshKeyFile.ReadError.PassphraseRequired) {
        }
    }

    @Test
    fun unsupportedCipherIsReportedByInspect() {
        // 4.8.0 RC7 (item 1): an AEAD cipher PGPony does not read is known up front.
        MlDsaEd25519Key.generate().use { key ->
            val file = OpenSshKeyFile.write(key, "c", "pw".toCharArray(), rounds = 4)
            val raw = Base64.getDecoder().decode(
                file.lines().filter { it.isNotBlank() && !it.startsWith("-----") }.joinToString("")
            )
            // Same length as "aes256-ctr", so the rest of the layout holds.
            val name = "aes256-xyz".toByteArray(Charsets.US_ASCII)
            System.arraycopy(name, 0, raw, 15 + 4, name.size)
            val changed = ("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(raw).chunked(70).joinToString("\n") +
                "\n-----END OPENSSH PRIVATE KEY-----\n").toByteArray()
            val info = OpenSshKeyFile.inspect(changed)
            assertEquals("aes256-xyz", info.cipher)
            assertTrue(info.unsupportedEncryption!!.contains("aes256-xyz"))
            try {
                OpenSshKeyFile.read(changed, null)
                fail("Expected UnsupportedEncryption")
            } catch (_: OpenSshKeyFile.ReadError.UnsupportedEncryption) {
            }
        }
    }

    // ── 4.8.0 RC7 (item 1): the 10.4 / 10.5 name ─────────────────────

    /** ssh-keygen 10.6 -l would print this for the 10.4 test key #1 once its
     *  blob is under the new name (10.4 printed MHrtMS/...). */
    private val legacyKeyNewFingerprint = "SHA256:fotS8vyYfLRDu95aRszDl72PPJ+TBnnJDnd3fhnW3LE"

    @Test
    fun legacyNamedFileImportsUnderTheNewName() {
        val file = resource("legacy-10.4-mldsa44_ed25519_1")
        val info = OpenSshKeyFile.inspect(file)
        assertEquals(MlDsaEd25519Ssh.LEGACY_KEY_TYPE, info.keyType)
        assertTrue(MlDsaEd25519Ssh.isKeyType(info.keyType))
        assertFalse(info.encrypted)

        val legacyLine = text("legacy-10.4-mldsa44_ed25519_1.pub").trim()
        val legacyBlob = Base64.getDecoder().decode(legacyLine.split(" ")[1])
        assertEquals("SHA256:MHrtMS/Vf35zxTemIBpFyKqv9rT1bd1XMLqM9CnT8WY", MlDsaEd25519Ssh.fingerprintOfBlob(legacyBlob))

        val d = OpenSshKeyFile.read(file, null)
        d.key.use { key ->
            assertEquals("MLDSA44-ED25519 test key #1", d.comment)
            assertArrayEquals(MlDsaEd25519Ssh.parsePublicKeyLine(legacyLine).first, key.publicKey)
            assertEquals(legacyKeyNewFingerprint, key.fingerprint)
            assertEquals(MlDsaEd25519Ssh.KEY_TYPE, SshReader(key.publicBlob).cstring())
            assertEquals(
                MlDsaEd25519Ssh.KEY_TYPE + " " + Base64.getEncoder().encodeToString(key.publicBlob) + " " + d.comment,
                key.publicKeyLine(d.comment)
            )

            // Written back, the file carries only the new name, in the public
            // blob and in the private section, and reads as the same key.
            val written = OpenSshKeyFile.write(key, d.comment, null)
            val raw = Base64.getDecoder().decode(
                written.lines().filter { it.isNotBlank() && !it.startsWith("-----") }.joinToString("")
            )
            assertFalse(String(raw, Charsets.ISO_8859_1).contains("@openssh.com"))
            assertEquals(MlDsaEd25519Ssh.KEY_TYPE, OpenSshKeyFile.inspect(written.toByteArray()).keyType)
            OpenSshKeyFile.read(written.toByteArray(), null).key.use { back ->
                assertArrayEquals(key.privateBytes(), back.privateBytes())
                assertEquals(legacyKeyNewFingerprint, back.fingerprint)
            }
        }
    }

    @Test
    fun newNameFileHasNoLegacyNameInIt() {
        val raw = Base64.getDecoder().decode(
            text("mldsa44_ed25519_1").lines().filter { it.isNotBlank() && !it.startsWith("-----") }.joinToString("")
        )
        assertFalse(String(raw, Charsets.ISO_8859_1).contains("@openssh.com"))
        assertEquals(MlDsaEd25519Ssh.KEY_TYPE, OpenSshKeyFile.inspect(resource("mldsa44_ed25519_1")).keyType)
    }
}
