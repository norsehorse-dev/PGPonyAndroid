// SshKeyStoreTest.kt
// PGPony Android, 4.8.0 RC7 (item 1): the SSH-only key store over an
// in-memory vault (the app's vault is SecureKeyStore, which needs Android):
// generate, list, get, sign, rename, delete, import of ssh-keygen's own files
// (openssh-mldsa/ test resources), typed import errors, encrypted export and
// re-import, the id scheme, and the backup entries and their merge on restore.
// Also the OpenSSH 10.6 rename: a 10.4 file imports under the new name, and a
// record an earlier RC7 build stored under the old name is skipped, not a crash.

package com.pgpony.android.data.ssh

import com.pgpony.android.backup.SshKeyBackup
import com.pgpony.android.backup.UstarArchive
import com.pgpony.android.crypto.ssh.MlDsaEd25519Key
import com.pgpony.android.crypto.ssh.MlDsaEd25519Ssh
import com.pgpony.android.crypto.ssh.OpenSshKeyFile
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class SshKeyStoreTest {

    /** An in-memory vault, with switches that make stored material unreadable
     *  (all of it, one key's seeds, or the store itself) or a write fail. */
    private class MemoryVault : SshKeyVault {
        val secrets = LinkedHashMap<String, ByteArray>()
        val metas = LinkedHashMap<String, ByteArray>()
        var unreadable = false
        val unreadableSecrets = HashSet<String>()
        var namesFail = false
        var writesLeft = Int.MAX_VALUE
        override fun names(): List<String> {
            if (namesFail) throw IllegalStateException("store unavailable")
            return (secrets.keys + metas.keys).distinct()
        }
        override fun readSecret(name: String): ByteArray? =
            if (unreadable || name in unreadableSecrets) null else secrets[name]?.copyOf()
        override fun readMeta(name: String): ByteArray? = if (unreadable) null else metas[name]?.copyOf()
        override fun write(name: String, secret: ByteArray, meta: ByteArray) {
            if (writesLeft-- <= 0) throw IllegalStateException("write failed")
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

    private fun text(name: String) = String(resource(name), Charsets.UTF_8)

    @Test
    fun generateListGetSignVerify() {
        val store = newStore()
        val a = store.generate("laptop")
        val b = store.generate("  server\nbox  ")
        assertEquals(listOf(a, b), store.list())
        assertEquals("server box", b.label)
        assertTrue(a.id.startsWith("ssh:SHA256:"))
        assertEquals("ssh:" + a.fingerprint, a.id)
        assertEquals(a, store.get(a.id))
        assertEquals(a.publicKeyLine, store.publicLine(a.id))
        assertTrue(a.publicKeyLine.endsWith(" laptop"))

        val data = "challenge".toByteArray()
        val sig = store.sign(a.id, data)
        assertTrue(MlDsaEd25519Ssh.verify(a.publicKey, sig, data))
        assertFalse(MlDsaEd25519Ssh.verify(b.publicKey, sig, data))
    }

    @Test
    fun idsNeverLookLikeOpenPgp() {
        val store = newStore()
        val e = store.generate("k")
        assertTrue(SshKeyStore.isSshKeyId(e.id))
        assertFalse(SshKeyStore.isSshKeyId("0123456789ABCDEF0123456789ABCDEF01234567"))
        assertFalse(SshKeyStore.isSshKeyId("-1234567890"))
        assertFalse(SshKeyStore.isSshKeyId(null))
        // The way the SSH provider tests an OpenPGP fingerprint must reject it.
        val hex = e.id.removePrefix("0x").filter { !it.isWhitespace() && it != ':' }
        assertFalse(hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' })
        assertNull(e.id.toLongOrNull())
        // Unknown or garbled ids are simply not found.
        assertNull(store.get("ssh:SHA256:AAAA"))
        assertNull(store.get("ssh:nonsense"))
        assertNull(store.get(e.fingerprint))
    }

    @Test
    fun renameAndDelete() {
        val store = newStore()
        val e = store.generate("old")
        val r = store.rename(e.id, "new name")
        assertEquals("new name", r.label)
        assertEquals("new name", store.get(e.id)!!.label)
        assertEquals(e.createdAt, store.get(e.id)!!.createdAt)
        assertTrue(store.delete(e.id))
        assertFalse(store.delete(e.id))
        assertNull(store.get(e.id))
        try {
            store.rename(e.id, "x")
            fail("Expected NotFound")
        } catch (_: SshKeyError.NotFound) {
        }
        try {
            store.sign(e.id, ByteArray(1))
            fail("Expected NotFound")
        } catch (_: SshKeyError.NotFound) {
        }
    }

    @Test
    fun importsSshKeygenFilesWithAndWithoutPassphrase() {
        val store = newStore()
        val plain = store.import(resource("mldsa44_ed25519_1"))
        assertTrue(plain.added)
        assertEquals("MLDSA44-ED25519 test key #1", plain.entry.label)
        assertEquals(text("mldsa44_ed25519_1.fp").trim(), plain.entry.fingerprint)
        assertEquals(text("mldsa44_ed25519_1.pub").trim(), plain.entry.publicKeyLine)

        // The same key, passphrase-protected: already held, label kept.
        val again = store.import(resource("mldsa44_ed25519_1_pw"), text("pw").trim().toCharArray(), label = "other")
        assertFalse(again.added)
        assertEquals(plain.entry.id, again.entry.id)
        assertEquals("MLDSA44-ED25519 test key #1", store.get(plain.entry.id)!!.label)
        assertEquals(1, store.list().size)

        val second = store.import(resource("mldsa44_ed25519_2"), null, label = "chosen")
        assertTrue(second.added)
        assertEquals("chosen", second.entry.label)
        assertEquals(2, store.list().size)
    }

    @Test
    fun importErrorsAreTyped() {
        val store = newStore()
        try {
            store.import(resource("mldsa44_ed25519_1_pw"), null)
            fail("Expected PassphraseRequired")
        } catch (_: SshKeyError.PassphraseRequired) {
        }
        try {
            store.import(resource("mldsa44_ed25519_1_pw"), "nope".toCharArray())
            fail("Expected WrongPassphrase")
        } catch (_: SshKeyError.WrongPassphrase) {
        }
        try {
            store.import(resource("ed25519_1"), null)
            fail("Expected WrongKeyType")
        } catch (e: SshKeyError.WrongKeyType) {
            assertEquals("ssh-ed25519", e.keyType)
        }
        try {
            store.import("not a key".toByteArray(), null)
            fail("Expected Malformed")
        } catch (_: SshKeyError.Malformed) {
        }
        assertTrue(store.list().isEmpty())
        assertTrue(store.inspectFile(resource("mldsa44_ed25519_1_pw")).encrypted)
    }

    @Test
    fun exportEncryptedThenImportGivesTheSameKey() {
        val source = newStore()
        val e = source.generate("exported")
        val file = source.exportPrivate(e.id, "pass phrase".toCharArray())
        assertTrue(OpenSshKeyFile.inspect(file.toByteArray()).encrypted)

        val target = newStore()
        try {
            target.import(file.toByteArray(), "wrong".toCharArray())
            fail("Expected WrongPassphrase")
        } catch (_: SshKeyError.WrongPassphrase) {
        }
        val imported = target.import(file.toByteArray(), "pass phrase".toCharArray())
        assertTrue(imported.added)
        assertEquals(e.id, imported.entry.id)
        assertEquals("exported", imported.entry.label)
        // Same private key: a signature from the copy verifies under the original.
        val data = byteArrayOf(9, 8, 7)
        assertTrue(MlDsaEd25519Ssh.verify(e.publicKey, target.sign(imported.entry.id, data), data))

        try {
            source.exportPrivate(e.id, CharArray(0))
            fail("An export without a passphrase must be refused")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun unreadableMaterialIsTypedAndHidden() {
        val vault = MemoryVault()
        val store = newStore(vault)
        val e = store.generate("k")
        vault.unreadable = true
        assertTrue(store.list().isEmpty())
        assertNull(store.get(e.id))
        try {
            store.sign(e.id, ByteArray(1))
            fail("Expected Unreadable")
        } catch (_: SshKeyError.Unreadable) {
        }
        // Clear All Data still removes it.
        store.deleteAll()
        assertTrue(vault.names().isEmpty())
    }

    @Test
    fun backupEntriesRestoreAndMergeByFingerprint() {
        val source = newStore()
        val a = source.generate("alpha")
        val b = source.import(resource("mldsa44_ed25519_1")).entry
        val set = source.backupItems()
        assertEquals(0, set.skipped)
        val entries = SshKeyBackup.entries(set.items)
        assertEquals(SshKeyBackup.INDEX_NAME, entries.first().name)
        assertEquals(3, entries.size)
        assertTrue(entries.drop(1).all { it.name.startsWith("ssh-keys/") && it.name.endsWith(".key") })
        // Each key file is a plain OpenSSH private key file, readable without a passphrase.
        assertFalse(OpenSshKeyFile.inspect(entries[1].data).encrypted)

        // Through the real archive writer and reader, as in a backup.
        val archived = UstarArchive.read(UstarArchive.write(entries))

        val target = newStore()
        target.generate("unrelated")
        target.import(resource("mldsa44_ed25519_1"), null, label = "kept locally")
        val report = target.restoreItems(SshKeyBackup.items(archived))
        assertEquals(listOf(a.id), report.added.map { it.id })
        assertEquals("alpha", report.added.single().label)
        assertEquals(a.createdAt, report.added.single().createdAt)
        assertEquals(listOf(b.id), report.unchanged.map { it.id })
        assertTrue(report.failed.isEmpty())
        assertEquals("kept locally", target.get(b.id)!!.label)
        assertEquals(3, target.list().size)

        // Restoring again changes nothing.
        val again = target.restoreItems(SshKeyBackup.items(archived))
        assertTrue(again.added.isEmpty())
        assertEquals(2, again.unchanged.size)
    }

    @Test
    fun backupWithoutSshEntriesHasNoItemsAndDamagedFilesFail() {
        assertTrue(SshKeyBackup.entries(emptyList()).isEmpty())
        val old = listOf(
            UstarArchive.Entry("pgpony-meta.json", "{}".toByteArray()),
            UstarArchive.Entry("keys/abcd.asc", "x".toByteArray())
        )
        assertTrue(SshKeyBackup.items(old).isEmpty())

        // A key file the index does not list still restores (comment as label);
        // a damaged one is reported as failed.
        val store = newStore()
        val good = UstarArchive.Entry("ssh-keys/aa.key", resource("mldsa44_ed25519_2"))
        val bad = UstarArchive.Entry("ssh-keys/bb.key", "garbage".toByteArray())
        val report = store.restoreItems(SshKeyBackup.items(listOf(good, bad)))
        assertEquals(1, report.added.size)
        assertEquals("MLDSA44-ED25519 test key #2", report.added.single().label)
        assertEquals(1, report.failed.size)
        assertNotNull(store.get(report.added.single().id))
    }

    @Test
    fun backupCountsKeysItCannotRead() {
        // 4.8.0 RC7 (item 1): an unreadable key is counted, not silently left out.
        val vault = MemoryVault()
        val store = newStore(vault)
        val a = store.generate("readable")
        val b = store.generate("lost seeds")
        val c = store.generate("lost record")
        vault.unreadableSecrets.add(SshKeyStore.storageName(b.id)!!)
        vault.metas[SshKeyStore.storageName(c.id)!!] = "not json".toByteArray()
        val set = store.backupItems()
        assertEquals(listOf(a.fingerprint), set.items.map { it.fingerprint })
        assertEquals(2, set.skipped)

        // A failure of the store itself is thrown, for BackupService to report.
        vault.namesFail = true
        try {
            store.backupItems()
            fail("Expected the store failure")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun restoreReportsOnlyTheItemsThatFailedToStore() {
        // 4.8.0 RC7 (item 1): a store() that throws partway fails that item only.
        val source = newStore()
        source.generate("one")
        source.generate("two")
        source.generate("three")
        val items = SshKeyBackup.items(UstarArchive.read(UstarArchive.write(SshKeyBackup.entries(source.backupItems().items))))
        assertEquals(3, items.size)

        val vault = MemoryVault()
        val target = newStore(vault)
        vault.writesLeft = 1
        val report = target.restoreItems(items)
        assertEquals(listOf("one"), report.added.map { it.label })
        assertEquals(listOf("two", "three"), report.failed)
        assertEquals(1, target.list().size)
    }

    @Test
    fun cancelledImportStoresNothing() {
        // 4.8.0 RC7 (item 1): shouldStore is asked after the file is read.
        val store = newStore()
        try {
            store.import(resource("mldsa44_ed25519_1"), null, shouldStore = { false })
            fail("Expected CancellationException")
        } catch (_: java.util.concurrent.CancellationException) {
        }
        assertTrue(store.list().isEmpty())
        assertTrue(store.import(resource("mldsa44_ed25519_1"), null, shouldStore = { true }).added)
    }

    @Test
    fun labelsAreNormalized() {
        assertEquals("a b", SshKeyStore.normalizeLabel(" a\tb \u0000"))
        assertEquals(SshKeyStore.MAX_LABEL_LENGTH, SshKeyStore.normalizeLabel("x".repeat(500)).length)
        val store = newStore()
        val e = store.generate("")
        assertEquals("", e.label)
        assertEquals(MlDsaEd25519Ssh.KEY_TYPE + " " + e.publicKeyLine.split(" ")[1], e.publicKeyLine)
    }

    @Test
    fun publicBlobMatchesTheLine() {
        val store = newStore()
        val e = store.generate("k")
        val blob = java.util.Base64.getDecoder().decode(e.publicKeyLine.split(" ")[1])
        assertArrayEquals(blob, e.publicBlob)
        assertEquals(e.fingerprint, MlDsaEd25519Ssh.fingerprintOfBlob(blob))
    }

    // ── 4.8.0 RC7 (item 1): the OpenSSH 10.6 name ────────────────────

    private fun sha256Hex(b: ByteArray): String =
        SshKeyStore.hex(java.security.MessageDigest.getInstance("SHA-256").digest(b))

    @Test
    fun idsAndStorageNamesHashTheNewNameBlob() {
        val vault = MemoryVault()
        val store = newStore(vault)
        val e = store.import(resource("mldsa44_ed25519_1")).entry
        assertEquals("ssh:" + text("mldsa44_ed25519_1.fp").trim(), e.id)
        assertEquals(MlDsaEd25519Ssh.KEY_TYPE, e.keyType)
        assertEquals(sha256Hex(MlDsaEd25519Ssh.publicBlob(e.publicKey)), SshKeyStore.storageName(e.id))
        assertEquals(listOf(SshKeyStore.storageName(e.id)), vault.names())
        val meta = String(vault.metas.values.single(), Charsets.UTF_8)
        assertTrue(meta.contains("\"type\":\"${MlDsaEd25519Ssh.KEY_TYPE}\""))
    }

    @Test
    fun legacyNamedFileImportsUnderTheNewName() {
        val vault = MemoryVault()
        val store = newStore(vault)
        val imported = store.import(resource("legacy-10.4-mldsa44_ed25519_1"))
        assertTrue(imported.added)
        val e = imported.entry
        val newFp = "SHA256:fotS8vyYfLRDu95aRszDl72PPJ+TBnnJDnd3fhnW3LE"
        assertEquals(newFp, e.fingerprint)
        assertEquals("ssh:$newFp", e.id)
        assertEquals("MLDSA44-ED25519 test key #1", e.label)
        assertTrue(e.publicKeyLine.startsWith(MlDsaEd25519Ssh.KEY_TYPE + " "))
        assertEquals(sha256Hex(e.publicBlob), SshKeyStore.storageName(e.id))
        assertFalse(String(vault.metas.values.single(), Charsets.UTF_8).contains("@openssh.com"))
        assertEquals(e, store.get(e.id))

        // Export and backup write the new name.
        val exported = store.exportPrivate(e.id, "pw".toCharArray())
        assertEquals(MlDsaEd25519Ssh.KEY_TYPE, OpenSshKeyFile.inspect(exported.toByteArray()).keyType)
        val item = store.backupItems().items.single()
        assertEquals(newFp, item.fingerprint)
        assertEquals(MlDsaEd25519Ssh.KEY_TYPE, OpenSshKeyFile.inspect(item.keyFile).keyType)

        // Importing the legacy file again finds the key already held.
        assertFalse(store.import(resource("legacy-10.4-mldsa44_ed25519_1")).added)
        assertEquals(1, store.list().size)
    }

    @Test
    fun preRenameRecordIsSkippedNotACrash() {
        // An earlier RC7 build stored keys under the SHA-256 of the
        // @openssh.com blob, with that name in the record. Not migrated.
        val vault = MemoryVault()
        val store = newStore(vault)
        val kept = store.generate("current")
        val seeds = ByteArray(MlDsaEd25519Ssh.PRIVATE_LEN) { (it * 7 + 1).toByte() }
        val pk = MlDsaEd25519Ssh.publicKeyFromSeeds(seeds)
        val legacyBlob = com.pgpony.android.crypto.ssh.SshWire().apply {
            string(MlDsaEd25519Ssh.LEGACY_KEY_TYPE); string(pk)
        }.bytes()
        val oldName = sha256Hex(legacyBlob)
        val oldId = SshKeyStore.idForFingerprint(MlDsaEd25519Ssh.fingerprintOfBlob(legacyBlob))
        assertEquals(oldName, SshKeyStore.storageName(oldId))
        val meta = "{\"v\":1,\"type\":\"${MlDsaEd25519Ssh.LEGACY_KEY_TYPE}\",\"label\":\"old test key\"," +
            "\"createdAt\":1,\"publicKey\":\"${java.util.Base64.getEncoder().encodeToString(pk)}\"}"
        vault.write(oldName, seeds, meta.toByteArray())

        assertEquals(listOf(kept), store.list())
        assertNull(store.get(oldId))
        assertNull(store.publicLine(oldId))
        try {
            store.sign(oldId, ByteArray(1))
            fail("Expected Unreadable")
        } catch (_: SshKeyError.Unreadable) {
        }
        try {
            store.rename(oldId, "x")
            fail("Expected Unreadable")
        } catch (_: SshKeyError.Unreadable) {
        }
        try {
            store.exportPrivate(oldId, "pw".toCharArray())
            fail("Expected Unreadable")
        } catch (_: SshKeyError.Unreadable) {
        }
        val set = store.backupItems()
        assertEquals(listOf(kept.fingerprint), set.items.map { it.fingerprint })
        assertEquals(1, set.skipped)

        // The same seeds, imported again, are a new key under the new name,
        // stored beside the old record; delete and Clear All Data remove both.
        val again = MlDsaEd25519Key.fromPrivateBytes(seeds).use { key ->
            store.import(OpenSshKeyFile.write(key, "again", null).toByteArray())
        }
        assertTrue(again.added)
        assertEquals("ssh:" + MlDsaEd25519Ssh.fingerprint(pk), again.entry.id)
        assertFalse(again.entry.id == oldId)
        assertEquals(2, store.list().size)
        assertTrue(store.delete(oldId))
        assertEquals(2, store.list().size)
        store.deleteAll()
        assertTrue(vault.names().isEmpty())
    }
}
