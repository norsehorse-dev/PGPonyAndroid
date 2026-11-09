// RecipientGroupBackupTest.kt
// PGPony Android, 4.8.0 RC8 (item 4n): the recipient-groups.json backup entry.
// Round trip through the ustar archive, only members whose key is in the
// backup, a reader that tolerates damage and unknown fields, and an archive
// laid out so a 4.7.x restore (keys/*.asc, pgpony-meta.json and
// pgpony-settings.json only) passes over the entry.

package com.pgpony.android.backup

import com.pgpony.android.data.groups.BackupGroup
import com.pgpony.android.data.groups.RecipientGroup
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RecipientGroupBackupTest {

    private fun fp(n: Int): String = n.toString(16).padStart(40, '0')

    private fun entry(json: String) = UstarArchive.Entry(RecipientGroupBackup.ENTRY_NAME, json.toByteArray())

    @Test
    fun `groups survive the archive, with only the members in the backup`() {
        val groups = listOf(
            RecipientGroup("1", "Work", 20L, listOf(fp(2), fp(1).uppercase(), fp(9))),
            RecipientGroup("2", "Binned only", 30L, listOf(fp(9))),
            RecipientGroup("3", "Family", 10L, listOf(fp(3)))
        )
        val e = RecipientGroupBackup.entry(groups, listOf(fp(1), fp(2), fp(3)))
        assertNotNull(e)
        val back = RecipientGroupBackup.groups(UstarArchive.read(UstarArchive.write(listOf(e!!))))
        assertEquals(
            listOf(
                BackupGroup("Family", 10L, listOf(fp(3))),
                BackupGroup("Work", 20L, listOf(fp(1), fp(2)))
            ),
            back
        )
    }

    @Test
    fun `no entry when no group has a member in the backup`() {
        assertNull(RecipientGroupBackup.entry(emptyList(), listOf(fp(1))))
        assertNull(RecipientGroupBackup.entry(listOf(RecipientGroup("1", "G", 1L, listOf(fp(5)))), listOf(fp(1))))
    }

    @Test
    fun `the entry carries a format version and plain fingerprints`() {
        val e = RecipientGroupBackup.entry(listOf(RecipientGroup("1", "G", 1L, listOf(fp(1)))), listOf(fp(1)))!!
        val text = String(e.data)
        assertTrue(text.contains("\"formatVersion\":1"))
        assertTrue(text.contains("\"members\":[\"${fp(1)}\"]"))
        assertFalse("the group id stays on the device", text.contains("\"id\""))
    }

    @Test
    fun `a backup without the entry has no groups`() {
        val meta = UstarArchive.Entry("pgpony-meta.json", "{}".toByteArray())
        assertTrue(RecipientGroupBackup.groups(listOf(meta)).isEmpty())
    }

    @Test
    fun `damaged json or a wrong shape gives no groups instead of failing the restore`() {
        assertTrue(RecipientGroupBackup.groups(listOf(entry("{not json"))).isEmpty())
        assertTrue(RecipientGroupBackup.groups(listOf(entry("[1,2]"))).isEmpty())
        assertTrue(RecipientGroupBackup.groups(listOf(entry("{\"groups\":7}"))).isEmpty())
    }

    @Test
    fun `bad groups and members are skipped, unknown fields ignored`() {
        val json = """
            {"formatVersion":2,"future":true,"groups":[
              {"name":"  Club ","createdAt":5,"members":["${fp(1).uppercase()}","zz",7,"${fp(1)}"],"color":"red"},
              {"name":"","members":["${fp(2)}"]},
              {"members":["${fp(2)}"]},
              {"name":"${"x".repeat(65)}","members":["${fp(2)}"]},
              "not an object",
              {"name":"No date","members":[]}
            ]}
        """.trimIndent()
        assertEquals(
            listOf(BackupGroup("Club", 5L, listOf(fp(1))), BackupGroup("No date", 0L, emptyList())),
            RecipientGroupBackup.groups(listOf(entry(json)))
        )
    }

    @Test
    fun `a 4_7 restore passes over the entry`() {
        // What BackupService.restoreBackup in 4.7.x reads from an archive.
        val name = RecipientGroupBackup.ENTRY_NAME
        assertFalse(name.startsWith("keys/") && name.endsWith(".asc"))
        assertFalse(name == "pgpony-meta.json" || name == "pgpony-settings.json")
        // And the archive with the entry in it still reads back whole.
        val archive = UstarArchive.write(
            listOf(
                UstarArchive.Entry("pgpony-meta.json", "{}".toByteArray()),
                UstarArchive.Entry("keys/${fp(1)}.asc", "armor".toByteArray()),
                RecipientGroupBackup.entry(listOf(RecipientGroup("1", "G", 1L, listOf(fp(1)))), listOf(fp(1)))!!,
                UstarArchive.Entry("pgpony-settings.json", "{}".toByteArray())
            )
        )
        assertEquals(
            listOf("pgpony-meta.json", "keys/${fp(1)}.asc", name, "pgpony-settings.json"),
            UstarArchive.read(archive).map { it.name }
        )
    }
}
