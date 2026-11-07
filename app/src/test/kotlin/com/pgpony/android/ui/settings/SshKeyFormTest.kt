// SshKeyFormTest.kt
// PGPony Android, 4.8.0 RC7 (item 1): the label, export passphrase and file
// name rules behind Settings > SSH keys.

package com.pgpony.android.ui.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SshKeyFormTest {

    // ── Label ────────────────────────────────────────────────────────

    @Test
    fun aBlankLabelIsRefused() {
        assertFalse(SshKeyForm.isLabelUsable(""))
        assertFalse(SshKeyForm.isLabelUsable("   "))
        assertFalse(SshKeyForm.isLabelUsable("\n\t"))
    }

    @Test
    fun aRealLabelIsKeptOnOneTrimmedLine() {
        assertTrue(SshKeyForm.isLabelUsable("phone"))
        assertEquals("work phone", SshKeyForm.cleanLabel("  work\nphone "))
    }

    @Test
    fun aLongLabelIsCut() {
        assertEquals(200, SshKeyForm.cleanLabel("a".repeat(500)).length)
    }

    // ── Export passphrase ────────────────────────────────────────────

    @Test
    fun anEmptyPassphraseIsRefused() {
        assertEquals(SshKeyForm.PassphraseProblem.EMPTY, SshKeyForm.passphraseProblem("", ""))
        assertEquals(SshKeyForm.PassphraseProblem.EMPTY, SshKeyForm.passphraseProblem("", "x"))
    }

    @Test
    fun theTwoEntriesMustMatch() {
        assertEquals(SshKeyForm.PassphraseProblem.MISMATCH, SshKeyForm.passphraseProblem("secret", "secret "))
        assertEquals(SshKeyForm.PassphraseProblem.MISMATCH, SshKeyForm.passphraseProblem("secret", "Secret"))
        assertEquals(SshKeyForm.PassphraseProblem.MISMATCH, SshKeyForm.passphraseProblem("secret", ""))
    }

    @Test
    fun matchingEntriesPass() {
        assertNull(SshKeyForm.passphraseProblem("correct horse", "correct horse"))
        assertNull(SshKeyForm.passphraseProblem(" ", " "))
    }

    // ── Export file name ─────────────────────────────────────────────

    @Test
    fun aSimpleLabelIsTheFileName() {
        assertEquals("phone", SshKeyForm.exportFileName("phone"))
        assertEquals("id_work-2026.key", SshKeyForm.exportFileName("id_work-2026.key"))
    }

    @Test
    fun otherCharactersBecomeOneUnderscore() {
        assertEquals("work_laptop", SshKeyForm.exportFileName("work laptop"))
        assertEquals("me_host", SshKeyForm.exportFileName("me@host"))
        assertEquals("a_b", SshKeyForm.exportFileName("a / \\ b"))
        assertEquals("caf_phone", SshKeyForm.exportFileName("café phone"))
    }

    @Test
    fun neverAHiddenFileOrAPathOutOfTheFolder() {
        assertEquals("ssh", SshKeyForm.exportFileName(".ssh"))
        assertEquals("passwd", SshKeyForm.exportFileName("../../etc/passwd").substringAfterLast('_'))
        assertFalse(SshKeyForm.exportFileName("../x").contains('/'))
        assertFalse(SshKeyForm.exportFileName("../x").startsWith("."))
    }

    @Test
    fun nothingUsableFallsBackToTheSshKeygenName() {
        assertEquals("id_mldsa44_ed25519", SshKeyForm.exportFileName(""))
        assertEquals("id_mldsa44_ed25519", SshKeyForm.exportFileName("日本"))
        assertEquals("id_mldsa44_ed25519", SshKeyForm.exportFileName("..."))
    }

    @Test
    fun aLongLabelGivesAShortName() {
        val name = SshKeyForm.exportFileName("k".repeat(300))
        assertEquals(SshKeyForm.MAX_FILE_NAME, name.length)
    }

    // ── Strings read from a picked file ──────────────────────────────

    @Test
    fun aFileTokenLosesControlCharactersAndIsCapped() {
        assertEquals("ssh-ed25519", SshKeyForm.displayToken("ssh-ed25519"))
        assertEquals("ssh-rsa", SshKeyForm.displayToken("ssh-\u0000rsa\n"))
        val long = SshKeyForm.displayToken("x".repeat(200))
        assertEquals(65, long.length)
        assertTrue(long.endsWith("…"))
    }
}
