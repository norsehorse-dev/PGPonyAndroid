// ShareFileActionsTest.kt
// PGPony Android, 4.8.0 (#72, #67): what the Quick Action offers for one
// shared file, and what a detached signature made there is called.

package com.pgpony.android.ui.share

import com.pgpony.android.ui.share.ShareFileActions.Action
import org.junit.Assert.assertEquals
import org.junit.Test

class ShareFileActionsTest {

    @Test
    fun `an ordinary file can be encrypted or signed`() {
        assertEquals(
            listOf(Action.ENCRYPT, Action.SIGN),
            ShareFileActions.forFile(isBackup = false, looksLikeMessage = false)
        )
    }

    @Test
    fun `an encrypted message is decrypted, not signed`() {
        assertEquals(
            listOf(Action.DECRYPT),
            ShareFileActions.forFile(isBackup = false, looksLikeMessage = true)
        )
    }

    @Test
    fun `a backup opens Restore only, though it is an encrypted message too`() {
        assertEquals(listOf(Action.RESTORE), ShareFileActions.forFile(isBackup = true, looksLikeMessage = true))
        assertEquals(listOf(Action.RESTORE), ShareFileActions.forFile(isBackup = true, looksLikeMessage = false))
    }

    @Test
    fun `a detached signature is named after the file, as the Sign a file sheet names it`() {
        assertEquals("report.pdf.asc", ShareFileActions.signatureName("report.pdf", armor = true))
        assertEquals("report.pdf.sig", ShareFileActions.signatureName("report.pdf", armor = false))
    }

    @Test
    fun `a shared name is reduced to a plain base name first`() {
        assertEquals("evil.txt.sig", ShareFileActions.signatureName("../x/evil.txt", armor = false))
        assertEquals("a_b.txt.asc", ShareFileActions.signatureName("a:b.txt", armor = true))
        assertEquals("file.asc", ShareFileActions.signatureName(null, armor = true))
        assertEquals("file.sig", ShareFileActions.signatureName("  ", armor = false))
    }
}
