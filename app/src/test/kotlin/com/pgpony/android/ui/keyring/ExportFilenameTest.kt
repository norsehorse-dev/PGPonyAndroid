// ExportFilenameTest.kt
// PGPony Android, 4.8.0 (item 4h): the email in exported key file names,
// matching iOS 8.4.0 (Name_email_KEYID_public.asc, the "@" written as "-").

package com.pgpony.android.ui.keyring

import org.junit.Assert.assertEquals
import org.junit.Test

class ExportFilenameTest {

    @Test
    fun `the email goes between the name and the key ID`() {
        assertEquals(
            "Riley_Park_riley-example.com_9D04ADE0_public.asc",
            KeyShareIntents.buildExportFilename("Riley Park", "9D04ADE0", "_public", "riley@example.com")
        )
        assertEquals(
            "Riley_Park_riley-example.com_9D04ADE0_private.asc",
            KeyShareIntents.buildExportFilename("Riley Park", "9D04 ADE0", "_private", "Riley@Example.com")
        )
        assertEquals(
            "Riley_Park_riley-example.com_9D04ADE0_revocation.asc",
            KeyShareIntents.buildExportFilename("Riley Park", "9D04ADE0", "_revocation", "riley@example.com")
        )
    }

    @Test
    fun `unsafe characters become underscores and the email is capped at 64`() {
        assertEquals(
            "Riley_riley_x-example.com_9D04ADE0_public.asc",
            KeyShareIntents.buildExportFilename("Riley", "9D04ADE0", "_public", "riley+x@example.com")
        )
        val long = "a".repeat(80) + "@example.com"
        val name = KeyShareIntents.buildExportFilename("Riley", "9D04ADE0", "_public", long)
        assertEquals("Riley_" + "a".repeat(64) + "_9D04ADE0_public.asc", name)
    }

    @Test
    fun `no email, or a label that is the email, keeps the old shape`() {
        assertEquals("Riley_9D04ADE0_public.asc", KeyShareIntents.buildExportFilename("Riley", "9D04ADE0", "_public"))
        assertEquals("Riley_9D04ADE0_public.asc", KeyShareIntents.buildExportFilename("Riley", "9D04ADE0", "_public", " "))
        assertEquals(
            "riley_example.com_9D04ADE0_public.asc",
            KeyShareIntents.buildExportFilename("riley@example.com", "9D04ADE0", "_public", "riley@example.com")
        )
    }
}
