// ExportFilenameTest.kt
// PGPony Android, 4.8.0 (item 4h): the email in exported key file names,
// matching iOS 8.4.0 (Name_email_KEYID_public.asc, the "@" written as "-").
// Moved from ui/keyring in 4.8.0 RC10 with the rule itself (crypto/ExportFilename).

package com.pgpony.android.crypto

import org.junit.Assert.assertEquals
import org.junit.Test

class ExportFilenameTest {

    @Test
    fun `the email goes between the name and the key ID`() {
        assertEquals(
            "Riley_Park_riley-example.com_9D04ADE0_public.asc",
            ExportFilename.build("Riley Park", "9D04ADE0", "_public", "riley@example.com")
        )
        assertEquals(
            "Riley_Park_riley-example.com_9D04ADE0_private.asc",
            ExportFilename.build("Riley Park", "9D04 ADE0", "_private", "Riley@Example.com")
        )
        assertEquals(
            "Riley_Park_riley-example.com_9D04ADE0_revocation.asc",
            ExportFilename.build("Riley Park", "9D04ADE0", "_revocation", "riley@example.com")
        )
    }

    @Test
    fun `unsafe characters become underscores and the email is capped at 64`() {
        assertEquals(
            "Riley_riley_x-example.com_9D04ADE0_public.asc",
            ExportFilename.build("Riley", "9D04ADE0", "_public", "riley+x@example.com")
        )
        val long = "a".repeat(80) + "@example.com"
        val name = ExportFilename.build("Riley", "9D04ADE0", "_public", long)
        assertEquals("Riley_" + "a".repeat(64) + "_9D04ADE0_public.asc", name)
    }

    @Test
    fun `no email, or a label that is the email, keeps the old shape`() {
        assertEquals("Riley_9D04ADE0_public.asc", ExportFilename.build("Riley", "9D04ADE0", "_public"))
        assertEquals("Riley_9D04ADE0_public.asc", ExportFilename.build("Riley", "9D04ADE0", "_public", " "))
        assertEquals(
            "riley_example.com_9D04ADE0_public.asc",
            ExportFilename.build("riley@example.com", "9D04ADE0", "_public", "riley@example.com")
        )
    }
}
