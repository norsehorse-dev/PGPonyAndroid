// BuildCommitTest.kt
// PGPony Android, 4.8.0 RC8 (#114): the commit hash shown on About.

package com.pgpony.android

import org.junit.Assert.assertEquals
import org.junit.Test

class BuildCommitTest {

    private val sha1 = "c1a43d0e5b6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"

    @Test fun `About shows the first seven characters of the commit`() {
        assertEquals("c1a43d0", BuildCommit.short(sha1))
        assertEquals("4.8.0 (c1a43d0)", BuildCommit.versionLabel("4.8.0", sha1))
        assertEquals("abcdef0", BuildCommit.short("abcdef0" + "1".repeat(57)))
    }

    @Test fun `no git or stray output shows the version alone`() {
        for (bad in listOf("", "c1a43d0", sha1.uppercase(), "$sha1-dirty", " $sha1", "fatal: not a git repository")) {
            assertEquals("", BuildCommit.short(bad))
            assertEquals("4.8.0", BuildCommit.versionLabel("4.8.0", bad))
        }
    }
}
