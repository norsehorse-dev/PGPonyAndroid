// ScratchFilesSafeChildTest.kt
// PGPony Android, 4.6.0 (item 17.3), split out of crypto/LiteralFilenameTest.kt
// in 4.7.0 so that file stays free of Android UI code for PGPony Desktop's
// vendored test suite. A literal-data filename is attacker-chosen, and
// ScratchFiles.safeChild never yields a file outside its parent.

package com.pgpony.android.ui.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class ScratchFilesSafeChildTest {

    private val hostile = "../../files/secure_keystore_v2/pgpony_key_0123_private"

    @Test
    fun `safeChild never escapes its parent`() {
        val parent = Files.createTempDirectory("exports").toFile()
        for (n in listOf(hostile, "..", ".", "a/../../b", "..\\..\\c", "", null, "ok.txt")) {
            val f = ScratchFiles.safeChild(parent, n, "fallback")
            assertEquals(parent.canonicalFile, f.canonicalFile.parentFile)
        }
        assertTrue(ScratchFiles.safeChild(parent, "..", "fallback").name == "fallback")
    }
}
