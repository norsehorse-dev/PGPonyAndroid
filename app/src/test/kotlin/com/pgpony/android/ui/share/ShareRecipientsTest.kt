// ShareRecipientsTest.kt
// PGPony Android, 4.6.1 (#67): the share Quick Action never encrypts with a
// selected recipient quietly left out. A composite ML-DSA recipient loads
// through the encryption-recipient loader (the plain BouncyCastle loader gives
// nothing for it), a v4 algo-35 recipient takes its own channel, and a
// recipient that gives no key at all is reported so nothing is encrypted.

package com.pgpony.android.ui.share

import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositePrimaryKeyGen
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.PGPCryptoService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ShareRecipientsTest {

    @Test
    fun `every loadable recipient is kept`() {
        val r = ShareRecipients.load(
            listOf("A", "B"),
            isV4Algo35 = { false },
            ring = { "ring-$it" },
            v4Algo35 = { null as String? }
        )
        assertEquals(listOf("ring-A", "ring-B"), r.rings)
        assertTrue(r.isComplete)
        assertFalse(r.isEmpty)
    }

    @Test
    fun `a recipient with no key is reported, not dropped`() {
        val r = ShareRecipients.load(
            listOf("A", "COMPOSITE", "B"),
            isV4Algo35 = { false },
            ring = { if (it == "COMPOSITE") null else "ring-$it" },
            v4Algo35 = { null as String? }
        )
        assertFalse(r.isComplete)
        assertEquals(listOf("COMPOSITE"), r.unusable)
    }

    @Test
    fun `a single unloadable recipient is incomplete, not merely empty`() {
        val r = ShareRecipients.load(
            listOf("X"),
            isV4Algo35 = { false },
            ring = { null as String? },
            v4Algo35 = { null as String? }
        )
        assertFalse(r.isComplete)
        assertTrue(r.isEmpty)
    }

    @Test
    fun `a v4 algo-35 recipient takes its own channel`() {
        val r = ShareRecipients.load(
            listOf("V4", "A"),
            isV4Algo35 = { it == "V4" },
            ring = { if (it == "V4") null else "ring-$it" },
            v4Algo35 = { if (it == "V4") "v4-$it" else null }
        )
        assertEquals(listOf("ring-A"), r.rings)
        assertEquals(listOf("v4-V4"), r.v4Algo35)
        assertTrue(r.isComplete)
    }

    @Test
    fun `a composite ML-DSA key needs the encryption-recipient loader`() {
        val raw = CompositePrimaryKeyGen.assemble("C <c@example.org>", CompositeSignSuite.MLDSA65_ED25519)
        val pub = CompositeKeyFacade.publicRingOf(raw)
        // What the Quick Action used before: BouncyCastle cannot load it.
        val plain = runCatching { PGPCryptoService.shared.importKeyData(pub).publicKeyRing }.getOrNull()
        assertNull(plain)
        // What the Encrypt screen uses, and the Quick Action now uses too.
        assertNotNull(CompositeKeyFacade.encryptionSubkeyRing(pub))
    }
}
