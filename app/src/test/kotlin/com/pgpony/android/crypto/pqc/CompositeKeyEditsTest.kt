// CompositeKeyEditsTest.kt
// PGPony Android, 4.8.1: key edits on composite ML-DSA keys. Changing the
// expiry of an ML-DSA-87 key failed (reported by email on 4.8.0), because the
// edit went through Bouncy Castle, which cannot load the primary; so did
// Refresh self-signatures, notations, the primary User ID and revoking the key
// or a User ID. CompositePrimaryKeyGen now makes these edits on the packets.
// Every new signature is checked with CertificateBindings, which verifies it
// on its own, and the facade readers Key Details uses read the result back.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Date

class CompositeKeyEditsTest {

    private val suites = listOf(CompositeSignSuite.MLDSA65_ED25519, CompositeSignSuite.MLDSA87_ED448)
    private val created = Date(1_760_000_000_000L)
    private val later = Date(1_770_000_000_000L)

    private fun key(suite: CompositeSignSuite, uid: String = "Edit <edit@pgpony.app>") =
        CompositePrimaryKeyGen.assemble(uid, suite, creationTime = created)

    private fun report(secretRing: ByteArray) =
        CertificateBindings.analyze(CompositeKeyFacade.publicRingOf(secretRing))!!

    private fun createdSec(ring: ByteArray) = CompositeKeyFacade.parse(ring).creationTimeMillis / 1000L

    @Test
    fun `the primary's expiry is set, extended and removed`() {
        for (suite in suites) {
            val ring = key(suite)
            val c = createdSec(ring)
            val first = c + 2 * 365 * 86400L
            val set = CompositePrimaryKeyGen.setExpiry(ring, CompositePrimaryKeyGen.ExpiryTarget.Primary(), first, now = later)
            assertEquals("$suite", first * 1000L, report(set).primaryExpiresAtMs)
            assertEquals(first - c, CompositeKeyFacade.parse(set).expirationSeconds)
            assertTrue(report(set).certifiedUserIds.contains("Edit <edit@pgpony.app>"))

            val extended = CompositePrimaryKeyGen.setExpiry(set, CompositePrimaryKeyGen.ExpiryTarget.Primary(), first + 86400L,
                now = Date(later.time + 1000))
            assertEquals((first + 86400L) * 1000L, report(extended).primaryExpiresAtMs)

            val never = CompositePrimaryKeyGen.setExpiry(extended, CompositePrimaryKeyGen.ExpiryTarget.Primary(), null,
                now = Date(later.time + 2000))
            assertNull(report(never).primaryExpiresAtMs)
            assertNull(CompositeKeyFacade.parse(never).expirationSeconds)
            // The subkey is untouched and still bound.
            assertTrue(report(never).subkeys.single().bound)
            assertNull(report(never).subkeys.single().expiresAtMs)
            // An edit replaces the signatures it supersedes: one direct-key signature stays.
            assertEquals(1, report(never).directKeySigs.size)
        }
    }

    @Test
    fun `a subkey's expiry changes only that subkey`() {
        for (suite in suites) {
            val ring = key(suite)
            val sub = CompositeKeyFacade.listSubkeys(ring).single()
            val at = sub.createdAtMillis / 1000L + 400 * 86400L
            val out = CompositePrimaryKeyGen.setExpiry(ring, CompositePrimaryKeyGen.ExpiryTarget.Subkey(sub.fingerprintHex), at, now = later)
            val r = report(out)
            assertEquals("$suite", at * 1000L, r.subkeys.single().expiresAtMs)
            assertTrue(r.subkeys.single().bound)
            assertNull(r.primaryExpiresAtMs)
            assertEquals(at - sub.createdAtMillis / 1000L, CompositeKeyFacade.listSubkeys(out).single().expirationSeconds)
            val cleared = CompositePrimaryKeyGen.setExpiry(out, CompositePrimaryKeyGen.ExpiryTarget.Subkey(sub.fingerprintHex), null,
                now = Date(later.time + 1000))
            assertNull(report(cleared).subkeys.single().expiresAtMs)
            assertNull(CompositeKeyFacade.listSubkeys(cleared).single().expirationSeconds)
        }
    }

    @Test
    fun `the primary with its current subkeys`() {
        val ring = key(CompositeSignSuite.MLDSA87_ED448)
        val sub = CompositeKeyFacade.listSubkeys(ring).single()
        val at = createdSec(ring) + 1000 * 86400L
        val out = CompositePrimaryKeyGen.setExpiry(
            ring, CompositePrimaryKeyGen.ExpiryTarget.Primary(setOf(sub.fingerprintHex)), at, now = later
        )
        val r = report(out)
        assertEquals(at * 1000L, r.primaryExpiresAtMs)
        assertEquals(at * 1000L, r.subkeys.single().expiresAtMs)
    }

    @Test
    fun `a signing subkey keeps its back-signature through an expiry change`() {
        val base = key(CompositeSignSuite.MLDSA65_ED25519)
        val withSign = CompositePrimaryKeyGen.addCompositeSigningSubkey(base, CompositeSignSuite.MLDSA65_ED25519, creationTime = created)
        val signSub = report(withSign).subkeys.first { it.backSigned }
        val at = createdSec(withSign) + 500 * 86400L
        val out = CompositePrimaryKeyGen.setExpiry(withSign, CompositePrimaryKeyGen.ExpiryTarget.Subkey(signSub.fingerprintHex), at, now = later)
        val after = report(out).subkeys.first { it.fingerprintHex.equals(signSub.fingerprintHex, ignoreCase = true) }
        assertTrue(after.bound)
        assertTrue(after.backSigned)
        assertEquals(at * 1000L, after.expiresAtMs)
    }

    @Test
    fun `an expiry before the key was made is refused`() {
        val ring = key(CompositeSignSuite.MLDSA65_ED25519)
        try {
            CompositePrimaryKeyGen.setExpiry(ring, CompositePrimaryKeyGen.ExpiryTarget.Primary(), createdSec(ring) - 10, now = later)
            fail("expected a refusal")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun `refresh keeps every expiry and re-dates the signatures`() {
        val ring = key(CompositeSignSuite.MLDSA87_ED448)
        val sub = CompositeKeyFacade.listSubkeys(ring).single()
        val pAt = createdSec(ring) + 900 * 86400L
        val sAt = createdSec(ring) + 300 * 86400L
        val edited = CompositePrimaryKeyGen.setExpiry(
            CompositePrimaryKeyGen.setExpiry(ring, CompositePrimaryKeyGen.ExpiryTarget.Primary(), pAt, now = later),
            CompositePrimaryKeyGen.ExpiryTarget.Subkey(sub.fingerprintHex), sAt, now = later
        )
        val refreshedAt = Date(later.time + 86_400_000L)
        val out = CompositePrimaryKeyGen.refreshSelfSignatures(edited, now = refreshedAt)
        val r = report(out)
        assertEquals(pAt * 1000L, r.primaryExpiresAtMs)
        assertEquals(sAt * 1000L, r.subkeys.single().expiresAtMs)
        assertEquals(refreshedAt.time / 1000L * 1000L, r.directKeySigs.maxOf { it.createdMs })
        assertEquals(1, r.directKeySigs.size)
    }

    @Test
    fun `the primary User ID moves`() {
        for (suite in suites) {
            val ring = CompositePrimaryKeyGen.addUserId(key(suite, "First <a@pgpony.app>"), "Second <b@pgpony.app>", creationTime = created)
            assertEquals("First <a@pgpony.app>", CompositePrimaryKeyGen.primaryUserIdOf(ring))
            val moved = CompositePrimaryKeyGen.setPrimaryUserId(ring, "Second <b@pgpony.app>", now = later)
            assertEquals("Second <b@pgpony.app>", CompositePrimaryKeyGen.primaryUserIdOf(moved))
            assertEquals(setOf("First <a@pgpony.app>", "Second <b@pgpony.app>"), report(moved).certifiedUserIds)
            val back = CompositePrimaryKeyGen.setPrimaryUserId(moved, "First <a@pgpony.app>", now = Date(later.time + 1000))
            assertEquals("First <a@pgpony.app>", CompositePrimaryKeyGen.primaryUserIdOf(back))
        }
    }

    @Test
    fun `notations are written and read back`() {
        val ring = key(CompositeSignSuite.MLDSA65_ED25519)
        assertTrue(CompositePrimaryKeyGen.readNotations(ring).isEmpty())
        val out = CompositePrimaryKeyGen.setNotations(ring, listOf("proof@ariadne.id" to "https://example.org/me", "x@pgpony.app" to "1"), now = later)
        assertEquals(listOf("proof@ariadne.id" to "https://example.org/me", "x@pgpony.app" to "1"), CompositePrimaryKeyGen.readNotations(out))
        assertTrue(report(out).certifiedUserIds.contains("Edit <edit@pgpony.app>"))
        val cleared = CompositePrimaryKeyGen.setNotations(out, emptyList(), now = Date(later.time + 1000))
        assertTrue(CompositePrimaryKeyGen.readNotations(cleared).isEmpty())
    }

    @Test
    fun `the key is revoked`() {
        for (suite in suites) {
            val ring = key(suite)
            assertFalse(report(ring).primaryRevoked)
            val (out, cert) = CompositePrimaryKeyGen.revokeKey(ring, reasonCode = 3, reasonText = "retired", now = later)
            assertTrue("$suite", report(out).primaryRevoked)
            assertTrue(cert.isNotEmpty())
            assertEquals(ring.size + cert.size, out.size)
        }
    }

    @Test
    fun `a User ID is revoked, never the last one`() {
        val ring = CompositePrimaryKeyGen.addUserId(key(CompositeSignSuite.MLDSA87_ED448, "First <a@pgpony.app>"), "Second <b@pgpony.app>", creationTime = created)
        val out = CompositePrimaryKeyGen.revokeUserId(ring, "Second <b@pgpony.app>", reasonCode = 32, now = later)
        assertEquals(setOf("First <a@pgpony.app>"), report(out).certifiedUserIds)
        try {
            CompositePrimaryKeyGen.revokeUserId(out, "First <a@pgpony.app>", reasonCode = 32, now = Date(later.time + 1000))
            fail("expected a refusal")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun `a protected key is edited with its passphrase and stays protected`() {
        val pass = "correct horse"
        val prot = CompositeKeyFacade.reprotect(key(CompositeSignSuite.MLDSA65_ED25519, "Locked <l@pgpony.app>"), null, pass.toCharArray())
        assertTrue(CompositeKeyFacade.isProtected(prot))
        val at = createdSec(prot) + 100 * 86400L
        val out = CompositePrimaryKeyGen.setExpiry(prot, CompositePrimaryKeyGen.ExpiryTarget.Primary(), at, pass.toCharArray(), now = later)
        assertTrue(CompositeKeyFacade.isProtected(out))
        assertEquals(at * 1000L, report(out).primaryExpiresAtMs)
        try {
            CompositePrimaryKeyGen.setExpiry(prot, CompositePrimaryKeyGen.ExpiryTarget.Primary(), at, "wrong".toCharArray(), now = later)
            fail("expected the wrong passphrase to be refused")
        } catch (_: Exception) {
        }
    }

    private fun dropped(secretRing: ByteArray): Int {
        val pub = CompositeKeyFacade.publicRingOf(secretRing)
        return pub.size - CertificateBindings.sanitized(pub).size
    }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun `every edit's signatures verify`() {
        // KeyRepository refuses an edit when sanitize drops more of the result than of the key.
        val ring = CompositePrimaryKeyGen.addUserId(key(CompositeSignSuite.MLDSA65_ED25519, "First <a@pgpony.app>"), "Second <b@pgpony.app>", creationTime = created)
        val base = dropped(ring)
        val c = createdSec(ring)
        val outs = listOf(
            CompositePrimaryKeyGen.setExpiry(ring, CompositePrimaryKeyGen.ExpiryTarget.Primary(), c + 9_000_000L, now = later),
            CompositePrimaryKeyGen.refreshSelfSignatures(ring, now = later),
            CompositePrimaryKeyGen.setPrimaryUserId(ring, "Second <b@pgpony.app>", now = later),
            CompositePrimaryKeyGen.setNotations(ring, listOf("a@pgpony.app" to "1"), now = later),
            CompositePrimaryKeyGen.revokeUserId(ring, "Second <b@pgpony.app>", reasonCode = 32, now = later),
            CompositePrimaryKeyGen.revokeKey(ring, reasonCode = 0, now = later).first
        )
        outs.forEach { assertTrue(dropped(it) <= base) }
    }

    @Test
    fun `a key made with an expiry states it in every self-signature`() {
        for (suite in suites) {
            val ring = CompositePrimaryKeyGen.assemble("Exp <exp@pgpony.app>", suite, creationTime = created, expirationSeconds = 2 * 365 * 86400L)
            val want = (createdSec(ring) + 2 * 365 * 86400L) * 1000L
            assertEquals("$suite", want, report(ring).primaryExpiresAtMs)
            // Edits that rewrite User ID certifications keep stating it.
            val two = CompositePrimaryKeyGen.addUserId(ring, "Two <two@pgpony.app>", creationTime = later)
            assertEquals(want, report(two).primaryExpiresAtMs)
            assertEquals(want, report(CompositePrimaryKeyGen.refreshSelfSignatures(two, now = Date(later.time + 1000))).primaryExpiresAtMs)
            assertEquals(want, report(CompositePrimaryKeyGen.setNotations(two, listOf("n@pgpony.app" to "v"), now = Date(later.time + 1000))).primaryExpiresAtMs)
            assertEquals(want, report(CompositePrimaryKeyGen.setPrimaryUserId(two, "Two <two@pgpony.app>", now = Date(later.time + 1000))).primaryExpiresAtMs)
        }
    }

    @Test
    fun `an edit that would change nothing is refused`() {
        val ring = key(CompositeSignSuite.MLDSA65_ED25519)
        val sub = CompositeKeyFacade.listSubkeys(ring).single()
        val revoked = CompositePrimaryKeyGen.revokeSubkey(ring, hex(sub.fingerprintHex), reasonCode = 3)
        try {
            CompositePrimaryKeyGen.setExpiry(revoked, CompositePrimaryKeyGen.ExpiryTarget.Subkey(sub.fingerprintHex), createdSec(ring) + 86400L, now = later)
            fail("expected a refusal")
        } catch (_: IllegalArgumentException) {
        }
        val two = CompositePrimaryKeyGen.addUserId(ring, "Two <two@pgpony.app>", creationTime = created)
        val gone = CompositePrimaryKeyGen.revokeUserId(two, "Two <two@pgpony.app>", reasonCode = 32, now = later)
        try {
            CompositePrimaryKeyGen.setPrimaryUserId(gone, "Two <two@pgpony.app>", now = Date(later.time + 1000))
            fail("expected a refusal")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun `an edited copy keeps what only the stored copy has`() {
        // The stored public copy has a second subkey the secret ring lacks.
        val withSecond = CompositePrimaryKeyGen.addCompositeSigningSubkey(key(CompositeSignSuite.MLDSA87_ED448), CompositeSignSuite.MLDSA87_ED448, creationTime = created)
        val stored = CompositeKeyFacade.publicRingOf(withSecond)
        val second = CompositeKeyFacade.listSubkeys(withSecond).map { it.fingerprintHex }.last()
        val secretWithout = CompositePrimaryKeyGen.removeSubkey(withSecond, hex(second))
        val edited = CompositeKeyFacade.publicRingOf(
            CompositePrimaryKeyGen.setExpiry(secretWithout, CompositePrimaryKeyGen.ExpiryTarget.Primary(), createdSec(withSecond) + 86400L * 90, now = later)
        )
        val out = CompositePrimaryKeyGen.withMissingComponents(edited, stored)
        val r = CertificateBindings.analyze(out)!!
        assertEquals(2, r.subkeys.count { it.bound })
        assertTrue(r.subkeys.any { it.fingerprintHex.equals(second, ignoreCase = true) && it.backSigned })
        assertEquals((createdSec(withSecond) + 86400L * 90) * 1000L, r.primaryExpiresAtMs)
        // Nothing is added twice.
        assertEquals(out.size, CompositePrimaryKeyGen.withMissingComponents(out, stored).size)
    }

    @Test
    fun `the edited key still lists its subkey and usage`() {
        val ring = key(CompositeSignSuite.MLDSA87_ED448)
        val out = CompositePrimaryKeyGen.refreshSelfSignatures(
            CompositePrimaryKeyGen.setExpiry(ring, CompositePrimaryKeyGen.ExpiryTarget.Primary(), createdSec(ring) + 86400L * 30, now = later),
            now = Date(later.time + 1000)
        )
        assertEquals(1, CompositeKeyFacade.listSubkeys(out).size)
        assertEquals(0x03, CompositeKeyFacade.primaryKeyFlags(out))
        assertEquals(CompositeKeyFacade.listSubkeys(ring).single().fingerprintHex, CompositeKeyFacade.listSubkeys(out).single().fingerprintHex)
    }
}
