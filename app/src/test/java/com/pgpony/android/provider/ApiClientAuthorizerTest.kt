// ApiClientAuthorizerTest.kt
// PGPony Android — 4.0.0 Succession Phase 1
//
// Contract tests for the provider's authorization decision table.
// Pure JVM: the DAO is an in-memory fake and the signature lookup is a
// mutable map, so every branch of the decision table runs without a
// device. The one Android-specific piece (platformSignatureLookup) is
// exercised by the instrumented handshake test instead.

package com.pgpony.android.provider

import com.pgpony.android.data.ApiClientDao
import com.pgpony.android.data.ApiClientEntity
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

private class FakeApiClientDao : ApiClientDao {
    val rows = LinkedHashMap<String, ApiClientEntity>()

    override suspend fun getAll(): List<ApiClientEntity> =
        rows.values.sortedByDescending { it.grantedAt }

    override suspend fun getByPackage(packageName: String): ApiClientEntity? =
        rows[packageName]

    override suspend fun insert(client: ApiClientEntity) {
        rows[client.packageName] = client
    }

    override suspend fun deleteByPackage(packageName: String) {
        rows.remove(packageName)
    }

    override suspend fun count(): Int = rows.size

    override suspend fun updateAccess(packageName: String, scopes: Int, sshKeyFingerprint: String?) {
        rows[packageName]?.let { rows[packageName] = it.copy(scopes = scopes, sshKeyFingerprint = sshKeyFingerprint) }
    }
}

class ApiClientAuthorizerTest {

    private val dao = FakeApiClientDao()
    private val signatures = mutableMapOf<String, String?>()
    private val authorizer = ApiClientAuthorizer(dao) { pkg -> signatures[pkg] }

    private val tbird = "net.thunderbird.android"
    private val agent = "org.ddosolitary.okcagent"
    private val PGP = ApiClientEntity.SCOPE_OPENPGP
    private val SSH = ApiClientEntity.SCOPE_SSH
    private val fpA = "AB".repeat(20)
    private val fpB = "CD".repeat(20)
    private val sigA = "aa".repeat(32)
    private val sigB = "bb".repeat(32)

    @Test
    fun unknownPackage_isUnknown_notAuthorized() = runTest {
        signatures[tbird] = sigA
        assertEquals(ApiClientAuthorizer.Decision.UNKNOWN, authorizer.authorize(tbird, PGP))
    }

    @Test
    fun grantThenAuthorize_isAuthorized() = runTest {
        signatures[tbird] = sigA
        assertTrue(authorizer.grant(tbird, PGP, grantedAt = 1_000L))
        assertEquals(ApiClientAuthorizer.Decision.AUTHORIZED, authorizer.authorize(tbird, PGP))
        assertEquals(sigA, dao.getByPackage(tbird)?.signatureSha256)
        assertEquals(1_000L, dao.getByPackage(tbird)?.grantedAt)
    }

    @Test
    fun signatureCase_isInsensitive() = runTest {
        signatures[tbird] = sigA.uppercase()
        assertTrue(authorizer.grant(tbird, PGP))
        // Stored lowercase, current reads uppercase — must still match.
        assertEquals(ApiClientAuthorizer.Decision.AUTHORIZED, authorizer.authorize(tbird, PGP))
    }

    @Test
    fun changedSignature_isMismatch_neverAuthorized() = runTest {
        signatures[tbird] = sigA
        assertTrue(authorizer.grant(tbird, PGP))
        // The impostor case: same package name, different signing cert.
        signatures[tbird] = sigB
        assertEquals(
            ApiClientAuthorizer.Decision.SIGNATURE_MISMATCH,
            authorizer.authorize(tbird, PGP)
        )
    }

    @Test
    fun revoke_returnsToUnknown() = runTest {
        signatures[tbird] = sigA
        assertTrue(authorizer.grant(tbird, PGP))
        authorizer.revoke(tbird)
        assertEquals(ApiClientAuthorizer.Decision.UNKNOWN, authorizer.authorize(tbird, PGP))
        assertNull(dao.getByPackage(tbird))
    }

    @Test
    fun unresolvableSignature_isHardError_notConsent() = runTest {
        signatures[tbird] = null
        assertEquals(ApiClientAuthorizer.Decision.UNRESOLVABLE, authorizer.authorize(tbird, PGP))
    }

    @Test
    fun grantWithUnresolvableSignature_refusesToStoreUnpinnedRow() = runTest {
        signatures[tbird] = null
        assertFalse(authorizer.grant(tbird, PGP))
        assertNull(dao.getByPackage(tbird))
    }

    @Test
    fun reGrantAfterSignatureChange_overwritesPin() = runTest {
        signatures[tbird] = sigA
        assertTrue(authorizer.grant(tbird, PGP))
        signatures[tbird] = sigB
        // User explicitly re-consents (REPLACE conflict strategy).
        assertTrue(authorizer.grant(tbird, PGP))
        assertEquals(ApiClientAuthorizer.Decision.AUTHORIZED, authorizer.authorize(tbird, PGP))
        assertEquals(sigB, dao.getByPackage(tbird)?.signatureSha256)
    }

    // ── 4.6.0: per-scope grants and the SSH key binding ──────────────────

    @Test
    fun openPgpGrant_isUnknownForSsh() = runTest {
        signatures[tbird] = sigA
        assertTrue(authorizer.grant(tbird, PGP))
        assertEquals(ApiClientAuthorizer.Decision.AUTHORIZED, authorizer.authorize(tbird, PGP))
        assertEquals(ApiClientAuthorizer.Decision.UNKNOWN, authorizer.authorize(tbird, SSH))
    }

    @Test
    fun sshGrant_doesNotGrantOpenPgp() = runTest {
        signatures[agent] = sigA
        assertTrue(authorizer.grant(agent, SSH))
        assertEquals(ApiClientAuthorizer.Decision.AUTHORIZED, authorizer.authorize(agent, SSH))
        assertEquals(ApiClientAuthorizer.Decision.UNKNOWN, authorizer.authorize(agent, PGP))
    }

    @Test
    fun secondScope_addsToTheFirst() = runTest {
        signatures[agent] = sigA
        assertTrue(authorizer.grant(agent, SSH))
        assertTrue(authorizer.grant(agent, PGP))
        assertEquals(ApiClientAuthorizer.Decision.AUTHORIZED, authorizer.authorize(agent, SSH))
        assertEquals(ApiClientAuthorizer.Decision.AUTHORIZED, authorizer.authorize(agent, PGP))
        assertEquals(PGP or SSH, dao.getByPackage(agent)?.scopes)
    }

    @Test
    fun mismatchedSignature_isMismatchForEitherScope() = runTest {
        signatures[agent] = sigA
        assertTrue(authorizer.grant(agent, SSH))
        signatures[agent] = sigB
        assertEquals(ApiClientAuthorizer.Decision.SIGNATURE_MISMATCH, authorizer.authorize(agent, SSH))
        assertEquals(ApiClientAuthorizer.Decision.SIGNATURE_MISMATCH, authorizer.authorize(agent, PGP))
    }

    @Test
    fun revokingOneScope_leavesTheOther() = runTest {
        signatures[agent] = sigA
        authorizer.grant(agent, PGP)
        authorizer.grant(agent, SSH)
        authorizer.revokeScope(agent, SSH)
        assertEquals(ApiClientAuthorizer.Decision.UNKNOWN, authorizer.authorize(agent, SSH))
        assertEquals(ApiClientAuthorizer.Decision.AUTHORIZED, authorizer.authorize(agent, PGP))
        authorizer.grant(agent, SSH)
        authorizer.revokeScope(agent, PGP)
        assertEquals(ApiClientAuthorizer.Decision.AUTHORIZED, authorizer.authorize(agent, SSH))
        assertEquals(ApiClientAuthorizer.Decision.UNKNOWN, authorizer.authorize(agent, PGP))
    }

    @Test
    fun revokingTheLastScope_deletesTheRow() = runTest {
        signatures[agent] = sigA
        authorizer.grant(agent, SSH)
        authorizer.revokeScope(agent, SSH)
        assertNull(dao.getByPackage(agent))
    }

    @Test
    fun rowsFromBeforeScopes_areOpenPgpOnly() = runTest {
        // What MIGRATION_11_12 leaves behind: the column default, no binding.
        signatures[tbird] = sigA
        dao.insert(ApiClientEntity(tbird, sigA, 1_000L))
        val row = dao.getByPackage(tbird)!!
        assertEquals(PGP, row.scopes)
        assertNull(row.sshKeyFingerprint)
        assertEquals(ApiClientAuthorizer.Decision.AUTHORIZED, authorizer.authorize(tbird, PGP))
        assertEquals(ApiClientAuthorizer.Decision.UNKNOWN, authorizer.authorize(tbird, SSH))
    }

    @Test
    fun sshKeyBinding_needsTheSshScope() = runTest {
        signatures[tbird] = sigA
        authorizer.grant(tbird, PGP)
        assertFalse(authorizer.bindSshKey(tbird, fpA))
        assertNull(authorizer.sshKey(tbird))
    }

    @Test
    fun sshKeyBinding_isTheOnlyKey_andClearsWithTheScope() = runTest {
        signatures[agent] = sigA
        authorizer.grant(agent, PGP)
        authorizer.grant(agent, SSH)
        assertNull(authorizer.sshKey(agent))
        assertTrue(authorizer.bindSshKey(agent, fpA.lowercase()))
        assertEquals(fpA, authorizer.sshKey(agent))
        assertFalse(fpB.equals(authorizer.sshKey(agent), ignoreCase = true))
        // Re-granting a scope keeps the binding.
        authorizer.grant(agent, PGP)
        assertEquals(fpA, authorizer.sshKey(agent))
        authorizer.revokeScope(agent, SSH)
        assertNull(authorizer.sshKey(agent))
        assertNull(dao.getByPackage(agent)?.sshKeyFingerprint)
        // Coming back for SSH starts unbound.
        authorizer.grant(agent, SSH)
        assertNull(authorizer.sshKey(agent))
    }

    @Test
    fun revokingTheApp_dropsTheBinding() = runTest {
        signatures[agent] = sigA
        authorizer.grant(agent, SSH)
        authorizer.bindSshKey(agent, fpA)
        authorizer.revoke(agent)
        authorizer.grant(agent, SSH)
        assertNull(authorizer.sshKey(agent))
    }

    @Test
    fun sshSigning_isAllowedOnlyForTheBoundKey() = runTest {
        signatures[agent] = sigA
        authorizer.grant(agent, SSH)
        // Nothing chosen yet: every key needs the picker first.
        assertFalse(authorizer.sshKeyAllowed(agent, fpA))
        authorizer.bindSshKey(agent, fpA)
        assertTrue(authorizer.sshKeyAllowed(agent, fpA))
        assertTrue(authorizer.sshKeyAllowed(agent, fpA.lowercase()))
        // Another key in the keyring with an auth subkey is still refused.
        assertFalse(authorizer.sshKeyAllowed(agent, fpB))
        // A mail client with an OpenPGP grant never gets an SSH key.
        signatures[tbird] = sigA
        authorizer.grant(tbird, PGP)
        assertFalse(authorizer.bindSshKey(tbird, fpA))
        assertFalse(authorizer.sshKeyAllowed(tbird, fpA))
    }
}
