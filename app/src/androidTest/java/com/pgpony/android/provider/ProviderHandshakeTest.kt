// ProviderHandshakeTest.kt
// PGPony Android — 4.0.0 Succession Phase 1
//
// Instrumented handshake test: binds PGPonyOpenPgpService exactly the
// way a real client's OpenPgpServiceConnection does (the
// IOpenPgpService2 action) and drives the Phase 1 contract end to end.
//
// A quirk that makes this test possible without a second APK: the
// instrumentation runs in the SAME uid as the app, so the service
// resolves the "calling package" as com.pgpony.android itself. The
// test pre-seeds / clears the allow-list row for our own package to
// flip between the authorized and consent-required paths.

package com.pgpony.android.provider

import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.ServiceTestRule
import com.pgpony.android.PGPonyApp
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.OpenPgpError
import org.openintents.openpgp.util.OpenPgpApi

@RunWith(AndroidJUnit4::class)
class ProviderHandshakeTest {

    @get:Rule
    val serviceRule = ServiceTestRule()

    private val app: PGPonyApp = ApplicationProvider.getApplicationContext()
    private val ownPackage = app.packageName

    private fun bind(): IOpenPgpService2 {
        val intent = Intent(OpenPgpApi.SERVICE_INTENT_2).setPackage(ownPackage)
        val binder = serviceRule.bindService(intent)
        return IOpenPgpService2.Stub.asInterface(binder)
    }

    private fun grantSelf() = runBlocking {
        ApiClientAuthorizer(
            dao = app.database.apiClientDao(),
            signatureSha256Of = ApiClientAuthorizer.platformSignatureLookup(app.packageManager)
        ).grant(ownPackage, com.pgpony.android.data.ApiClientEntity.SCOPE_OPENPGP)
    }

    private fun revokeSelf() = runBlocking {
        app.database.apiClientDao().deleteByPackage(ownPackage)
    }

    @Before
    fun cleanSlate() {
        revokeSelf()
    }

    private fun request(action: String, apiVersion: Int = 11): Intent =
        Intent(action).putExtra(OpenPgpApi.EXTRA_API_VERSION, apiVersion)

    // ── The handshake ──────────────────────────────────────────────────

    @Test
    fun wrongApiVersion_isIncompatibleError_beforeAnythingElse() {
        val service = bind()
        val result = service.execute(
            request(OpenPgpApi.ACTION_CHECK_PERMISSION, apiVersion = 3), null, 1
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_ERROR,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        @Suppress("DEPRECATION")
        val error = result.getParcelableExtra<OpenPgpError>(OpenPgpApi.RESULT_ERROR)
        assertNotNull(error)
        assertEquals(OpenPgpError.INCOMPATIBLE_API_VERSIONS, error!!.errorId)
    }

    @Test
    fun unknownClient_getsConsentPendingIntent() {
        val service = bind()
        val result = service.execute(request(OpenPgpApi.ACTION_CHECK_PERMISSION), null, 2)
        assertEquals(
            OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        @Suppress("DEPRECATION")
        val pi = result.getParcelableExtra<android.app.PendingIntent>(OpenPgpApi.RESULT_INTENT)
        assertNotNull("consent PendingIntent must be attached", pi)
    }

    @Test
    fun authorizedClient_checkPermission_succeeds() {
        grantSelf()
        val service = bind()
        val result = service.execute(request(OpenPgpApi.ACTION_CHECK_PERMISSION), null, 3)
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
    }

    @Test
    fun everySupportedApiVersion_passesTheGate() {
        grantSelf()
        val service = bind()
        // 7–12: P1 Fix1 widened the gate to 12 (Thunderbird for
        // Android sends 12; OpenKeychain master accepts 7–12).
        for (version in 7..12) {
            val result = service.execute(
                request(OpenPgpApi.ACTION_CHECK_PERMISSION, apiVersion = version), null, 10 + version
            )
            assertEquals(
                "api version $version should be accepted",
                OpenPgpApi.RESULT_CODE_SUCCESS,
                result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
            )
        }
    }

    @Test
    fun getKeyIds_returnsLongArray_forAuthorizedClient() {
        grantSelf()
        val service = bind()
        val result = service.execute(
            request(OpenPgpApi.ACTION_GET_KEY_IDS)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf("nobody@example.invalid")),
            null, 4
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        val ids = result.getLongArrayExtra(OpenPgpApi.RESULT_KEY_IDS)
        assertNotNull(ids)
        // Fresh test DB holds no key for that address.
        assertEquals(0, ids!!.size)
    }

    @Test
    fun cryptoActions_areHonestlyStubbed_notSilentlyBroken() {
        grantSelf()
        val service = bind()
        val result = service.execute(request(OpenPgpApi.ACTION_DECRYPT_VERIFY), null, 5)
        assertEquals(
            OpenPgpApi.RESULT_CODE_ERROR,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        @Suppress("DEPRECATION")
        val error = result.getParcelableExtra<OpenPgpError>(OpenPgpApi.RESULT_ERROR)
        assertNotNull(error)
        // RC3 §K sweep: this assertion predated P2b, when DECRYPT_VERIFY
        // was a stub and the message really did say "not implemented
        // yet". The action has been fully implemented since; what an
        // inputless call must do NOW is fail loudly with a real error,
        // never succeed or hang.
        assertTrue(
            "an inputless DECRYPT_VERIFY must return a non-blank error message",
            !error!!.message.isNullOrBlank()
        )
    }

    // ── P2a-1: GET_SIGN_KEY_ID ─────────────────────────────────────────

    @Test
    fun getSignKeyId_withoutSelection_returnsPickerIntentAndNoKey() {
        grantSelf()
        val service = bind()
        val result = service.execute(
            request(OpenPgpApi.ACTION_GET_SIGN_KEY_ID)
                .putExtra(OpenPgpApi.EXTRA_USER_ID, "Norse Horse <norsehorse@norsehor.se>"),
            null, 20
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        @Suppress("DEPRECATION")
        val pi = result.getParcelableExtra<android.app.PendingIntent>(OpenPgpApi.RESULT_INTENT)
        assertNotNull("picker PendingIntent must be attached", pi)
        assertEquals(0L, result.getLongExtra(OpenPgpApi.RESULT_SIGN_KEY_ID, -1L))
    }

    @Test
    fun getSignKeyId_reExecutionWithNoKey_succeedsWithoutKeyInfo() {
        grantSelf()
        val service = bind()
        // Simulates the client re-executing after the user chose
        // "No key — don't sign" in the picker.
        val result = service.execute(
            request(OpenPgpApi.ACTION_GET_SIGN_KEY_ID)
                .putExtra(OpenPgpApi.RESULT_SIGN_KEY_ID, 0L),
            null, 21
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertEquals(0L, result.getLongExtra(OpenPgpApi.RESULT_SIGN_KEY_ID, -1L))
        assertEquals(null, result.getStringExtra(OpenPgpApi.RESULT_PRIMARY_USER_ID))
        // The change-selection PendingIntent rides along even on success.
        @Suppress("DEPRECATION")
        val pi = result.getParcelableExtra<android.app.PendingIntent>(OpenPgpApi.RESULT_INTENT)
        assertNotNull(pi)
    }

    @Test
    fun getSignKeyId_unknownKeyId_isHardError() {
        grantSelf()
        val service = bind()
        val result = service.execute(
            request(OpenPgpApi.ACTION_GET_SIGN_KEY_ID)
                .putExtra(OpenPgpApi.RESULT_SIGN_KEY_ID, 0x0123456789ABCDEFL),
            null, 22
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_ERROR,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        @Suppress("DEPRECATION")
        val error = result.getParcelableExtra<OpenPgpError>(OpenPgpApi.RESULT_ERROR)
        assertNotNull(error)
        assertTrue(error!!.message.contains("not found", ignoreCase = true))
    }

    @Test
    fun revokedClient_fallsBackToConsentFlow() {
        grantSelf()
        val service = bind()
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            service.execute(request(OpenPgpApi.ACTION_CHECK_PERMISSION), null, 6)
                .getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        revokeSelf()
        assertEquals(
            OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED,
            service.execute(request(OpenPgpApi.ACTION_CHECK_PERMISSION), null, 7)
                .getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
    }
}
