// ProviderGetKeyTest.kt
// PGPony Android — 4.0.0 Succession Phase P2b-2
//
// ACTION_GET_KEY end-to-end: address a held public key by key id or
// email, read it back off the output pipe, and prove it re-imports as
// the same fingerprint via the app's own crypto layer.

package com.pgpony.android.provider

import android.content.Intent
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.ServiceTestRule
import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.util.OpenPgpApi
import java.io.ByteArrayOutputStream

@RunWith(AndroidJUnit4::class)
class ProviderGetKeyTest {

    companion object {
        private const val TEST_EMAIL = "provider-send-test@pgpony.invalid"
    }

    @get:Rule
    val serviceRule = ServiceTestRule()

    private val app: PGPonyApp = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() = runBlocking {
        ApiClientAuthorizer(
            dao = app.database.apiClientDao(),
            signatureSha256Of = ApiClientAuthorizer.platformSignatureLookup(app.packageManager)
        ).grant(app.packageName, com.pgpony.android.data.ApiClientEntity.SCOPE_OPENPGP)
        if (app.keyRepository.getByEmail(TEST_EMAIL).isEmpty()) {
            app.keyRepository.generateKey(
                name = "Provider Send Test",
                email = TEST_EMAIL,
                algorithm = KeyAlgorithm.ED25519_CV25519,
                passphrase = null
            )
        }
        Unit
    }

    private fun bind(): IOpenPgpService2 {
        val intent = Intent(OpenPgpApi.SERVICE_INTENT_2).setPackage(app.packageName)
        return IOpenPgpService2.Stub.asInterface(serviceRule.bindService(intent))
    }

    private fun executeCollectingOutput(request: Intent, pipeId: Int): Pair<Intent, ByteArray> {
        val service = bind()
        val outputRead = service.createOutputPipe(pipeId)
        val collected = ByteArrayOutputStream()
        val reader = Thread {
            ParcelFileDescriptor.AutoCloseInputStream(outputRead).use { it.copyTo(collected) }
        }.also { it.start() }
        val result = service.execute(request, null, pipeId)
        reader.join(5_000)
        return result to collected.toByteArray()
    }

    private fun request(action: String): Intent =
        Intent(action).putExtra(OpenPgpApi.EXTRA_API_VERSION, 12)

    @Test
    fun getKey_byKeyId_returnsArmoredKey_matchingFingerprint() {
        val entity = runBlocking { app.keyRepository.getByEmail(TEST_EMAIL).first() }
        val keyId = java.lang.Long.parseUnsignedLong(entity.longKeyId, 16)
        val (result, output) = executeCollectingOutput(
            request(OpenPgpApi.ACTION_GET_KEY)
                .putExtra(OpenPgpApi.EXTRA_KEY_ID, keyId)
                .putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true),
            60
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        val armored = output.toString(Charsets.UTF_8)
        assertTrue(armored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        val reimported = PGPCryptoService.shared.importArmoredKey(armored)
        assertEquals(entity.fingerprint, reimported.fingerprint)
    }

    @Test
    fun getKey_byUserId_returnsKey() {
        val (result, output) = executeCollectingOutput(
            request(OpenPgpApi.ACTION_GET_KEY)
                .putExtra(OpenPgpApi.EXTRA_USER_ID, TEST_EMAIL)
                .putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true),
            61
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertTrue(
            output.toString(Charsets.UTF_8).contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        )
    }

    @Test
    fun getKey_unknownKeyId_isReadableError() {
        val (result, output) = executeCollectingOutput(
            request(OpenPgpApi.ACTION_GET_KEY)
                .putExtra(OpenPgpApi.EXTRA_KEY_ID, 0x0011223344556677L),
            62
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_ERROR,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertEquals(0, output.size)
    }
}
