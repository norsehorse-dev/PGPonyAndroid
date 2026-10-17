// ProviderMultiIdentityTest.kt
// PGPony Android — 4.2.1 (#27, bluemle)
//
// The provider-level proof for #27: a mail client resolving a recipient
// address through ACTION_GET_KEY_IDS must find a key by ANY of its
// identities, not only the primary. Before the fix, a key whose match
// was a SECONDARY identity (added via 4.2.0 multiple-identities) returned
// an empty key-id array, so K-9 concluded there was no key and never
// offered encryption. ACTION_GET_KEY (hand over the public key by
// address) had the same gap and is covered too.
//
// This is the wiring test. The resolution logic itself is exercised
// directly in data/MultiIdentityLookupTest; this proves the provider
// actions route through it.
//
// Instrumented, and like the sibling provider tests the DEVICE SCREEN
// MUST BE ON AND UNLOCKED for the service to run.

package com.pgpony.android.provider

import android.content.Intent
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.ServiceTestRule
import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.KeyAlgorithm
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.util.OpenPgpApi
import java.io.ByteArrayOutputStream

@RunWith(AndroidJUnit4::class)
class ProviderMultiIdentityTest {

    companion object {
        private const val PRIMARY = "provider-primary-2701@pgpony.invalid"
        private const val SECONDARY = "provider-secondary-2701@pgpony.invalid"
    }

    @get:Rule
    val serviceRule = ServiceTestRule()

    private val app: PGPonyApp = ApplicationProvider.getApplicationContext()
    private var fingerprint: String = ""

    @Before
    fun setUp() = runBlocking {
        ApiClientAuthorizer(
            dao = app.database.apiClientDao(),
            signatureSha256Of = ApiClientAuthorizer.platformSignatureLookup(app.packageManager)
        ).grant(app.packageName, com.pgpony.android.data.ApiClientEntity.SCOPE_OPENPGP)
        val entity = app.keyRepository.generateKey(
            name = "Provider Multi Identity",
            email = PRIMARY,
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = null
        )
        fingerprint = entity.fingerprint
        // The secondary identity is the whole point of the test.
        app.keyRepository.addUserId(fingerprint, "Alt <$SECONDARY>", makePrimary = false, passphrase = null)
        Unit
    }

    @After
    fun tearDown() = runBlocking {
        if (fingerprint.isNotEmpty()) app.keyRepository.deleteByFingerprint(fingerprint)
        Unit
    }

    private fun bind(): IOpenPgpService2 {
        val intent = Intent(OpenPgpApi.SERVICE_INTENT_2).setPackage(app.packageName)
        return IOpenPgpService2.Stub.asInterface(serviceRule.bindService(intent))
    }

    private fun request(action: String): Intent =
        Intent(action).putExtra(OpenPgpApi.EXTRA_API_VERSION, 12)

    private val expectedKeyId: Long
        get() = runBlocking {
            java.lang.Long.parseUnsignedLong(
                app.keyRepository.getByFingerprint(fingerprint)!!.longKeyId, 16
            )
        }

    @Test
    fun getKeyIds_resolvesSecondaryIdentityAddress() {
        val result = bind().execute(
            request(OpenPgpApi.ACTION_GET_KEY_IDS)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf(SECONDARY)),
            null, 40
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        val ids = result.getLongArrayExtra(OpenPgpApi.RESULT_KEY_IDS)
        assertNotNull("secondary identity must resolve to a key id", ids)
        assertTrue(
            "key id array must contain the multi-identity key",
            ids!!.contains(expectedKeyId)
        )
    }

    @Test
    fun getKeyIds_stillResolvesPrimaryAddress() {
        val result = bind().execute(
            request(OpenPgpApi.ACTION_GET_KEY_IDS)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf(PRIMARY)),
            null, 41
        )
        val ids = result.getLongArrayExtra(OpenPgpApi.RESULT_KEY_IDS)
        assertNotNull(ids)
        assertTrue(ids!!.contains(expectedKeyId))
    }

    @Test
    fun getKey_bySecondaryIdentity_returnsKeyBlock() {
        val service = bind()
        val outputRead = service.createOutputPipe(42)
        val collected = ByteArrayOutputStream()
        val reader = Thread {
            ParcelFileDescriptor.AutoCloseInputStream(outputRead).use { it.copyTo(collected) }
        }.also { it.start() }
        val result = service.execute(
            request(OpenPgpApi.ACTION_GET_KEY)
                .putExtra(OpenPgpApi.EXTRA_USER_ID, SECONDARY)
                .putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true),
            null, 42
        )
        reader.join(5_000)
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertTrue(
            collected.toByteArray().toString(Charsets.UTF_8)
                .contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        )
    }
}
