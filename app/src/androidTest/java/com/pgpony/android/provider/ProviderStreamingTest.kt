// ProviderStreamingTest.kt
// PGPony Android — 4.0.0 Succession Phase P2d
//
// Large-payload round-trip over the provider's streaming paths: a 5 MB
// attachment is encrypted+signed through ACTION_SIGN_AND_ENCRYPT and
// decrypted back through ACTION_DECRYPT_VERIFY, entirely over real
// binder + pipe plumbing. Proves the streaming encrypt/decrypt produce
// interoperable output and that a payload well past a mail body's size
// survives intact. (5 MB keeps CI fast; the path is O(1) in memory, so
// 5 MB and 50 MB exercise the same code.)

package com.pgpony.android.provider

import android.content.Intent
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.ServiceTestRule
import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.KeyAlgorithm
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.OpenPgpSignatureResult
import org.openintents.openpgp.util.OpenPgpApi
import java.io.ByteArrayOutputStream

@RunWith(AndroidJUnit4::class)
class ProviderStreamingTest {

    companion object {
        private const val TEST_EMAIL = "provider-send-test@pgpony.invalid"
        private const val SIZE = 5 * 1024 * 1024
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

    private fun run(
        request: Intent,
        pipeId: Int,
        inputBytes: ByteArray
    ): Pair<Intent, ByteArray> {
        val service = bind()
        val outputRead = service.createOutputPipe(pipeId)
        val inPipe = ParcelFileDescriptor.createPipe()
        val writer = Thread {
            ParcelFileDescriptor.AutoCloseOutputStream(inPipe[1]).use { it.write(inputBytes) }
        }.also { it.start() }
        val collected = ByteArrayOutputStream()
        val reader = Thread {
            ParcelFileDescriptor.AutoCloseInputStream(outputRead).use { it.copyTo(collected) }
        }.also { it.start() }
        val result = service.execute(request, inPipe[0], pipeId)
        writer.join(30_000)
        reader.join(30_000)
        return result to collected.toByteArray()
    }

    private fun signKeyId(): Long = runBlocking {
        val e = app.keyRepository.getByEmail(TEST_EMAIL).first()
        java.lang.Long.parseUnsignedLong(e.longKeyId, 16)
    }

    private fun request(action: String): Intent =
        Intent(action).putExtra(OpenPgpApi.EXTRA_API_VERSION, 12)

    @Test
    fun fiveMegabyte_signEncrypt_thenDecrypt_roundTrips() {
        val payload = ByteArray(SIZE) { (it * 31 + 7).toByte() }

        val (encResult, ciphertext) = run(
            request(OpenPgpApi.ACTION_SIGN_AND_ENCRYPT)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf(TEST_EMAIL))
                .putExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, signKeyId())
                .putExtra(OpenPgpApi.EXTRA_ORIGINAL_FILENAME, "big.bin"),
            70,
            payload
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            encResult.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )

        val (decResult, plaintext) = run(
            request(OpenPgpApi.ACTION_DECRYPT_VERIFY)
                .putExtra(OpenPgpApi.EXTRA_SENDER_ADDRESS, TEST_EMAIL),
            71,
            ciphertext
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            decResult.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertEquals(SIZE, plaintext.size)
        assertArrayEquals(payload, plaintext)

        @Suppress("DEPRECATION")
        val sig = decResult.getParcelableExtra<OpenPgpSignatureResult>(OpenPgpApi.RESULT_SIGNATURE)
        // Signed by our own key over the streamed content, verified.
        assertEquals(
            OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED,
            sig!!.result
        )
    }
}
