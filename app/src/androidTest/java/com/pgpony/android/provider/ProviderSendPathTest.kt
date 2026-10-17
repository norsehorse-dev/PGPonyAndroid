// ProviderSendPathTest.kt
// PGPony Android — 4.0.0 Succession Phase P2a-2
//
// Instrumented end-to-end tests for the provider send path, driving
// the service over real binder + pipe plumbing exactly like a mail
// client: input plaintext through a pipe, ciphertext back through
// createOutputPipe, then decrypt/verify IN-PROCESS with the app's own
// crypto layer to prove the output is real OpenPGP, not just bytes.
//
// A passphrase-less Ed25519 test key pair is generated once into the
// app's repository (the fingerprint-identity dedup from 4.0.0 Phase 1
// makes re-runs harmless).

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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.OpenPgpError
import org.openintents.openpgp.util.OpenPgpApi
import java.io.ByteArrayOutputStream

@RunWith(AndroidJUnit4::class)
class ProviderSendPathTest {

    companion object {
        private const val TEST_NAME = "Provider Send Test"
        private const val TEST_EMAIL = "provider-send-test@pgpony.invalid"
        private const val PLAINTEXT = "The quick brown pony jumps over the lazy dog.\n"
    }

    @get:Rule
    val serviceRule = ServiceTestRule()

    private val app: PGPonyApp = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        runBlocking {
            // Authorize ourselves (instrumentation shares the app uid).
            ApiClientAuthorizer(
                dao = app.database.apiClientDao(),
                signatureSha256Of = ApiClientAuthorizer.platformSignatureLookup(app.packageManager)
            ).grant(app.packageName, com.pgpony.android.data.ApiClientEntity.SCOPE_OPENPGP)
            // Ensure the test key pair exists (passphrase-less Ed25519).
            if (app.keyRepository.getByEmail(TEST_EMAIL).isEmpty()) {
                app.keyRepository.generateKey(
                    name = TEST_NAME,
                    email = TEST_EMAIL,
                    algorithm = KeyAlgorithm.ED25519_CV25519,
                    passphrase = null
                )
            }
        }
    }

    private fun bind(): IOpenPgpService2 {
        val intent = Intent(OpenPgpApi.SERVICE_INTENT_2).setPackage(app.packageName)
        return IOpenPgpService2.Stub.asInterface(serviceRule.bindService(intent))
    }

    /**
     * Run one execute() with plaintext piped in and output collected —
     * the same mechanics OpenPgpApi.executeApi uses on the client side.
     */
    private fun executeWithStreams(
        service: IOpenPgpService2,
        request: Intent,
        pipeId: Int,
        inputBytes: ByteArray?
    ): Pair<Intent, ByteArray> {
        val outputRead = service.createOutputPipe(pipeId)

        var inputRead: ParcelFileDescriptor? = null
        var inputWriteThread: Thread? = null
        if (inputBytes != null) {
            val pipe = ParcelFileDescriptor.createPipe()
            inputRead = pipe[0]
            val writeSide = pipe[1]
            inputWriteThread = Thread {
                ParcelFileDescriptor.AutoCloseOutputStream(writeSide).use {
                    it.write(inputBytes)
                }
            }.also { it.start() }
        }

        // Collect output concurrently so a large write can't deadlock.
        val collected = ByteArrayOutputStream()
        val outputReadThread = Thread {
            ParcelFileDescriptor.AutoCloseInputStream(outputRead).use { stream ->
                stream.copyTo(collected)
            }
        }.also { it.start() }

        val result = service.execute(request, inputRead, pipeId)

        inputWriteThread?.join(5_000)
        outputReadThread.join(5_000)
        return result to collected.toByteArray()
    }

    private fun signKeyId(): Long = runBlocking {
        val entity = app.keyRepository.getByEmail(TEST_EMAIL).first()
        java.lang.Long.parseUnsignedLong(entity.longKeyId, 16)
    }

    private fun request(action: String): Intent =
        Intent(action).putExtra(OpenPgpApi.EXTRA_API_VERSION, 12)

    // ── Tests ──────────────────────────────────────────────────────────

    @Test
    fun encrypt_toOwnKey_producesArmoredCiphertext_thatDecrypts() {
        val service = bind()
        val (result, ciphertext) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_ENCRYPT)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf(TEST_EMAIL))
                .putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true),
            30,
            PLAINTEXT.toByteArray()
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        val armored = ciphertext.toString(Charsets.UTF_8)
        assertTrue(armored.contains("-----BEGIN PGP MESSAGE-----"))

        // Prove it round-trips with the app's own crypto layer.
        val entity = runBlocking { app.keyRepository.getByEmail(TEST_EMAIL).first() }
        val secretRing = app.keyRepository.loadSecretKeyRing(entity.fingerprint)
        assertNotNull(secretRing)
        val decrypted = PGPCryptoService.shared.decrypt(
            encryptedData = ciphertext,
            secretKeyRings = listOf(secretRing!!),
            passphrase = ""
        )
        assertEquals(PLAINTEXT, decrypted.data.toString(Charsets.UTF_8))
    }

    @Test
    fun signAndEncrypt_embedsSignature() {
        val service = bind()
        val (result, ciphertext) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_SIGN_AND_ENCRYPT)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf(TEST_EMAIL))
                .putExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, signKeyId())
                .putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true),
            31,
            PLAINTEXT.toByteArray()
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertTrue(ciphertext.isNotEmpty())
        // Decrypt in-process; signed payload decrypts to the plaintext.
        val entity = runBlocking { app.keyRepository.getByEmail(TEST_EMAIL).first() }
        val secretRing = app.keyRepository.loadSecretKeyRing(entity.fingerprint)!!
        val decrypted = PGPCryptoService.shared.decrypt(
            encryptedData = ciphertext,
            secretKeyRings = listOf(secretRing),
            passphrase = ""
        )
        assertEquals(PLAINTEXT, decrypted.data.toString(Charsets.UTF_8))
    }

    @Test
    fun encrypt_missingRecipient_isReadableError() {
        val service = bind()
        val (result, _) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_ENCRYPT)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf("nokey@nowhere.invalid"))
                .putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true),
            32,
            PLAINTEXT.toByteArray()
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_ERROR,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        @Suppress("DEPRECATION")
        val error = result.getParcelableExtra<OpenPgpError>(OpenPgpApi.RESULT_ERROR)
        assertNotNull(error)
        assertTrue(error!!.message.contains("nokey@nowhere.invalid"))
    }

    @Test
    fun encrypt_missingRecipient_opportunistic_getsDedicatedErrorId() {
        val service = bind()
        val (result, _) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_ENCRYPT)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf("nokey@nowhere.invalid"))
                .putExtra(OpenPgpApi.EXTRA_OPPORTUNISTIC_ENCRYPTION, true),
            33,
            PLAINTEXT.toByteArray()
        )
        @Suppress("DEPRECATION")
        val error = result.getParcelableExtra<OpenPgpError>(OpenPgpApi.RESULT_ERROR)
        assertNotNull(error)
        assertEquals(OpenPgpError.OPPORTUNISTIC_MISSING_KEYS, error!!.errorId)
    }

    @Test
    fun detachedSign_returnsArmoredSignatureExtra_andMicalg() {
        val service = bind()
        val (result, _) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_DETACHED_SIGN)
                .putExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, signKeyId())
                .putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true),
            34,
            PLAINTEXT.toByteArray()
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        val signature = result.getByteArrayExtra(OpenPgpApi.RESULT_DETACHED_SIGNATURE)
        assertNotNull(signature)
        assertTrue(
            signature!!.toString(Charsets.UTF_8).contains("-----BEGIN PGP SIGNATURE-----")
        )
        assertEquals(
            "pgp-sha256",
            result.getStringExtra(OpenPgpApi.RESULT_SIGNATURE_MICALG)
        )
    }

    @Test
    fun cleartextSign_producesClearSignedBlock() {
        val service = bind()
        val (result, output) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_CLEARTEXT_SIGN)
                .putExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, signKeyId()),
            35,
            PLAINTEXT.toByteArray()
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        val text = output.toString(Charsets.UTF_8)
        assertTrue(text.contains("-----BEGIN PGP SIGNED MESSAGE-----"))
        assertTrue(text.contains("-----BEGIN PGP SIGNATURE-----"))
    }

    @Test
    fun queryAutocryptStatus_knownRecipient_isEncryptable() {
        val service = bind()
        val (result, _) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_QUERY_AUTOCRYPT_STATUS)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf(TEST_EMAIL)),
            37,
            null
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        // Key held, no autocrypt peer state → DISCOURAGE (encryptable;
        // OpenKeychain parity for manually-imported keys).
        assertEquals(
            OpenPgpApi.AUTOCRYPT_STATUS_DISCOURAGE,
            result.getIntExtra(OpenPgpApi.RESULT_AUTOCRYPT_STATUS, -1)
        )
    }

    @Test
    fun queryAutocryptStatus_unknownRecipient_isUnavailable() {
        val service = bind()
        val (result, _) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_QUERY_AUTOCRYPT_STATUS)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf("nokey@nowhere.invalid")),
            38,
            null
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertEquals(
            OpenPgpApi.AUTOCRYPT_STATUS_UNAVAILABLE,
            result.getIntExtra(OpenPgpApi.RESULT_AUTOCRYPT_STATUS, -1)
        )
        assertEquals(
            false,
            result.getBooleanExtra(OpenPgpApi.RESULT_KEYS_CONFIRMED, true)
        )
    }

    @Test
    fun signAndEncrypt_withoutSignKey_isReadableError() {
        val service = bind()
        val (result, _) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_SIGN_AND_ENCRYPT)
                .putExtra(OpenPgpApi.EXTRA_USER_IDS, arrayOf(TEST_EMAIL)),
            36,
            PLAINTEXT.toByteArray()
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_ERROR,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        @Suppress("DEPRECATION")
        val error = result.getParcelableExtra<OpenPgpError>(OpenPgpApi.RESULT_ERROR)
        assertNotNull(error)
        assertTrue(error!!.message.contains("signing key", ignoreCase = true))
    }
}
