// ProviderReceivePathTest.kt
// PGPony Android — 4.0.0 Succession Phase P2b-1
//
// Instrumented end-to-end tests for DECRYPT_VERIFY / DECRYPT_METADATA:
// ciphertext (produced by the app's own crypto layer or the provider
// itself) goes in through real pipes, plaintext and populated
// OpenPgpSignatureResult / OpenPgpDecryptionResult come back. Covers
// the §6 Q12 requirement — signature state populated for every decrypt
// path — including the unknown-signer (KEY_MISSING) case.

package com.pgpony.android.provider

import android.content.Intent
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.ServiceTestRule
import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SigningService
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.OpenPgpDecryptionResult
import org.openintents.openpgp.OpenPgpMetadata
import org.openintents.openpgp.OpenPgpSignatureResult
import org.openintents.openpgp.util.OpenPgpApi
import java.io.ByteArrayOutputStream

@RunWith(AndroidJUnit4::class)
class ProviderReceivePathTest {

    companion object {
        private const val TEST_EMAIL = "provider-send-test@pgpony.invalid"
        private const val PLAINTEXT = "Receive-path round trip.\n"
    }

    @get:Rule
    val serviceRule = ServiceTestRule()

    private val app: PGPonyApp = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        runBlocking {
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
        }
    }

    private fun bind(): IOpenPgpService2 {
        val intent = Intent(OpenPgpApi.SERVICE_INTENT_2).setPackage(app.packageName)
        return IOpenPgpService2.Stub.asInterface(serviceRule.bindService(intent))
    }

    private fun executeWithStreams(
        service: IOpenPgpService2,
        request: Intent,
        pipeId: Int,
        inputBytes: ByteArray?
    ): Pair<Intent, ByteArray> {
        val outputRead = service.createOutputPipe(pipeId)
        var inputRead: ParcelFileDescriptor? = null
        var writer: Thread? = null
        if (inputBytes != null) {
            val pipe = ParcelFileDescriptor.createPipe()
            inputRead = pipe[0]
            val writeSide = pipe[1]
            writer = Thread {
                ParcelFileDescriptor.AutoCloseOutputStream(writeSide).use { it.write(inputBytes) }
            }.also { it.start() }
        }
        val collected = ByteArrayOutputStream()
        val reader = Thread {
            ParcelFileDescriptor.AutoCloseInputStream(outputRead).use { it.copyTo(collected) }
        }.also { it.start() }
        val result = service.execute(request, inputRead, pipeId)
        writer?.join(5_000)
        reader.join(5_000)
        return result to collected.toByteArray()
    }

    private fun request(action: String): Intent =
        Intent(action).putExtra(OpenPgpApi.EXTRA_API_VERSION, 12)

    private fun entityAndRings() = runBlocking {
        val entity = app.keyRepository.getByEmail(TEST_EMAIL).first()
        Triple(
            entity,
            app.keyRepository.loadPublicKeyRing(entity.fingerprint)!!,
            app.keyRepository.loadSecretKeyRing(entity.fingerprint)!!
        )
    }

    @Suppress("DEPRECATION")
    private fun Intent.signature(): OpenPgpSignatureResult? =
        getParcelableExtra(OpenPgpApi.RESULT_SIGNATURE)

    @Suppress("DEPRECATION")
    private fun Intent.decryption(): OpenPgpDecryptionResult? =
        getParcelableExtra(OpenPgpApi.RESULT_DECRYPTION)

    // ── Tests ──────────────────────────────────────────────────────────

    @Test
    fun decryptVerify_unsignedMessage_reportsNoSignature() {
        val (_, pubRing, _) = entityAndRings()
        val ciphertext = PGPCryptoService.shared.encrypt(
            data = PLAINTEXT.toByteArray(),
            recipientPublicKeys = listOf(pubRing),
            armor = true
        )
        val service = bind()
        val (result, plain) = executeWithStreams(
            service, request(OpenPgpApi.ACTION_DECRYPT_VERIFY), 50, ciphertext
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertEquals(PLAINTEXT, plain.toString(Charsets.UTF_8))
        assertEquals(OpenPgpDecryptionResult.RESULT_ENCRYPTED, result.decryption()!!.result)
        assertEquals(OpenPgpSignatureResult.RESULT_NO_SIGNATURE, result.signature()!!.result)
    }

    @Test
    fun decryptVerify_signedMessage_reportsValidUnconfirmedSigner() {
        val (_, pubRing, secRing) = entityAndRings()
        val ciphertext = PGPCryptoService.shared.encrypt(
            data = PLAINTEXT.toByteArray(),
            recipientPublicKeys = listOf(pubRing),
            signingSecretKey = secRing,
            passphrase = null,
            armor = true
        )
        val service = bind()
        val (result, plain) = executeWithStreams(
            service, request(OpenPgpApi.ACTION_DECRYPT_VERIFY), 51, ciphertext
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertEquals(PLAINTEXT, plain.toString(Charsets.UTF_8))
        val sig = result.signature()!!
        // Freshly generated key: trust UNKNOWN → valid but unconfirmed.
        assertEquals(OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED, sig.result)
        assertNotEquals(0L, sig.keyId)
        assertTrue(sig.primaryUserId.contains(TEST_EMAIL))
    }

    @Test
    fun decryptVerify_uncompressedSignedMessage_iosLayout_reportsValidSigner() {
        // Replicates the exact wire shape PGPony iOS emits (verified via
        // gpg --list-packets on a real iOS message): v3 PKESK + SEIPD
        // containing OnePassSig ‖ Literal ‖ Signature with NO Compressed
        // Data wrapper. The app's own encrypt() always compresses, so
        // this layout is otherwise untested.
        val (_, pubRing, secRing) = entityAndRings()

        val signingKey = secRing.secretKey
        val privateKey = signingKey.extractPrivateKey(
            org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
            ).build(CharArray(0))
        )
        val sigGen = org.bouncycastle.openpgp.PGPSignatureGenerator(
            org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(
                signingKey.publicKey.algorithm,
                org.bouncycastle.bcpg.HashAlgorithmTags.SHA256
            ),
            signingKey.publicKey
        )
        sigGen.init(org.bouncycastle.openpgp.PGPSignature.BINARY_DOCUMENT, privateKey)

        val encKey = pubRing.publicKeys.asSequence().first { it.isEncryptionKey && !it.isMasterKey }
        val encGen = org.bouncycastle.openpgp.PGPEncryptedDataGenerator(
            org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(
                org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256
            ).setWithIntegrityPacket(true).setSecureRandom(java.security.SecureRandom())
        )
        encGen.addMethod(
            org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator(encKey)
        )

        val out = java.io.ByteArrayOutputStream()
        val armored = org.bouncycastle.bcpg.ArmoredOutputStream(out)
        val encOut = encGen.open(armored, ByteArray(4096))
        // NO compression generator — packets go straight into the SEIPD.
        sigGen.generateOnePassVersion(false).encode(encOut)
        val litGen = org.bouncycastle.openpgp.PGPLiteralDataGenerator()
        val payload = PLAINTEXT.toByteArray()
        val litOut = litGen.open(
            encOut, org.bouncycastle.openpgp.PGPLiteralData.BINARY, "",
            payload.size.toLong(), java.util.Date()
        )
        litOut.write(payload)
        litOut.close()
        litGen.close()
        sigGen.update(payload)
        sigGen.generate().encode(encOut)
        encOut.close()
        encGen.close()
        armored.close()

        val service = bind()
        val (result, plain) = executeWithStreams(
            service, request(OpenPgpApi.ACTION_DECRYPT_VERIFY), 56, out.toByteArray()
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertEquals(PLAINTEXT, plain.toString(Charsets.UTF_8))
        val sig = result.signature()!!
        assertEquals(
            "iOS-layout (uncompressed) signed message must report its signature",
            OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED,
            sig.result
        )
    }

    @Test
    fun decryptVerify_signedByUnknownKey_reportsKeyMissing() {
        // Generate a throwaway signer, capture its ring, then delete the
        // key so the signer is unknown at verify time.
        val strangerEmail = "stranger-${System.nanoTime()}@pgpony.invalid"
        val (ciphertext, _) = runBlocking {
            val stranger = app.keyRepository.generateKey(
                name = "Stranger",
                email = strangerEmail,
                algorithm = KeyAlgorithm.ED25519_CV25519,
                passphrase = null
            )
            val strangerSecret = app.keyRepository.loadSecretKeyRing(stranger.fingerprint)!!
            val ownPub = app.keyRepository.loadPublicKeyRing(
                app.keyRepository.getByEmail(TEST_EMAIL).first().fingerprint
            )!!
            val ct = PGPCryptoService.shared.encrypt(
                data = PLAINTEXT.toByteArray(),
                recipientPublicKeys = listOf(ownPub),
                signingSecretKey = strangerSecret,
                passphrase = null,
                armor = true
            )
            app.keyRepository.deleteByFingerprint(stranger.fingerprint)
            ct to stranger
        }
        val service = bind()
        val (result, _) = executeWithStreams(
            service, request(OpenPgpApi.ACTION_DECRYPT_VERIFY), 52, ciphertext
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        val sig = result.signature()!!
        assertEquals(OpenPgpSignatureResult.RESULT_KEY_MISSING, sig.result)
        assertNotEquals(0L, sig.keyId)
    }

    @Test
    fun decryptVerify_detachedSignature_verifiesWithoutDecryption() {
        val (_, _, secRing) = entityAndRings()
        val signature = SigningService.shared.signDetached(
            data = PLAINTEXT.toByteArray(),
            secretKeyRing = secRing,
            passphrase = null,
            armor = true
        )
        val service = bind()
        val (result, echoed) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_DECRYPT_VERIFY)
                .putExtra(OpenPgpApi.EXTRA_DETACHED_SIGNATURE, signature),
            53,
            PLAINTEXT.toByteArray()
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertEquals(
            OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED,
            result.decryption()!!.result
        )
        assertEquals(
            OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED,
            result.signature()!!.result
        )
        assertEquals(PLAINTEXT, echoed.toString(Charsets.UTF_8))
    }

    @Test
    fun decryptVerify_clearSigned_extractsContentAndVerifies() {
        val (_, _, secRing) = entityAndRings()
        val clearSigned = SigningService.shared.signClear(
            text = PLAINTEXT.trimEnd('\n'),
            secretKeyRing = secRing,
            passphrase = null
        )
        val service = bind()
        val (result, content) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_DECRYPT_VERIFY),
            54,
            clearSigned.toByteArray()
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        assertEquals(
            OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED,
            result.signature()!!.result
        )
        assertTrue(content.toString(Charsets.UTF_8).contains(PLAINTEXT.trimEnd('\n')))
    }

    // ── P2b-2: sender-status matching ──────────────────────────────────

    private fun signedCiphertext(): ByteArray {
        val (_, pubRing, secRing) = entityAndRings()
        return PGPCryptoService.shared.encrypt(
            data = PLAINTEXT.toByteArray(),
            recipientPublicKeys = listOf(pubRing),
            signingSecretKey = secRing,
            passphrase = null,
            armor = true
        )
    }

    @Test
    fun decryptVerify_senderMatchesSignerUserId_isUserIdUnconfirmed() {
        val service = bind()
        val (result, _) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_DECRYPT_VERIFY)
                .putExtra(OpenPgpApi.EXTRA_SENDER_ADDRESS, TEST_EMAIL),
            57,
            signedCiphertext()
        )
        val sig = result.signature()!!
        assertEquals(OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED, sig.result)
        // Address matches a signer user id; key trust is Unknown →
        // USER_ID_UNCONFIRMED (Thunderbird: "unverified" display).
        assertEquals(
            OpenPgpSignatureResult.SenderStatusResult.USER_ID_UNCONFIRMED,
            sig.senderStatusResult
        )
    }

    @Test
    fun decryptVerify_senderMismatch_isUserIdMissing() {
        val service = bind()
        val (result, _) = executeWithStreams(
            service,
            request(OpenPgpApi.ACTION_DECRYPT_VERIFY)
                .putExtra(OpenPgpApi.EXTRA_SENDER_ADDRESS, "spoofer@evil.invalid"),
            58,
            signedCiphertext()
        )
        val sig = result.signature()!!
        assertEquals(OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED, sig.result)
        // Valid signature but from a key carrying NO user id for the
        // claimed sender → the spoof-warning state.
        assertEquals(
            OpenPgpSignatureResult.SenderStatusResult.USER_ID_MISSING,
            sig.senderStatusResult
        )
    }

    @Test
    fun decryptMetadata_returnsFilename_withoutPlaintextOutput() {
        val (_, pubRing, _) = entityAndRings()
        val ciphertext = PGPCryptoService.shared.encrypt(
            data = PLAINTEXT.toByteArray(),
            recipientPublicKeys = listOf(pubRing),
            filename = "report.pdf",
            armor = true
        )
        val service = bind()
        val (result, output) = executeWithStreams(
            service, request(OpenPgpApi.ACTION_DECRYPT_METADATA), 55, ciphertext
        )
        assertEquals(
            OpenPgpApi.RESULT_CODE_SUCCESS,
            result.getIntExtra(OpenPgpApi.RESULT_CODE, -99)
        )
        @Suppress("DEPRECATION")
        val metadata = result.getParcelableExtra<OpenPgpMetadata>(OpenPgpApi.RESULT_METADATA)
        assertNotNull(metadata)
        assertEquals("report.pdf", metadata!!.filename)
        assertEquals(PLAINTEXT.length.toLong(), metadata.originalSize)
        assertEquals(0, output.size)
    }
}
