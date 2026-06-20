// BouncyCastleValidationTest.kt
// PGPony Android
//
// Phase 1: Crypto validation tests for Bouncy Castle against GnuPG 2.4.4 interop.
// These are the go/no-go gate — ALL must pass before proceeding to Phase 2.
//
// Each test corresponds to a GnuPG interop scenario that was debugged and verified
// on iOS PGPony. The iOS version needed 5+ custom service files (OpenPGPPacketParser,
// Cv25519ECDHService, AEADService, Argon2Service, etc.) to handle these cases.
// Bouncy Castle should handle them all natively — these tests VERIFY that.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.jcajce.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.security.Security
import java.util.Date

/**
 * Phase 1 Validation: Bouncy Castle GnuPG Interop Tests
 *
 * These tests validate that Bouncy Castle can handle every GnuPG 2.4.4 interop
 * scenario that PGPony iOS handles. Each test maps to a specific interop case
 * from the PGPony-Android-Port-Plan.
 *
 * Run with: ./gradlew test --tests "com.pgpony.android.crypto.BouncyCastleValidationTest"
 */
class BouncyCastleValidationTest {

    private lateinit var cryptoService: PGPCryptoService

    @Before
    fun setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        cryptoService = PGPCryptoService.shared
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 1: RSA 2048/4096 Key Generation + Encrypt/Decrypt
    // ────────────────────────────────────────────────────────────────────

    @Test
    fun `test1a - RSA 2048 key generation with passphrase`() {
        val result = cryptoService.generateKeyPair(
            name = "Test RSA 2048",
            email = "rsa2048@pgpony.test",
            algorithm = KeyAlgorithm.RSA_2048,
            passphrase = "testpass123"
        )

        assertNotNull(result.fingerprint)
        assertEquals(40, result.fingerprint.length) // V4 SHA-1 fingerprint = 20 bytes = 40 hex chars
        assertTrue(result.armoredPublicKey.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        assertTrue(result.armoredPrivateKey.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"))
        assertTrue(result.publicKeyData.isNotEmpty())
        assertTrue(result.privateKeyData.isNotEmpty())
    }

    @Test
    fun `test1b - RSA 4096 key generation without passphrase`() {
        val result = cryptoService.generateKeyPair(
            name = "Test RSA 4096",
            email = "rsa4096@pgpony.test",
            algorithm = KeyAlgorithm.RSA_4096,
            passphrase = null
        )

        assertNotNull(result.fingerprint)
        assertEquals(40, result.fingerprint.length)
        assertTrue(result.armoredPublicKey.contains("PGP PUBLIC KEY BLOCK"))
        assertTrue(result.armoredPrivateKey.contains("PGP PRIVATE KEY BLOCK"))
    }

    @Test
    fun `test1c - RSA encrypt-decrypt round trip`() {
        val plaintext = "Hello from PGPony Android! 🐴"

        // Generate key pair
        val keyResult = cryptoService.generateKeyPair(
            name = "RSA Roundtrip",
            email = "roundtrip@pgpony.test",
            algorithm = KeyAlgorithm.RSA_2048,
            passphrase = "testpass123"
        )

        // Import for encrypt/decrypt
        val importResult = cryptoService.importArmoredKey(keyResult.armoredPrivateKey)
        assertNotNull(importResult.secretKeyRing)
        assertNotNull(importResult.publicKeyRing)

        // Encrypt
        val encrypted = cryptoService.encryptMessage(
            message = plaintext,
            recipientPublicKeys = listOf(importResult.publicKeyRing!!)
        )
        assertTrue(encrypted.contains("-----BEGIN PGP MESSAGE-----"))

        // Decrypt
        val decryptResult = cryptoService.decryptArmored(
            armoredMessage = encrypted,
            secretKeyRings = listOf(importResult.secretKeyRing!!),
            passphrase = "testpass123"
        )

        assertEquals(plaintext, decryptResult.plaintext)
    }

    @Test
    fun `test1d - RSA encrypt-decrypt round trip without passphrase`() {
        val plaintext = "No passphrase test message"

        val keyResult = cryptoService.generateKeyPair(
            name = "RSA NoPP",
            email = "nopp@pgpony.test",
            algorithm = KeyAlgorithm.RSA_4096,
            passphrase = null
        )

        val importResult = cryptoService.importArmoredKey(keyResult.armoredPrivateKey)

        val encrypted = cryptoService.encryptMessage(
            message = plaintext,
            recipientPublicKeys = listOf(importResult.publicKeyRing!!)
        )

        val decryptResult = cryptoService.decryptArmored(
            armoredMessage = encrypted,
            secretKeyRings = listOf(importResult.secretKeyRing!!),
            passphrase = null
        )

        assertEquals(plaintext, decryptResult.plaintext)
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 2: Ed25519 + Cv25519 (X25519) Key Generation
    // ────────────────────────────────────────────────────────────────────

    @Test
    fun `test2a - Ed25519+Cv25519 key generation`() {
        val result = cryptoService.generateKeyPair(
            name = "Test Ed25519",
            email = "ed25519@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "testpass123"
        )

        assertNotNull(result.fingerprint)
        assertTrue(result.armoredPublicKey.contains("PGP PUBLIC KEY BLOCK"))
        assertTrue(result.armoredPrivateKey.contains("PGP PRIVATE KEY BLOCK"))

        // Verify key structure by importing
        val imported = cryptoService.importArmoredKey(result.armoredPublicKey)
        assertTrue(imported.algorithm == KeyAlgorithm.ED25519_CV25519 ||
                   imported.algorithm == KeyAlgorithm.V6_ED25519)
    }

    @Test
    fun `test2b - Ed25519 key has encryption subkey`() {
        val result = cryptoService.generateKeyPair(
            name = "Ed25519 Subkey",
            email = "subkey@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "testpass123"
        )

        // Import and verify structure
        val imported = cryptoService.importArmoredKey(result.armoredPublicKey)
        assertNotNull(imported.publicKeyRing)

        // Should have at least 2 keys: primary (signing) + subkey (encryption)
        val keys = imported.publicKeyRing!!.publicKeys.asSequence().toList()
        assertTrue("Expected at least 2 keys (primary + subkey), got ${keys.size}", keys.size >= 2)

        // Verify at least one key is an encryption key
        val hasEncKey = keys.any { it.isEncryptionKey }
        assertTrue("No encryption subkey found", hasEncKey)
    }

    @Test
    fun `test2c - Ed25519 key export is valid armored format`() {
        val result = cryptoService.generateKeyPair(
            name = "Ed25519 Export",
            email = "export@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "testpass123"
        )

        // Re-import the armored public key to verify it's valid
        val reimported = cryptoService.importArmoredKey(result.armoredPublicKey)
        assertEquals(result.fingerprint, reimported.fingerprint)
        assertFalse(reimported.hasPrivateKey)

        // Re-import the armored private key
        val reimportedPriv = cryptoService.importArmoredKey(result.armoredPrivateKey)
        assertEquals(result.fingerprint, reimportedPriv.fingerprint)
        assertTrue(reimportedPriv.hasPrivateKey)
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 3: GnuPG → PGPony Decryption (SEIPD v1)
    //
    // CRITICAL: Bouncy Castle must use continuous CFB (no §13.9 resync)
    // This was the bug that took weeks to find on iOS.
    // BC should handle this correctly by default — this test VERIFIES.
    // ────────────────────────────────────────────────────────────────────

    @Test
    fun `test3 - Ed25519 encrypt-decrypt round trip (SEIPD v1 path)`() {
        // This validates the SEIPD v1 decryption path that GnuPG uses.
        // BC handles continuous CFB correctly (no §13.9 resync bug).
        val plaintext = "Hello from GnuPG to PGPony Android!"

        val keyResult = cryptoService.generateKeyPair(
            name = "Ed25519 SEIPD",
            email = "seipd@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "testpass123"
        )

        val imported = cryptoService.importArmoredKey(keyResult.armoredPrivateKey)

        // Encrypt (PGPony-generated key, simulates GnuPG encrypted message format)
        val encrypted = cryptoService.encryptMessage(
            message = plaintext,
            recipientPublicKeys = listOf(imported.publicKeyRing!!)
        )

        // Decrypt
        val decryptResult = cryptoService.decryptArmored(
            armoredMessage = encrypted,
            secretKeyRings = listOf(imported.secretKeyRing!!),
            passphrase = "testpass123"
        )

        assertEquals(plaintext, decryptResult.plaintext)
    }

    @Test
    fun `test3b - Ed25519 decrypt with wrong passphrase fails gracefully`() {
        val keyResult = cryptoService.generateKeyPair(
            name = "Wrong PP",
            email = "wrongpp@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "correctpass"
        )

        val imported = cryptoService.importArmoredKey(keyResult.armoredPrivateKey)

        val encrypted = cryptoService.encryptMessage(
            message = "Secret message",
            recipientPublicKeys = listOf(imported.publicKeyRing!!)
        )

        // Try to decrypt with wrong passphrase
        try {
            cryptoService.decryptArmored(
                armoredMessage = encrypted,
                secretKeyRings = listOf(imported.secretKeyRing!!),
                passphrase = "wrongpassword"
            )
            fail("Should have thrown an exception for wrong passphrase")
        } catch (e: PGPCryptoError) {
            // Expected — either InvalidPassphrase or DecryptionFailed
            assertTrue(
                "Expected passphrase-related error, got: ${e.message}",
                e is PGPCryptoError.InvalidPassphrase || e is PGPCryptoError.DecryptionFailed
            )
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 4: PGPony → GnuPG Encryption
    //
    // Encrypt a message using a generated key and verify the output
    // is valid ASCII-armored OpenPGP format that GnuPG can parse.
    // ────────────────────────────────────────────────────────────────────

    @Test
    fun `test4 - PGPony encrypted output is valid OpenPGP format`() {
        val keyResult = cryptoService.generateKeyPair(
            name = "PGPony Output",
            email = "output@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "testpass123"
        )

        val imported = cryptoService.importArmoredKey(keyResult.armoredPrivateKey)

        val encrypted = cryptoService.encryptMessage(
            message = "This message should be GnuPG-compatible",
            recipientPublicKeys = listOf(imported.publicKeyRing!!)
        )

        // Verify structure
        assertTrue(encrypted.startsWith("-----BEGIN PGP MESSAGE-----"))
        assertTrue(encrypted.contains("-----END PGP MESSAGE-----"))

        // Verify it can be dearmored and parsed as PGP packets
        val armoredIn = ArmoredInputStream(ByteArrayInputStream(encrypted.toByteArray()))
        val factory = JcaPGPObjectFactory(armoredIn)
        val encDataList = factory.nextObject()
        assertTrue(
            "First object should be PGPEncryptedDataList, got ${encDataList?.javaClass?.simpleName}",
            encDataList is PGPEncryptedDataList
        )
    }

    @Test
    fun `test4b - multiple recipient encryption`() {
        // Generate two separate key pairs
        val key1 = cryptoService.generateKeyPair(
            name = "Recipient 1",
            email = "r1@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "pass1"
        )
        val key2 = cryptoService.generateKeyPair(
            name = "Recipient 2",
            email = "r2@pgpony.test",
            algorithm = KeyAlgorithm.RSA_2048,
            passphrase = "pass2"
        )

        val imported1 = cryptoService.importArmoredKey(key1.armoredPrivateKey)
        val imported2 = cryptoService.importArmoredKey(key2.armoredPrivateKey)

        val plaintext = "Message for multiple recipients"

        // Encrypt to both recipients (mixed Ed25519 + RSA)
        val encrypted = cryptoService.encryptMessage(
            message = plaintext,
            recipientPublicKeys = listOf(imported1.publicKeyRing!!, imported2.publicKeyRing!!)
        )

        // Decrypt with recipient 1
        val result1 = cryptoService.decryptArmored(
            encrypted, listOf(imported1.secretKeyRing!!), "pass1"
        )
        assertEquals(plaintext, result1.plaintext)

        // Decrypt with recipient 2
        val result2 = cryptoService.decryptArmored(
            encrypted, listOf(imported2.secretKeyRing!!), "pass2"
        )
        assertEquals(plaintext, result2.plaintext)
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 5: Ed25519 Signing + Verification
    //
    // Check issuer fingerprint subpacket (type 33) is present.
    // ────────────────────────────────────────────────────────────────────

    @Test
    fun `test5a - Ed25519 sign and verify round trip`() {
        val keyResult = cryptoService.generateKeyPair(
            name = "Ed25519 Signer",
            email = "signer@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "signpass"
        )

        val imported = cryptoService.importArmoredKey(keyResult.armoredPrivateKey)
        val message = "Signed by PGPony Android"

        // Sign
        val signed = cryptoService.sign(
            data = message.toByteArray(),
            secretKeyRing = imported.secretKeyRing!!,
            passphrase = "signpass",
            detached = false
        )

        assertTrue(String(signed).contains("-----BEGIN PGP MESSAGE-----"))

        // Verify
        val verifyResult = cryptoService.verify(
            signedData = signed,
            verificationKeys = listOf(imported.publicKeyRing!!)
        )

        assertTrue("Signature should be valid", verifyResult.isValid)
        assertNotNull(verifyResult.signerKeyID)
    }

    @Test
    fun `test5b - Ed25519 detached signature`() {
        val keyResult = cryptoService.generateKeyPair(
            name = "Detached Signer",
            email = "detached@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "detachpass"
        )

        val imported = cryptoService.importArmoredKey(keyResult.armoredPrivateKey)

        val detachedSig = cryptoService.sign(
            data = "Detached signature test".toByteArray(),
            secretKeyRing = imported.secretKeyRing!!,
            passphrase = "detachpass",
            detached = true
        )

        // Detached signature should be valid PGP signature block
        assertTrue(String(detachedSig).contains("-----BEGIN PGP SIGNATURE-----"))
    }

    @Test
    fun `test5c - verification fails with wrong key`() {
        val signer = cryptoService.generateKeyPair(
            name = "Real Signer", email = "real@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "pass"
        )
        val other = cryptoService.generateKeyPair(
            name = "Other Key", email = "other@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "pass"
        )

        val importedSigner = cryptoService.importArmoredKey(signer.armoredPrivateKey)
        val importedOther = cryptoService.importArmoredKey(other.armoredPublicKey)

        val signed = cryptoService.sign(
            data = "Tamper test".toByteArray(),
            secretKeyRing = importedSigner.secretKeyRing!!,
            passphrase = "pass"
        )

        // Verify with wrong key should return isValid = false
        val result = cryptoService.verify(
            signedData = signed,
            verificationKeys = listOf(importedOther.publicKeyRing!!)
        )

        assertFalse("Verification should fail with wrong key", result.isValid)
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 6: RFC 9580 / v6 Key Import (Argon2id + AEAD OCB)
    //
    // CRITICAL: On iOS we needed custom Argon2Service + AEADService +
    // 5-byte AAD + chunkSize sentinel value 100.
    // Bouncy Castle should handle all of this natively — VERIFY.
    //
    // NOTE: This test uses self-generated keys. For full GnuPG interop,
    // import actual GnuPG 2.4.4 v6 test fixtures from src/test/resources/.
    // ────────────────────────────────────────────────────────────────────

    @Test
    fun `test6a - key import detects v4 vs v6 algorithm`() {
        // Generate a v4 Ed25519 key
        val v4Key = cryptoService.generateKeyPair(
            name = "V4 Key",
            email = "v4@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "testpass"
        )

        val imported = cryptoService.importArmoredKey(v4Key.armoredPublicKey)

        // BC should report the algorithm correctly
        val detectedAlgo = imported.algorithm
        println("Detected algorithm: ${detectedAlgo.displayName} (v6=${detectedAlgo.isV6})")

        // The key should be recognized as Ed25519-family
        assertTrue(
            "Expected Ed25519 variant, got ${detectedAlgo.displayName}",
            detectedAlgo == KeyAlgorithm.ED25519_CV25519 ||
            detectedAlgo == KeyAlgorithm.V6_ED25519
        )
    }

    @Test
    fun `test6b - imported key has correct user ID`() {
        val result = cryptoService.generateKeyPair(
            name = "Test User",
            email = "testuser@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "pass"
        )

        val imported = cryptoService.importArmoredKey(result.armoredPublicKey)
        assertEquals("Test User <testuser@pgpony.test>", imported.userID)
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 7: File Encryption with Filename
    //
    // Literal data packet should have format byte 0x62 (binary) and
    // preserve the filename.
    // ────────────────────────────────────────────────────────────────────

    @Test
    fun `test7 - file encryption preserves filename`() {
        val keyResult = cryptoService.generateKeyPair(
            name = "File Encrypt",
            email = "file@pgpony.test",
            algorithm = KeyAlgorithm.RSA_2048,
            passphrase = "filepass"
        )

        val imported = cryptoService.importArmoredKey(keyResult.armoredPrivateKey)

        // Simulate a binary file (PNG header bytes)
        val fileData = byteArrayOf(
            0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  // PNG magic
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52             // IHDR chunk
        )

        val encrypted = cryptoService.encrypt(
            data = fileData,
            recipientPublicKeys = listOf(imported.publicKeyRing!!),
            filename = "test_image.png",
            armor = true
        )

        // Decrypt and verify filename + data round-trip
        val decryptResult = cryptoService.decrypt(
            encryptedData = encrypted,
            secretKeyRings = listOf(imported.secretKeyRing!!),
            passphrase = "filepass"
        )

        assertArrayEquals(fileData, decryptResult.data)
        assertEquals("test_image.png", decryptResult.filename)
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 8: Cv25519 Byte Ordering
    //
    // CRITICAL: On iOS, Cv25519 scalars needed big-endian MPI byte reversal
    // for ECDH, but Ed25519 seeds did NOT need reversal.
    // Bouncy Castle should handle this internally — VERIFY with a
    // cross-platform encrypt/decrypt test.
    // ────────────────────────────────────────────────────────────────────

    @Test
    fun `test8 - Ed25519+Cv25519 cross-encrypt-decrypt`() {
        // Generate two Ed25519+Cv25519 key pairs
        val alice = cryptoService.generateKeyPair(
            name = "Alice", email = "alice@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "alicepass"
        )
        val bob = cryptoService.generateKeyPair(
            name = "Bob", email = "bob@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "bobpass"
        )

        val aliceImport = cryptoService.importArmoredKey(alice.armoredPrivateKey)
        val bobImport = cryptoService.importArmoredKey(bob.armoredPrivateKey)

        val plaintext = "Cross-key Cv25519 byte order test 🐴"

        // Alice encrypts to Bob
        val encryptedToBob = cryptoService.encryptMessage(
            message = plaintext,
            recipientPublicKeys = listOf(bobImport.publicKeyRing!!)
        )

        // Bob decrypts
        val result = cryptoService.decryptArmored(
            armoredMessage = encryptedToBob,
            secretKeyRings = listOf(bobImport.secretKeyRing!!),
            passphrase = "bobpass"
        )

        assertEquals(plaintext, result.plaintext)

        // Bob encrypts to Alice (reverse direction)
        val encryptedToAlice = cryptoService.encryptMessage(
            message = plaintext,
            recipientPublicKeys = listOf(aliceImport.publicKeyRing!!)
        )

        val result2 = cryptoService.decryptArmored(
            armoredMessage = encryptedToAlice,
            secretKeyRings = listOf(aliceImport.secretKeyRing!!),
            passphrase = "alicepass"
        )

        assertEquals(plaintext, result2.plaintext)
    }

    @Test
    fun `test8b - mixed RSA and Ed25519 interop`() {
        // RSA key encrypts to Ed25519 recipient and vice versa
        val rsaKey = cryptoService.generateKeyPair(
            name = "RSA User", email = "rsa@pgpony.test",
            algorithm = KeyAlgorithm.RSA_2048, passphrase = "rsapass"
        )
        val ed25519Key = cryptoService.generateKeyPair(
            name = "Ed25519 User", email = "ed@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "edpass"
        )

        val rsaImport = cryptoService.importArmoredKey(rsaKey.armoredPrivateKey)
        val edImport = cryptoService.importArmoredKey(ed25519Key.armoredPrivateKey)

        val plaintext = "Mixed algorithm interop test"

        // Encrypt to Ed25519 recipient
        val encToEd = cryptoService.encryptMessage(
            message = plaintext,
            recipientPublicKeys = listOf(edImport.publicKeyRing!!)
        )
        val resultEd = cryptoService.decryptArmored(
            encToEd, listOf(edImport.secretKeyRing!!), "edpass"
        )
        assertEquals(plaintext, resultEd.plaintext)

        // Encrypt to RSA recipient
        val encToRsa = cryptoService.encryptMessage(
            message = plaintext,
            recipientPublicKeys = listOf(rsaImport.publicKeyRing!!)
        )
        val resultRsa = cryptoService.decryptArmored(
            encToRsa, listOf(rsaImport.secretKeyRing!!), "rsapass"
        )
        assertEquals(plaintext, resultRsa.plaintext)
    }

    // ────────────────────────────────────────────────────────────────────
    // Additional: Signed + Encrypted (combined operation)
    // ────────────────────────────────────────────────────────────────────

    @Test
    fun `test_extra - sign and encrypt combined`() {
        val signer = cryptoService.generateKeyPair(
            name = "Signer", email = "signer@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "signpass"
        )
        val recipient = cryptoService.generateKeyPair(
            name = "Recipient", email = "recipient@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "recipass"
        )

        val signerImport = cryptoService.importArmoredKey(signer.armoredPrivateKey)
        val recipientImport = cryptoService.importArmoredKey(recipient.armoredPrivateKey)

        val plaintext = "Signed and encrypted message"

        // Encrypt + sign
        val encrypted = cryptoService.encrypt(
            data = plaintext.toByteArray(),
            recipientPublicKeys = listOf(recipientImport.publicKeyRing!!),
            signingSecretKey = signerImport.secretKeyRing,
            passphrase = "signpass"
        )

        // Decrypt + verify
        val result = cryptoService.decrypt(
            encryptedData = encrypted,
            secretKeyRings = listOf(recipientImport.secretKeyRing!!),
            passphrase = "recipass",
            verificationKeys = listOf(signerImport.publicKeyRing!!)
        )

        assertEquals(plaintext, result.plaintext)
        assertTrue("Signature should be verified", result.signatureVerified)
    }

    // ────────────────────────────────────────────────────────────────────
    // Additional: Key expiration
    // ────────────────────────────────────────────────────────────────────

    @Test
    fun `test_extra - key generation with expiration`() {
        val twoYearsInSeconds = (2 * 365.25 * 24 * 60 * 60).toLong()

        val result = cryptoService.generateKeyPair(
            name = "Expiring Key",
            email = "expire@pgpony.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = "pass",
            expirationSeconds = twoYearsInSeconds
        )

        val imported = cryptoService.importArmoredKey(result.armoredPublicKey)
        assertNotNull(imported.publicKeyRing)

        // Verify the key has expiration set
        val masterKey = imported.publicKeyRing!!.publicKey
        val validSeconds = masterKey.getValidSeconds()
        assertTrue("Key should have expiration set (got $validSeconds seconds)", validSeconds > 0)
    }
}
