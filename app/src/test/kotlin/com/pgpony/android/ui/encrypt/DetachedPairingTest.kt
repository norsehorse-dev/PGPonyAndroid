// DetachedPairingTest.kt
// PGPony Android 4.8.0 (#106): several files picked at once on Verify are
// sorted into signatures and data by content, and each signature is matched
// to its file by name.

package com.pgpony.android.ui.encrypt

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.ui.encrypt.DetachedPairing.SigMatch
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.Security

private class PairTestKey(val sec: PGPSecretKeyRing, val pub: PGPPublicKeyRing, val armoredPublic: String)

class DetachedPairingTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun installBouncyCastle() {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        private fun key(algorithm: KeyAlgorithm): PairTestKey {
            val k = PGPCryptoService.shared.generateKeyPair("Pair Test", "pair@example.com", algorithm, null, null)
            return PairTestKey(
                PGPSecretKeyRing(ByteArrayInputStream(k.privateKeyData), JcaKeyFingerprintCalculator()),
                PGPPublicKeyRing(ByteArrayInputStream(k.publicKeyData), JcaKeyFingerprintCalculator()),
                k.armoredPublicKey
            )
        }

        private val v4 by lazy { key(KeyAlgorithm.ED25519_CV25519) }
        private val v6 by lazy { key(KeyAlgorithm.V6_ED25519) }
    }

    private val content = "the signed file\n".toByteArray()

    private fun sign(k: PairTestKey, data: ByteArray = content, armor: Boolean) =
        SigningService.shared.signDetached(data = data, secretKeyRing = k.sec, armor = armor)

    // ── Classification by content ─────────────────────────────────────

    @Test
    fun armoredAndBinarySignatures_areSignatures() {
        assertTrue(DetachedPairing.isDetachedSignature(sign(v4, armor = true)))
        assertTrue(DetachedPairing.isDetachedSignature(sign(v4, armor = false)))
        assertTrue(DetachedPairing.isDetachedSignature(sign(v6, armor = true)))
        assertTrue(DetachedPairing.isDetachedSignature(sign(v6, armor = false)))
    }

    @Test
    fun armoredSignature_withBomOrLeadingProse_isASignature() {
        val armored = sign(v4, armor = true)
        val bom = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte())
        assertTrue(DetachedPairing.isDetachedSignature(bom + armored))
        assertTrue(DetachedPairing.isDetachedSignature("Signed release\r\n\r\n".toByteArray() + armored))
    }

    @Test
    fun clearSignedKeysMessagesAndOrdinaryFiles_areData() {
        val clear = SigningService.shared.signClear("hello", v4.sec).toByteArray()
        assertFalse(DetachedPairing.isDetachedSignature(clear))
        assertFalse(DetachedPairing.isDetachedSignature(v4.armoredPublic.toByteArray()))
        assertFalse(DetachedPairing.isDetachedSignature(v4.pub.encoded))
        val message = "-----BEGIN PGP MESSAGE-----\n\nwcBMA\n-----END PGP MESSAGE-----\n".toByteArray()
        assertFalse(DetachedPairing.isDetachedSignature(message))
        assertFalse(DetachedPairing.isDetachedSignature(content))
        assertFalse(DetachedPairing.isDetachedSignature(ByteArray(0)))
        // A PNG's first byte reads as an old-format signature header (#67).
        val png = byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte()) +
            ByteArray(100) { 1 }
        assertFalse(DetachedPairing.isDetachedSignature(png))
    }

    @Test
    fun aSignatureFollowedByItsFile_isData() {
        // A binary signature with other packets after it is a signed message
        // or something else, not a detached signature.
        assertFalse(DetachedPairing.isDetachedSignature(sign(v4, armor = false) + content))
    }

    // ── Pairing by name ───────────────────────────────────────────────

    @Test
    fun signatureExtensions_pairWithTheFileTheyName() {
        val r = DetachedPairing.pair(
            listOf("report.pdf.sig", "notes.txt.asc", "tool.tar.gz.sign", "data.bin.gpg"),
            listOf("notes.txt", "data.bin", "report.pdf", "tool.tar.gz")
        )
        assertEquals(
            listOf(SigMatch.Paired(2), SigMatch.Paired(0), SigMatch.Paired(3), SigMatch.Paired(1)),
            r.signatures
        )
        assertTrue(r.unpairedData.isEmpty())
    }

    @Test
    fun exactNameWins_overOneInAnotherCase() {
        val r = DetachedPairing.pair(listOf("Photo.JPG.asc"), listOf("photo.jpg", "Photo.JPG", "other.txt"))
        assertEquals(listOf(SigMatch.Paired(1)), r.signatures)
        assertEquals(listOf(0, 2), r.unpairedData)
        val caseOnly = DetachedPairing.pair(listOf("README.SIG", "x.sig"), listOf("readme"))
        assertEquals(SigMatch.Paired(0), caseOnly.signatures[0])
    }

    @Test
    fun gnupgNameWithoutTheFilesExtension_pairsWhenOnlyOneFileFits() {
        val r = DetachedPairing.pair(listOf("release.sig", "a.sig"), listOf("release.iso", "b.txt"))
        assertEquals(SigMatch.Paired(0), r.signatures[0])
        assertEquals(SigMatch.NotPicked, r.signatures[1])
        assertEquals(listOf(1), r.unpairedData)
    }

    @Test
    fun gnupgName_skipsAFileAnotherSignatureNamesExactly() {
        // report.txt has its own report.txt.sig, so report.sig can only be
        // the PDF's.
        val r = DetachedPairing.pair(
            listOf("report.sig", "report.txt.sig"),
            listOf("report.pdf", "report.txt")
        )
        assertEquals(listOf(SigMatch.Paired(0), SigMatch.Paired(1)), r.signatures)
    }

    @Test
    fun twoFilesThatBothFit_leaveTheSignatureAmbiguous() {
        val gnu = DetachedPairing.pair(listOf("report.sig", "z.sig"), listOf("report.pdf", "report.txt"))
        assertEquals(SigMatch.Ambiguous, gnu.signatures[0])
        assertEquals(listOf(0, 1), gnu.unpairedData)
        // Two picked files with the same display name, from different folders.
        val same = DetachedPairing.pair(listOf("a.txt.asc", "b.asc"), listOf("a.txt", "a.txt"))
        assertEquals(SigMatch.Ambiguous, same.signatures[0])
    }

    @Test
    fun oneSignatureAndOneFile_goTogetherWhateverTheirNames() {
        val r = DetachedPairing.pair(listOf("signature"), listOf("download (3)"))
        assertEquals(listOf(SigMatch.Paired(0)), r.signatures)
        assertTrue(r.unpairedData.isEmpty())
    }

    @Test
    fun unmatchedSignaturesAndFiles_areReported() {
        val r = DetachedPairing.pair(listOf("a.txt.sig", "b.txt.sig"), listOf("a.txt", "c.txt"))
        assertEquals(listOf(SigMatch.Paired(0), SigMatch.NotPicked), r.signatures)
        assertEquals(listOf(1), r.unpairedData)
        val noFiles = DetachedPairing.pair(listOf("a.txt.sig", "b.txt.asc"), emptyList())
        assertEquals(listOf(SigMatch.NotPicked, SigMatch.NotPicked), noFiles.signatures)
    }

    @Test
    fun twoSignaturesForOneFile_bothPairWithIt() {
        val r = DetachedPairing.pair(listOf("pkg.zip.asc", "pkg.zip.sig"), listOf("pkg.zip", "other.bin"))
        assertEquals(listOf(SigMatch.Paired(0), SigMatch.Paired(0)), r.signatures)
        assertEquals(listOf(1), r.unpairedData)
    }

    @Test
    fun signatureStem_stripsOnlyASignatureExtension() {
        assertEquals("file.txt", DetachedPairing.signatureStem("file.txt.SIG"))
        assertEquals("file.txt", DetachedPairing.signatureStem("file.txt.sign"))
        assertNull(DetachedPairing.signatureStem("file.txt"))
        assertNull(DetachedPairing.signatureStem(".sig"))
    }

    // ── A paired file verifies against its own signature ──────────────

    @Test
    fun pairedFiles_verifyAgainstTheirOwnSignatures() {
        val other = "a different file\n".toByteArray()
        val files = mapOf("a.txt" to content, "b.txt" to other)
        val sigs = listOf(
            "a.txt.asc" to sign(v4, content, armor = true),
            "b.txt.sig" to sign(v6, other, armor = false),
        )
        for ((_, bytes) in sigs) assertTrue(DetachedPairing.isDetachedSignature(bytes))
        val names = files.keys.toList()
        val r = DetachedPairing.pair(sigs.map { it.first }, names)
        r.signatures.forEachIndexed { i, m ->
            val paired = m as SigMatch.Paired
            val data = files.getValue(names[paired.dataIndex])
            val result = VerifyService.shared.verifyDetachedStream(
                sigs[i].second, ByteArrayInputStream(data), listOf(v4.pub, v6.pub)
            )
            assertTrue("expected Verified for ${sigs[i].first}, got $result", result is VerificationResult.Verified)
        }
        // The same signature over the other file does not verify.
        val crossed = VerifyService.shared.verifyDetachedStream(
            sigs[0].second, ByteArrayInputStream(other), listOf(v4.pub, v6.pub)
        )
        assertTrue(crossed is VerificationResult.Invalid)
    }
}
